mod checksum;
mod cli;
mod config;
mod server;
mod signature;
mod tls;
mod tus;
mod tus_middleware;
mod webdav;

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use clap::Parser;
use dav_server::DavHandler;
use dav_server::localfs::LocalFs;
use dav_server::memls::MemLs;
use http::StatusCode;
use tracing::info;

use crate::checksum::{ChecksumAlgorithm, ChecksumManager};
use crate::cli::Args;
use crate::config::{FileConfig, SignatureSetting, load_config};
use crate::signature::SignatureVerifier;
use crate::tus::{TusConfig, TusUploadManager};
use crate::tus_middleware::tus_routes;
use crate::webdav::ChecksumAwareFileSystem;

/// Credentials for basic auth.
#[derive(Clone)]
struct BasicCredentials {
    username: String,
    password: String,
}

/// Per-path signature rule.
#[derive(Clone)]
enum SignRule {
    /// No auth needed for GET on this path prefix.
    Open,
    /// Use a specific HMAC key for signature verification.
    Key(Arc<SignatureVerifier>),
}

/// Auth configuration shared by the middleware.
#[derive(Clone)]
struct AuthConfig {
    basic: Option<BasicCredentials>,
    /// Global signature verifier (used when no per-path override matches).
    sign_global: Option<Arc<SignatureVerifier>>,
    /// Per-path overrides, sorted by prefix length DESC (longest first).
    sign_overrides: Vec<(String, SignRule)>,
    /// The URL prefix to strip when computing the DAV path.
    prefix: String,
}

/// Unified auth middleware:
/// - GET requests: check per-path overrides first, then global signature, then basic auth
/// - Non-GET: basic auth only
async fn auth_middleware(
    config: AuthConfig,
    req: Request,
    next: Next,
) -> Response {
    if req.method() == http::Method::GET {
        let uri_path = req.uri().path();

        // Compute the DAV-relative path by stripping the prefix
        let dav_path = strip_prefix_path(uri_path, &config.prefix);

        // Find longest matching prefix in sign_overrides
        let matched_rule = config
            .sign_overrides
            .iter()
            .find(|(prefix, _)| dav_path.starts_with(prefix.as_str()));

        // Determine which verifier (if any) to use
        let effective_verifier: Option<&Arc<SignatureVerifier>> = if let Some((_, rule)) = matched_rule {
            match rule {
                SignRule::Open => {
                    // Open path — no auth at all for GET
                    return next.run(req).await;
                }
                SignRule::Key(v) => Some(v),
            }
        } else {
            // No override matched — use global
            config.sign_global.as_ref()
        };

        // Try signature verification if `$` param is present
        if let Some(verifier) = effective_verifier {
            let query = req.uri().query().unwrap_or("");
            if let Some(sign_str) = extract_sign_param(query) {
                let path = req.uri().path();
                let range_header = req
                    .headers()
                    .get(http::header::RANGE)
                    .and_then(|v| v.to_str().ok());
                match verifier.verify(path, &sign_str, range_header) {
                    Ok(()) => return next.run(req).await,
                    Err(e) => {
                        tracing::warn!("Signature verification failed: {e}");
                        return (StatusCode::FORBIDDEN, format!("Forbidden: {e}"))
                            .into_response();
                    }
                }
            }
        }
    }

    // Fall through to basic auth
    if let Some(creds) = &config.basic {
        if !check_basic_auth(&req, creds) {
            return (
                StatusCode::UNAUTHORIZED,
                [(http::header::WWW_AUTHENTICATE, "Basic realm=\"WebDAV\"")],
                "Unauthorized",
            )
                .into_response();
        }
    }

    next.run(req).await
}

/// Strip the configured prefix from a URI path to get the DAV-relative path.
fn strip_prefix_path<'a>(uri_path: &'a str, prefix: &str) -> &'a str {
    if prefix == "/" {
        uri_path
    } else {
        uri_path
            .strip_prefix(prefix)
            .unwrap_or(uri_path)
    }
}

/// Validate the Authorization header against expected credentials.
fn check_basic_auth(req: &Request, creds: &BasicCredentials) -> bool {
    let Some(auth_header) = req.headers().get(http::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(auth_str) = auth_header.to_str() else {
        return false;
    };
    let Some(encoded) = auth_str.strip_prefix("Basic ") else {
        return false;
    };
    use base64::Engine;
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(decoded_str) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((user, pass)) = decoded_str.split_once(':') else {
        return false;
    };
    user == creds.username && pass == creds.password
}

/// Extract the `$` query parameter value from a query string.
fn extract_sign_param(query: &str) -> Option<String> {
    for part in query.split('&') {
        // Handle both `$=value` and `%24=value` (URL-encoded `$`)
        if let Some(value) = part.strip_prefix("$=").or_else(|| part.strip_prefix("%24=")) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn build_router(
    root: &std::path::Path,
    prefix: &str,
    auth: AuthConfig,
    tus_manager: Option<Arc<TusUploadManager>>,
) -> Router {
    let inner = LocalFs::new(root, true, false, false);
    let checksum_manager = ChecksumManager::new(vec![
        ChecksumAlgorithm::SHA1,
        ChecksumAlgorithm::MD5,
    ]);

    let fs = ChecksumAwareFileSystem::new(inner, checksum_manager, root.to_path_buf());

    let mut builder = DavHandler::builder()
        .filesystem(Box::new(fs))
        .locksystem(MemLs::new());

    if prefix != "/" {
        builder = builder.strip_prefix(prefix);
    }

    let dav = Arc::new(builder.build_handler());

    let mut router = Router::new();

    // If TUS is enabled, merge TUS routes BEFORE the DavHandler fallback
    if let Some(mgr) = tus_manager {
        router = router.merge(tus_routes(prefix, mgr, root.to_path_buf()));
    }

    router
        .fallback(move |req: axum::extract::Request| {
            let dav = dav.clone();
            async move { dav.handle(req).await }
        })
        .layer(middleware::from_fn(move |req, next| {
            let auth = auth.clone();
            auth_middleware(auth, req, next)
        }))
}

/// Build AuthConfig from CLI args (legacy mode, no config file).
fn build_auth_from_args(args: &Args) -> AuthConfig {
    AuthConfig {
        basic: args
            .username
            .as_ref()
            .zip(args.password.as_ref())
            .map(|(u, p)| BasicCredentials {
                username: u.clone(),
                password: p.clone(),
            }),
        sign_global: args
            .sign_key
            .as_deref()
            .map(|key| Arc::new(SignatureVerifier::new(key))),
        sign_overrides: Vec::new(),
        prefix: args.prefix.clone(),
    }
}

/// Build AuthConfig from a parsed config file.
fn build_auth_from_config(file_config: &FileConfig, prefix: &str) -> AuthConfig {
    let basic = file_config
        .username
        .as_ref()
        .zip(file_config.password.as_ref())
        .map(|(u, p)| BasicCredentials {
            username: u.clone(),
            password: p.clone(),
        });

    let sign_global = file_config
        .sign_key
        .as_deref()
        .map(|key| Arc::new(SignatureVerifier::new(key)));

    // Build per-path overrides
    let mut sign_overrides: Vec<(String, SignRule)> = Vec::new();
    if let Some(paths) = &file_config.paths {
        for (path_prefix, path_config) in paths {
            if let Some(sig_setting) = &path_config.signature {
                let rule = match sig_setting {
                    SignatureSetting::Open(false) => SignRule::Open,
                    SignatureSetting::Open(true) => {
                        // true = use global key
                        if let Some(ref global) = sign_global {
                            SignRule::Key(global.clone())
                        } else {
                            // No global key configured but signature: true — treat as no override
                            continue;
                        }
                    }
                    SignatureSetting::Key(key) => {
                        SignRule::Key(Arc::new(SignatureVerifier::new(key)))
                    }
                };
                sign_overrides.push((path_prefix.clone(), rule));
            }
        }
    }

    // Sort by prefix length descending (longest match first)
    sign_overrides.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

    AuthConfig {
        basic,
        sign_global,
        sign_overrides,
        prefix: prefix.to_string(),
    }
}

/// Build TusConfig + temp_dir from a parsed config file's TUS section.
fn build_tus_from_config(
    tus_file: &crate::config::TusFileConfig,
    root: &std::path::Path,
) -> (TusConfig, PathBuf) {
    let config = TusConfig {
        enabled: tus_file.enabled.unwrap_or(true),
        upload_timeout_hours: tus_file.upload_timeout_hours.unwrap_or(24),
        max_concurrent_uploads: tus_file.max_concurrent_uploads.unwrap_or(100),
        max_upload_size: tus_file.max_upload_size.unwrap_or(5 * 1024 * 1024 * 1024),
    };

    let temp_dir = tus_file
        .temp_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".tus-tmp"));

    (config, temp_dir)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    args.validate()?;

    let root = PathBuf::from(&args.root).canonicalize()?;
    info!("Serving directory: {}", root.display());

    // Load config file or use CLI args
    let file_config: Option<FileConfig> = if let Some(config_path) = &args.config {
        let path = std::path::Path::new(config_path);
        let cfg = load_config(path)?;
        info!("Loaded config from: {}", config_path);
        Some(cfg)
    } else {
        None
    };

    // Build auth
    let auth = if let Some(ref fc) = file_config {
        build_auth_from_config(fc, &args.prefix)
    } else {
        build_auth_from_args(&args)
    };

    // Build TUS manager (if configured)
    let tus_manager: Option<Arc<TusUploadManager>> = if let Some(ref fc) = file_config {
        if let Some(ref tus_file) = fc.tus {
            let (tus_config, temp_dir) = build_tus_from_config(tus_file, &root);
            if tus_config.enabled {
                let mgr = TusUploadManager::new(temp_dir, tus_config)?;
                info!("TUS resumable uploads enabled");
                Some(Arc::new(mgr))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Spawn TUS cleanup task if enabled
    if let Some(ref mgr) = tus_manager {
        let cleanup_mgr = mgr.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = cleanup_mgr.cleanup_expired_sessions().await {
                    tracing::warn!("TUS cleanup error: {e}");
                }
            }
        });
    }

    let app = build_router(&root, &args.prefix, auth, tus_manager);

    let mut handles = Vec::new();

    // HTTP server
    if let Some(port) = args.http_port {
        let app = app.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = server::http::serve(port, app).await {
                tracing::error!("HTTP server error: {e}");
            }
        }));
    }

    // HTTPS server
    if let Some(port) = args.https_port {
        let app = app.clone();
        let cert = PathBuf::from(args.cert.as_ref().unwrap());
        let key = PathBuf::from(args.key.as_ref().unwrap());
        handles.push(tokio::spawn(async move {
            if let Err(e) = server::https::serve(port, &cert, &key, app).await {
                tracing::error!("HTTPS server error: {e}");
            }
        }));
    }

    // HTTP/3 server
    if let Some(port) = args.http3_port {
        let app = app.clone();
        let cert = PathBuf::from(args.cert.as_ref().unwrap());
        let key = PathBuf::from(args.key.as_ref().unwrap());
        handles.push(tokio::spawn(async move {
            if let Err(e) = server::http3::serve(port, &cert, &key, app).await {
                tracing::error!("HTTP/3 server error: {e}");
            }
        }));
    }

    info!("All servers started. Press Ctrl+C to stop.");

    // Wait for all servers (they run indefinitely)
    for handle in handles {
        handle.await?;
    }

    Ok(())
}
