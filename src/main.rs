mod auth;
mod config;
mod dav;
mod server;
mod stun;
mod tus;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware;
use clap::Parser;
use dav_server::DavHandler;
use dav_server::localfs::LocalFs;
use dav_server::memls::MemLs;
use tracing::info;

use crate::auth::{AuthConfig, auth_middleware, build_auth_from_args, build_auth_from_config};
use crate::config::cli::Args;
use crate::config::{FileConfig, load_config};
use crate::dav::ChecksumAwareFileSystem;
use crate::dav::checksum::{ChecksumAlgorithm, ChecksumManager};
use crate::stun::StunConfig;
use crate::tus::{TusConfig, TusUploadManager};
use crate::tus::handler::tus_routes;

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

    let mut router = Router::new()
        .route("/-/ping", axum::routing::get(|| async { "pong" }));

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
    // Install the ring crypto provider before any rustls usage (quinn, tokio-rustls, etc.)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

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

    // Resolve STUN config (CLI > config file > none)
    let stun_config: Option<StunConfig> = {
        let stun_server_str = args.stun_server.as_deref().or_else(|| {
            file_config
                .as_ref()
                .and_then(|fc| fc.stun.as_ref())
                .and_then(|s| s.server.as_deref())
        });
        let stun_interval_secs = args.stun_interval_secs.or_else(|| {
            file_config
                .as_ref()
                .and_then(|fc| fc.stun.as_ref())
                .and_then(|s| s.interval_secs)
        });

        if let Some(server_str) = stun_server_str {
            // Resolve STUN server address (DNS lookup at startup)
            use std::net::ToSocketAddrs;
            let server = server_str
                .to_socket_addrs()?
                .find(|a| a.is_ipv4()) // Prefer IPv4 for NAT traversal
                .or_else(|| server_str.to_socket_addrs().ok()?.next())
                .ok_or_else(|| anyhow::anyhow!("Failed to resolve STUN server: {server_str}"))?;
            let interval = Duration::from_secs(stun_interval_secs.unwrap_or(20));
            info!("STUN NAT traversal configured: {server} (interval: {interval:?})");
            Some(StunConfig { server, interval })
        } else {
            None
        }
    };

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

    // HTTP/3 server (with optional STUN NAT traversal)
    if let Some(port) = args.http3_port {
        let app = app.clone();
        let cert = PathBuf::from(args.cert.as_ref().unwrap());
        let key = PathBuf::from(args.key.as_ref().unwrap());
        let h3_handle = server::http3::spawn(port, &cert, &key, app, stun_config)?;

        // Log public address discovery in background (if STUN enabled)
        // and optionally notify via webhook
        let mut public_addr_rx = h3_handle.public_addr;
        let webhook_url = args.webhook_url.clone().or_else(|| {
            file_config.as_ref().and_then(|fc| fc.webhook_url.clone())
        });
        tokio::spawn(async move {
            // Build a reusable HTTP client for webhook calls
            let webhook_client = webhook_url.as_deref().map(|raw_url| {
                build_webhook_client(raw_url)
            });

            while public_addr_rx.changed().await.is_ok() {
                let addr = match *public_addr_rx.borrow_and_update() {
                    Some(a) => a,
                    None => continue,
                };
                // borrow dropped here — safe to .await below
                info!("Public UDP endpoint available at: {addr}");

                // Fire webhook if configured
                if let Some(Ok((client, url, auth))) = &webhook_client {
                    let body = addr.to_string();
                    let mut req = client.post(url.clone()).body(body);
                    if let Some((user, pass)) = auth {
                        req = req.basic_auth(user, Some(pass));
                    }
                    match req.send().await {
                        Ok(resp) => {
                            info!("Webhook notified: {addr} → {} {}", url, resp.status());
                        }
                        Err(e) => {
                            tracing::warn!("Webhook failed: {e}");
                        }
                    }
                }
            }
        });

        handles.push(tokio::spawn(async move {
            if let Err(e) = h3_handle.task.await {
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

/// Parse a webhook URL, extracting optional basic auth credentials.
///
/// Supports URLs like `https://user:pass@host/path` — the credentials are
/// stripped from the URL and returned separately for use with reqwest's
/// `.basic_auth()`.
fn build_webhook_client(
    raw_url: &str,
) -> anyhow::Result<(reqwest::Client, String, Option<(String, String)>)> {
    let parsed = url::Url::parse(raw_url)
        .map_err(|e| anyhow::anyhow!("Invalid webhook URL: {e}"))?;

    // Extract basic auth from URL
    let auth = if !parsed.username().is_empty() {
        Some((
            parsed.username().to_string(),
            parsed.password().unwrap_or("").to_string(),
        ))
    } else {
        None
    };

    // Rebuild URL without credentials
    let mut clean = parsed.clone();
    let _ = clean.set_username("");
    let _ = clean.set_password(None);
    let clean_url = clean.to_string();

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    Ok((client, clean_url, auth))
}
