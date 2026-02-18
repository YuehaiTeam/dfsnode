pub mod signature;

use std::sync::Arc;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::StatusCode;

use crate::auth::signature::SignatureVerifier;
use crate::config::cli::Args;
use crate::config::{FileConfig, SignatureSetting};

/// Credentials for basic auth.
#[derive(Clone)]
pub(crate) struct BasicCredentials {
    username: String,
    password: String,
}

/// Per-path signature rule.
#[derive(Clone)]
pub(crate) enum SignRule {
    /// No auth needed for GET on this path prefix.
    Open,
    /// Use a specific HMAC key for signature verification.
    Key(Arc<SignatureVerifier>),
}

/// Auth configuration shared by the middleware.
#[derive(Clone)]
pub struct AuthConfig {
    basic: Option<BasicCredentials>,
    /// Global signature verifier (used when no per-path override matches).
    sign_global: Option<Arc<SignatureVerifier>>,
    /// Per-path overrides, sorted by prefix length DESC (longest first).
    sign_overrides: Vec<(String, SignRule)>,
    /// The URL prefix to strip when computing the DAV path.
    prefix: String,
    /// When true, block GET downloads via HTTP/1.1 and HTTP/2 (H3 unaffected).
    pub no_tcp_download: bool,
}

impl AuthConfig {
    /// Find the effective sign rule for a DAV-relative path.
    ///
    /// Returns `(Some(rule), true)` if a per-path override matched,
    /// `(Some(global_key_rule), false)` if the global key applies,
    /// or `(None, false)` if no signing rule applies.
    /// Whether basic auth credentials are configured.
    pub fn has_basic_auth(&self) -> bool {
        self.basic.is_some()
    }

    /// Verify a GET-like download request without HTTP context.
    ///
    /// Used by WebTransport and other non-HTTP channels that cannot carry
    /// Basic Auth headers. Mirrors the auth middleware GET logic:
    ///
    /// 1. Per-path override → `Open` = allow, `Key` = verify signature
    /// 2. Global sign key → verify signature
    /// 3. No sign rule → if basic auth is also not configured, allow (open access);
    ///    otherwise deny (caller cannot provide basic auth)
    pub fn verify_signature(&self, uri_path: &str, sign_param: Option<&str>) -> bool {
        let dav_path = strip_prefix_path(uri_path, &self.prefix);
        let (rule, _has_override) = self.find_sign_rule(dav_path);

        match rule {
            Some(SignRule::Open) => true,
            Some(SignRule::Key(verifier)) => {
                let Some(sign_str) = sign_param else {
                    return false;
                };
                verifier.verify(uri_path, sign_str, None).is_ok()
            }
            None => !self.has_basic_auth(),
        }
    }

    pub fn find_sign_rule(&self, dav_path: &str) -> (Option<SignRule>, bool) {
        // Check per-path overrides first (already sorted longest-prefix-first)
        if let Some((_, rule)) = self
            .sign_overrides
            .iter()
            .find(|(prefix, _)| dav_path.starts_with(prefix.as_str()))
        {
            return (Some(rule.clone()), true);
        }

        // Fall back to global
        if let Some(ref global) = self.sign_global {
            return (Some(SignRule::Key(global.clone())), false);
        }

        (None, false)
    }
}

/// Unified auth middleware:
/// - --no-tcp-download: block GET downloads via H1/H2 (non-management paths)
/// - GET requests: check per-path overrides first, then global signature, then basic auth
/// - Non-GET: basic auth only
pub async fn auth_middleware(
    config: AuthConfig,
    req: Request,
    next: Next,
) -> Response {
    // Block H1/H2 GET downloads when --no-tcp-download is active.
    // Management paths (/-/) and non-GET methods are always allowed.
    // H3 requests never reach this middleware (they go through Quinn, not TCP listener).
    if config.no_tcp_download
        && req.method() == http::Method::GET
        && !req.uri().path().starts_with("/-/")
    {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(http::header::ALLOW, "PROPFIND, LOCK, OPTIONS, HEAD")],
            "TCP downloads disabled. Use H3, WebTransport, or WebRTC.",
        )
            .into_response();
    }

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
    if let Some(creds) = &config.basic
        && !check_basic_auth(&req, creds) {
            return (
                StatusCode::UNAUTHORIZED,
                [(http::header::WWW_AUTHENTICATE, "Basic realm=\"WebDAV\"")],
                "Unauthorized",
            )
                .into_response();
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
pub fn extract_sign_param(query: &str) -> Option<String> {
    for part in query.split('&') {
        // Handle both `$=value` and `%24=value` (URL-encoded `$`)
        if let Some(value) = part.strip_prefix("$=").or_else(|| part.strip_prefix("%24="))
            && !value.is_empty() {
                return Some(value.to_string());
            }
    }
    None
}

/// Build AuthConfig from CLI args (legacy mode, no config file).
pub fn build_auth_from_args(args: &Args) -> AuthConfig {
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
        no_tcp_download: args.no_tcp_download,
    }
}

/// Build AuthConfig from a parsed config file.
pub fn build_auth_from_config(file_config: &FileConfig, prefix: &str) -> AuthConfig {
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
        no_tcp_download: false,
    }
}
