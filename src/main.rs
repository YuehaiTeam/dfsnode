mod auth;
mod config;
mod dav;
mod metrics;
mod panic_recovery;
mod rtc;
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
use tracing::info;

use crate::auth::{AuthConfig, auth_middleware, build_auth_from_args, build_auth_from_config};
use crate::config::cli::Args;
use crate::config::{FileConfig, load_config};
use crate::dav::ChecksumAwareFileSystem;
use crate::dav::checksum::{ChecksumAlgorithm, ChecksumManager};
use crate::server::selfsign::RotatingCertResolver;
use crate::stun::StunConfig;
use crate::tus::{TusConfig, TusUploadManager};
use crate::tus::handler::tus_routes;

fn build_router(
    root: &std::path::Path,
    prefix: &str,
    auth: AuthConfig,
    tus_manager: Option<Arc<TusUploadManager>>,
    rtc_state: Option<rtc::handler::RtcState>,
) -> Router {
    let inner = LocalFs::new(root, true, false, false);
    let checksum_manager = ChecksumManager::new(vec![
        ChecksumAlgorithm::SHA1,
        ChecksumAlgorithm::MD5,
    ]);

    let fs = ChecksumAwareFileSystem::new(inner, checksum_manager, root.to_path_buf());

    let mut builder = DavHandler::builder()
        .filesystem(Box::new(fs));

    if prefix != "/" {
        builder = builder.strip_prefix(prefix);
    }

    let dav = Arc::new(builder.build_handler());

    let mut router = Router::new()
        .route("/-/ping", axum::routing::get(|| async { "pong" }))
        .route("/-/metrics", axum::routing::get(|| async {
            let body = metrics::gather_metrics();
            (
                axum::http::StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                body,
            )
        }))
        .route("/minio/metrics/v3/bucket/api/dfs", {
            let credentials: Option<(String, String)> = auth.basic_username()
                .zip(auth.basic_password())
                .map(|(u, p)| (u.to_string(), p.to_string()));
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let credentials = credentials.clone();
                async move {
                    // If basic auth is configured, require either a valid MinIO JWT or Basic Auth
                    if let Some((ref username, ref password)) = credentials {
                        let auth_header = headers
                            .get(axum::http::header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok());

                        let authorized = match auth_header {
                            // MinIO-compatible JWT: Bearer <token>
                            Some(h) if h.starts_with("Bearer ") => {
                                metrics::validate_minio_jwt(&h[7..], password)
                            }
                            // WebDAV Basic Auth: Basic <base64>
                            Some(h) if h.starts_with("Basic ") => {
                                use base64::Engine;
                                base64::engine::general_purpose::STANDARD
                                    .decode(&h[6..])
                                    .ok()
                                    .and_then(|bytes| String::from_utf8(bytes).ok())
                                    .map(|decoded| {
                                        decoded.split_once(':')
                                            .map(|(u, p)| u == username && p == password)
                                            .unwrap_or(false)
                                    })
                                    .unwrap_or(false)
                            }
                            _ => false,
                        };

                        if !authorized {
                            return (
                                axum::http::StatusCode::UNAUTHORIZED,
                                [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                                String::from("Unauthorized"),
                            );
                        }
                    }
                    let body = metrics::gather_minio_compat_metrics();
                    (
                        axum::http::StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                        body,
                    )
                }
            })
        });

    // If TUS is enabled, merge TUS routes BEFORE the DavHandler fallback
    if let Some(mgr) = tus_manager {
        router = router.merge(tus_routes(prefix, mgr, root.to_path_buf()));
    }

    // Build the fallback that handles both LOCK (WebRTC signaling) and
    // regular WebDAV methods.  LOCK is checked first; everything else
    // falls through to the DavHandler.
    let lock_prefix = prefix.to_string();
    router
        .fallback(move |req: axum::extract::Request| {
            let dav = dav.clone();
            let rtc_state = rtc_state.clone();
            let prefix = lock_prefix.clone();
            async move {
                use axum::response::IntoResponse;

                // Check for LOCK method — dispatch to WebRTC handler
                if req.method().as_str() == "LOCK" {
                    if let Some(state) = rtc_state {
                        return handle_lock(state, &prefix, req).await;
                    }
                    // RTC not enabled — LOCK is not supported
                    return axum::http::StatusCode::NOT_IMPLEMENTED.into_response();
                }

                // All other methods → DavHandler
                dav.handle(req).await.into_response()
            }
        })
        .layer(middleware::from_fn(move |req, next| {
            let auth = auth.clone();
            auth_middleware(auth, req, next)
        }))
}

/// Extract the file-relative path from the request URI, strip the DAV prefix,
/// parse the JSON body, and forward to [`rtc::handler::lock_handler`].
async fn handle_lock(
    rtc_state: rtc::handler::RtcState,
    prefix: &str,
    req: axum::extract::Request,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // Strip prefix from URI path to get the file-relative path.
    let uri_path = req.uri().path().to_string();
    let rel_path = if prefix != "/" && !prefix.is_empty() {
        uri_path
            .strip_prefix(prefix.trim_end_matches('/'))
            .unwrap_or(&uri_path)
            .to_string()
    } else {
        uri_path
    };

    // Parse JSON body
    let body_bytes = match axum::body::to_bytes(req.into_body(), 64 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({ "error": format!("Failed to read body: {e}") })),
            )
                .into_response();
        }
    };

    let lock_req: rtc::handler::LockRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({ "error": format!("Invalid JSON: {e}") })),
            )
                .into_response();
        }
    };

    // Call the actual lock handler (passing state, path, parsed body directly).
    rtc::handler::lock_handler(
        axum::extract::State(rtc_state),
        rel_path,
        axum::Json(lock_req),
    )
    .await
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

const TOKIO_WORKER_STACK_SIZE: usize = 16 * 1024 * 1024;

fn main() -> anyhow::Result<()> {
    // Install the ring crypto provider before any rustls usage (quinn, tokio-rustls, etc.)
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(TOKIO_WORKER_STACK_SIZE)
        .build()?;

    rt.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {

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
    let mut auth = if let Some(ref fc) = file_config {
        build_auth_from_config(fc, &args.prefix)
    } else {
        build_auth_from_args(&args)
    };
    // Override no_tcp_download from CLI (config file doesn't have this setting)
    if args.no_tcp_download {
        auth.no_tcp_download = true;
    }

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
        panic_recovery::spawn_catch_panic("tus-cleanup", async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = cleanup_mgr.cleanup_expired_sessions().await {
                    tracing::warn!("TUS cleanup error: {e}");
                }
            }
        });
    }

    // -------------------------------------------------------------------
    // WebRTC DataChannel setup — create channels + handle BEFORE
    // build_router so the LOCK route is wired into the fallback.
    // The actual RtcManager is spawned later once we have the UDP socket.
    // -------------------------------------------------------------------
    let rtc_packet_tx = if args.enable_rtc {
        Some(tokio::sync::mpsc::channel::<(Vec<u8>, std::net::SocketAddr)>(1024))
    } else {
        None
    };
    let (rtc_tx_for_h3, rtc_rx_for_manager) = match rtc_packet_tx {
        Some((tx, rx)) => (Some(tx), Some(rx)),
        None => (None, None),
    };

    let (rtc_handle_holder, rtc_rx_holder) = if let Some(rtc_rx) = rtc_rx_for_manager {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<rtc::CreateSessionCmd>(32);
        let handle = rtc::RtcHandle::new(cmd_tx);
        (Some(handle), Some((cmd_rx, rtc_rx)))
    } else {
        (None, None)
    };

    let rtc_state_for_router = rtc_handle_holder.as_ref().map(|handle| {
        rtc::handler::RtcState {
            rtc_handle: handle.clone(),
            root: root.clone(),
            prefix: args.prefix.clone(),
        }
    });

    let app = build_router(&root, &args.prefix, auth.clone(), tus_manager, rtc_state_for_router);

    // Determine TLS source: file-based or self-signed
    let needs_tls = args.https_port.is_some() || args.http3_port.is_some();
    let tls_source: Option<TlsSource> = if needs_tls {
        if let (Some(cert_path), Some(key_path)) = (&args.cert, &args.key) {
            let cert = PathBuf::from(cert_path);
            let key = PathBuf::from(key_path);

            // --ssl-generate: check cert validity & system trust, regenerate if needed
            if args.ssl_generate {
                match server::ssl_generate::maybe_regenerate_cert(&cert, &key) {
                    Ok(true) => info!("Certificate was regenerated"),
                    Ok(false) => {}
                    Err(e) => tracing::warn!("Certificate check failed: {e}"),
                }
            }

            info!("Using TLS certificate from: {}", cert.display());
            Some(TlsSource::File { cert, key })
        } else {
            info!("No certificate provided — generating self-signed certificate (7-day validity)");
            let resolver = RotatingCertResolver::new()?;
            Some(TlsSource::SelfSigned(resolver))
        }
    } else {
        None
    };

    // Resolve STUN config (CLI > config file > none)
    let stun_config: Option<StunConfig> = {
        // Collect server strings: CLI args take priority, fallback to config file
        let server_strs: Vec<String> = if !args.stun_server.is_empty() {
            args.stun_server.clone()
        } else if let Some(ref fc) = file_config {
            fc.stun.as_ref().map(|s| s.all_servers()).unwrap_or_default()
        } else {
            vec![]
        };

        let stun_interval_secs = args.stun_interval_secs.or_else(|| {
            file_config
                .as_ref()
                .and_then(|fc| fc.stun.as_ref())
                .and_then(|s| s.interval_secs)
        });

        if !server_strs.is_empty() {
            use std::net::ToSocketAddrs;
            let mut all_addrs = Vec::new();
            for server_str in &server_strs {
                match server_str.to_socket_addrs() {
                    Ok(addrs) => {
                        let resolved: Vec<_> = addrs.map(stun::normalize_addr).collect();
                        if resolved.is_empty() {
                            tracing::warn!("STUN server '{server_str}' resolved to no addresses");
                        } else {
                            for addr in &resolved {
                                info!("STUN server '{server_str}' resolved to {addr}");
                            }
                            all_addrs.extend(resolved);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to resolve STUN server '{server_str}': {e}");
                    }
                }
            }
            if all_addrs.is_empty() {
                anyhow::bail!("No STUN server addresses could be resolved");
            }
            // Deduplicate
            all_addrs.sort();
            all_addrs.dedup();
            let interval = Duration::from_secs(stun_interval_secs.unwrap_or(20));
            info!(
                "STUN NAT traversal configured: {} address(es) (interval: {interval:?})",
                all_addrs.len()
            );
            Some(StunConfig { servers: all_addrs, interval })
        } else {
            None
        }
    };

    let mut handles = Vec::new();
    let mut h3_endpoint: Option<quinn::Endpoint> = None;

    // HTTP server
    if let Some(port) = args.http_port {
        let http_app = app.clone().layer(server::metrics_layer::MetricsLayer::new("http"));
        handles.push(panic_recovery::spawn_catch_panic("http-server", async move {
            if let Err(e) = server::http::serve(port, http_app).await {
                tracing::error!("HTTP server error: {e}");
            }
        }));
    }

    // SSH server (HTTP-over-SSH via direct-tcpip port forwarding)
    if let Some(port) = args.ssh_port {
        let host_key = args
            .ssh_host_key
            .clone()
            .expect("validate() ensures ssh_host_key is present when ssh_port is set");
        let ssh_app = app.clone().layer(server::metrics_layer::MetricsLayer::new("ssh"));
        let ssh_auth = auth.clone();
        let ssh_root = root.clone();
        let ssh_prefix = args.prefix.clone();
        handles.push(panic_recovery::spawn_catch_panic("ssh-server", async move {
            if let Err(e) = server::ssh::serve(port, &PathBuf::from(host_key), ssh_app, ssh_auth, ssh_root, ssh_prefix).await {
                tracing::error!("SSH server error: {e}");
            }
        }));
    }

    // HTTPS server
    if let Some(port) = args.https_port {
        let https_app = app.clone().layer(server::metrics_layer::MetricsLayer::new("http"));
        let https_config = match tls_source.as_ref().unwrap() {
            TlsSource::File { cert, key } => server::tls::build_https_config(cert, key)?,
            TlsSource::SelfSigned(resolver) => {
                server::selfsign::build_https_config_dynamic(resolver.clone())
            }
        };
        handles.push(panic_recovery::spawn_catch_panic("https-server", async move {
            if let Err(e) = server::https::serve(port, https_config, https_app).await {
                tracing::error!("HTTPS server error: {e}");
            }
        }));
    }

    // HTTP/3 server (with optional STUN NAT traversal + WebTransport)
    if let Some(port) = args.http3_port {
        let h3_app = app.clone().layer(server::metrics_layer::MetricsLayer::new("h3"));
        let quic_config = match tls_source.as_ref().unwrap() {
            TlsSource::File { cert, key } => server::tls::build_quic_config(cert, key)?,
            TlsSource::SelfSigned(resolver) => {
                server::selfsign::build_quic_config_self_signed(resolver)?
            }
        };
        let wt_config = server::webtransport::WtConfig {
            auth: auth.clone(),
            root: root.clone(),
            prefix: args.prefix.clone(),
        };
        let h3_handle = server::http3::spawn(port, quic_config, h3_app, stun_config, wt_config, rtc_tx_for_h3)?;

        // Log public address discovery in background (if STUN enabled)
        // and optionally notify via webhook.
        // Clone the receiver before moving into the webhook task so the
        // RtcManager can also observe public address changes.
        let public_addr_for_rtc = h3_handle.public_addr.clone();
        let mut public_addr_rx = h3_handle.public_addr;
        let webhook_url = args.webhook_url.clone().or_else(|| {
            file_config.as_ref().and_then(|fc| fc.webhook_url.clone())
        });
        panic_recovery::spawn_catch_panic("addr-watcher", async move {
            // Build a reusable HTTP client for webhook calls
            let webhook_client = webhook_url.as_deref().map(|raw_url| {
                build_webhook_client(raw_url)
            });

            while public_addr_rx.changed().await.is_ok() {
                let addrs: std::collections::HashSet<std::net::SocketAddr> = public_addr_rx.borrow_and_update().clone();
                if addrs.is_empty() {
                    continue;
                }
                // borrow dropped here (cloned) — safe to .await below
                let addrs_str: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
                let body = addrs_str.join(",");
                info!("Public UDP endpoint(s) available: {body}");

                // Fire webhook if configured
                if let Some(Ok((client, url, auth))) = &webhook_client {
                    let mut req = client.post(url.clone()).body(body.clone());
                    if let Some((user, pass)) = auth {
                        req = req.basic_auth(user, Some(pass));
                    }
                    match req.send().await {
                        Ok(resp) => {
                            info!("Webhook notified: {body} → {} {}", url, resp.status());
                        }
                        Err(e) => {
                            tracing::warn!("Webhook failed: {e}");
                        }
                    }
                }
            }
        });

        h3_endpoint = Some(h3_handle.endpoint);

        // Spawn RtcManager if WebRTC is enabled
        if let Some((cmd_rx, rtc_rx)) = rtc_rx_holder {
            let udp_tx = h3_handle
                .udp_socket
                .expect("WebRTC requires STUN — udp_socket must be present");

            let manager = rtc::RtcManager::from_parts(
                udp_tx,
                public_addr_for_rtc,
                rtc_rx,
                cmd_rx,
            );

            panic_recovery::spawn_catch_panic("rtc-manager", manager.run());
            info!("WebRTC DataChannel enabled (LOCK method signaling)");
        }

        handles.push(panic_recovery::spawn_catch_panic("h3-server", async move {
            if let Err(e) = h3_handle.task.await {
                tracing::error!("HTTP/3 server error: {e}");
            }
        }));
    }

    // Spawn self-signed cert refresh task if using auto-generated certs
    if let Some(TlsSource::SelfSigned(resolver)) = tls_source {
        server::selfsign::spawn_refresh_task(resolver, h3_endpoint);
    }

    // --- Metrics push ---
    // Merge URLs from CLI and config file; if both define an interval, take the smaller.
    {
        let mut push_urls: Vec<String> = args.metrics_push_url.clone();
        let mut interval_secs: Option<u64> = args.metrics_push_interval_secs;

        if let Some(ref mp) = file_config.as_ref().and_then(|c| c.metrics_push.as_ref()) {
            push_urls.extend(mp.all_urls());
            if let Some(cfg_interval) = mp.interval_secs {
                interval_secs = Some(match interval_secs {
                    Some(cli_interval) => cli_interval.min(cfg_interval),
                    None => cfg_interval,
                });
            }
        }

        if !push_urls.is_empty() {
            let interval = std::time::Duration::from_secs(interval_secs.unwrap_or(15));
            info!(
                "Starting metrics push to {} target(s), interval={}s",
                push_urls.len(),
                interval.as_secs()
            );
            metrics::spawn_metrics_push(push_urls, interval);
        }
    }

    info!("All servers started. Press Ctrl+C to stop.");

    // Wait for all servers (they run indefinitely)
    for handle in handles {
        handle.await?;
    }

    Ok(())
}

enum TlsSource {
    File { cert: PathBuf, key: PathBuf },
    SelfSigned(Arc<RotatingCertResolver>),
}

/// Parse a webhook URL, extracting optional basic auth credentials.
///
/// Supports URLs like `https://user:pass@host/path` — the credentials are
/// stripped from the URL and returned separately for use with reqwest's
/// `.basic_auth()`.
type WebhookConfig = (reqwest::Client, String, Option<(String, String)>);

fn build_webhook_client(raw_url: &str) -> anyhow::Result<WebhookConfig> {
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
