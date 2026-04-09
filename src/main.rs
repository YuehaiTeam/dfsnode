mod auth;
mod config;
mod dav;
mod metrics;
mod panic_recovery;
mod path_policy;
mod rtc;
mod runtime_config;
mod server;
mod stun;
mod tus;
mod windows_service;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::middleware;
use axum_client_ip::ClientIpSource;
use clap::Parser;
use dav_server::DavHandler;
use dav_server::localfs::LocalFs;
use tracing::{debug, info};

use crate::auth::{AuthConfig, auth_middleware, build_auth_from_args, build_auth_from_live_config, extract_sign_param, extract_uuid_from_sign};
use crate::config::cli::{Cli, Command, RunArgs, WindowsServiceArgs};
use crate::dav::ChecksumAwareFileSystem;
use crate::dav::checksum::{ChecksumAlgorithm, ChecksumManager};
use crate::path_policy::PathPolicy;
use crate::runtime_config::{LiveConfigHandle, build_live_runtime_config, effective_stun_config, load_service_config_source, spawn_remote_refresh_loop};
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
    path_policy: Arc<PathPolicy>,
) -> Router {
    let inner = LocalFs::new(root, true, false, false);
    let checksum_manager = ChecksumManager::new(vec![
        ChecksumAlgorithm::SHA1,
        ChecksumAlgorithm::MD5,
    ]);

    let fs = ChecksumAwareFileSystem::new(inner, checksum_manager, root.to_path_buf(), path_policy.clone());

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
            let auth = auth.clone();
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let auth = auth.clone();
                async move {
                    let auth_header = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok());

                    if !auth.authorize_metrics_request(auth_header) {
                        return (
                            axum::http::StatusCode::UNAUTHORIZED,
                            [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                            String::from("Unauthorized"),
                        );
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
        router = router.merge(tus_routes(prefix, mgr, root.to_path_buf(), path_policy));
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

    // Extract UUID from the $ signature query param
    let uuid = req
        .uri()
        .query()
        .and_then(extract_sign_param)
        .as_deref()
        .and_then(extract_uuid_from_sign);

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
        uuid,
    )
    .await
}

/// Build TusConfig + temp_dir from CLI args.
fn build_tus_from_args(args: &RunArgs, root: &std::path::Path) -> Option<(TusConfig, PathBuf)> {
    let enabled = args.enable_tus
        || args.tus_temp_dir.is_some()
        || args.tus_upload_timeout_hours.is_some()
        || args.tus_max_concurrent_uploads.is_some()
        || args.tus_max_upload_size.is_some();

    if !enabled {
        return None;
    }

    let config = TusConfig {
        enabled: true,
        upload_timeout_hours: args.tus_upload_timeout_hours.unwrap_or(24),
        max_concurrent_uploads: args.tus_max_concurrent_uploads.unwrap_or(100),
        max_upload_size: args.tus_max_upload_size.unwrap_or(5 * 1024 * 1024 * 1024),
    };

    let temp_dir = args
        .tus_temp_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".tus-tmp"));

    Some((config, temp_dir))
}

const TOKIO_WORKER_STACK_SIZE: usize = 16 * 1024 * 1024;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    cli.validate()?;

    if let Some(Command::WindowsService(cmd)) = cli.command {
        return handle_windows_service_command(cmd);
    }

    init_console_logging();
    run_with_runtime(cli.run)
}

fn init_console_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}

fn run_with_runtime(args: RunArgs) -> anyhow::Result<()> {
    // Install the ring crypto provider before any rustls usage (quinn, tokio-rustls, etc.)
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(TOKIO_WORKER_STACK_SIZE)
        .build()?;

    rt.block_on(async_main(args))
}

fn handle_windows_service_command(cmd: WindowsServiceArgs) -> anyhow::Result<()> {
    if cmd.service_supervisor {
        #[cfg(windows)]
        {
            windows_service::setup_file_logging()?;
            let service_name = cmd
                .service_name
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--service-name is required in supervisor mode"))?;
            return windows_service::run_as_service(service_name, cmd.run);
        }

        #[cfg(not(windows))]
        {
            anyhow::bail!("windows-service supervisor mode is only supported on Windows");
        }
    }

    if cmd.service_child {
        #[cfg(windows)]
        {
            windows_service::setup_file_logging()?;
        }

        #[cfg(not(windows))]
        {
            init_console_logging();
        }

        let result = run_with_runtime(cmd.run);
        if let Err(err) = &result {
            tracing::error!(error = %format!("{err:#}"), "Windows service child exited with error");
        }
        return result;
    }

    if let Some(name) = cmd.install {
        #[cfg(windows)]
        {
            init_console_logging();
            return windows_service::install_service(&name, &cmd.run);
        }

        #[cfg(not(windows))]
        {
            anyhow::bail!("windows-service install is only supported on Windows");
        }
    }

    if let Some(name) = cmd.uninstall {
        #[cfg(windows)]
        {
            init_console_logging();
            return windows_service::uninstall_service(&name);
        }

        #[cfg(not(windows))]
        {
            anyhow::bail!("windows-service uninstall is only supported on Windows");
        }
    }

    anyhow::bail!("Invalid windows-service command")
}

async fn async_main(args: RunArgs) -> anyhow::Result<()> {
    let root = PathBuf::from(&args.root).canonicalize()?;
    info!("Serving directory: {}", root.display());
    let path_policy = Arc::new(PathPolicy::new(root.clone(), &args.allow_link_target)?);

    let service_config = load_service_config_source(&args).await?;
    if let Some(config_url) = &args.config_url {
        info!("Loaded service config from remote URL: {config_url}");
    } else if let Some(config_path) = &args.config {
        info!("Loaded service config from: {config_path}");
    }

    let auth = if let Some(ref cfg) = service_config {
        build_auth_from_live_config(&cfg.live.auth, &args.prefix, args.no_tcp_download)
    } else {
        build_auth_from_args(&args)
    };
    let live_config = LiveConfigHandle::new(build_live_runtime_config(&args, service_config.as_ref()));
    let effective_stun = effective_stun_config(&args, service_config.as_ref());

    if args.enable_rtc && effective_stun.is_none() {
        anyhow::bail!(
            "--enable-rtc requires STUN config from either CLI flags or the service config"
        );
    }

    let tus_manager: Option<Arc<TusUploadManager>> =
        if let Some((tus_config, temp_dir)) = build_tus_from_args(&args, &root) {
            if tus_config.enabled {
                let mgr = TusUploadManager::new(temp_dir, tus_config, path_policy.clone())?;
                info!("TUS resumable uploads enabled");
                Some(Arc::new(mgr))
            } else {
                None
            }
        } else {
            None
        };

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
            path_policy: path_policy.clone(),
        }
    });

    let app = build_router(
        &root,
        &args.prefix,
        auth.clone(),
        tus_manager,
        rtc_state_for_router,
        path_policy.clone(),
    );

    let real_ip_source: ClientIpSource = match args.real_ip.as_deref() {
        Some(s) => s.parse::<ClientIpSource>().unwrap_or_else(|_| {
            tracing::warn!(
                "Unknown --real-ip value '{s}', falling back to ConnectInfo"
            );
            ClientIpSource::ConnectInfo
        }),
        None => ClientIpSource::ConnectInfo,
    };
    if !matches!(real_ip_source, ClientIpSource::ConnectInfo) {
        info!("Real-IP enabled: source = {real_ip_source:?}");
    }

    /// Build a protocol-specific app by applying: MetricsLayer → real-ip middleware → source extension.
    /// Execution order: source extension (outermost) → real-ip → MetricsLayer (innermost of these three).
    fn build_protocol_app(app: Router, protocol: &'static str, source: ClientIpSource) -> Router {
        app.layer(server::metrics_layer::MetricsLayer::new(protocol))
            .layer(axum::middleware::from_fn(server::real_ip_middleware))
            .layer(source.into_extension())
    }

    let needs_tls = args.https_port.is_some() || args.http3_port.is_some();
    let tls_source: Option<TlsSource> = if needs_tls {
        if let (Some(cert_path), Some(key_path)) = (&args.cert, &args.key) {
            let cert = PathBuf::from(cert_path);
            let key = PathBuf::from(key_path);

            if args.ssl_generate {
                match server::ssl_generate::prepare_tls_identity(&cert, &key)? {
                    server::ssl_generate::PreparedTlsIdentity::Files => {
                        info!("Using TLS certificate from: {}", cert.display());
                        Some(TlsSource::File { cert, key })
                    }
                    server::ssl_generate::PreparedTlsIdentity::InMemory(resolver) => {
                        tracing::warn!(
                            "Using in-memory self-signed TLS certificate because persisting the regenerated pair failed"
                        );
                        Some(TlsSource::SelfSigned(resolver))
                    }
                }
            } else {
                info!("Using TLS certificate from: {}", cert.display());
                Some(TlsSource::File { cert, key })
            }
        } else {
            info!("No certificate provided — generating self-signed certificate (7-day validity)");
            let resolver = RotatingCertResolver::new()?;
            Some(TlsSource::SelfSigned(resolver))
        }
    } else {
        None
    };

    let stun_config: Option<StunConfig> = {
        let server_strs: Vec<String> = effective_stun
            .as_ref()
            .map(|stun| stun.servers.clone())
            .unwrap_or_default();
        let stun_interval_secs = effective_stun.as_ref().and_then(|stun| stun.interval_secs);

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
                                debug!("STUN server '{server_str}' resolved to {addr}");
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
            all_addrs.sort();
            all_addrs.dedup();
            let interval = Duration::from_secs(stun_interval_secs.unwrap_or(20));
            info!(
                "STUN NAT traversal configured: {} address(es) (interval: {interval:?})",
                all_addrs.len()
            );
            Some(StunConfig {
                servers: all_addrs,
                interval,
            })
        } else {
            None
        }
    };

    let mut handles = Vec::new();
    let mut h3_endpoint: Option<quinn::Endpoint> = None;

    if let Some(port) = args.http_port {
        let http_app = build_protocol_app(app.clone(), "http", real_ip_source.clone());
        handles.push(tokio::spawn(async move {
            server::http::serve(port, http_app)
                .await
                .with_context(|| format!("HTTP server failed on port {port}"))
        }));
    }

    if let Some(port) = args.ssh_port {
        let host_key = args
            .ssh_host_key
            .clone()
            .expect("validate() ensures ssh_host_key is present when ssh_port is set");
        let ssh_app = build_protocol_app(app.clone(), "ssh", real_ip_source.clone());
        let ssh_auth = auth.clone();
        let ssh_root = root.clone();
        let ssh_prefix = args.prefix.clone();
        let ssh_path_policy = path_policy.clone();
        handles.push(tokio::spawn(async move {
            server::ssh::serve(
                port,
                &PathBuf::from(host_key),
                ssh_app,
                ssh_auth,
                ssh_root,
                ssh_prefix,
                ssh_path_policy,
            )
            .await
            .with_context(|| format!("SSH server failed on port {port}"))
        }));
    }

    if let Some(port) = args.https_port {
        let https_app = build_protocol_app(app.clone(), "http", real_ip_source.clone());
        let https_config = match tls_source.as_ref().unwrap() {
            TlsSource::File { cert, key } => server::tls::build_https_config(cert, key)?,
            TlsSource::SelfSigned(resolver) => {
                server::selfsign::build_https_config_dynamic(resolver.clone())
            }
        };
        handles.push(tokio::spawn(async move {
            server::https::serve(port, https_config, https_app)
                .await
                .with_context(|| format!("HTTPS server failed on port {port}"))
        }));
    }

    if let Some(port) = args.http3_port {
        let h3_app = build_protocol_app(app.clone(), "h3", real_ip_source);
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
            path_policy: path_policy.clone(),
        };
        let h3_handle = server::http3::spawn(
            port,
            quic_config,
            h3_app,
            stun_config,
            wt_config,
            rtc_tx_for_h3,
        )?;

        let public_addr_for_rtc = h3_handle.public_addr.clone();
        let mut public_addr_rx = h3_handle.public_addr;
        let webhook_config = live_config.clone();
        panic_recovery::spawn_catch_panic("addr-watcher", async move {
            while public_addr_rx.changed().await.is_ok() {
                let addrs: std::collections::HashSet<std::net::SocketAddr> =
                    public_addr_rx.borrow_and_update().clone();
                if addrs.is_empty() {
                    continue;
                }

                let addrs_str: Vec<String> = addrs.iter().map(|addr| addr.to_string()).collect();
                let body = addrs_str.join(",");
                info!("Public UDP endpoint(s) available: {body}");

                if let Some(webhook_url) = webhook_config.load_full().webhook_url.clone() {
                    match build_webhook_client(
                        &webhook_url,
                        args.dangerous_ignore_ssl_certificate,
                    ) {
                        Ok((client, url, auth)) => {
                            let mut req = client.post(url.clone()).body(body.clone());
                            if let Some((user, pass)) = auth.as_ref() {
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
                        Err(e) => {
                            tracing::warn!("Invalid webhook URL '{webhook_url}': {e}");
                        }
                    }
                }
            }
        });

        h3_endpoint = Some(h3_handle.endpoint);

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

        handles.push(tokio::spawn(async move {
            h3_handle
                .task
                .await
                .context("HTTP/3 server task join failed")?
                .with_context(|| format!("HTTP/3 server failed on port {port}"))
        }));
    }

    if let Some(TlsSource::SelfSigned(resolver)) = tls_source {
        server::selfsign::spawn_refresh_task(resolver, h3_endpoint);
    }

    let initial_metrics = live_config.load_full();
    if args.config_url.is_some() || !initial_metrics.metrics_push.urls.is_empty() {
        if !initial_metrics.metrics_push.urls.is_empty() {
            info!(
                "Starting metrics push to {} target(s), interval={}s",
                initial_metrics.metrics_push.urls.len(),
                initial_metrics.metrics_push.interval.as_secs()
            );
        } else {
            info!("Starting dynamic metrics push task (awaiting remote targets)");
        }
        metrics::spawn_metrics_push_dynamic(
            live_config.clone(),
            args.dangerous_ignore_ssl_certificate,
        );
    }

    if let Some(initial_service_config) = service_config.clone()
        && args.config_url.is_some()
    {
        let restart_required = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _refresh_task = spawn_remote_refresh_loop(
            args.clone(),
            auth.clone(),
            live_config.clone(),
            initial_service_config,
            effective_stun.clone(),
            restart_required,
        )?;
    }

    info!("All servers started. Press Ctrl+C to stop.");

    for handle in handles {
        handle.await.context("server task join failed")??;
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

fn build_webhook_client(
    raw_url: &str,
    ignore_invalid_certs: bool,
) -> anyhow::Result<WebhookConfig> {
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
        .danger_accept_invalid_certs(ignore_invalid_certs)
        .build()?;

    Ok((client, clean_url, auth))
}
