use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use bytes::Buf;
use http_body_util::BodyExt;
use tokio::sync::watch;
use tower::Service;
use tracing::info;

use crate::server::tls;
use crate::stun::{self, StunConfig};

/// Handle returned by [`spawn()`] for the HTTP/3 server.
///
/// Contains the server task handle and the public address watch channel
/// (populated only when STUN is active, stays `None` otherwise).
pub struct Http3Handle {
    pub task: tokio::task::JoinHandle<anyhow::Result<()>>,
    pub public_addr: watch::Receiver<Option<SocketAddr>>,
}

/// Spawn an HTTP/3 (QUIC) server, optionally with STUN NAT traversal.
///
/// When `stun_config` is provided:
/// 1. A raw UDP socket is created manually (same port)
/// 2. Cloned for the STUN keepalive sender
/// 3. Wrapped in a [`StunDemuxSocket`] that intercepts STUN responses
/// 4. Passed to `Endpoint::new_with_abstract_socket()`
/// 5. A background keepalive task is spawned
///
/// When `stun_config` is `None`, uses the standard `Endpoint::server()`.
pub fn spawn(
    port: u16,
    cert_path: &Path,
    key_path: &Path,
    app: Router,
    stun_config: Option<StunConfig>,
) -> anyhow::Result<Http3Handle> {
    let rustls_config = tls::build_quic_config(cert_path, key_path)?;

    let quic_server_config =
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config.clone())?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(0_u8.into());
    server_config.transport_config(Arc::new(transport));

    let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;

    // Build endpoint with or without STUN
    let (endpoint, public_addr_rx) = if let Some(stun_cfg) = stun_config {
        // Manual socket creation for STUN demuxing
        let raw_socket = std::net::UdpSocket::bind(addr)?;
        raw_socket.set_nonblocking(true)?;

        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);

        let stun_setup = stun::setup_stun_socket(raw_socket, stun_cfg, &runtime)?;

        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            stun_setup.socket,
            runtime,
        )?;

        // Start STUN keepalive task
        stun::spawn_stun_keepalive(stun_setup.keepalive_socket, stun_setup.config);

        info!("HTTP/3 server listening on https://{addr} (QUIC/UDP) with STUN NAT traversal");
        (endpoint, stun_setup.public_addr_rx)
    } else {
        // Standard path — no STUN
        let endpoint = quinn::Endpoint::server(server_config, addr)?;
        let (_, rx) = watch::channel(None);
        info!("HTTP/3 server listening on https://{addr} (QUIC/UDP)");
        (endpoint, rx)
    };

    let task = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let app = app.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(incoming, app).await {
                    tracing::debug!("HTTP/3 connection error: {e}");
                }
            });
        }
        Ok(())
    });

    Ok(Http3Handle {
        task,
        public_addr: public_addr_rx,
    })
}

/// Start an HTTP/3 (QUIC) server on the given UDP port (without STUN).
///
/// Convenience wrapper around [`spawn()`] that awaits the task.
/// Kept for backward compatibility.
pub async fn serve(
    port: u16,
    cert_path: &Path,
    key_path: &Path,
    app: Router,
) -> anyhow::Result<()> {
    let handle = spawn(port, cert_path, key_path, app, None)?;
    handle.task.await??;
    Ok(())
}

async fn handle_connection(
    incoming: quinn::Incoming,
    app: Router,
) -> anyhow::Result<()> {
    let connection = incoming.await?;
    let mut h3_conn =
        h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;

    while let Some(resolver) = h3_conn.accept().await? {
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_request(resolver, app).await {
                tracing::debug!("HTTP/3 request error: {e}");
            }
        });
    }

    Ok(())
}

/// Bridge a single h3 request into the axum Router.
///
/// 1. Read the full request body from the QUIC stream
/// 2. Build an `http::Request<axum::body::Body>` and call `Router::call()`
/// 3. Stream the axum response back over h3
async fn handle_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, bytes::Bytes>,
    mut app: Router,
) -> anyhow::Result<()> {
    let (req, mut stream) = resolver.resolve_request().await?;

    // Read the full request body from the QUIC stream
    let (parts, _) = req.into_parts();
    let mut body_data = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        body_data.extend_from_slice(chunk.chunk());
    }

    // Build an axum-compatible request with a real Body
    let body = axum::body::Body::from(bytes::Bytes::from(body_data));
    let request = http::Request::from_parts(parts, body);

    // Dispatch through the axum Router (same routes as HTTP/HTTPS)
    let response = app
        .call(request)
        .await
        .unwrap_or_else(|err| match err {});

    let (resp_parts, resp_body) = response.into_parts();

    // Send response headers over h3
    let resp_head = http::Response::from_parts(resp_parts, ());
    stream.send_response(resp_head).await?;

    // Stream response body back over QUIC
    let collected = resp_body.collect().await.map_err(|e| {
        anyhow::anyhow!("Failed to collect response body: {e}")
    })?;
    let body_bytes = collected.to_bytes();
    if !body_bytes.is_empty() {
        stream.send_data(body_bytes).await?;
    }

    stream.finish().await?;
    Ok(())
}
