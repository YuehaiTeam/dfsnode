use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use bytes::Buf;
use http_body_util::BodyExt;
use tower::Service;
use tracing::info;

use crate::server::tls;

/// Start an HTTP/3 (QUIC) server on the given UDP port.
///
/// Bridges h3/quinn connections into an axum Router, following the h3-axum pattern:
/// each QUIC request is converted into an `http::Request` and dispatched through
/// the same axum Router used by HTTP/HTTPS, making all routes and middleware shared.
pub async fn serve(
    port: u16,
    cert_path: &Path,
    key_path: &Path,
    app: Router,
) -> anyhow::Result<()> {
    let rustls_config = tls::build_quic_config(cert_path, key_path)?;

    let quic_server_config =
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config.clone())?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

    // HTTP/3 doesn't use unidirectional streams for request/response
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(0_u8.into());
    server_config.transport_config(Arc::new(transport));

    let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    info!("HTTP/3 server listening on https://{addr} (QUIC/UDP)");

    while let Some(incoming) = endpoint.accept().await {
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, app).await {
                tracing::debug!("HTTP/3 connection error: {e}");
            }
        });
    }

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
