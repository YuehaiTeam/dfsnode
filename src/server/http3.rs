use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use bytes::Buf;
use http_body_util::BodyExt;
use tokio::sync::watch;
use tower::Service;
use tracing::{debug, info};

use crate::server::webtransport::WtConfig;
use crate::stun::{self, StunConfig};

/// Handle returned by [`spawn()`] for the HTTP/3 server.
pub struct Http3Handle {
    pub task: tokio::task::JoinHandle<anyhow::Result<()>>,
    pub public_addr: watch::Receiver<HashSet<SocketAddr>>,
    pub endpoint: quinn::Endpoint,
    /// Cloned raw UDP socket for RtcManager to send packets.
    /// Only available when STUN is enabled.
    pub udp_socket: Option<Arc<std::net::UdpSocket>>,
}

/// Spawn an HTTP/3 (QUIC) server, optionally with STUN NAT traversal.
pub fn spawn(
    port: u16,
    rustls_config: Arc<rustls::ServerConfig>,
    app: Router,
    stun_config: Option<StunConfig>,
    wt_config: WtConfig,
    rtc_packet_tx: Option<tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>>,
) -> anyhow::Result<Http3Handle> {
    let quic_server_config =
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

    let mut transport = quinn::TransportConfig::default();
    // Allow unidirectional streams for WebTransport server→client file push
    transport.max_concurrent_uni_streams(16_u16.into());
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    // Disable PMTUD and fix MTU at the QUIC minimum (1200).  Our connections
    // are short-lived (single file transfer) so probing gains little, and
    // IPv6 path MTU variance causes sporadic WSAEMSGSIZE / silent drops that
    // quinn's PMTUD may not recover from quickly enough.
    transport.mtu_discovery_config(None);
    transport.initial_mtu(1200);
    server_config.transport_config(Arc::new(transport));

    let addr: SocketAddr = format!("[::]:{port}").parse()?;

    // Build endpoint with or without STUN
    let (endpoint, public_addr_rx, udp_socket_for_rtc) = if let Some(stun_cfg) = stun_config {
        // Create a dual-stack UDP socket so we can send/receive both
        // IPv4 and IPv6.  Windows defaults IPV6_V6ONLY=true, so we
        // must use socket2 to explicitly disable it.
        let raw_socket = {
            use socket2::{Domain, Protocol, Socket, Type};
            let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            sock.set_only_v6(false)?;
            sock.set_nonblocking(true)?;
            // Enlarge send buffer to reduce WSAEWOULDBLOCK (10035) under
            // bursty WebRTC + QUIC traffic on the shared socket.
            sock.set_send_buffer_size(4096 * 1024)?; // 512 KiB
            sock.set_recv_buffer_size(4096 * 1024)?; // 512 KiB
            sock.bind(&addr.into())?;
            std::net::UdpSocket::from(sock)
        };

        // Clone for RtcManager sending (before moving into stun setup)
        let rtc_udp_socket = Arc::new(raw_socket.try_clone()?);

        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let stun_setup = stun::setup_stun_socket(raw_socket, stun_cfg, &runtime, rtc_packet_tx)?;

        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            stun_setup.socket,
            runtime,
        )?;

        stun::spawn_stun_keepalive(stun_setup.keepalive_socket, stun_setup.config);

        info!("HTTP/3 server listening on https://{addr} (QUIC/UDP) with STUN NAT traversal");
        (endpoint, stun_setup.public_addr_rx, Some(rtc_udp_socket))
    } else {
        let endpoint = quinn::Endpoint::server(server_config, addr)?;
        let (_, rx) = watch::channel(HashSet::new());
        info!("HTTP/3 server listening on https://{addr} (QUIC/UDP)");
        (endpoint, rx, None)
    };

    let endpoint_handle = endpoint.clone();
    let task = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let app = app.clone();
            let wt_config = wt_config.clone();
            crate::panic_recovery::spawn_catch_panic("h3-conn", async move {
                if let Err(e) = handle_connection(incoming, app, wt_config).await {
                    debug!("HTTP/3 connection error: {e}");
                }
            });
        }
        Ok(())
    });

    Ok(Http3Handle {
        task,
        public_addr: public_addr_rx,
        endpoint: endpoint_handle,
        udp_socket: udp_socket_for_rtc,
    })
}

async fn handle_connection(
    incoming: quinn::Incoming,
    app: Router,
    wt_config: WtConfig,
) -> anyhow::Result<()> {
    let connection = incoming.await?;
    let peer_addr = connection.remote_address();

    // Use builder to enable WebTransport + Extended CONNECT (no datagram)
    let mut h3_conn = h3::server::builder()
        .enable_webtransport(true)
        .enable_extended_connect(true)
        .enable_datagram(true)
        .max_webtransport_sessions(1)
        .build(h3_quinn::Connection::new(connection))
        .await?;

    while let Some(resolver) = h3_conn.accept().await? {
        let (req, stream) = resolver.resolve_request().await?;

        // Check if this is a WebTransport CONNECT request
        if req.method() == http::Method::CONNECT
            && let Some(protocol) = req.extensions().get::<h3::ext::Protocol>()
            && protocol.as_str() == "webtransport"
        {
            debug!("WebTransport CONNECT request: {}", req.uri());

            // Handle WebTransport — this moves h3_conn, so we return after
            if let Err(e) =
                super::webtransport::handle_webtransport(req, stream, h3_conn, &wt_config, peer_addr).await
            {
                tracing::warn!("WebTransport session error: {e}");
            }
            return Ok(());
        }

        // Normal H3 request — dispatch through axum
        let app = app.clone();
        let addr = peer_addr;
        crate::panic_recovery::spawn_catch_panic("h3-request", async move {
            if let Err(e) = handle_request(req, stream, app, addr).await {
                debug!("HTTP/3 request error: {e}");
            }
        });
    }

    Ok(())
}

/// Bridge a single h3 request into the axum Router.
///
/// The `app` Router has a `MetricsLayer("h3")` applied, so the response body is
/// a `MetricsBody<_>`.  We stream frames from it one by one, sending each data
/// chunk over the QUIC stream.  MetricsBody counts bytes as they are polled and
/// records both request count and bytes_sent in its Drop — even on early `?` exit.
async fn handle_request(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
    mut app: Router,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    // Read the full request body from the QUIC stream (capped to prevent memory DoS).
    const MAX_H3_BODY_SIZE: usize = 2 * 1024 * 1024; // 2 MiB — sufficient for WebDAV XML / LOCK JSON
    let (mut parts, _) = req.into_parts();
    let mut body_data = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        body_data.extend_from_slice(chunk.chunk());
        if body_data.len() > MAX_H3_BODY_SIZE {
            let resp = http::Response::builder()
                .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                .body(())
                .unwrap();
            stream.send_response(resp).await?;
            stream.finish().await?;
            return Ok(());
        }
    }

    // Inject peer address so MetricsLayer can extract it
    parts
        .extensions
        .insert(axum::extract::ConnectInfo(peer_addr));

    // Build an axum-compatible request with a real Body
    let body = axum::body::Body::from(bytes::Bytes::from(body_data));
    let request = http::Request::from_parts(parts, body);

    // Dispatch through the axum Router (response body is MetricsBody from Layer)
    let response = app.call(request).await.unwrap_or_else(|err| match err {});

    let (resp_parts, resp_body) = response.into_parts();

    // Send response headers over h3
    let resp_head = http::Response::from_parts(resp_parts, ());
    stream.send_response(resp_head).await?;

    // Stream response body back over QUIC — frame by frame (no full buffering).
    // MetricsBody tracks bytes as each frame is polled via poll_frame().
    let mut body = resp_body;
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result
            .map_err(|e| anyhow::anyhow!("body frame error: {e}"))?;

        if let Ok(data) = frame.into_data() {
            if !data.is_empty() {
                stream.send_data(data).await?;
            }
        }
        // Trailers and other frame types are silently ignored for H3.
    }

    stream.finish().await?;

    Ok(())
}
