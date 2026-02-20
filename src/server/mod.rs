use std::net::{IpAddr, SocketAddr};

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum_client_ip::ClientIpSource;
use tokio::net::TcpListener;

pub mod http;
pub mod http3;
pub mod https;
pub mod metrics_body;
pub mod metrics_layer;
pub mod selfsign;
pub mod sftp;
pub mod ssh;
pub mod ssl_generate;
pub mod tls;
pub mod webtransport;

/// Real client IP extracted by the real-ip middleware.
///
/// Inserted into request extensions so that downstream layers
/// (e.g. [`MetricsLayer`]) can read it without re-parsing headers.
#[derive(Clone, Debug)]
pub struct RealIp(pub IpAddr);

/// Axum middleware that resolves the client's real IP address.
///
/// 1. Reads the [`ClientIpSource`] extension (set by `source.into_extension()`)
/// 2. Extracts the IP from the corresponding header (X-Real-Ip, X-Forwarded-For, etc.)
/// 3. Falls back to [`axum::extract::ConnectInfo<SocketAddr>`] (socket address)
/// 4. Stores the result as [`RealIp`] extension for downstream consumers.
pub async fn real_ip_middleware(mut req: Request, next: Next) -> Response {
    let header_ip: Option<IpAddr> = req
        .extensions()
        .get::<ClientIpSource>()
        .and_then(|source| extract_ip_from_source(source, req.headers()));

    let ip = header_ip.or_else(|| {
        req.extensions()
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
    });

    if let Some(ip) = ip {
        req.extensions_mut().insert(RealIp(ip));
    }
    next.run(req).await
}

/// Parse the client IP from request headers based on the configured source.
fn extract_ip_from_source(
    source: &ClientIpSource,
    headers: &axum::http::HeaderMap,
) -> Option<IpAddr> {
    match source {
        ClientIpSource::ConnectInfo => None, // handled by ConnectInfo fallback
        ClientIpSource::XRealIp => headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok()),
        ClientIpSource::RightmostXForwardedFor => headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.rsplit(',').next())
            .and_then(|s| s.trim().parse().ok()),
        ClientIpSource::CfConnectingIp => headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok()),
        ClientIpSource::TrueClientIp => headers
            .get("true-client-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok()),
        ClientIpSource::FlyClientIp => headers
            .get("fly-client-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok()),
        ClientIpSource::RightmostForwarded => headers
            .get("forwarded")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| {
                // Parse rightmost "for=<ip>" directive from the Forwarded header.
                s.rsplit(',')
                    .filter_map(|part| {
                        part.split(';')
                            .find(|d| d.trim().to_ascii_lowercase().starts_with("for="))
                            .map(|d| d.trim().splitn(2, '=').nth(1).unwrap_or("").trim())
                    })
                    .next()
            })
            .and_then(|s| {
                // Strip surrounding quotes and brackets: "1.2.3.4" or "[::1]"
                let s = s.trim_matches('"');
                let s = s.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(s);
                s.parse().ok()
            }),
        ClientIpSource::CloudFrontViewerAddress => headers
            .get("cloudfront-viewer-address")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| {
                // Format: "ip:port" — take only the IP part
                s.rsplit_once(':').map_or(s, |(ip, _)| ip).trim().parse().ok()
            }),
        ClientIpSource::XEnvoyExternalAddress => headers
            .get("x-envoy-external-address")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok()),
        // For unknown/future variants, fall through to ConnectInfo
        _ => None,
    }
}

/// Create a dual-stack TCP listener bound to `[::]:{port}`.
///
/// On Windows and macOS, `IPV6_V6ONLY` defaults to `true`, meaning an IPv6
/// socket will *not* accept IPv4 connections.  We use `socket2` to explicitly
/// disable it — the same approach used for the UDP socket in `http3.rs`.
pub fn bind_dual_stack_tcp(port: u16) -> anyhow::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let addr: SocketAddr = format!("[::]:{port}").parse()?;
    let sock = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_only_v6(false)?;
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;

    let std_listener: std::net::TcpListener = sock.into();
    let listener = TcpListener::from_std(std_listener)?;
    Ok(listener)
}
