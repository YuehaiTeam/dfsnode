use std::net::SocketAddr;

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
