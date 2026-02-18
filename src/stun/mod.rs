//! STUN NAT traversal integration for the HTTP/3 (QUIC) server.
//!
//! Provides a [`StunDemuxSocket`] that wraps Quinn's `AsyncUdpSocket` to
//! intercept STUN Binding Responses on the same UDP port used for QUIC,
//! plus a keepalive task that periodically sends STUN Binding Requests to
//! maintain the NAT mapping.
//!
//! When WebRTC is enabled, also demuxes ICE STUN (first byte 0–3 from
//! non-STUN-server sources) and DTLS (first byte 20–63) packets to the
//! RtcManager via an mpsc channel.

pub mod protocol;

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::watch;
use tracing::{debug, info, trace, warn};

/// Normalize a [`SocketAddr`] by unwrapping IPv4-mapped IPv6 addresses
/// (`::ffff:x.x.x.x`) back to plain IPv4.  On dual-stack sockets (Windows),
/// the OS reports IPv4 peers as `::ffff:` — this breaks direct equality
/// checks against stored IPv4 `SocketAddr` values.
pub fn normalize_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => {
            if let Some(ipv4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::new(std::net::IpAddr::V4(ipv4), v6.port())
            } else {
                addr
            }
        }
        other => other,
    }
}

/// Convert an IPv4 `SocketAddr` to its IPv4-mapped IPv6 form so it can be
/// used with a dual-stack `[::]` socket on Windows.  IPv6 addresses pass
/// through unchanged.
fn to_v6_mapped(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::new(
            std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()),
            v4.port(),
        ),
        v6 => v6,
    }
}

/// Runtime configuration for STUN NAT traversal.
#[derive(Debug, Clone)]
pub struct StunConfig {
    /// Resolved STUN server socket addresses (all IPs from all servers).
    pub servers: Vec<SocketAddr>,
    /// Interval between STUN keepalive requests.
    pub interval: Duration,
}

/// Result of setting up STUN on a UDP socket.
pub struct StunSetup {
    /// The demux socket to hand to Quinn (wraps the original socket).
    pub socket: Arc<dyn AsyncUdpSocket>,
    /// Receiver for discovered public addresses (accumulated set).
    pub public_addr_rx: watch::Receiver<HashSet<SocketAddr>>,
    /// The cloned raw UDP socket for the keepalive task.
    pub keepalive_socket: std::net::UdpSocket,
    /// STUN configuration (servers + interval).
    pub config: StunConfig,
}

/// Sets up a STUN-demuxing socket around a raw UDP socket.
///
/// 1. Clones the raw socket (for the keepalive sender).
/// 2. Wraps the original via `runtime.wrap_udp_socket()`.
/// 3. Wraps that in a [`StunDemuxSocket`] that intercepts STUN responses
///    and optionally routes ICE/DTLS packets to the RtcManager.
///
/// Returns a [`StunSetup`] containing everything needed to start the
/// keepalive task and hand the socket to Quinn.
pub fn setup_stun_socket(
    raw_socket: std::net::UdpSocket,
    config: StunConfig,
    runtime: &Arc<dyn quinn::Runtime>,
    rtc_packet_tx: Option<tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>>,
) -> io::Result<StunSetup> {
    // Clone for the keepalive sender (uses the same local port / NAT mapping)
    let keepalive_socket = raw_socket.try_clone()?;

    // Wrap into Quinn's async socket
    let inner = runtime.wrap_udp_socket(raw_socket)?;

    // Create watch channel for public address discovery (set of addresses)
    let (pub_addr_tx, pub_addr_rx) = watch::channel(HashSet::new());

    // Build the set of normalized STUN server addresses for fast lookup
    let stun_servers: HashSet<SocketAddr> = config.servers.iter().copied().map(normalize_addr).collect();

    let demux = Arc::new(StunDemuxSocket {
        inner,
        stun_servers,
        public_addr_tx: pub_addr_tx,
        rtc_packet_tx,
    });

    Ok(StunSetup {
        socket: demux,
        public_addr_rx: pub_addr_rx,
        keepalive_socket,
        config,
    })
}

/// Spawns the STUN keepalive background task.
///
/// Periodically sends STUN Binding Requests to ALL configured STUN servers
/// using the cloned raw UDP socket (same local port as Quinn). Also fires
/// requests immediately on startup so we get the public addresses ASAP.
pub fn spawn_stun_keepalive(
    raw_socket: std::net::UdpSocket,
    config: StunConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let servers = config.servers;
        let interval = config.interval;

        info!(
            "STUN keepalive started → {} server(s) every {interval:?}",
            servers.len()
        );
        for s in &servers {
            info!("  STUN target: {s}");
        }

        // Send immediately on startup, then at intervals
        let mut timer = tokio::time::interval(interval);

        loop {
            timer.tick().await;

            for &stun_server in &servers {
                let req = protocol::build_binding_request();
                // On dual-stack sockets ([::]), must use IPv4-mapped IPv6
                // addresses when sending to IPv4 targets (Windows requirement).
                let dest = to_v6_mapped(stun_server);
                match raw_socket.send_to(&req, dest) {
                    Ok(n) => debug!("STUN Binding Request sent to {stun_server} ({n} bytes)"),
                    Err(e) => {
                        // WouldBlock is expected on non-blocking sockets under load
                        if e.kind() != io::ErrorKind::WouldBlock {
                            warn!("Failed to send STUN request to {stun_server}: {e}");
                        }
                    }
                }
            }
        }
    })
}

// ─────────────────────────────────────────────────────────────
// StunDemuxSocket — AsyncUdpSocket wrapper that intercepts STUN
// ─────────────────────────────────────────────────────────────

/// A wrapper around Quinn's `AsyncUdpSocket` that transparently intercepts
/// STUN Binding Responses from the configured STUN servers before they reach
/// Quinn's QUIC stack.
///
/// When WebRTC is enabled, also routes:
/// - ICE STUN packets (first byte 0–3 from non-STUN-server) → RtcManager
/// - DTLS packets (first byte 20–63) → RtcManager
/// - QUIC packets (first byte 64–255) → Quinn
struct StunDemuxSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    stun_servers: HashSet<SocketAddr>,
    public_addr_tx: watch::Sender<HashSet<SocketAddr>>,
    /// Channel to forward ICE STUN and DTLS packets to the RtcManager.
    /// None when WebRTC is disabled.
    rtc_packet_tx: Option<tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>>,
}

impl fmt::Debug for StunDemuxSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StunDemuxSocket")
            .field("stun_servers", &self.stun_servers)
            .finish()
    }
}

impl StunDemuxSocket {
    /// Check if a received datagram is a STUN response from one of our servers
    /// and handle it. Returns `true` if the packet was consumed (should NOT be
    /// forwarded to Quinn).
    fn try_handle_stun(&self, data: &[u8], source: SocketAddr) -> bool {
        // Fast path: wrong source or clearly not STUN
        if !self.stun_servers.contains(&normalize_addr(source)) {
            return false;
        }
        if !protocol::could_be_stun(data) {
            return false;
        }

        // Attempt full parse
        if let Some(public_addr) = protocol::parse_binding_response(data) {
            // Add to the set of discovered public addresses
            self.public_addr_tx.send_if_modified(|current| {
                // Only track changes when the public IP changes.
                // Some NATs may vary the observed port over time even when the IP is stable;
                // updating srflx candidates on port-only changes can cause jitter in the
                // WebRTC stack, so we keep the first-seen port per IP.
                if current.iter().any(|a| a.ip() == public_addr.ip()) {
                    trace!(
                        "STUN public IP unchanged (ignoring port-only update): {public_addr}"
                    );
                    return false;
                }

                if current.insert(public_addr) {
                    info!("STUN discovered public address: {public_addr}");
                    true
                } else {
                    trace!("STUN public address already known: {public_addr}");
                    false
                }
            });
            true
        } else {
            debug!("Packet from STUN server was not a valid Binding Response");
            true // still consume it — don't let Quinn see garbage from the STUN server
        }
    }

    /// Classify a packet and decide where to route it.
    /// Returns `true` if the packet was consumed (should NOT go to Quinn).
    fn try_route_packet(&self, data: &[u8], source: SocketAddr) -> bool {
        if data.is_empty() {
            return false;
        }

        let first_byte = data[0];

        // STUN range: first byte 0–3
        if first_byte <= 3 {
            // From one of our STUN servers → handle as NAT traversal response
            if self.stun_servers.contains(&normalize_addr(source)) {
                return self.try_handle_stun(data, source);
            }
            // From other source → ICE connectivity check → route to RtcManager
            if let Some(ref tx) = self.rtc_packet_tx {
                let _ = tx.try_send((data.to_vec(), source));
                return true;
            }
            // No RTC enabled — let Quinn handle it (it'll ignore it)
            return false;
        }

        // DTLS range: first byte 20–63 → route to RtcManager
        if (20..=63).contains(&first_byte) {
            if let Some(ref tx) = self.rtc_packet_tx {
                let _ = tx.try_send((data.to_vec(), source));
                return true;
            }
            // No RTC enabled — drop DTLS packets
            return true;
        }

        // QUIC range: first byte 64–255 → pass to Quinn
        false
    }
}

impl AsyncUdpSocket for StunDemuxSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // Delegate write-readiness polling to the inner socket.
        // STUN sends happen out-of-band via the cloned raw socket.
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let n = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) => n,
                other => return other,
            };

            if n == 0 {
                return Poll::Ready(Ok(0));
            }

            // Filter out STUN/ICE/DTLS packets, compact remaining QUIC packets
            let mut write_idx = 0;
            for read_idx in 0..n {
                let data = &bufs[read_idx][..meta[read_idx].len];
                if self.try_route_packet(data, meta[read_idx].addr) {
                    // Consumed — don't forward to Quinn
                    continue;
                }
                // Keep this packet for Quinn
                if write_idx != read_idx {
                    bufs.swap(write_idx, read_idx);
                    meta.swap(write_idx, read_idx);
                }
                write_idx += 1;
            }

            if write_idx > 0 {
                return Poll::Ready(Ok(write_idx));
            }

            // ALL packets in this batch were consumed — loop back to recv more.
            continue;
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        // Disable receive GRO (Generic Receive Offload) when STUN is active.
        // With GRO, multiple datagrams can be packed into a single buffer
        // with RecvMeta.stride > 0, which would require splitting segments
        // within a buffer to filter out STUN packets — significantly more
        // complex. Returning 1 ensures each buffer entry = one datagram.
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
