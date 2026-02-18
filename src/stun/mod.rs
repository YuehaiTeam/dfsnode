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

/// Runtime configuration for STUN NAT traversal.
#[derive(Debug, Clone)]
pub struct StunConfig {
    /// Resolved STUN server socket address.
    pub server: SocketAddr,
    /// Interval between STUN keepalive requests.
    pub interval: Duration,
}

/// Result of setting up STUN on a UDP socket.
pub struct StunSetup {
    /// The demux socket to hand to Quinn (wraps the original socket).
    pub socket: Arc<dyn AsyncUdpSocket>,
    /// Receiver for the discovered public address.
    pub public_addr_rx: watch::Receiver<Option<SocketAddr>>,
    /// The cloned raw UDP socket for the keepalive task.
    pub keepalive_socket: std::net::UdpSocket,
    /// STUN configuration (server + interval).
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

    // Create watch channel for public address discovery
    let (pub_addr_tx, pub_addr_rx) = watch::channel(None);

    let demux = Arc::new(StunDemuxSocket {
        inner,
        stun_server: config.server,
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
/// Periodically sends STUN Binding Requests to the configured STUN server
/// using the cloned raw UDP socket (same local port as Quinn). Also fires
/// one request immediately on startup so we get the public address ASAP.
pub fn spawn_stun_keepalive(
    raw_socket: std::net::UdpSocket,
    config: StunConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let stun_server = config.server;
        let interval = config.interval;

        info!("STUN keepalive started → {stun_server} every {interval:?}");

        // Send immediately on startup, then at intervals
        let mut timer = tokio::time::interval(interval);

        loop {
            timer.tick().await;

            let req = protocol::build_binding_request();
            match raw_socket.send_to(&req, stun_server) {
                Ok(n) => debug!("STUN Binding Request sent to {stun_server} ({n} bytes)"),
                Err(e) => {
                    // WouldBlock is expected on non-blocking sockets under load
                    if e.kind() != io::ErrorKind::WouldBlock {
                        warn!("Failed to send STUN request: {e}");
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
/// STUN Binding Responses from the configured STUN server before they reach
/// Quinn's QUIC stack.
///
/// When WebRTC is enabled, also routes:
/// - ICE STUN packets (first byte 0–3 from non-STUN-server) → RtcManager
/// - DTLS packets (first byte 20–63) → RtcManager
/// - QUIC packets (first byte 64–255) → Quinn
struct StunDemuxSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    stun_server: SocketAddr,
    public_addr_tx: watch::Sender<Option<SocketAddr>>,
    /// Channel to forward ICE STUN and DTLS packets to the RtcManager.
    /// None when WebRTC is disabled.
    rtc_packet_tx: Option<tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>>,
}

impl fmt::Debug for StunDemuxSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StunDemuxSocket")
            .field("stun_server", &self.stun_server)
            .finish()
    }
}

impl StunDemuxSocket {
    /// Check if a received datagram is a STUN response from our server and
    /// handle it. Returns `true` if the packet was consumed (should NOT be
    /// forwarded to Quinn).
    fn try_handle_stun(&self, data: &[u8], source: SocketAddr) -> bool {
        // Fast path: wrong source or clearly not STUN
        if source != self.stun_server {
            return false;
        }
        if !protocol::could_be_stun(data) {
            return false;
        }

        // Attempt full parse
        if let Some(public_addr) = protocol::parse_binding_response(data) {
            // Only log on change (watch::Sender::send_if_modified)
            self.public_addr_tx.send_if_modified(|current| {
                if *current != Some(public_addr) {
                    info!("STUN discovered public address: {public_addr}");
                    *current = Some(public_addr);
                    true
                } else {
                    trace!("STUN public address unchanged: {public_addr}");
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
            // From our STUN server → handle as NAT traversal response
            if source == self.stun_server {
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
