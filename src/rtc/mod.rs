pub mod handler;
pub mod session;

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use str0m::change::SdpOffer;
use str0m::{Candidate, Rtc};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info, warn};

use self::session::RtcSession;

// ---------------------------------------------------------------------------
// Command channel for session creation
// ---------------------------------------------------------------------------

/// Command sent from the LOCK handler to the RtcManager run loop.
pub struct CreateSessionCmd {
    pub file_path: PathBuf,
    /// Pre-collected file size (from tokio::fs::metadata) so RtcSession
    /// doesn't need to do blocking I/O.
    pub file_size: u64,
    pub sdp_offer: String,
    pub remote_candidates: Vec<handler::IceCandidate>,
    pub reply: oneshot::Sender<Result<(u64, String, Vec<handler::IceCandidate>), anyhow::Error>>,
}

/// A cloneable handle for sending session-creation commands to the RtcManager.
///
/// Used by the LOCK handler to request new WebRTC sessions.
#[derive(Clone)]
pub struct RtcHandle {
    cmd_tx: mpsc::Sender<CreateSessionCmd>,
}

impl RtcHandle {
    /// Create a new `RtcHandle` from a command channel sender.
    pub fn new(cmd_tx: mpsc::Sender<CreateSessionCmd>) -> Self {
        Self { cmd_tx }
    }

    /// Request the RtcManager to create a new session.
    ///
    /// Collects file metadata asynchronously before sending the command so
    /// that no blocking I/O happens on the RtcManager task path.
    ///
    /// Returns `(session_id, sdp_answer_string, local_candidates)` on success.
    pub async fn create_session(
        &self,
        file_path: PathBuf,
        sdp_offer: String,
        remote_candidates: Vec<handler::IceCandidate>,
    ) -> Result<(u64, String, Vec<handler::IceCandidate>), anyhow::Error> {
        // Collect file size asynchronously before entering the sync manager path.
        // If this fails, bail out early rather than sending incorrect size=0.
        let meta = tokio::fs::metadata(&file_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to stat file {:?}: {e}", file_path))?;
        if !meta.is_file() {
            return Err(anyhow::anyhow!("Not a file: {:?}", file_path));
        }
        let file_size = meta.len();

        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(CreateSessionCmd {
                file_path,
                file_size,
                sdp_offer,
                remote_candidates,
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("RtcManager has shut down"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("RtcManager dropped the reply channel"))?
    }
}

// ---------------------------------------------------------------------------
// RtcManager
// ---------------------------------------------------------------------------

/// Manages all active WebRTC DataChannel sessions.
///
/// Owns the str0m [`Rtc`] instances and drives them from a single async loop,
/// feeding UDP packets in and sending transmit packets out via the shared
/// `udp_tx` socket.
pub struct RtcManager {
    /// Active sessions keyed by auto-incrementing session ID.
    sessions: HashMap<u64, RtcSession>,
    /// Reverse lookup: remote SocketAddr → session ID, for routing incoming
    /// packets to the correct session.
    addr_map: HashMap<SocketAddr, u64>,
    /// Cloned raw UDP socket used for sending outgoing packets.
    udp_tx: Arc<UdpSocket>,
    /// Receives the STUN-discovered public (server-reflexive) addresses.
    public_addr_rx: watch::Receiver<HashSet<SocketAddr>>,
    /// Receives demuxed ICE/DTLS packets from the DemuxSocket.
    rtc_packet_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    /// Receives session-creation commands from the LOCK handler.
    cmd_rx: mpsc::Receiver<CreateSessionCmd>,
    /// Auto-incrementing session ID counter.
    next_session_id: u64,
    /// Sender half of the wake channel — cloned into every `RtcSession` /
    /// file-reader so they can nudge this manager when new data is ready.
    wake_tx: mpsc::Sender<u64>,
    /// Receiver half of the wake channel — polled in `run()`.
    wake_rx: mpsc::Receiver<u64>,
}

impl RtcManager {
    /// Create a new `RtcManager` and its corresponding [`RtcHandle`].
    ///
    /// - `udp_tx`: cloned raw UDP socket for sending.
    /// - `public_addr_rx`: watch channel carrying the STUN-discovered public
    ///   addresses (may be empty if STUN hasn't resolved yet).
    /// - `rtc_packet_rx`: channel carrying `(data, source_addr)` tuples from
    ///   the DemuxSocket for ICE STUN [0-3] and DTLS [20-63] byte ranges.
    pub fn new(
        udp_tx: Arc<UdpSocket>,
        public_addr_rx: watch::Receiver<HashSet<SocketAddr>>,
        rtc_packet_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    ) -> (Self, RtcHandle) {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        // Wake channel: bounded(8) — small capacity; try_send coalesces naturally.
        let (wake_tx, wake_rx) = mpsc::channel(8);
        let manager = Self {
            sessions: HashMap::new(),
            addr_map: HashMap::new(),
            udp_tx,
            public_addr_rx,
            rtc_packet_rx,
            cmd_rx,
            next_session_id: 1,
            wake_tx,
            wake_rx,
        };
        let handle = RtcHandle { cmd_tx };
        (manager, handle)
    }

    /// Create an `RtcManager` from pre-built parts.
    ///
    /// Used when the command channel is created separately (e.g., to wire up
    /// the handler before the UDP socket is available from the H3 server).
    pub fn from_parts(
        udp_tx: Arc<UdpSocket>,
        public_addr_rx: watch::Receiver<HashSet<SocketAddr>>,
        rtc_packet_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
        cmd_rx: mpsc::Receiver<CreateSessionCmd>,
    ) -> Self {
        // Wake channel: bounded(8) — small capacity; try_send coalesces naturally.
        let (wake_tx, wake_rx) = mpsc::channel(8);
        Self {
            sessions: HashMap::new(),
            addr_map: HashMap::new(),
            udp_tx,
            public_addr_rx,
            rtc_packet_rx,
            cmd_rx,
            next_session_id: 1,
            wake_tx,
            wake_rx,
        }
    }

    // ------------------------------------------------------------------
    // Session creation (called inside the run loop)
    // ------------------------------------------------------------------

    /// Create a new WebRTC session for transferring `file_path`.
    ///
    /// Accepts the remote SDP offer, generates an SDP answer, and sets up ICE
    /// candidates.  Returns `(session_id, sdp_answer_string)`.
    fn create_session(
        &mut self,
        file_path: PathBuf,
        file_size: u64,
        sdp_offer: &str,
        remote_candidates: Vec<handler::IceCandidate>,
    ) -> Result<(u64, String, Vec<handler::IceCandidate>), anyhow::Error> {
        let mut rtc = Rtc::new(Instant::now());

        // Determine our local bound address from the UDP socket.
        let local_addr = self.udp_tx.local_addr()?;

        // Add host candidates.  When bound to a wildcard address (0.0.0.0
        // or [::]), add loopback candidates so local peers can connect.
        let mut local_candidates: Vec<handler::IceCandidate> = Vec::new();

        if local_addr.ip().is_unspecified() {
            let port = local_addr.port();
            // IPv6 loopback
            match Candidate::host(SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port), "udp") {
                Ok(c) => {
                    let sdp = c.to_sdp_string();
                    rtc.add_local_candidate(c);
                    local_candidates.push(handler::IceCandidate { candidate: sdp, sdp_mid: Some("0".into()), sdp_mline_index: Some(0) });
                }
                Err(e) => warn!("Failed to create IPv6 loopback candidate: {e}"),
            }
            // IPv4 loopback
            match Candidate::host(SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port), "udp") {
                Ok(c) => {
                    let sdp = c.to_sdp_string();
                    rtc.add_local_candidate(c);
                    local_candidates.push(handler::IceCandidate { candidate: sdp, sdp_mid: Some("0".into()), sdp_mline_index: Some(0) });
                }
                Err(e) => warn!("Failed to create IPv4 loopback candidate: {e}"),
            }
        } else {
            let host_candidate = Candidate::host(local_addr, "udp")?;
            let sdp = host_candidate.to_sdp_string();
            rtc.add_local_candidate(host_candidate);
            local_candidates.push(handler::IceCandidate { candidate: sdp, sdp_mid: Some("0".into()), sdp_mline_index: Some(0) });
        }

        // If we have STUN-discovered public addresses, add a server-reflexive
        // candidate for each so the remote peer can reach us through NAT.
        for public_addr in self.public_addr_rx.borrow().iter() {
            if *public_addr == local_addr {
                continue;
            }
            // str0m requires addr and base to be the same IP version.
            // When bound to a wildcard ([::] or 0.0.0.0), pick a base
            // address that matches public_addr's address family.
            let base = if local_addr.ip().is_unspecified() {
                let port = local_addr.port();
                match public_addr {
                    SocketAddr::V4(_) => SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port),
                    SocketAddr::V6(_) => SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port),
                }
            } else {
                local_addr
            };
            match Candidate::server_reflexive(*public_addr, base, "udp") {
                Ok(srflx) => {
                    let sdp = srflx.to_sdp_string();
                    rtc.add_local_candidate(srflx);
                    local_candidates.push(handler::IceCandidate { candidate: sdp, sdp_mid: Some("0".into()), sdp_mline_index: Some(0) });
                    debug!("Added server-reflexive candidate: {public_addr}");
                }
                Err(e) => {
                    warn!("Failed to create srflx candidate for {public_addr}: {e}");
                }
            }
        }

        // Parse the remote SDP offer.
        let offer = SdpOffer::from_sdp_string(sdp_offer)
            .map_err(|e| anyhow::anyhow!("Invalid SDP offer: {e}"))?;

        // Accept the offer and generate our answer.
        let answer = rtc
            .sdp_api()
            .accept_offer(offer)
            .map_err(|e| anyhow::anyhow!("Failed to accept SDP offer: {e}"))?;

        let sdp_answer_string = answer.to_sdp_string();

        // Add remote ICE candidates (skip mDNS .local candidates that
        // str0m cannot resolve).
        for ice in &remote_candidates {
            if ice.candidate.contains(".local") {
                debug!("Skipping mDNS candidate: {}", ice.candidate);
                continue;
            }
            match Candidate::from_sdp_string(&ice.candidate) {
                Ok(c) => {
                    rtc.add_remote_candidate(c);
                }
                Err(e) => {
                    warn!("Ignoring invalid remote candidate: {e}");
                }
            }
        }

        // Assign a session ID.
        let session_id = self.next_session_id;
        self.next_session_id += 1;

        // Collect the actual candidate addresses so the session can pick
        // the correct `Receive.destination` by address-family.
        let candidate_addrs: Vec<SocketAddr> = local_candidates
            .iter()
            .filter_map(|c| {
                // Parse the SDP candidate string to extract the address.
                Candidate::from_sdp_string(&c.candidate)
                    .ok()
                    .map(|parsed| parsed.addr())
            })
            .collect();

        let session = RtcSession::new(rtc, session_id, file_path, file_size, local_addr, candidate_addrs, self.wake_tx.clone());
        self.sessions.insert(session_id, session);

        info!("Created RTC session {session_id}");

        Ok((session_id, sdp_answer_string, local_candidates))
    }

    // ------------------------------------------------------------------
    // Main drive loop
    // ------------------------------------------------------------------

    /// Run the RtcManager event loop.
    ///
    /// This is a long-running task that:
    /// 1. Receives session-creation commands from the LOCK handler.
    /// 2. Receives demuxed ICE/DTLS packets and routes them to sessions.
    /// 3. Drives session timeouts.
    /// 4. Sends outgoing packets via the shared UDP socket.
    /// 5. Cleans up completed or failed sessions.
    pub async fn run(mut self) {
        info!("RtcManager run loop started");

        loop {
            // Find the nearest timeout across all sessions.
            let timeout_instant = self.nearest_timeout();
            let sleep_until = timeout_instant.unwrap_or_else(|| {
                // No sessions — sleep for 1 second and check again.
                Instant::now() + std::time::Duration::from_secs(1)
            });

            // Convert std::time::Instant to tokio::time::Instant.
            let tokio_deadline = tokio_instant_from_std(sleep_until);

            tokio::select! {
                // Handle session-creation commands from the LOCK handler.
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => {
                            let result = self.create_session(
                                cmd.file_path,
                                cmd.file_size,
                                &cmd.sdp_offer,
                                cmd.remote_candidates,
                            );
                            let _ = cmd.reply.send(result);
                        }
                        None => {
                            // All handles dropped — shut down.
                            info!("RTC command channel closed — shutting down RtcManager");
                            break;
                        }
                    }
                }
                // Handle incoming ICE/DTLS packets.
                packet = self.rtc_packet_rx.recv() => {
                    match packet {
                        Some((data, source)) => {
                            self.handle_incoming_packet(&data, source);
                        }
                        None => {
                            // Channel closed — shut down.
                            info!("RTC packet channel closed — shutting down RtcManager");
                            break;
                        }
                    }
                }
                // File-reader produced new data — drive the session.
                wake_sid = self.wake_rx.recv() => {
                    if let Some(sid) = wake_sid {
                        if let Some(session) = self.sessions.get_mut(&sid) {
                            session.poll_outputs(&self.udp_tx);
                        }
                    }
                }
                // Drive session timeouts.
                _ = tokio::time::sleep_until(tokio_deadline) => {
                    self.drive_timeouts();
                }
            }

            // Clean up completed / failed sessions.
            self.cleanup_sessions();
        }

        info!("RtcManager run loop exited");
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Route an incoming packet to the appropriate session.
    fn handle_incoming_packet(&mut self, data: &[u8], source: SocketAddr) {
        // Normalize the source so that ::ffff:x.x.x.x matches plain IPv4
        // entries already stored in the addr_map.
        let source = crate::stun::normalize_addr(source);

        // Look up session by source address.
        let session_id = if let Some(&sid) = self.addr_map.get(&source) {
            sid
        } else {
            // Unknown source — try to find a Pending session (newly created,
            // hasn't received packets yet). This handles the first packet from
            // a new remote peer.
            if let Some((&sid, _)) = self.sessions.iter().find(|(_, s)| {
                s.state() == session::SessionState::Pending
            }) {
                self.addr_map.insert(source, sid);
                sid
            } else {
                debug!("No session found for packet from {source} — dropping");
                return;
            }
        };

        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.handle_input(data, source);
            session.poll_outputs(&self.udp_tx);
        }
    }

    /// Drive timeouts for all sessions.
    fn drive_timeouts(&mut self) {
        let session_ids: Vec<u64> = self.sessions.keys().copied().collect();
        for sid in session_ids {
            if let Some(session) = self.sessions.get_mut(&sid) {
                session.handle_timeout();
                session.poll_outputs(&self.udp_tx);
            }
        }
    }

    /// Find the nearest timeout across all sessions.
    fn nearest_timeout(&self) -> Option<Instant> {
        self.sessions
            .values()
            .filter_map(|s| s.next_timeout())
            .min()
    }

    /// Remove completed or failed sessions and their addr_map entries.
    fn cleanup_sessions(&mut self) {
        let dead_ids: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_done())
            .map(|(&id, _)| id)
            .collect();

        for id in &dead_ids {
            if let Some(session) = self.sessions.remove(id) {
                let sent = session.bytes_sent();
                let mut guard = crate::metrics::MetricsGuard::new("rtc");
                guard.set_bytes(sent);
                // guard Drop will record request + bytes_sent
                info!(
                    "Removed RTC session {id} (state={:?}, bytes_sent={sent})",
                    session.state()
                );
            }
        }

        if !dead_ids.is_empty() {
            // Purge addr_map entries that pointed to dead sessions.
            self.addr_map.retain(|_, sid| !dead_ids.contains(sid));
        }
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Convert a `std::time::Instant` to a `tokio::time::Instant`.
///
/// Tokio's `Instant` and std's `Instant` are different types but measure the
/// same clock.  We bridge them by computing the offset from "now".
fn tokio_instant_from_std(std_instant: Instant) -> tokio::time::Instant {
    let now_std = Instant::now();
    let now_tokio = tokio::time::Instant::now();

    if std_instant > now_std {
        now_tokio + (std_instant - now_std)
    } else {
        // Already in the past — return now (will fire immediately).
        now_tokio
    }
}
