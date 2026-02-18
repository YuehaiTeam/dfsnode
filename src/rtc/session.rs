use std::fs::File;
use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::Instant;

use str0m::channel::ChannelId;
use str0m::net::{Protocol, Receive};
use str0m::{Event, IceConnectionState, Input, Output, Rtc};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Chunk size for file transfer (64 KB).
const CHUNK_SIZE: usize = 64 * 1024;

/// ICE connection timeout — give up if not connected within 30 s.
const ICE_TIMEOUT_SECS: u64 = 30;

/// Transfer idle timeout — abort if no progress for 60 s.
const IDLE_TIMEOUT_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// SessionState
// ---------------------------------------------------------------------------

/// Lifecycle state of a single WebRTC file-transfer session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// ICE negotiation in progress — waiting for connectivity.
    Pending,
    /// ICE connected but DataChannel not yet open.
    Connected,
    /// DataChannel open — actively sending file data.
    Transferring,
    /// Transfer completed successfully.
    Done,
    /// Session terminated due to error or timeout.
    Failed,
}

// ---------------------------------------------------------------------------
// RtcSession
// ---------------------------------------------------------------------------

/// A single WebRTC DataChannel file-transfer session backed by str0m.
///
/// The session is driven synchronously: the owning [`RtcManager`] calls
/// [`handle_input`], [`handle_timeout`], and [`poll_outputs`] from its
/// async run-loop.
pub struct RtcSession {
    /// The str0m Rtc instance for this session.
    rtc: Rtc,
    /// Path of the file to transfer.
    file_path: PathBuf,
    /// DataChannel ID — set once the channel opens via Event::ChannelOpen.
    channel_id: Option<ChannelId>,
    /// Current session state.
    state: SessionState,
    /// Open file handle for reading (set when DataChannel opens).
    file_reader: Option<File>,
    /// Reusable read buffer (64 KB).
    read_buf: Vec<u8>,
    /// When this session was created.
    created_at: Instant,
    /// Last time activity (packet or data send) occurred.
    last_activity: Instant,
    /// The local socket address used for `Receive.destination`.
    local_addr: SocketAddr,
    /// Cached next timeout from str0m.
    cached_timeout: Option<Instant>,
    /// Whether we've finished reading the file (EOF).
    eof_reached: bool,
    /// Total bytes sent so far.
    bytes_sent: u64,
}

impl RtcSession {
    /// Create a new session wrapping an already-configured [`Rtc`] instance.
    ///
    /// The DataChannel ID will be discovered at runtime via the
    /// `Event::ChannelOpen` event once ICE + DTLS complete.
    pub fn new(rtc: Rtc, file_path: PathBuf, local_addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            rtc,
            file_path,
            channel_id: None,
            state: SessionState::Pending,
            file_reader: None,
            read_buf: vec![0u8; CHUNK_SIZE],
            created_at: now,
            last_activity: now,
            local_addr,
            cached_timeout: None,
            eof_reached: false,
            bytes_sent: 0,
        }
    }

    // ------------------------------------------------------------------
    // Input handling
    // ------------------------------------------------------------------

    /// Feed a received UDP datagram into str0m.
    pub fn handle_input(&mut self, data: &[u8], source: SocketAddr) {
        if self.is_terminal() {
            return;
        }
        let now = Instant::now();
        self.last_activity = now;

        let receive = match Receive::new(Protocol::Udp, source, self.local_addr, data) {
            Ok(r) => r,
            Err(e) => {
                debug!("Ignoring unparseable packet from {source}: {e}");
                return;
            }
        };

        if let Err(e) = self.rtc.handle_input(Input::Receive(now, receive)) {
            warn!("str0m handle_input error: {e}");
            self.state = SessionState::Failed;
        }
    }

    /// Advance str0m's internal timers.
    pub fn handle_timeout(&mut self) {
        if self.is_terminal() {
            return;
        }
        let now = Instant::now();
        if let Err(e) = self.rtc.handle_input(Input::Timeout(now)) {
            warn!("str0m timeout error: {e}");
            self.state = SessionState::Failed;
        }
    }

    // ------------------------------------------------------------------
    // Output processing
    // ------------------------------------------------------------------

    /// Drain all pending outputs from str0m, sending UDP packets via `udp_tx`.
    ///
    /// Processes events (ICE state changes, channel open/close, etc.) and
    /// drives the file transfer forward.
    pub fn poll_outputs(&mut self, udp_tx: &UdpSocket) {
        if self.is_terminal() {
            return;
        }

        loop {
            match self.rtc.poll_output() {
                Ok(output) => match output {
                    Output::Transmit(t) => {
                        if let Err(e) = udp_tx.send_to(&t.contents, t.destination) {
                            warn!("UDP send error to {}: {e}", t.destination);
                        }
                    }
                    Output::Timeout(t) => {
                        self.cached_timeout = Some(t);
                        // Timeout is the last output in a poll cycle — break.
                        break;
                    }
                    Output::Event(event) => {
                        self.handle_event(event);
                    }
                },
                Err(e) => {
                    warn!("str0m poll_output error: {e}");
                    self.state = SessionState::Failed;
                    break;
                }
            }
        }

        // After processing events, try to resume sending if we were paused
        // due to backpressure. In str0m 0.6 there is no ChannelBufferedAmountLow
        // event, so we attempt to send after every poll cycle.
        if self.state == SessionState::Transferring && !self.eof_reached {
            self.try_send_chunks();
        }

        // Check timeouts after processing.
        self.check_timeouts();
    }

    /// Handle a single str0m event.
    fn handle_event(&mut self, event: Event) {
        match event {
            Event::Connected => {
                info!("ICE+DTLS connected");
                if self.state == SessionState::Pending {
                    self.state = SessionState::Connected;
                    self.last_activity = Instant::now();
                }
            }

            Event::IceConnectionStateChange(ice_state) => {
                debug!("ICE state change: {ice_state:?}");
                if ice_state == IceConnectionState::Disconnected {
                    info!("ICE disconnected — marking session as failed");
                    self.state = SessionState::Failed;
                }
            }

            Event::ChannelOpen(id, label) => {
                info!("DataChannel opened: id={id:?}, label={label}");
                self.channel_id = Some(id);
                self.state = SessionState::Transferring;
                self.last_activity = Instant::now();

                // Open the file for reading.
                match File::open(&self.file_path) {
                    Ok(f) => {
                        self.file_reader = Some(f);
                        // Send metadata first, then start chunked transfer.
                        self.send_metadata();
                        self.try_send_chunks();
                    }
                    Err(e) => {
                        warn!("Failed to open file {:?}: {e}", self.file_path);
                        self.state = SessionState::Failed;
                    }
                }
            }

            Event::ChannelData(_data) => {
                // We are the sender — ignore incoming data from the remote.
            }

            Event::ChannelClose(id) => {
                info!("DataChannel closed: id={id:?}");
                if self.channel_id == Some(id) {
                    self.state = SessionState::Done;
                }
            }

            // Ignore all other events (media stats, BWE, etc.).
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // File transfer
    // ------------------------------------------------------------------

    /// Send a JSON metadata header as a text message on the DataChannel.
    ///
    /// Format: `{"filename": "<name>", "size": <bytes>}`
    fn send_metadata(&mut self) {
        let Some(cid) = self.channel_id else { return };

        // Gather metadata.
        let filename = self
            .file_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".to_string());

        let size = std::fs::metadata(&self.file_path)
            .map(|m| m.len())
            .unwrap_or(0);

        let json = serde_json::json!({
            "filename": filename,
            "size": size,
        });
        let json_bytes = json.to_string().into_bytes();

        // Send as text (binary = false).
        match self.rtc.channel(cid) {
            Some(mut ch) => {
                if let Err(e) = ch.write(false, &json_bytes) {
                    warn!("Failed to send metadata: {e}");
                    self.state = SessionState::Failed;
                }
            }
            None => {
                warn!("Channel {cid:?} not available for metadata send");
                self.state = SessionState::Failed;
            }
        }
    }

    /// Read up to 64 KB chunks from the file and send them as binary messages.
    ///
    /// Respects backpressure: stops when `channel.write()` returns `Ok(false)`.
    pub fn try_send_chunks(&mut self) {
        let Some(cid) = self.channel_id else { return };

        if self.eof_reached {
            return;
        }

        let Some(ref mut reader) = self.file_reader else {
            return;
        };

        loop {
            let n = match reader.read(&mut self.read_buf) {
                Ok(0) => {
                    // EOF — we're done reading the file.
                    self.eof_reached = true;
                    info!(
                        "File transfer complete ({} bytes sent): {:?}",
                        self.bytes_sent, self.file_path
                    );
                    // Close the DataChannel.
                    self.rtc.direct_api().close_data_channel(cid);
                    return;
                }
                Ok(n) => n,
                Err(e) => {
                    warn!("File read error: {e}");
                    self.state = SessionState::Failed;
                    return;
                }
            };

            // Send as binary (binary = true).
            match self.rtc.channel(cid) {
                Some(mut ch) => match ch.write(true, &self.read_buf[..n]) {
                    Ok(written) => {
                        // Buffer accepted — continue reading.
                        self.bytes_sent += written as u64;
                        self.last_activity = Instant::now();
                        if written == 0 {
                            // Buffer full — stop sending, will resume on next
                            // poll cycle when buffer space becomes available.
                            debug!("DataChannel buffer full — pausing send");
                            return;
                        }
                    }
                    Err(e) => {
                        warn!("DataChannel write error: {e}");
                        self.state = SessionState::Failed;
                        return;
                    }
                },
                None => {
                    warn!("Channel {cid:?} disappeared during transfer");
                    self.state = SessionState::Failed;
                    return;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // State queries
    // ------------------------------------------------------------------

    /// Returns `true` if the session has reached a terminal state (Done or
    /// Failed) or if a timeout has been exceeded.
    pub fn is_done(&self) -> bool {
        if self.is_terminal() {
            return true;
        }
        // Also check timeouts.
        self.is_timed_out()
    }

    /// Returns the next instant at which str0m expects to be woken up.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.cached_timeout
    }

    /// Current session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// True if the session is in a terminal state.
    fn is_terminal(&self) -> bool {
        matches!(self.state, SessionState::Done | SessionState::Failed)
    }

    /// Check whether any timeout has been exceeded and transition to Failed.
    fn check_timeouts(&mut self) {
        if self.is_terminal() {
            return;
        }

        let now = Instant::now();

        // ICE timeout: must reach Connected within ICE_TIMEOUT_SECS.
        if self.state == SessionState::Pending
            && now.duration_since(self.created_at).as_secs() > ICE_TIMEOUT_SECS
        {
            warn!("ICE connection timeout ({ICE_TIMEOUT_SECS}s) — aborting session");
            self.state = SessionState::Failed;
            return;
        }

        // Transfer idle timeout: no activity for IDLE_TIMEOUT_SECS.
        if now.duration_since(self.last_activity).as_secs() > IDLE_TIMEOUT_SECS {
            warn!("Transfer idle timeout ({IDLE_TIMEOUT_SECS}s) — aborting session");
            self.state = SessionState::Failed;
        }
    }

    /// True if any timeout has been exceeded.
    fn is_timed_out(&self) -> bool {
        let now = Instant::now();

        if self.state == SessionState::Pending
            && now.duration_since(self.created_at).as_secs() > ICE_TIMEOUT_SECS
        {
            return true;
        }

        now.duration_since(self.last_activity).as_secs() > IDLE_TIMEOUT_SECS
    }
}
