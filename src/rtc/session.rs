use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::Instant;

use bytes::Bytes;
use str0m::channel::ChannelId;
use str0m::net::{Protocol, Receive};
use str0m::{Event, IceConnectionState, Input, Output, Rtc};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Chunk size for file reads (64 KB).
const CHUNK_SIZE: usize = 64 * 1024;

/// Limit how many bytes we enqueue into the DataChannel per `poll_outputs` call.
///
/// `str0m` can recurse internally while turning queued SCTP data into outputs;
/// enqueueing too much at once (especially after loss/retransmits) can trigger
/// a stack overflow in the tokio worker thread.
const MAX_WRITE_PER_CYCLE: usize = 512 * 1024;

/// Limit how many `Rtc::poll_output()` results we process per drain.
///
/// On `str0m` v0.15, `poll_output()` can recurse internally when SCTP has a
/// large amount of work to flush (e.g. after retransmits). Draining unboundedly
/// increases the risk of stack overflow.
const MAX_POLL_OUTPUTS_PER_DRAIN: usize = 2048;

/// High watermark: stop injecting when `buffered_amount()` >= this value.
const HIGH_WATERMARK: usize = 4 * 1024 * 1024;

/// Low watermark: set as the `buffered_amount_low_threshold` so str0m
/// fires `Event::ChannelBufferedAmountLow` when buffered drops below this.
const LOW_WATERMARK: usize = 64 * 1024;

/// Bounded channel capacity for the async file-reader task.
/// Small so the reader doesn't race far ahead of the sender.
const FILE_READER_CHANNEL_CAP: usize = 4;

/// ICE connection timeout — give up if not connected within 30 s.
const ICE_TIMEOUT_SECS: u64 = 30;

/// Transfer idle timeout — abort if no progress for 60 s.
const IDLE_TIMEOUT_SECS: u64 = 60;

/// Draining timeout — after sending EOF marker, allow this long for str0m
/// to finish SCTP retransmissions.  Incoming SACKs update `last_activity`,
/// so this only fires once the peer stops acknowledging (data fully delivered
/// or connection lost).
const DRAINING_TIMEOUT_SECS: u64 = 10;

// ---------------------------------------------------------------------------
// Async file reader items
// ---------------------------------------------------------------------------

/// Items produced by the background file-reader task.
enum FileChunk {
    /// A chunk of file data.
    Data(Bytes),
    /// The file has been fully read.
    Eof,
    /// A read error occurred; the string describes the error.
    Error(String),
}

/// Spawn an async file-reader task that reads `path` in `CHUNK_SIZE` chunks
/// and pushes them into a bounded channel.
///
/// The task stops automatically when the receiver is dropped (send fails).
///
/// `wake_tx` / `session_id` are used to nudge the `RtcManager` run-loop
/// after each chunk is enqueued so it calls `poll_outputs` promptly.
fn spawn_file_reader(
    path: PathBuf,
    wake_tx: mpsc::Sender<u64>,
    session_id: u64,
) -> mpsc::Receiver<FileChunk> {
    let (tx, rx) = mpsc::channel(FILE_READER_CHANNEL_CAP);
    tokio::spawn(async move {
        use bytes::BytesMut;
        use tokio::io::AsyncReadExt;

        let file = match tokio::fs::File::open(&path).await {
            Ok(f) => f,
            Err(e) => {
                let _ = tx
                    .send(FileChunk::Error(format!(
                        "Failed to open {}: {e}",
                        path.display()
                    )))
                    .await;
                // Wake manager so the session can observe the error.
                let _ = wake_tx.try_send(session_id);
                return;
            }
        };
        let mut reader = tokio::io::BufReader::new(file);
        let mut buf = BytesMut::with_capacity(CHUNK_SIZE);

        loop {
            buf.resize(CHUNK_SIZE, 0);
            match reader.read(&mut buf[..]).await {
                Ok(0) => {
                    let _ = tx.send(FileChunk::Eof).await;
                    // Wake manager for EOF as well.
                    let _ = wake_tx.try_send(session_id);
                    return;
                }
                Ok(n) => {
                    let chunk = buf.split_to(n).freeze();
                    // Reserve capacity for next read.
                    buf.reserve(CHUNK_SIZE);
                    if tx.send(FileChunk::Data(chunk)).await.is_err() {
                        // Receiver dropped — session is gone.
                        return;
                    }
                    // Nudge the manager so it calls poll_outputs promptly.
                    // try_send + ignore-full provides cheap coalescing.
                    let _ = wake_tx.try_send(session_id);
                }
                Err(e) => {
                    let _ = tx
                        .send(FileChunk::Error(format!("File read error: {e}")))
                        .await;
                    // Wake manager so the session can observe the error.
                    let _ = wake_tx.try_send(session_id);
                    return;
                }
            }
        }
    });
    rx
}

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
    /// File fully read & EOF marker sent — flushing remaining SCTP data.
    Draining,
    /// Transfer completed successfully (all data flushed).
    Done,
    /// Session terminated due to error or timeout.
    Failed,
}

// ---------------------------------------------------------------------------
// RtcSession
// ---------------------------------------------------------------------------

/// A single WebRTC DataChannel file-transfer session backed by str0m.
///
/// File I/O is performed by an async background task; this struct only
/// consumes pre-read [`Bytes`] chunks from a bounded channel.
pub struct RtcSession {
    /// The str0m Rtc instance for this session.
    rtc: Rtc,
    /// Unique session identifier (matches the key in RtcManager::sessions).
    session_id: u64,
    /// Path of the file to transfer.
    file_path: PathBuf,
    /// Pre-collected file size (collected asynchronously before session creation).
    file_size: u64,
    /// DataChannel ID — set once the channel opens via Event::ChannelOpen.
    channel_id: Option<ChannelId>,
    /// Current session state.
    state: SessionState,
    /// Receiver end of the async file-reader channel.
    chunk_rx: Option<mpsc::Receiver<FileChunk>>,
    /// Current chunk being written into the DataChannel (zero-copy cursor).
    current_chunk: Option<Bytes>,
    /// Offset into `current_chunk` — bytes already written to str0m.
    current_off: usize,
    /// When this session was created.
    created_at: Instant,
    /// Last time activity (packet or data send) occurred.
    last_activity: Instant,
    /// The local socket address used for `Receive.destination`.
    local_addr: SocketAddr,
    /// Local candidate addresses (one per address family) used to pick
    /// the correct `Receive.destination` for str0m.
    local_candidates: Vec<SocketAddr>,
    /// Cached next timeout from str0m.
    cached_timeout: Option<Instant>,
    /// Whether the file reader has signalled EOF.
    eof_reached: bool,
    /// Whether the EOF marker JSON has been sent on the DataChannel.
    eof_marker_sent: bool,
    /// Total bytes written to str0m so far.
    bytes_sent: u64,
    /// Sender half of the wake channel used to nudge the RtcManager.
    wake_tx: mpsc::Sender<u64>,
}

impl RtcSession {
    /// Create a new session wrapping an already-configured [`Rtc`] instance.
    ///
    /// `file_size` should be pre-collected via `tokio::fs::metadata` so that
    /// no blocking I/O happens on this path.
    pub fn new(
        rtc: Rtc,
        session_id: u64,
        file_path: PathBuf,
        file_size: u64,
        local_addr: SocketAddr,
        local_candidate_addrs: Vec<SocketAddr>,
        wake_tx: mpsc::Sender<u64>,
    ) -> Self {
        let now = Instant::now();
        Self {
            rtc,
            session_id,
            file_path,
            file_size,
            channel_id: None,
            state: SessionState::Pending,
            chunk_rx: None,
            current_chunk: None,
            current_off: 0,
            created_at: now,
            last_activity: now,
            local_addr,
            local_candidates: local_candidate_addrs,
            cached_timeout: None,
            eof_reached: false,
            eof_marker_sent: false,
            bytes_sent: 0,
            wake_tx,
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

        // Pick a local candidate address whose address-family matches the
        // source so that str0m can match the correct candidate pair.
        let destination = self
            .local_candidates
            .iter()
            .find(|c| {
                matches!(
                    (source, c),
                    (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_))
                )
            })
            .copied()
            .unwrap_or(self.local_addr);

        let receive = match Receive::new(Protocol::Udp, source, destination, data) {
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
        if self.state == SessionState::Failed {
            return;
        }

        self.drain_poll_output(udp_tx);

        // Try to write more file data (respects watermarks).
        if self.state == SessionState::Transferring {
            self.try_send_chunks(udp_tx);

            // Once the file reader is finished AND there is no remaining
            // current chunk, send the EOF marker and enter Draining.
            if self.eof_reached && self.current_chunk.is_none() && !self.eof_marker_sent {
                if let Some(cid) = self.channel_id {
                    info!(
                        "All file data written to DataChannel ({} bytes) — sending EOF marker, entering Draining",
                        self.bytes_sent
                    );
                    // Send EOF as a text (binary=false) JSON message.
                    if let Some(mut ch) = self.rtc.channel(cid) {
                        let eof_msg = br#"{"type":"eof"}"#;
                        if let Err(e) = ch.write(false, eof_msg) {
                            warn!("Failed to send EOF marker: {e}");
                        }
                    }
                    self.eof_marker_sent = true;
                    self.state = SessionState::Draining;
                    // Drain once more so the EOF marker gets segmented into
                    // UDP packets immediately.
                    self.drain_poll_output(udp_tx);
                }
            }
        }

        // In Draining state: str0m still has SCTP data to flush.
        // Do NOT mark Done while buffered_amount > 0.
        if self.state == SessionState::Draining {
            let buffered = self.channel_buffered_amount();
            if !self.rtc.is_alive() && buffered == 0 {
                info!("Draining complete — str0m connection closed, buffer empty");
                self.state = SessionState::Done;
            }
        }

        self.check_timeouts();
    }

    /// Drain `rtc.poll_output()` until we get a `Timeout`, sending any
    /// `Transmit` packets and processing events.
    fn drain_poll_output(&mut self, udp_tx: &UdpSocket) {
        let mut n: usize = 0;
        loop {
            if n >= MAX_POLL_OUTPUTS_PER_DRAIN {
                // We didn't reach a Timeout yet, but we must bound work per call.
                // Schedule an immediate wake so we continue draining soon.
                self.cached_timeout = Some(Instant::now());
                warn!(
                    session_id = self.session_id,
                    max_outputs = MAX_POLL_OUTPUTS_PER_DRAIN,
                    "Reached poll_output drain cap; yielding to avoid stack overflow"
                );
                break;
            }
            match self.rtc.poll_output() {
                Ok(output) => match output {
                    Output::Transmit(t) => {
                        n = n.saturating_add(1);
                        let dest = to_v6_mapped(t.destination);
                        if let Err(e) = udp_tx.send_to(&t.contents, dest) {
                            warn!("UDP send error to {}: {e}", t.destination);
                        }
                    }
                    Output::Timeout(t) => {
                        self.cached_timeout = Some(t);
                        break;
                    }
                    Output::Event(event) => {
                        n = n.saturating_add(1);
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
                if ice_state == IceConnectionState::Disconnected
                    && self.state != SessionState::Draining
                {
                    info!("ICE disconnected — marking session as failed");
                    self.state = SessionState::Failed;
                }
            }

            Event::ChannelOpen(id, label) => {
                info!("DataChannel opened: id={id:?}, label={label}");
                self.channel_id = Some(id);
                self.state = SessionState::Transferring;
                self.last_activity = Instant::now();

                // Set the buffered amount low threshold so we get notified
                // when it's safe to resume sending.
                if let Some(mut ch) = self.rtc.channel(id) {
                    ch.set_buffered_amount_low_threshold(LOW_WATERMARK);
                }

                // Spawn the async file reader task.
                self.chunk_rx = Some(spawn_file_reader(
                    self.file_path.clone(),
                    self.wake_tx.clone(),
                    self.session_id,
                ));

                // Send metadata first (uses pre-collected file_size).
                self.send_metadata();
            }

            Event::ChannelData(_data) => {
                // We are the sender — ignore incoming data from the remote.
            }

            Event::ChannelClose(id) => {
                info!("DataChannel closed: id={id:?}");
                if self.channel_id == Some(id) && self.state != SessionState::Draining {
                    // Remote initiated close or echo of our own close.
                    self.state = SessionState::Draining;
                }
            }

            Event::ChannelBufferedAmountLow(_id) => {
                // This event is informational; the actual gating is done by
                // checking buffered_amount() in try_send_chunks.
                debug!("Buffered amount low — will resume sending");
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

        let filename = self
            .file_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".to_string());

        let json = serde_json::json!({
            "filename": filename,
            "size": self.file_size,
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

    /// Consume chunks from the async file reader and write them into str0m,
    /// respecting the high watermark for backpressure.
    ///
    /// Uses a `current_chunk: Option<Bytes>` + `current_off: usize` cursor
    /// to avoid any Vec cloning on partial writes.
    ///
    /// After each batch of writes, re-drains `poll_output()` so new SCTP
    /// payloads are immediately segmented into UDP packets.
    pub fn try_send_chunks(&mut self, udp_tx: &UdpSocket) {
        let Some(cid) = self.channel_id else { return };

        let mut did_write = false;
        let mut wrote_this_cycle: usize = 0;

        loop {
            if wrote_this_cycle >= MAX_WRITE_PER_CYCLE {
                break;
            }

            // Check backpressure: if buffered_amount >= HIGH_WATERMARK, stop.
            {
                let Some(mut ch) = self.rtc.channel(cid) else {
                    warn!("Channel {cid:?} disappeared during transfer");
                    self.state = SessionState::Failed;
                    return;
                };
                if ch.buffered_amount() >= HIGH_WATERMARK {
                    break;
                }
            }

            // Ensure we have a current chunk to write.
            if self.current_chunk.is_none() {
                if self.eof_reached {
                    break;
                }
                // Try to receive the next chunk from the async reader (non-blocking).
                let Some(ref mut rx) = self.chunk_rx else {
                    break;
                };
                match rx.try_recv() {
                    Ok(FileChunk::Data(chunk)) => {
                        self.current_chunk = Some(chunk);
                        self.current_off = 0;
                    }
                    Ok(FileChunk::Eof) => {
                        self.eof_reached = true;
                        // Drop the receiver so the task can clean up.
                        self.chunk_rx = None;
                        break;
                    }
                    Ok(FileChunk::Error(e)) => {
                        warn!("Async file reader error: {e}");
                        self.state = SessionState::Failed;
                        return;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        // Reader hasn't produced a chunk yet — yield.
                        break;
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        // Reader task died without sending EOF — treat as EOF.
                        warn!("File reader channel disconnected unexpectedly — treating as EOF");
                        self.eof_reached = true;
                        self.chunk_rx = None;
                        break;
                    }
                }
            }

            // Write from the current chunk at the current offset.
            let chunk = self.current_chunk.as_ref().unwrap();
            let remaining = &chunk[self.current_off..];

            match self.rtc.channel(cid) {
                Some(mut ch) => match ch.write(true, remaining) {
                    Ok(false) => {
                        // Buffer full — leave current_chunk as-is, retry later.
                        break;
                    }
                    Ok(true) => {
                        // str0m v0.16 write is all-or-nothing.
                        self.bytes_sent += remaining.len() as u64;
                        self.last_activity = Instant::now();
                        did_write = true;
                        wrote_this_cycle = wrote_this_cycle.saturating_add(remaining.len());

                        // Whole remaining slice accepted.
                        self.current_chunk = None;
                        self.current_off = 0;
                        // Continue the loop to try writing more.
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

        // After writing data, re-drain poll_output so that new SCTP payload
        // turns into Output::Transmit immediately (avoids waiting for next tick).
        if did_write {
            self.drain_poll_output(udp_tx);
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

    /// Total bytes sent to the remote peer over the DataChannel.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// True if the session is in a terminal state.
    fn is_terminal(&self) -> bool {
        matches!(self.state, SessionState::Done | SessionState::Failed)
    }

    /// Get the current `buffered_amount` for our data channel (0 if unavailable).
    fn channel_buffered_amount(&mut self) -> usize {
        self.channel_id
            .and_then(|cid| self.rtc.channel(cid))
            .map(|mut ch| ch.buffered_amount())
            .unwrap_or(0)
    }

    /// Check whether any timeout has been exceeded and transition accordingly.
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

        // Draining timeout: shorter grace period after file is fully written.
        // SACKs arriving via handle_input keep last_activity fresh, so this
        // only expires once the peer stops acknowledging.
        //
        // IMPORTANT: Do NOT mark Done if buffered_amount > 0 — data is still
        // in flight.  The timeout only applies when the buffer is empty OR
        // truly stale.
        if self.state == SessionState::Draining
            && now.duration_since(self.last_activity).as_secs() > DRAINING_TIMEOUT_SECS
        {
            let buffered = self.channel_buffered_amount();
            if buffered == 0 {
                info!(
                    "Draining timeout ({DRAINING_TIMEOUT_SECS}s) — session complete (buffer empty)"
                );
                self.state = SessionState::Done;
            } else {
                debug!(
                    "Draining timeout reached but buffered_amount={buffered} > 0 — keeping session alive"
                );
            }
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

/// Convert an IPv4 `SocketAddr` to an IPv4-mapped IPv6 address so it can be
/// sent on a dual-stack `[::]` socket (required on Windows).  IPv6 addresses
/// are returned unchanged.
fn to_v6_mapped(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => {
            let mapped = v4.ip().to_ipv6_mapped();
            SocketAddr::new(std::net::IpAddr::V6(mapped), v4.port())
        }
        v6 => v6,
    }
}
