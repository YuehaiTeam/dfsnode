use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Buf;
use http_body::{Body, Frame};
use tracing::{debug, info};

use crate::metrics;

/// A wrapper around a response body that tracks bytes sent for metrics.
///
/// Tracks both response header size (estimated) and body bytes, matching
/// the semantics of nginx `$bytes_sent` and MinIO traffic metrics.
///
/// When this body is dropped, it records:
/// - One request count increment (unless `skip` is true)
/// - Total bytes sent (header + body)
/// - A structured request log line (protocol, peer IP, path, bytes, UUID)
pub struct MetricsBody<B> {
    inner: B,
    bytes_sent: u64,
    flushed_bytes: u64,
    last_flush_at: Instant,
    start_send_at: Option<Instant>,
    last_send_at: Option<Instant>,
    protocol: &'static str,
    /// If true, skip recording metrics (e.g. for /-/metrics endpoint itself).
    skip: bool,
    /// Client IP (real or socket).
    peer_ip: Option<IpAddr>,
    /// Request URI path.
    path: String,
    /// UUID from signature `$` param (first 32 hex chars), if present.
    uuid: Option<String>,
}

impl<B> MetricsBody<B> {
    /// Create a new MetricsBody wrapping the given body.
    ///
    /// `header_bytes` is the estimated size of the response status line + headers,
    /// which is included in the total bytes_sent count.
    pub fn new(
        inner: B,
        protocol: &'static str,
        skip: bool,
        header_bytes: u64,
        peer_ip: Option<IpAddr>,
        path: String,
        uuid: Option<String>,
    ) -> Self {
        Self {
            inner,
            bytes_sent: header_bytes,
            flushed_bytes: 0,
            last_flush_at: Instant::now(),
            start_send_at: None,
            last_send_at: None,
            protocol,
            skip,
            peer_ip,
            path,
            uuid,
        }
    }
}

impl<B> Body for MetricsBody<B>
where
    B: Body + Unpin,
    B::Data: Buf,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let inner = Pin::new(&mut this.inner);

        match inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if this.skip {
                        return Poll::Ready(Some(Ok(frame)));
                    }

                    let now = Instant::now();
                    if this.start_send_at.is_none() {
                        this.start_send_at = Some(now);
                        metrics::flush_pending_bytes(
                            this.protocol,
                            this.bytes_sent,
                            &mut this.flushed_bytes,
                            &mut this.last_flush_at,
                        );
                    }
                    this.last_send_at = Some(now);

                    this.bytes_sent = this.bytes_sent.saturating_add(data.remaining() as u64);

                    if metrics::should_flush_bytes(
                        this.bytes_sent,
                        this.flushed_bytes,
                        this.last_flush_at,
                    ) {
                        metrics::flush_pending_bytes(
                            this.protocol,
                            this.bytes_sent,
                            &mut this.flushed_bytes,
                            &mut this.last_flush_at,
                        );
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for MetricsBody<B> {
    fn drop(&mut self) {
        if self.skip {
            return;
        }

        metrics::record_request(self.protocol);
        metrics::flush_pending_bytes(
            self.protocol,
            self.bytes_sent,
            &mut self.flushed_bytes,
            &mut self.last_flush_at,
        );

        let (elapsed_ms, avg_bps) = metrics::elapsed_ms_and_avg_bps_between(
            self.start_send_at,
            self.last_send_at,
            self.bytes_sent,
        );

        let ip_str = self
            .peer_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "-".into());
        let uuid_str = self.uuid.as_deref().unwrap_or("-");

        info!(
            "[{}] {} {} {} {} {}ms {}bps",
            self.protocol, ip_str, self.path, self.bytes_sent, uuid_str, elapsed_ms, avg_bps,
        );

        debug!("[{}] {} bytes sent", self.protocol, self.bytes_sent,);
    }
}
