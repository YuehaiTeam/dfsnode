use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

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
                    this.bytes_sent = this.bytes_sent.saturating_add(data.remaining() as u64);
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
        metrics::record_bytes_sent(self.protocol, self.bytes_sent);

        let ip_str = self
            .peer_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "-".into());
        let uuid_str = self.uuid.as_deref().unwrap_or("-");

        info!(
            "[{}] {} {} {} {}",
            self.protocol, ip_str, self.path, self.bytes_sent, uuid_str,
        );

        debug!("[{}] {} bytes sent", self.protocol, self.bytes_sent,);
    }
}
