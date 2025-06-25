use std::io::Error as IoError;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Poll, ready};
use std::time::Instant;

use futures_util::Stream;
use hyper::body::{Bytes, Frame};
use hyper::http::StatusCode;
use hyper::{Method, Uri};

use crate::metrics::{HTTP_BYTES_SENT_TOTAL, HTTP_REQUESTS_TOTAL};

pub struct StaticMetrics {
    pub method: Method,
    pub uri: Uri,
    pub status: StatusCode,
}

pub enum ResBody {
    Static {
        inner: hyper_staticfile::Body,
        start_time: Instant,
        bytes_sent: u32,
        metrics: Arc<StaticMetrics>,
    },
    Dav(dav_server::body::Body),
    Bytes(Bytes),
    Empty,
}

impl hyper::body::Body for ResBody {
    type Data = Bytes;
    type Error = IoError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, IoError>>> {
        let opt = ready!(match *self {
            ResBody::Static {
                ref mut inner,
                ref mut bytes_sent,
                ..
            } => {
                let result = ready!(match inner {
                    hyper_staticfile::Body::Empty => return Poll::Ready(None),
                    hyper_staticfile::Body::Full(stream) => Pin::new(stream).poll_next(cx),
                    hyper_staticfile::Body::Range(stream) => Pin::new(stream).poll_next(cx),
                    hyper_staticfile::Body::MultiRange(stream) => Pin::new(stream).poll_next(cx),
                });
                let bytes = result.map(|res| res.map(Frame::data));
                if let Some(Ok(ref bytes)) = bytes {
                    if bytes.is_data() {
                        // Update bytes sent count
                        let add = bytes.data_ref().unwrap().len() as u32;
                        *bytes_sent += add;
                    }
                }
                Poll::Ready(bytes)
            }
            ResBody::Dav(ref mut dav_body) => {
                let result = ready!(Pin::new(dav_body).poll_next(cx));
                Poll::Ready(result.map(|res| res.map(Frame::data)))
            }
            ResBody::Empty => return Poll::Ready(None),
            ResBody::Bytes(ref mut bytes) => {
                if bytes.is_empty() {
                    return Poll::Ready(None);
                }
                // Use take to avoid cloning
                let content = std::mem::take(bytes);
                Poll::Ready(Some(Ok(Frame::data(content))))
            }
        });
        Poll::Ready(opt)
    }
}

// 实现析构 - 优化日志记录性能
impl Drop for ResBody {
    fn drop(&mut self) {
        if let ResBody::Static {
            start_time,
            bytes_sent,
            metrics,
            ..
        } = self
        {
            // 增加请求计数
            HTTP_REQUESTS_TOTAL.inc();
            // 记录发送的字节数到 metrics
            HTTP_BYTES_SENT_TOTAL.inc_by(*bytes_sent as u64);

            // 优化日志记录 - 只在debug模式下记录详细信息
            if cfg!(debug_assertions) {
                let est_speed = if start_time.elapsed().as_millis() > 0 {
                    *bytes_sent as f64 / start_time.elapsed().as_secs_f64()
                } else {
                    0.0
                };
                tracing::debug!(
                    "{} {} -> {} ({}ms) {}b {:.0}b/s",
                    metrics.method,
                    metrics.uri,
                    metrics.status,
                    start_time.elapsed().as_millis(),
                    bytes_sent,
                    est_speed
                );
            }
        }
    }
}
