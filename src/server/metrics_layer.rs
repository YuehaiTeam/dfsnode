use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use http::{Request, Response};
use tower::{Layer, Service};

use super::metrics_body::MetricsBody;
use super::RealIp;
use crate::auth::{extract_sign_param, extract_uuid_from_sign};

/// Estimate the wire size of an HTTP response status line + headers.
///
/// This approximates the bytes nginx counts in `$bytes_sent` (minus body).
/// Format: `HTTP/1.1 200 OK\r\n` + `Header-Name: value\r\n` + `\r\n`
fn estimate_response_header_size<B>(resp: &Response<B>) -> u64 {
    // Status line: "HTTP/1.1 " (9) + status (3) + " " + reason (~2-20) + "\r\n"
    // Approximate with 20 bytes for the status line
    let mut size: u64 = 20;

    for (name, value) in resp.headers() {
        // "Header-Name: value\r\n"
        size += name.as_str().len() as u64 + 2 + value.len() as u64 + 2;
    }

    // Final "\r\n" after headers
    size += 2;

    size
}

/// Determine whether a request should be excluded from metrics.
///
/// We only count **file download** traffic, which means:
/// - Internal / metrics endpoints (`/-/*`, `/minio/*`) are excluded.
/// - Only GET method is counted (HEAD, WebDAV PROPFIND, PUT, DELETE, etc. are excluded).
/// - Requests authenticated via Basic Auth are excluded (those are WebDAV management sessions;
///   public downloads use signature-based auth or no auth).
fn should_skip_metrics<B>(req: &Request<B>) -> bool {
    // 1. All internal endpoints (/-/metrics, /-/ping, /minio/metrics/*, etc.)
    let path = req.uri().path();
    if path.starts_with("/-/") || path.starts_with("/minio/") {
        return true;
    }

    // 2. Only count GET (file download); HEAD is excluded from metrics
    if req.method() != http::Method::GET {
        return true;
    }

    // 3. Exclude requests with Basic Auth (WebDAV management browsing)
    if let Some(auth) = req.headers().get(http::header::AUTHORIZATION) {
        if let Ok(value) = auth.to_str() {
            if value.starts_with("Basic ") {
                return true;
            }
        }
    }

    false
}

/// Tower Layer that wraps response bodies with [`MetricsBody`] for byte counting.
///
/// Only file download requests are counted:
/// - `/-/*` and `/minio/*` endpoints are excluded
/// - Only GET method is counted (HEAD is excluded)
/// - Basic Auth requests (WebDAV management) are excluded
#[derive(Clone)]
pub struct MetricsLayer {
    protocol: &'static str,
}

impl MetricsLayer {
    pub fn new(protocol: &'static str) -> Self {
        Self { protocol }
    }
}

impl<S> Layer<S> for MetricsLayer {
    type Service = MetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsService {
            inner,
            protocol: self.protocol,
        }
    }
}

#[derive(Clone)]
pub struct MetricsService<S> {
    inner: S,
    protocol: &'static str,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for MetricsService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: http_body::Body + Unpin + Send + 'static,
{
    type Response = Response<MetricsBody<ResBody>>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let protocol = self.protocol;

        let skip = should_skip_metrics(&req);

        // Extract request info for access logging before passing request to inner service.
        let peer_ip: Option<IpAddr> = req
            .extensions()
            .get::<RealIp>()
            .map(|r| r.0)
            .or_else(|| {
                req.extensions()
                    .get::<axum::extract::ConnectInfo<SocketAddr>>()
                    .map(|ci| super::normalize_ip(ci.0.ip()))
            });

        let path = req.uri().path().to_owned();
        let uuid = if skip {
            None
        } else {
            req.uri()
                .query()
                .and_then(extract_sign_param)
                .as_deref()
                .and_then(extract_uuid_from_sign)
        };

        // Clone the service to avoid borrowing issues with poll_ready
        let mut svc = self.inner.clone();
        // Swap so self retains the "ready" service (Tower poll_ready contract)
        std::mem::swap(&mut svc, &mut self.inner);

        Box::pin(async move {
            let resp = svc.call(req).await?;

            // Estimate response header size (status line + headers) to include
            // in bytes_sent, matching nginx $bytes_sent / MinIO semantics.
            let header_bytes = if skip { 0 } else { estimate_response_header_size(&resp) };

            let (parts, body) = resp.into_parts();
            let tracked = MetricsBody::new(body, protocol, skip, header_bytes, peer_ip, path, uuid);
            Ok(Response::from_parts(parts, tracked))
        })
    }
}
