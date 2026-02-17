use std::sync::Arc;

use axum::Router;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tracing::info;

/// Start an HTTPS server with a pre-built rustls ServerConfig.
pub async fn serve(
    port: u16,
    rustls_config: Arc<rustls::ServerConfig>,
    app: Router,
) -> anyhow::Result<()> {
    let tls_acceptor = TlsAcceptor::from(rustls_config);

    let addr = format!("[::]:{port}");
    let listener = TcpListener::bind(&addr).await?;
    info!("HTTPS server listening on https://{addr}");

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("TLS handshake failed from {peer_addr}: {e}");
                    return;
                }
            };

            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let mut app = app.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(app.call(req).await.into_response())
                }
            });

            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new(),
            )
            .serve_connection(io, service)
            .await
            {
                tracing::debug!("HTTPS connection error from {peer_addr}: {e}");
            }
        });
    }
}

trait IntoAxumResponse {
    fn into_response(self) -> axum::response::Response;
}

impl<T> IntoAxumResponse for Result<axum::response::Response, T> {
    fn into_response(self) -> axum::response::Response {
        match self {
            Ok(resp) => resp,
            Err(_) => axum::response::Response::builder()
                .status(500)
                .body(axum::body::Body::empty())
                .unwrap(),
        }
    }
}
