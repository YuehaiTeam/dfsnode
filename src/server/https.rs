use std::sync::Arc;

use axum::Router;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tracing::info;

/// Start an HTTPS server with a pre-built rustls ServerConfig.
///
/// The `app` Router should already have a `MetricsLayer` applied so that
/// response bodies are automatically tracked.
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
                    let resp = app.call(req).await.unwrap_or_else(|err| match err {});
                    Ok::<_, std::convert::Infallible>(resp)
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
