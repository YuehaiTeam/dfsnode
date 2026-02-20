use std::sync::Arc;

use axum::Router;
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

    let listener = super::bind_dual_stack_tcp(port)?;
    info!("HTTPS server listening on https://[::]:{port}");

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let app = app.clone();

        crate::panic_recovery::spawn_catch_panic("https-conn", async move {
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
