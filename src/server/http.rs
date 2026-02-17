use axum::Router;
use tokio::net::TcpListener;
use tracing::info;

/// Start a plain HTTP server on the given port.
pub async fn serve(port: u16, app: Router) -> anyhow::Result<()> {
    let addr = format!("[::]:{port}");
    let listener = TcpListener::bind(&addr).await?;
    info!("HTTP server listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
