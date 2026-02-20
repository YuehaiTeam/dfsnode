use std::net::SocketAddr;

use axum::Router;
use tracing::info;

/// Start a plain HTTP server on the given port.
///
/// Uses `into_make_service_with_connect_info` so that every request carries
/// `ConnectInfo<SocketAddr>` — used by MetricsLayer for access logging.
pub async fn serve(port: u16, app: Router) -> anyhow::Result<()> {
    let listener = super::bind_dual_stack_tcp(port)?;
    info!("HTTP server listening on http://[::]:{port}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
