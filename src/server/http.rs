use axum::Router;
use tracing::info;

/// Start a plain HTTP server on the given port.
///
/// The `app` Router should already have a `MetricsLayer` applied so that
/// response bodies are automatically tracked.
pub async fn serve(port: u16, app: Router) -> anyhow::Result<()> {
    let listener = super::bind_dual_stack_tcp(port)?;
    info!("HTTP server listening on http://[::]:{port}");
    axum::serve(listener, app).await?;
    Ok(())
}
