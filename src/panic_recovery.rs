use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::time::Duration;

use futures_util::FutureExt;
use tokio::task::JoinHandle;

/// Spawn a tokio task that catches panics and logs them via `tracing::error`.
///
/// Use this as a drop-in replacement for `tokio::spawn` in fire-and-forget
/// scenarios (per-connection handlers, background workers, etc.).
///
/// `handler` is a human-readable identifier (e.g. `"https-conn"`, `"h3-req"`)
/// included in the log line so operators can tell *which* handler panicked.
pub fn spawn_catch_panic<F>(handler: &'static str, fut: F) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(payload) = AssertUnwindSafe(fut).catch_unwind().await {
            tracing::error!(
                handler,
                panic = %panic_payload_to_string(&payload),
                "task panicked"
            );
        }
    })
}

/// Run a future that is expected to live forever (accept loops, manager
/// event loops, etc.).  If it panics, log the error and restart with
/// exponential back-off (capped at 5 s).
///
/// Returns only when the future completes *normally* (i.e. without panic).
pub async fn run_with_restart<F, Fut>(handler: &'static str, factory: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = ()> + Send,
{
    let mut backoff = Duration::from_millis(100);
    loop {
        match AssertUnwindSafe(factory()).catch_unwind().await {
            Ok(()) => {
                tracing::info!(handler, "exited normally");
                break;
            }
            Err(payload) => {
                tracing::error!(
                    handler,
                    panic = %panic_payload_to_string(&payload),
                    backoff_ms = backoff.as_millis() as u64,
                    "panicked — restarting after backoff"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
            }
        }
    }
}

/// Extract a human-readable message from a panic payload.
fn panic_payload_to_string(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}
