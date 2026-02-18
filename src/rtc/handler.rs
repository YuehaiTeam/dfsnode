use std::path::PathBuf;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Router;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Shared state for the LOCK / WebRTC signaling handler.
#[derive(Clone)]
pub struct RtcState {
    /// Handle to the RtcManager for creating sessions.
    pub rtc_handle: super::RtcHandle,
    /// Root directory for file serving.
    pub root: PathBuf,
    /// URL prefix to strip from paths (e.g. "/dav").
    pub prefix: String,
}

/// Incoming SDP offer + ICE candidates from the client.
#[derive(serde::Deserialize)]
pub struct LockRequest {
    pub sdp: String,
    pub candidates: Vec<String>,
}

/// SDP answer + server ICE candidates returned to the client.
#[derive(serde::Serialize)]
pub struct LockResponse {
    pub sdp: String,
    pub candidates: Vec<String>,
}

// ---------------------------------------------------------------------------
// Router constructor
// ---------------------------------------------------------------------------

/// Build a router that intercepts the LOCK HTTP method on every path and
/// delegates to [`lock_handler`].  Merge this into the main app *before* the
/// DavHandler fallback so that LOCK requests never reach the DAV layer.
///
/// Since LOCK is not a standard HTTP method, we use `any()` as the method
/// filter on the fallback and check the method inside the handler.  Non-LOCK
/// requests pass through (returning 405) so the outer router's own fallback
/// (DavHandler) still handles them.
pub fn lock_routes(_prefix: &str, rtc_state: RtcState) -> Router {
    Router::new()
        .fallback(lock_handler)
        .with_state(rtc_state)
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// LOCK handler — WebRTC DataChannel signaling endpoint.
///
/// Exchanges an SDP offer/answer so the client can open a DataChannel for
/// high-speed file transfer.  Authentication is enforced by the auth
/// middleware layer that wraps the entire router; this handler does **not**
/// perform its own auth checks.
///
/// Only the LOCK method is accepted.  Any other method receives 405 Method
/// Not Allowed so the caller can fall through to alternative handlers.
pub async fn lock_handler(
    State(rtc_state): State<RtcState>,
    req: axum::extract::Request,
) -> impl IntoResponse {
    // Only accept the LOCK method.
    if req.method().as_str() != "LOCK" {
        return (StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed").into_response();
    }

    // 1. Extract the URI path.
    let path = req.uri().path().to_string();

    // 2. Strip the configured prefix (e.g. "/dav/file.zip" → "/file.zip").
    let stripped = strip_prefix(&path, &rtc_state.prefix);

    // 3. Parse the JSON body.
    let body_bytes = match axum::body::to_bytes(req.into_body(), 64 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            warn!("LOCK: failed to read request body: {e}");
            return error_response(StatusCode::BAD_REQUEST, format!("Failed to read body: {e}"));
        }
    };

    let lock_req: LockRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => {
            warn!("LOCK: invalid JSON body: {e}");
            return error_response(StatusCode::BAD_REQUEST, format!("Invalid JSON: {e}"));
        }
    };

    if lock_req.sdp.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Missing sdp field".to_string());
    }

    // 4. Resolve the file path on disk.
    let rel = stripped.trim_start_matches('/');
    let file_path = rtc_state.root.join(rel);

    // 5. Verify the file exists and is a regular file.
    match tokio::fs::metadata(&file_path).await {
        Ok(meta) if meta.is_file() => { /* ok */ }
        Ok(_) => {
            return error_response(
                StatusCode::NOT_FOUND,
                format!("Not a regular file: {}", stripped),
            );
        }
        Err(_) => {
            return error_response(
                StatusCode::NOT_FOUND,
                format!("File not found: {}", stripped),
            );
        }
    }

    // 6. Create a WebRTC session via the RtcHandle.
    match rtc_state
        .rtc_handle
        .create_session(file_path, lock_req.sdp, lock_req.candidates)
        .await
    {
        Ok((_session_id, sdp_answer)) => {
            info!("LOCK: created RTC session for {stripped}");

            let resp = LockResponse {
                sdp: sdp_answer,
                // Server-side ICE candidates are baked into the SDP answer
                // by the RtcManager.  Return an empty vec here; if the
                // manager later exposes trickle candidates they can be added.
                candidates: Vec::new(),
            };

            (StatusCode::OK, axum::Json(resp)).into_response()
        }
        Err(e) => {
            warn!("LOCK: RtcManager error: {e}");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("WebRTC session setup failed: {e}"),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strip `prefix` from the beginning of `path`.
///
/// Example: `strip_prefix("/dav/file.zip", "/dav")` → `"/file.zip"`.
/// If the path does not start with the prefix it is returned unchanged.
fn strip_prefix<'a>(path: &'a str, prefix: &str) -> &'a str {
    let clean = prefix.trim_end_matches('/');
    if clean.is_empty() || clean == "/" {
        return path;
    }
    path.strip_prefix(clean).unwrap_or(path)
}

/// Build a JSON error response with the given status code and message.
fn error_response(status: StatusCode, message: String) -> Response {
    let body = serde_json::json!({ "error": message });
    (status, axum::Json(body)).into_response()
}
