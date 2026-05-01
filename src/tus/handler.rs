use std::path::{Path as StdPath, PathBuf};
use std::sync::Arc;

use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{head, options};
use axum::Router;
use tracing::{debug, info, warn};

use crate::path_policy::PathPolicyError;
use crate::tus::{TusUploadManager, decode_tus_metadata};

/// Shared state for TUS handlers.
#[derive(Clone)]
pub struct TusState {
    pub manager: Arc<TusUploadManager>,
    pub root: PathBuf,
    pub prefix: String,
    pub path_policy: Arc<crate::path_policy::PathPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TusCreateMode {
    FixedCollection,
    DirectoryScoped { relative_dir: PathBuf },
}

/// Build axum routes for TUS resumable uploads.
///
/// All routes are mounted under `{prefix}/.tus-uploads`.
pub fn tus_routes(
    prefix: &str,
    manager: Arc<TusUploadManager>,
    root: PathBuf,
    path_policy: Arc<crate::path_policy::PathPolicy>,
) -> Router {
    let prefix_clean = prefix.trim_end_matches('/').to_string();
    let tus_base = tus_collection_path(&prefix_clean);

    let state = TusState {
        manager,
        root,
        prefix: prefix_clean,
        path_policy,
    };

    Router::new()
        .route(&tus_base, options(tus_options).post(tus_create))
        .route(&format!("{}/", tus_base), options(tus_options).post(tus_create))
        .route(
            &format!("{}/{{session_id}}", tus_base),
            head(tus_head)
                .patch(tus_patch)
                .delete(tus_delete)
                .options(tus_options),
        )
        .with_state(state)
}

pub(crate) fn is_directory_scoped_tus_create_request(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    prefix: &str,
) -> bool {
    if method != Method::POST || !headers.contains_key("tus-resumable") {
        return false;
    }

    matches!(
        classify_tus_create_path(path, prefix),
        Some(TusCreateMode::DirectoryScoped { .. })
    )
}

pub(crate) async fn handle_directory_scoped_tus_create(state: TusState, req: Request) -> Response {
    let path = req.uri().path().to_string();
    let Some(mode @ TusCreateMode::DirectoryScoped { .. }) = classify_tus_create_path(&path, &state.prefix) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    tus_create_with_mode(state, req, mode).await
}

/// Check that Tus-Resumable header is present and equals "1.0.0".
/// Returns Err(412) if missing or wrong.
fn check_tus_resumable(headers: &HeaderMap) -> Result<(), Box<Response>> {
    match headers.get("tus-resumable") {
        Some(v) if v == "1.0.0" => Ok(()),
        Some(v) => {
            warn!("Unsupported TUS version: {:?}", v);
            Err(Box::new(
                (
                    StatusCode::PRECONDITION_FAILED,
                    [("tus-resumable", "1.0.0")],
                    format!("Unsupported TUS version: {:?}", v),
                )
                    .into_response(),
            ))
        }
        None => Err(Box::new(
            (
                StatusCode::PRECONDITION_FAILED,
                [("tus-resumable", "1.0.0")],
                "Missing Tus-Resumable header",
            )
                .into_response(),
        )),
    }
}

/// OPTIONS — advertise TUS capabilities.
async fn tus_options(State(state): State<TusState>) -> Response {
    let algos = TusUploadManager::get_supported_checksum_algorithms().join(",");
    let max_size = state.manager.max_upload_size().to_string();

    (
        StatusCode::NO_CONTENT,
        [
            ("tus-resumable", "1.0.0"),
            ("tus-version", "1.0.0"),
            ("tus-extension", "creation,termination,checksum"),
            ("tus-checksum-algorithm", &algos),
            ("tus-max-size", &max_size),
        ],
    )
        .into_response()
}

/// POST — create a new upload session.
async fn tus_create(State(state): State<TusState>, req: Request) -> Response {
    tus_create_with_mode(state, req, TusCreateMode::FixedCollection).await
}

async fn tus_create_with_mode(state: TusState, req: Request, mode: TusCreateMode) -> Response {
    let headers = req.headers().clone();

    if let Err(r) = check_tus_resumable(&headers) {
        return *r;
    }

    let upload_length = match parse_header_u64(&headers, "upload-length") {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                [("tus-resumable", "1.0.0")],
                "Missing Upload-Length header",
            )
                .into_response();
        }
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                [("tus-resumable", "1.0.0")],
                msg,
            )
                .into_response();
        }
    };

    let metadata = match parse_upload_metadata(&headers) {
        Ok(metadata) => metadata,
        Err(response) => return response,
    };

    let target_path = match build_target_path(&state, &mode, &metadata) {
        Ok(path) => path,
        Err(response) => return response,
    };

    info!(
        "Creating TUS upload session: target={:?}, size={}, mode={:?}",
        target_path, upload_length, mode
    );

    match state
        .manager
        .create_session(target_path, upload_length, metadata)
        .await
    {
        Ok(session_id) => {
            let location = build_location(&req, &state.prefix, &session_id);
            info!("Created TUS session: {}", session_id);
            (
                StatusCode::CREATED,
                [
                    ("tus-resumable", "1.0.0"),
                    ("location", location.as_str()),
                ],
            )
                .into_response()
        }
        Err(e) => {
            warn!("Failed to create TUS session: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("tus-resumable", "1.0.0")],
                format!("Failed to create session: {e}"),
            )
                .into_response()
        }
    }
}

fn parse_upload_metadata(
    headers: &HeaderMap,
) -> Result<std::collections::HashMap<String, String>, Response> {
    if let Some(meta_val) = headers.get("upload-metadata") {
        match meta_val.to_str() {
            Ok(s) => match decode_tus_metadata(s) {
                Ok(m) => Ok(m),
                Err(e) => Err((
                    StatusCode::BAD_REQUEST,
                    [("tus-resumable", "1.0.0")],
                    format!("Invalid Upload-Metadata: {e}"),
                )
                    .into_response()),
            },
            Err(_) => Err((
                StatusCode::BAD_REQUEST,
                [("tus-resumable", "1.0.0")],
                "Invalid Upload-Metadata header encoding",
            )
                .into_response()),
        }
    } else {
        Ok(std::collections::HashMap::new())
    }
}

fn build_target_path(
    state: &TusState,
    mode: &TusCreateMode,
    metadata: &std::collections::HashMap<String, String>,
) -> Result<PathBuf, Response> {
    match mode {
        TusCreateMode::FixedCollection => {
            let filename = metadata
                .get("filename")
                .cloned()
                .unwrap_or_else(|| format!("upload-{}", uuid::Uuid::new_v4()));
            let rel_dir = metadata.get("directory").cloned().unwrap_or_default();

            let rel_path = if rel_dir.is_empty() {
                PathBuf::from(&filename)
            } else {
                PathBuf::from(&rel_dir).join(&filename)
            };

            resolve_target_path(state, &rel_path)
        }
        TusCreateMode::DirectoryScoped { relative_dir } => {
            let Some(filename) = metadata.get("filename") else {
                return Err((
                    StatusCode::BAD_REQUEST,
                    [("tus-resumable", "1.0.0")],
                    "Missing Upload-Metadata filename entry",
                )
                    .into_response());
            };

            if let Some(ignored_dir) = metadata.get("directory") {
                debug!(
                    "Ignoring Upload-Metadata.directory in directory-scoped TUS create: {}",
                    ignored_dir
                );
            }

            if !is_valid_filename_segment(filename) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    [("tus-resumable", "1.0.0")],
                    "Invalid filename: expected a single safe path segment",
                )
                    .into_response());
            }

            let rel_path = if relative_dir.as_os_str().is_empty() {
                PathBuf::from(filename)
            } else {
                relative_dir.join(filename)
            };

            resolve_target_path(state, &rel_path)
        }
    }
}

fn resolve_target_path(state: &TusState, rel_path: &StdPath) -> Result<PathBuf, Response> {
    if !is_safe_relative_path(rel_path) {
        return Err((
            StatusCode::BAD_REQUEST,
            [("tus-resumable", "1.0.0")],
            "Invalid path: path traversal detected",
        )
            .into_response());
    }

    let target_path = state.root.join(rel_path);
    match state.path_policy.resolve_for_create(&target_path) {
        Ok(path) => Ok(path),
        Err(PathPolicyError::Forbidden { .. }) => Err((
            StatusCode::FORBIDDEN,
            [("tus-resumable", "1.0.0")],
            "Forbidden: path outside allowed roots",
        )
            .into_response()),
        Err(_) => Err((
            StatusCode::BAD_REQUEST,
            [("tus-resumable", "1.0.0")],
            "Invalid upload target path",
        )
            .into_response()),
    }
}

fn build_location(req: &Request, prefix: &str, session_id: &str) -> String {
    let path = format!("{}/.tus-uploads/{}", prefix.trim_end_matches('/'), session_id);
    let Some(host) = req
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .filter(|host| !host.is_empty())
    else {
        return path;
    };

    let scheme = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .filter(|scheme| !scheme.is_empty())
        .or_else(|| req.uri().scheme_str())
        .unwrap_or("http");

    format!("{}://{}{}", scheme, host, path)
}

fn tus_collection_path(prefix: &str) -> String {
    format!("{}/.tus-uploads", prefix.trim_end_matches('/'))
}

fn classify_tus_create_path(path: &str, prefix: &str) -> Option<TusCreateMode> {
    let relative_path = strip_prefix_path(path, prefix)?;
    if relative_path == "/.tus-uploads" || relative_path == "/.tus-uploads/" {
        return Some(TusCreateMode::FixedCollection);
    }
    if relative_path.starts_with("/.tus-uploads/") {
        return None;
    }

    Some(TusCreateMode::DirectoryScoped {
        relative_dir: normalize_directory_path(&relative_path),
    })
}

fn strip_prefix_path(path: &str, prefix: &str) -> Option<String> {
    let prefix_clean = prefix.trim_end_matches('/');
    if prefix_clean.is_empty() {
        return Some(path.to_string());
    }
    if path == prefix_clean {
        return Some("/".to_string());
    }
    path.strip_prefix(prefix_clean)
        .filter(|rest| rest.starts_with('/'))
        .map(ToString::to_string)
}

fn normalize_directory_path(path: &str) -> PathBuf {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        PathBuf::new()
    } else {
        PathBuf::from(trimmed)
    }
}

fn is_valid_filename_segment(filename: &str) -> bool {
    if filename.is_empty()
        || filename == "."
        || filename == ".."
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains('\0')
    {
        return false;
    }

    let mut components = StdPath::new(filename).components();
    match components.next() {
        Some(std::path::Component::Normal(_)) => components.next().is_none(),
        _ => false,
    }
}

/// PATCH — upload a chunk of data.
async fn tus_patch(
    State(state): State<TusState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> Response {
    if let Err(r) = check_tus_resumable(&headers) {
        return *r;
    }

    if let Some(ct) = headers.get("content-type")
        && ct != "application/offset+octet-stream"
    {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            [("tus-resumable", "1.0.0")],
            "Content-Type must be application/offset+octet-stream",
        )
            .into_response();
    }

    let upload_offset = match parse_header_u64(&headers, "upload-offset") {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                [("tus-resumable", "1.0.0")],
                "Missing Upload-Offset header",
            )
                .into_response();
        }
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                [("tus-resumable", "1.0.0")],
                msg,
            )
                .into_response();
        }
    };

    let checksum_info = if let Some(cksum_val) = headers.get("upload-checksum") {
        match cksum_val.to_str() {
            Ok(s) => match parse_upload_checksum(s) {
                Ok(info) => info,
                Err(msg) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        [("tus-resumable", "1.0.0")],
                        msg,
                    )
                        .into_response();
                }
            },
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    [("tus-resumable", "1.0.0")],
                    "Invalid Upload-Checksum header encoding",
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    debug!(
        "TUS upload chunk: session={}, offset={}, size={}",
        session_id,
        upload_offset,
        body.len()
    );

    let new_offset = match state
        .manager
        .upload_chunk_with_checksum(&session_id, upload_offset, &body, checksum_info)
        .await
    {
        Ok(off) => off,
        Err(e) => {
            let msg = e.to_string();
            let status = if msg.contains("Checksum mismatch") {
                StatusCode::from_u16(460).unwrap_or(StatusCode::BAD_REQUEST)
            } else if msg.contains("Offset mismatch") {
                StatusCode::CONFLICT
            } else if msg.contains("Session not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            warn!("Failed to upload chunk: {}", msg);
            return (status, [("tus-resumable", "1.0.0")], msg).into_response();
        }
    };

    match state.manager.get_session(&session_id).await {
        Ok(session) if session.is_complete() => {
            if let Err(e) = state.manager.finalize_upload(&session_id).await {
                warn!("Failed to finalize upload: {}", e);
                let msg = e.to_string();
                if msg.contains("outside allowed roots") {
                    return (
                        StatusCode::FORBIDDEN,
                        [("tus-resumable", "1.0.0")],
                        msg,
                    )
                        .into_response();
                }
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("tus-resumable", "1.0.0")],
                    format!("Failed to finalize upload: {msg}"),
                )
                    .into_response();
            }
            info!("TUS upload completed and finalized: {}", session_id);
        }
        _ => {}
    }

    let offset_str = new_offset.to_string();
    (
        StatusCode::NO_CONTENT,
        [
            ("tus-resumable", "1.0.0"),
            ("upload-offset", &offset_str),
        ],
    )
        .into_response()
}

/// HEAD — get upload progress.
async fn tus_head(
    State(state): State<TusState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check_tus_resumable(&headers) {
        return *r;
    }

    match state.manager.get_session(&session_id).await {
        Ok(session) => {
            let offset_str = session.current_offset.to_string();
            let length_str = session.total_size.to_string();
            (
                StatusCode::OK,
                [
                    ("tus-resumable", "1.0.0"),
                    ("upload-offset", &offset_str),
                    ("upload-length", &length_str),
                    ("cache-control", "no-store"),
                ],
            )
                .into_response()
        }
        Err(e) => {
            let status = if e.to_string().contains("Session not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, [("tus-resumable", "1.0.0")], e.to_string()).into_response()
        }
    }
}

/// DELETE — terminate an upload session.
async fn tus_delete(
    State(state): State<TusState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check_tus_resumable(&headers) {
        return *r;
    }

    match state.manager.delete_session(&session_id).await {
        Ok(()) => {
            info!("Deleted TUS session: {}", session_id);
            (StatusCode::NO_CONTENT, [("tus-resumable", "1.0.0")]).into_response()
        }
        Err(e) => {
            let status = if e.to_string().contains("Session not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, [("tus-resumable", "1.0.0")], e.to_string()).into_response()
        }
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Reject paths that contain `..` components or are absolute.
fn is_safe_relative_path(path: &std::path::Path) -> bool {
    if path.is_absolute() {
        return false;
    }
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => return false,
            std::path::Component::RootDir => return false,
            std::path::Component::Prefix(_) => return false,
            _ => {}
        }
    }
    true
}

/// Parse a header value as u64.
fn parse_header_u64(headers: &HeaderMap, name: &str) -> Result<Option<u64>, String> {
    let Some(val) = headers.get(name) else {
        return Ok(None);
    };
    let s = val
        .to_str()
        .map_err(|_| format!("Invalid {} header encoding", name))?;
    let n = s
        .parse::<u64>()
        .map_err(|_| format!("Invalid {} value: {}", name, s))?;
    Ok(Some(n))
}

/// Parse `Upload-Checksum` header: `algorithm base64checksum`
fn parse_upload_checksum(value: &str) -> Result<Option<(String, String)>, String> {
    let parts: Vec<&str> = value.trim().splitn(2, ' ').collect();
    if parts.len() != 2 {
        return Err("Invalid Upload-Checksum format".to_string());
    }

    let algorithm = parts[0].to_lowercase();
    let checksum = parts[1];

    if !TusUploadManager::get_supported_checksum_algorithms().contains(&algorithm.as_str()) {
        return Err(format!("Unsupported checksum algorithm: {}", algorithm));
    }

    Ok(Some((algorithm, checksum.to_string())))
}

#[cfg(test)]
mod tests {
    use super::{
        TusCreateMode, build_location, classify_tus_create_path,
        is_directory_scoped_tus_create_request, is_valid_filename_segment,
        normalize_directory_path,
    };
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::{HeaderMap, Method, Uri};
    use std::path::PathBuf;

    #[test]
    fn normalize_directory_scoped_request_path() {
        assert_eq!(normalize_directory_path("/nested/dir"), PathBuf::from("nested/dir"));
        assert_eq!(normalize_directory_path("/nested/dir/"), PathBuf::from("nested/dir"));
        assert_eq!(normalize_directory_path("/"), PathBuf::new());
    }

    #[test]
    fn validate_directory_scoped_filename_rejects_invalid_values() {
        for invalid in ["", ".", "..", "a/b", "a\\b", "bad\0name"] {
            assert!(
                !is_valid_filename_segment(invalid),
                "{} should be invalid",
                invalid.escape_debug()
            );
        }
        assert!(is_valid_filename_segment("file.txt"));
    }

    #[test]
    fn classify_fixed_collection_path_separately() {
        assert_eq!(
            classify_tus_create_path("/remote/.tus-uploads", "/remote"),
            Some(TusCreateMode::FixedCollection)
        );
        assert_eq!(
            classify_tus_create_path("/remote/.tus-uploads/", "/remote"),
            Some(TusCreateMode::FixedCollection)
        );
        assert_eq!(
            classify_tus_create_path("/remote/copy", "/remote"),
            Some(TusCreateMode::DirectoryScoped {
                relative_dir: PathBuf::from("copy"),
            })
        );
    }

    #[test]
    fn directory_scoped_request_detection_requires_post_tus_and_non_collection_path() {
        let mut headers = HeaderMap::new();
        headers.insert("tus-resumable", "1.0.0".parse().unwrap());

        assert!(is_directory_scoped_tus_create_request(
            &Method::POST,
            "/remote/copy",
            &headers,
            "/remote"
        ));
        assert!(!is_directory_scoped_tus_create_request(
            &Method::POST,
            "/remote/.tus-uploads",
            &headers,
            "/remote"
        ));
        assert!(!is_directory_scoped_tus_create_request(
            &Method::PATCH,
            "/remote/copy",
            &headers,
            "/remote"
        ));
    }

    #[test]
    fn build_location_returns_absolute_url_when_host_present() {
        let req = Request::builder()
            .uri(Uri::from_static("/remote/copy"))
            .header("host", "example.test:8080")
            .header("x-forwarded-proto", "https")
            .body(Body::empty())
            .unwrap();

        assert_eq!(
            build_location(&req, "/remote", "abc"),
            "https://example.test:8080/remote/.tus-uploads/abc"
        );
    }

    #[test]
    fn build_location_returns_relative_path_without_host() {
        let req = Request::builder()
            .uri(Uri::from_static("/remote/copy"))
            .body(Body::empty())
            .unwrap();

        assert_eq!(
            build_location(&req, "/remote", "abc"),
            "/remote/.tus-uploads/abc"
        );
    }
}
