pub mod signature;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::StatusCode;

use crate::auth::signature::SignatureVerifier;
use crate::config::cli::RunArgs;
use crate::config::{LiveAuthConfig, SignatureSetting};

/// WebDAV methods that mutate state.
const WRITE_METHODS: &[&str] = &[
    "PUT",
    "DELETE",
    "MKCOL",
    "MOVE",
    "COPY",
    "PROPPATCH",
    "PATCH",
    "POST",
];

/// Credentials for basic auth.
#[derive(Clone, Debug)]
pub(crate) struct BasicCredentials {
    username: String,
    password: String,
}

impl BasicCredentials {
    pub(crate) fn password(&self) -> &str {
        &self.password
    }
}

#[derive(Clone, Default)]
struct AuthMaterial {
    basic: Option<BasicCredentials>,
    sign_global: Option<Arc<SignatureVerifier>>,
    path_specific_sign: HashMap<String, Arc<SignatureVerifier>>,
}

impl AuthMaterial {
    fn has_auth_material(&self) -> bool {
        self.basic.is_some() || self.sign_global.is_some() || !self.path_specific_sign.is_empty()
    }
}

#[derive(Clone)]
struct ExpiringAuthMaterial {
    material: AuthMaterial,
    valid_until: Instant,
}

#[derive(Clone, Copy)]
enum PathRule {
    Open,
    GlobalSign,
    DedicatedSign,
}

#[derive(Clone)]
struct AuthState {
    current: AuthMaterial,
    previous: Option<ExpiringAuthMaterial>,
    path_rules: Vec<(String, PathRule)>,
    prefix: String,
    #[allow(dead_code)]
    no_tcp_download: bool,
}

impl AuthState {
    fn previous_material_if_valid(&self) -> Option<&AuthMaterial> {
        self.previous
            .as_ref()
            .filter(|previous| Instant::now() <= previous.valid_until)
            .map(|previous| &previous.material)
    }

    fn has_basic_auth(&self) -> bool {
        self.current.basic.is_some()
            || self
                .previous_material_if_valid()
                .and_then(|previous| previous.basic.as_ref())
                .is_some()
    }

    fn has_any_auth(&self) -> bool {
        !self.path_rules.is_empty()
            || self.current.has_auth_material()
            || self
                .previous_material_if_valid()
                .is_some_and(AuthMaterial::has_auth_material)
    }

    fn matches_basic_credentials(&self, user: &str, pass: &str) -> bool {
        self.current
            .basic
            .as_ref()
            .is_some_and(|basic| basic.username == user && basic.password == pass)
            || self
                .previous_material_if_valid()
                .and_then(|previous| previous.basic.as_ref())
                .is_some_and(|basic| basic.username == user && basic.password == pass)
    }

    fn current_and_previous_passwords(&self) -> impl Iterator<Item = &str> {
        self.current
            .basic
            .iter()
            .map(BasicCredentials::password)
            .chain(
                self.previous_material_if_valid()
                    .and_then(|previous| previous.basic.as_ref())
                    .into_iter()
                    .map(BasicCredentials::password),
            )
    }

    fn find_path_rule(&self, dav_path: &str) -> Option<(&str, PathRule)> {
        self.path_rules
            .iter()
            .find(|(prefix, _)| path_rule_matches(prefix, dav_path))
            .map(|(prefix, rule)| (prefix.as_str(), *rule))
    }

    fn verify_signature(
        &self,
        uri_path: &str,
        sign_param: Option<&str>,
        range_header: Option<&str>,
        skip_range_check: bool,
    ) -> (bool, Option<String>) {
        let dav_path = strip_prefix_path(uri_path, &self.prefix);
        let matched_rule = self.find_path_rule(dav_path);

        match matched_rule {
            Some((_prefix, PathRule::Open)) => (true, None),
            Some((_prefix, PathRule::GlobalSign)) => self.verify_against_verifiers(
                self.current.sign_global.as_ref(),
                self.previous_material_if_valid()
                    .and_then(|previous| previous.sign_global.as_ref()),
                uri_path,
                sign_param,
                range_header,
                skip_range_check,
            ),
            Some((prefix, PathRule::DedicatedSign)) => self.verify_against_verifiers(
                self.current.path_specific_sign.get(prefix),
                self.previous_material_if_valid()
                    .and_then(|previous| previous.path_specific_sign.get(prefix)),
                uri_path,
                sign_param,
                range_header,
                skip_range_check,
            ),
            None => {
                if self.current.sign_global.is_some()
                    || self
                        .previous_material_if_valid()
                        .and_then(|previous| previous.sign_global.as_ref())
                        .is_some()
                {
                    self.verify_against_verifiers(
                        self.current.sign_global.as_ref(),
                        self.previous_material_if_valid()
                            .and_then(|previous| previous.sign_global.as_ref()),
                        uri_path,
                        sign_param,
                        range_header,
                        skip_range_check,
                    )
                } else {
                    (!self.has_basic_auth(), None)
                }
            }
        }
    }

    fn verify_against_verifiers(
        &self,
        current: Option<&Arc<SignatureVerifier>>,
        previous: Option<&Arc<SignatureVerifier>>,
        uri_path: &str,
        sign_param: Option<&str>,
        range_header: Option<&str>,
        skip_range_check: bool,
    ) -> (bool, Option<String>) {
        let Some(sign_str) = sign_param else {
            return (false, None);
        };

        let uuid = extract_uuid_from_sign(sign_str);
        for verifier in [current, previous].into_iter().flatten() {
            if verifier
                .verify(uri_path, sign_str, range_header, skip_range_check)
                .is_ok()
            {
                return (true, uuid.clone());
            }
        }

        (false, None)
    }

    fn authorize_metrics_request(&self, auth_header: Option<&str>) -> bool {
        if !self.has_basic_auth() {
            return true;
        }

        match auth_header {
            Some(header) if header.starts_with("Bearer ") => self
                .current_and_previous_passwords()
                .any(|password| crate::metrics::validate_minio_jwt(&header[7..], password)),
            Some(header) if header.starts_with("Basic ") => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(&header[6..])
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .and_then(|decoded| {
                        decoded
                            .split_once(':')
                            .map(|(u, p)| (u.to_string(), p.to_string()))
                    })
                    .is_some_and(|(user, pass)| self.matches_basic_credentials(&user, &pass))
            }
            _ => false,
        }
    }

    fn path_requires_signature(&self, uri_path: &str) -> bool {
        let dav_path = strip_prefix_path(uri_path, &self.prefix);
        match self.find_path_rule(dav_path) {
            Some((_prefix, PathRule::Open)) => false,
            Some((_prefix, PathRule::GlobalSign | PathRule::DedicatedSign)) => true,
            None => {
                self.current.sign_global.is_some()
                    || self
                        .previous_material_if_valid()
                        .and_then(|previous| previous.sign_global.as_ref())
                        .is_some()
            }
        }
    }
}

fn path_rule_matches(prefix: &str, dav_path: &str) -> bool {
    if prefix == "/" {
        return dav_path.starts_with('/');
    }

    if dav_path == prefix {
        return true;
    }

    if let Some(rest) = dav_path.strip_prefix(prefix) {
        return rest.starts_with('/');
    }

    false
}

fn compile_auth_material(auth_config: &LiveAuthConfig) -> AuthMaterial {
    let basic = auth_config
        .username
        .as_ref()
        .zip(auth_config.password.as_ref())
        .map(|(username, password)| BasicCredentials {
            username: username.clone(),
            password: password.clone(),
        });

    let sign_global = auth_config
        .sign_key
        .as_deref()
        .map(|key| Arc::new(SignatureVerifier::new(key)));

    let mut path_specific_sign = HashMap::new();
    if let Some(paths) = &auth_config.paths {
        for (prefix, path_config) in paths {
            if let Some(SignatureSetting::Key(key)) = path_config.signature() {
                path_specific_sign.insert(prefix.clone(), Arc::new(SignatureVerifier::new(key)));
            }
        }
    }

    AuthMaterial {
        basic,
        sign_global,
        path_specific_sign,
    }
}

fn compile_path_rules(
    auth_config: &LiveAuthConfig,
    global_sign_exists: bool,
) -> Vec<(String, PathRule)> {
    let mut path_rules = Vec::new();

    if let Some(paths) = &auth_config.paths {
        for (prefix, path_config) in paths {
            let Some(signature) = path_config.signature() else {
                continue;
            };

            let rule = match signature {
                SignatureSetting::Open(false) => PathRule::Open,
                SignatureSetting::Open(true) if global_sign_exists => PathRule::GlobalSign,
                SignatureSetting::Open(true) => continue,
                SignatureSetting::Key(_) => PathRule::DedicatedSign,
            };

            path_rules.push((prefix.clone(), rule));
        }
    }

    path_rules.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    path_rules
}

/// Auth configuration shared by the middleware and protocol adapters.
#[derive(Clone)]
pub struct AuthConfig {
    state: Arc<ArcSwap<AuthState>>,
}

impl AuthConfig {
    fn from_state(state: AuthState) -> Self {
        Self {
            state: Arc::new(ArcSwap::from_pointee(state)),
        }
    }

    fn load_state(&self) -> Arc<AuthState> {
        self.state.load_full()
    }

    pub fn apply_live_config(
        &self,
        auth_config: &LiveAuthConfig,
        prefix: &str,
        no_tcp_download: bool,
        previous_grace: Option<Duration>,
    ) {
        let old_state = self.load_state();
        let current = compile_auth_material(auth_config);
        let path_rules = compile_path_rules(auth_config, current.sign_global.is_some());

        let previous = previous_grace
            .filter(|grace| !grace.is_zero())
            .and_then(|grace| {
                old_state.current.has_auth_material().then(|| ExpiringAuthMaterial {
                    material: old_state.current.clone(),
                    valid_until: Instant::now() + grace,
                })
            });

        self.state.store(Arc::new(AuthState {
            current,
            previous,
            path_rules,
            prefix: prefix.to_string(),
            no_tcp_download,
        }));
    }

    #[allow(dead_code)]
    pub fn has_basic_auth(&self) -> bool {
        self.load_state().has_basic_auth()
    }

    pub fn has_any_auth(&self) -> bool {
        self.load_state().has_any_auth()
    }

    pub fn matches_basic_credentials(&self, user: &str, pass: &str) -> bool {
        self.load_state().matches_basic_credentials(user, pass)
    }

    pub fn authorize_metrics_request(&self, auth_header: Option<&str>) -> bool {
        self.load_state().authorize_metrics_request(auth_header)
    }

    /// Verify a GET-like download request without HTTP context.
    ///
    /// Used by WebTransport and other non-HTTP channels that cannot carry
    /// Basic Auth headers.
    pub fn verify_signature(
        &self,
        uri_path: &str,
        sign_param: Option<&str>,
        skip_range_check: bool,
    ) -> (bool, Option<String>) {
        self.load_state()
            .verify_signature(uri_path, sign_param, None, skip_range_check)
    }
}

/// Append CORS headers to a response.
fn cors_headers(resp: &mut Response) {
    let headers = resp.headers_mut();
    headers.insert(
        http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        http::HeaderValue::from_static("*"),
    );
    headers.insert(
        http::header::ACCESS_CONTROL_ALLOW_METHODS,
        http::HeaderValue::from_static("GET, HEAD, PUT, DELETE, PROPFIND, LOCK, OPTIONS, PATCH"),
    );
    headers.insert(
        http::header::ACCESS_CONTROL_ALLOW_HEADERS,
        http::HeaderValue::from_static(
            "Content-Type, Authorization, Depth, Overwrite, Destination",
        ),
    );
    headers.insert(
        http::header::ACCESS_CONTROL_MAX_AGE,
        http::HeaderValue::from_static("86400"),
    );
}

/// Unified auth middleware:
/// - CORS: handle OPTIONS preflight and add CORS headers to all responses
/// - GET/PROPFIND requests: check per-path overrides first, then signature, then basic auth
/// - Other methods: basic auth only
pub async fn auth_middleware(config: AuthConfig, req: Request, next: Next) -> Response {
    let mut resp = if req.method() == http::Method::OPTIONS {
        next.run(req).await
    } else {
        auth_inner(config, req, next).await
    };
    cors_headers(&mut resp);
    resp
}

/// Core auth logic, separated so the outer function can uniformly apply CORS
/// headers to the response.
async fn auth_inner(config: AuthConfig, req: Request, next: Next) -> Response {
    if req.uri().path().starts_with("/minio/") {
        return next.run(req).await;
    }

    let state = config.load_state();

    if !state.has_basic_auth() {
        let method_str = req.method().as_str();
        let path = req.uri().path();
        if WRITE_METHODS.iter().any(|method| method.eq_ignore_ascii_case(method_str))
            && !path.starts_with("/-/")
            && !path.starts_with("/minio/")
            && method_str != "LOCK"
        {
            return (
                StatusCode::FORBIDDEN,
                "Forbidden: server is read-only (no WebDAV password configured)",
            )
                .into_response();
        }
    }

    if req.method() == http::Method::GET
        || req.method() == http::Method::from_bytes(b"PROPFIND").unwrap()
        || req.method().as_str() == "LOCK"
    {
        let uri_path = req.uri().path();
        let requires_signature = state.path_requires_signature(uri_path);
        let query = req.uri().query().unwrap_or("");
        if let Some(sign_str) = extract_sign_param(query) {
            let range_header = req
                .headers()
                .get(http::header::RANGE)
                .and_then(|value| value.to_str().ok());
            let (verified, _) = state.verify_signature(
                uri_path,
                Some(&sign_str),
                range_header,
                false,
            );
            if verified {
                return next.run(req).await;
            }
            tracing::warn!("Signature verification failed for {uri_path}");
            return (StatusCode::FORBIDDEN, "Forbidden: invalid signature").into_response();
        }

        let dav_path = strip_prefix_path(uri_path, &state.prefix);
        if matches!(state.find_path_rule(dav_path), Some((_prefix, PathRule::Open))) {
            return next.run(req).await;
        }

        if requires_signature && !state.has_basic_auth() {
            return (StatusCode::FORBIDDEN, "Forbidden: signature required").into_response();
        }
    }

    if state.has_basic_auth() && !check_basic_auth(&req, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            [(http::header::WWW_AUTHENTICATE, "Basic realm=\"WebDAV\"")],
            "Unauthorized",
        )
            .into_response();
    }

    next.run(req).await
}

/// Strip the configured prefix from a URI path to get the DAV-relative path.
fn strip_prefix_path<'a>(uri_path: &'a str, prefix: &str) -> &'a str {
    if prefix == "/" {
        uri_path
    } else {
        uri_path.strip_prefix(prefix).unwrap_or(uri_path)
    }
}

/// Validate the Authorization header against the current or previous credentials.
fn check_basic_auth(req: &Request, state: &AuthState) -> bool {
    let Some(auth_header) = req.headers().get(http::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(auth_str) = auth_header.to_str() else {
        return false;
    };
    let Some(encoded) = auth_str.strip_prefix("Basic ") else {
        return false;
    };
    use base64::Engine;
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(decoded_str) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((user, pass)) = decoded_str.split_once(':') else {
        return false;
    };
    state.matches_basic_credentials(user, pass)
}

/// Extract the `$` query parameter value from a query string.
pub fn extract_sign_param(query: &str) -> Option<String> {
    for part in query.split('&') {
        if let Some(value) = part.strip_prefix("$=").or_else(|| part.strip_prefix("%24="))
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
    }
    None
}

/// Extract the UUID (first 32 hex characters) from a signature string.
///
/// Signature format: `{32B uuid hex}{8B expire hex}{64B hmac hex}{ranges…}`
pub fn extract_uuid_from_sign(sign: &str) -> Option<String> {
    let prefix = sign.get(..32)?;
    if prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(prefix.to_string())
    } else {
        None
    }
}

/// Build AuthConfig from CLI args (legacy mode, no service config).
pub fn build_auth_from_args(args: &RunArgs) -> AuthConfig {
    let auth = LiveAuthConfig {
        username: args.username.clone(),
        password: args.password.clone(),
        sign_key: args.sign_key.clone(),
        paths: None,
    };
    build_auth_from_live_config(&auth, &args.prefix, args.no_tcp_download)
}

/// Build AuthConfig from a service config snapshot.
pub fn build_auth_from_live_config(
    auth_config: &LiveAuthConfig,
    prefix: &str,
    no_tcp_download: bool,
) -> AuthConfig {
    let current = compile_auth_material(auth_config);
    let path_rules = compile_path_rules(auth_config, current.sign_global.is_some());
    AuthConfig::from_state(AuthState {
        current,
        previous: None,
        path_rules,
        prefix: prefix.to_string(),
        no_tcp_download,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::{build_auth_from_live_config, extract_sign_param};
    use crate::config::{LiveAuthConfig, PathAuthConfig, SignatureSetting};

    #[test]
    fn keeps_previous_basic_credentials_during_graceful_rotation() {
        let current = LiveAuthConfig {
            username: Some("alice".to_string()),
            password: Some("old-password".to_string()),
            sign_key: None,
            paths: None,
        };
        let auth = build_auth_from_live_config(&current, "/", false);
        assert!(auth.matches_basic_credentials("alice", "old-password"));

        let next = LiveAuthConfig {
            username: Some("alice".to_string()),
            password: Some("new-password".to_string()),
            sign_key: None,
            paths: None,
        };
        auth.apply_live_config(&next, "/", false, Some(Duration::from_secs(60)));

        assert!(auth.matches_basic_credentials("alice", "new-password"));
        assert!(auth.matches_basic_credentials("alice", "old-password"));
    }

    #[test]
    fn path_rules_switch_immediately_when_config_rotates() {
        let mut open_paths = HashMap::new();
        open_paths.insert(
            "/public".to_string(),
            PathAuthConfig::Signature(SignatureSetting::Open(false)),
        );

        let current = LiveAuthConfig {
            username: None,
            password: None,
            sign_key: None,
            paths: Some(open_paths),
        };
        let auth = build_auth_from_live_config(&current, "/", false);
        assert_eq!(auth.verify_signature("/public/file.txt", None, false), (true, None));

        let mut protected_paths = HashMap::new();
        protected_paths.insert(
            "/public".to_string(),
            PathAuthConfig::Signature(SignatureSetting::Open(true)),
        );
        let next = LiveAuthConfig {
            username: None,
            password: None,
            sign_key: Some("00112233445566778899aabbccddeeff".to_string()),
            paths: Some(protected_paths),
        };
        auth.apply_live_config(&next, "/", false, Some(Duration::from_secs(60)));

        assert_eq!(extract_sign_param(""), None);
        assert_eq!(auth.verify_signature("/public/file.txt", None, false), (false, None));
    }

    #[test]
    fn path_rule_does_not_match_sibling_prefixes() {
        let mut paths = HashMap::new();
        paths.insert(
            "/public".to_string(),
            PathAuthConfig::Signature(SignatureSetting::Open(false)),
        );

        let auth = build_auth_from_live_config(
            &LiveAuthConfig {
                username: None,
                password: None,
                sign_key: Some("00112233445566778899aabbccddeeff".to_string()),
                paths: Some(paths),
            },
            "/",
            false,
        );

        assert_eq!(auth.verify_signature("/public/file.txt", None, false), (true, None));
        assert_eq!(auth.verify_signature("/publicity/file.txt", None, false), (false, None));
    }
}
