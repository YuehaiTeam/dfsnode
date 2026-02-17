pub mod handler;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose};
use sha1::{Sha1, Digest};
use std::{
    collections::HashMap,
    fs::File,
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Supported TUS checksum algorithms.
pub const SUPPORTED_CHECKSUM_ALGORITHMS: &[&str] = &["sha1", "md5"];

/// TUS protocol configuration.
#[derive(Debug, Clone)]
pub struct TusConfig {
    pub enabled: bool,
    pub upload_timeout_hours: u64,
    pub max_concurrent_uploads: usize,
    pub max_upload_size: u64,
}

impl Default for TusConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            upload_timeout_hours: 24,
            max_concurrent_uploads: 100,
            max_upload_size: 5 * 1024 * 1024 * 1024, // 5GB
        }
    }
}

/// A single TUS upload session.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TusSession {
    pub id: String,
    pub target_path: PathBuf,
    pub temp_file: PathBuf,
    pub total_size: u64,
    pub current_offset: u64,
    pub metadata: HashMap<String, String>,
    pub created_at: SystemTime,
    pub last_access: SystemTime,
}

impl TusSession {
    pub fn new(
        id: String,
        target_path: PathBuf,
        temp_file: PathBuf,
        total_size: u64,
        metadata: HashMap<String, String>,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            id,
            target_path,
            temp_file,
            total_size,
            current_offset: 0,
            metadata,
            created_at: now,
            last_access: now,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.current_offset >= self.total_size
    }

    pub fn update_access_time(&mut self) {
        self.last_access = SystemTime::now();
    }
}

/// Manages TUS resumable upload sessions.
pub struct TusUploadManager {
    temp_dir: PathBuf,
    sessions: Arc<RwLock<HashMap<String, TusSession>>>,
    config: TusConfig,
}

impl TusUploadManager {
    /// Create a new upload manager, ensuring the temp directory exists.
    pub fn new(temp_dir: PathBuf, config: TusConfig) -> Result<Self> {
        std::fs::create_dir_all(&temp_dir)
            .with_context(|| format!("Failed to create TUS temp directory: {:?}", temp_dir))?;

        info!("TUS upload manager initialized with temp dir: {:?}", temp_dir);

        Ok(Self {
            temp_dir,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
        })
    }

    pub fn max_upload_size(&self) -> u64 {
        self.config.max_upload_size
    }

    /// Create a new upload session.
    pub async fn create_session(
        &self,
        target_path: PathBuf,
        total_size: u64,
        metadata: HashMap<String, String>,
    ) -> Result<String> {
        if total_size > self.config.max_upload_size {
            bail!(
                "Upload size {} exceeds maximum allowed size {}",
                total_size,
                self.config.max_upload_size
            );
        }

        let session_id = Uuid::new_v4().to_string();
        let temp_file = self.temp_dir.join(format!("{}.partial", session_id));

        // Create the temp file
        File::create(&temp_file)
            .with_context(|| format!("Failed to create temp file: {:?}", temp_file))?;

        let session = TusSession::new(
            session_id.clone(),
            target_path.clone(),
            temp_file,
            total_size,
            metadata,
        );

        let mut sessions = self.sessions.write().await;

        // Check concurrent upload limit
        if sessions.len() >= self.config.max_concurrent_uploads {
            bail!(
                "Maximum concurrent uploads ({}) exceeded",
                self.config.max_concurrent_uploads
            );
        }

        sessions.insert(session_id.clone(), session);

        info!(
            "Created TUS session: {} for target: {:?}, size: {}",
            session_id, target_path, total_size
        );

        Ok(session_id)
    }

    /// Upload a data chunk without checksum verification.
    #[allow(dead_code)]
    pub async fn upload_chunk(
        &self,
        session_id: &str,
        expected_offset: u64,
        data: &[u8],
    ) -> Result<u64> {
        self.upload_chunk_with_checksum(session_id, expected_offset, data, None)
            .await
    }

    /// Upload a data chunk with optional checksum verification.
    pub async fn upload_chunk_with_checksum(
        &self,
        session_id: &str,
        expected_offset: u64,
        data: &[u8],
        checksum_info: Option<(String, String)>, // (algorithm, base64_checksum)
    ) -> Result<u64> {
        // Verify checksum first if provided
        if let Some((algorithm, expected_checksum)) = &checksum_info {
            self.verify_chunk_checksum(data, algorithm, expected_checksum)
                .context("Checksum verification failed")?;
        }

        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;

        // Validate offset
        if expected_offset != session.current_offset {
            bail!(
                "Offset mismatch: expected {}, got {}",
                session.current_offset,
                expected_offset
            );
        }

        // Check total size won't be exceeded
        let new_offset = session.current_offset + data.len() as u64;
        if new_offset > session.total_size {
            bail!(
                "Upload would exceed total size: {} + {} > {}",
                session.current_offset,
                data.len(),
                session.total_size
            );
        }

        // Write data to temp file
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&session.temp_file)
            .with_context(|| format!("Failed to open temp file: {:?}", session.temp_file))?;

        file.seek(SeekFrom::Start(session.current_offset))
            .with_context(|| "Failed to seek in temp file")?;

        file.write_all(data)
            .with_context(|| "Failed to write data to temp file")?;

        file.sync_all()
            .with_context(|| "Failed to sync temp file")?;

        // Update session state
        session.current_offset = new_offset;
        session.update_access_time();

        debug!(
            "Uploaded chunk to session {}: {} bytes, new offset: {}",
            session_id,
            data.len(),
            new_offset
        );

        Ok(new_offset)
    }

    /// Finalize an upload: move temp file to target path.
    /// On Windows, falls back to copy+delete if rename fails (cross-drive).
    pub async fn finalize_upload(&self, session_id: &str) -> Result<PathBuf> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;

        if !session.is_complete() {
            bail!(
                "Upload not complete: {}/{} bytes",
                session.current_offset,
                session.total_size
            );
        }

        let target_path = session.target_path.clone();
        let temp_file = session.temp_file.clone();

        // Ensure target directory exists
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create target directory: {:?}", parent))?;
        }

        // Try atomic rename first; fall back to copy+delete for cross-drive on Windows
        if let Err(_rename_err) = std::fs::rename(&temp_file, &target_path) {
            std::fs::copy(&temp_file, &target_path).with_context(|| {
                format!(
                    "Failed to copy temp file {:?} to target {:?}",
                    temp_file, target_path
                )
            })?;
            let _ = std::fs::remove_file(&temp_file);
        }

        // Remove session
        sessions.remove(session_id);

        info!(
            "Finalized TUS upload: session {} -> {:?}",
            session_id, target_path
        );

        Ok(target_path)
    }

    /// Get session info (updates access time).
    pub async fn get_session(&self, session_id: &str) -> Result<TusSession> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;

        session.update_access_time();
        Ok(session.clone())
    }

    /// Delete an upload session and its temp file.
    pub async fn delete_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.remove(session_id) {
            if session.temp_file.exists() {
                std::fs::remove_file(&session.temp_file).with_context(|| {
                    format!("Failed to remove temp file: {:?}", session.temp_file)
                })?;
            }
            info!("Deleted TUS session: {}", session_id);
        }
        Ok(())
    }

    /// Remove sessions that have exceeded the timeout.
    pub async fn cleanup_expired_sessions(&self) -> Result<()> {
        let timeout = Duration::from_secs(self.config.upload_timeout_hours * 3600);
        let now = SystemTime::now();

        let mut sessions = self.sessions.write().await;
        let expired: Vec<String> = sessions
            .iter()
            .filter_map(|(id, s)| {
                now.duration_since(s.last_access)
                    .ok()
                    .filter(|elapsed| *elapsed > timeout)
                    .map(|_| id.clone())
            })
            .collect();

        let mut cleaned = 0usize;
        for id in expired {
            if let Some(session) = sessions.remove(&id) {
                if session.temp_file.exists()
                    && let Err(e) = std::fs::remove_file(&session.temp_file) {
                        warn!(
                            "Failed to remove expired temp file {:?}: {}",
                            session.temp_file, e
                        );
                    }
                cleaned += 1;
                debug!("Cleaned up expired TUS session: {}", id);
            }
        }

        if cleaned > 0 {
            info!("Cleaned up {} expired TUS sessions", cleaned);
        }

        Ok(())
    }

    /// Verify a chunk's checksum.
    pub fn verify_chunk_checksum(
        &self,
        data: &[u8],
        algorithm: &str,
        expected_checksum: &str,
    ) -> Result<()> {
        let algorithm = algorithm.to_lowercase();

        if !SUPPORTED_CHECKSUM_ALGORITHMS.contains(&algorithm.as_str()) {
            bail!("Unsupported checksum algorithm: {}", algorithm);
        }

        let actual_checksum = match algorithm.as_str() {
            "sha1" => {
                let mut hasher = Sha1::new();
                hasher.update(data);
                general_purpose::STANDARD.encode(hasher.finalize())
            }
            "md5" => {
                let digest = md5::compute(data);
                general_purpose::STANDARD.encode(digest.as_ref())
            }
            _ => unreachable!(),
        };

        if actual_checksum != expected_checksum {
            bail!(
                "Checksum mismatch for algorithm {}: expected {}, got {}",
                algorithm,
                expected_checksum,
                actual_checksum
            );
        }

        debug!(
            "Checksum verification passed: {} {}",
            algorithm, expected_checksum
        );
        Ok(())
    }

    /// Get the list of supported checksum algorithms.
    pub fn get_supported_checksum_algorithms() -> &'static [&'static str] {
        SUPPORTED_CHECKSUM_ALGORITHMS
    }
}

/// Decode TUS metadata header value.
/// Format: `key base64value,key2 base64value2`
pub fn decode_tus_metadata(encoded: &str) -> Result<HashMap<String, String>> {
    let mut metadata = HashMap::new();

    for pair in encoded.split(',') {
        let parts: Vec<&str> = pair.trim().splitn(2, ' ').collect();
        if parts.len() == 2 {
            let key = parts[0].trim();
            let encoded_value = parts[1].trim();

            match general_purpose::STANDARD.decode(encoded_value) {
                Ok(decoded_bytes) => match String::from_utf8(decoded_bytes) {
                    Ok(value) => {
                        metadata.insert(key.to_string(), value);
                    }
                    Err(e) => {
                        warn!("Failed to decode UTF-8 for metadata key {}: {}", key, e);
                    }
                },
                Err(e) => {
                    warn!("Failed to decode base64 for metadata key {}: {}", key, e);
                }
            }
        }
    }

    Ok(metadata)
}
