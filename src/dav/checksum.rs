use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha1::Digest;

const XATTR_KEY: &str = "oc.checksums";
/// Allow mtime to differ by up to 60 seconds before invalidating cache
const MTIME_TOLERANCE_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAlgorithm {
    SHA1,
    MD5,
}

impl std::fmt::Display for ChecksumAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChecksumAlgorithm::SHA1 => write!(f, "SHA1"),
            ChecksumAlgorithm::MD5 => write!(f, "MD5"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ChecksumMetadata {
    mtime_secs: u64,
    file_size: u64,
    checksums: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ChecksumManager {
    algorithms: Vec<ChecksumAlgorithm>,
}

impl ChecksumManager {
    pub fn new(algorithms: Vec<ChecksumAlgorithm>) -> Arc<Self> {
        Arc::new(Self { algorithms })
    }

    /// Get checksums for a file, using xattr cache if valid
    pub async fn get_checksums(
        &self,
        file_path: &Path,
    ) -> Result<Option<HashMap<String, String>>> {
        let metadata = tokio::fs::metadata(file_path)
            .await
            .with_context(|| format!("Failed to read metadata for {}", file_path.display()))?;

        if metadata.is_dir() {
            return Ok(None);
        }

        let file_size = metadata.len();
        let mtime_secs = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Try reading from xattr cache
        if let Some(cached) = self.read_cached_checksums(file_path, mtime_secs, file_size) {
            return Ok(Some(cached));
        }

        // Calculate fresh checksums
        let checksums = self.calculate_checksums(file_path).await?;

        // Store in xattr cache
        let cache = ChecksumMetadata {
            mtime_secs,
            file_size,
            checksums: checksums.clone(),
        };
        if let Ok(json) = serde_json::to_vec(&cache) {
            let _ = fsquirrel::set(file_path, XATTR_KEY, &json);
        }

        Ok(Some(checksums))
    }

    fn read_cached_checksums(
        &self,
        file_path: &Path,
        current_mtime: u64,
        current_size: u64,
    ) -> Option<HashMap<String, String>> {
        let data = fsquirrel::get(file_path, XATTR_KEY).ok()??;
        let cached: ChecksumMetadata = serde_json::from_slice(&data).ok()?;

        // Validate: size must match exactly, mtime within tolerance
        if cached.file_size != current_size {
            return None;
        }
        let mtime_diff = current_mtime.abs_diff(cached.mtime_secs);
        if mtime_diff > MTIME_TOLERANCE_SECS {
            return None;
        }

        // Verify all requested algorithms are present
        for algo in &self.algorithms {
            if !cached.checksums.contains_key(&algo.to_string()) {
                return None;
            }
        }

        Some(cached.checksums)
    }

    async fn calculate_checksums(&self, file_path: &Path) -> Result<HashMap<String, String>> {
        let data = tokio::fs::read(file_path)
            .await
            .with_context(|| format!("Failed to read file for checksums: {}", file_path.display()))?;

        let mut checksums = HashMap::new();
        for algo in &self.algorithms {
            let hash = match algo {
                ChecksumAlgorithm::SHA1 => {
                    let mut hasher = sha1::Sha1::new();
                    hasher.update(&data);
                    format!("{:x}", hasher.finalize())
                }
                ChecksumAlgorithm::MD5 => {
                    let digest = md5::compute(&data);
                    format!("{:x}", digest)
                }
            };
            checksums.insert(algo.to_string(), hash);
        }
        Ok(checksums)
    }

    /// Calculate checksums from provided data (for upload path)
    pub fn calculate_from_data(&self, data: &[u8]) -> HashMap<String, String> {
        let mut checksums = HashMap::new();
        for algo in &self.algorithms {
            let hash = match algo {
                ChecksumAlgorithm::SHA1 => {
                    let mut hasher = sha1::Sha1::new();
                    hasher.update(data);
                    format!("{:x}", hasher.finalize())
                }
                ChecksumAlgorithm::MD5 => {
                    let digest = md5::compute(data);
                    format!("{:x}", digest)
                }
            };
            checksums.insert(algo.to_string(), hash);
        }
        checksums
    }
}

/// Format checksums as OwnCloud-style string: "SHA1:abc123 MD5:def456"
pub fn format_oc_checksums(checksums: &HashMap<String, String>) -> String {
    checksums
        .iter()
        .map(|(algo, hash)| format!("{algo}:{hash}"))
        .collect::<Vec<_>>()
        .join(" ")
}
