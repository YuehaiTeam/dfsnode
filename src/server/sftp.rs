//! SFTP server handler for the embedded SSH server.
//!
//! Two access modes:
//! - **FullAccess** (WebDAV login / no-auth): read-only access to all files under root, respecting prefix.
//! - **SingleFile** (path/signature login): read-only access to a single file, visible at
//!   its original path (under prefix) and at `/data.bin` (at filesystem root, NOT under prefix).
//!
//! All metadata is minimized: uid=0, gid=0, permissions=0o555, mtime=0, atime=0.
//! Only `size` and directory/file distinction use real values.
//! Symlinks are not supported.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use russh_sftp::protocol::{
    Attrs, Data, File as SftpFile, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};
use std::future::Future;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum read size per request (4 MiB) to prevent memory DoS.
const MAX_READ_LEN: u32 = 4 * 1024 * 1024;

/// Maximum number of open handles per session.
const MAX_HANDLES: usize = 256;

// ---------------------------------------------------------------------------
// Access mode
// ---------------------------------------------------------------------------

/// SFTP access mode, determined by SSH authentication.
#[derive(Clone, Debug)]
pub(crate) enum SftpAccess {
    /// WebDAV / no-auth login — read-only access to entire root.
    FullAccess { root: PathBuf, prefix: String },
    /// Signature login — read-only access to a single file.
    /// `dav_path` is the prefix-stripped relative path (e.g. "/foo.txt").
    /// The file is visible at `{prefix}{dav_path}` and `/data.bin` (at absolute root).
    SingleFile {
        root: PathBuf,
        prefix: String,
        dav_path: String,
        real_path: PathBuf,
    },
}

impl SftpAccess {
    /// Create a full-access mode.
    pub fn full(root: PathBuf, prefix: String) -> Self {
        Self::FullAccess { root, prefix }
    }

    /// Create a single-file access mode.
    /// `full_path` is the path with prefix (e.g. "/dav/foo.txt").
    pub fn single_file(root: PathBuf, prefix: String, full_path: String) -> Self {
        let dav_path = strip_prefix_path(&full_path, &prefix);
        let rel = dav_path.trim_start_matches('/');
        let real_path = root.join(rel);
        // Canonicalize real_path and validate within root for safety.
        let real_path = real_path.canonicalize().unwrap_or_else(|_| root.join(rel));
        Self::SingleFile {
            root,
            prefix,
            dav_path,
            real_path,
        }
    }

    fn prefix(&self) -> &str {
        match self {
            Self::FullAccess { prefix, .. } | Self::SingleFile { prefix, .. } => prefix,
        }
    }

    fn root(&self) -> &Path {
        match self {
            Self::FullAccess { root, .. } | Self::SingleFile { root, .. } => root,
        }
    }
}

// ---------------------------------------------------------------------------
// Handle types
// ---------------------------------------------------------------------------

enum OpenHandle {
    File(std::fs::File),
    Dir { entries: Vec<SftpFile>, read: bool },
}

// ---------------------------------------------------------------------------
// SftpHandler
// ---------------------------------------------------------------------------

pub(crate) struct SftpHandler {
    access: SftpAccess,
    handles: HashMap<String, OpenHandle>,
    next_handle: u64,
    /// Track total bytes read across all file handles for access logging.
    bytes_sent: u64,
    /// Client IP for access logging.
    peer_addr: Option<SocketAddr>,
    /// UUID from signature auth, if present.
    uuid: Option<String>,
    /// Last opened file path (SFTP path as seen by the client).
    path: String,
}

impl SftpHandler {
    pub fn new(access: SftpAccess, peer_addr: Option<SocketAddr>, uuid: Option<String>) -> Self {
        Self {
            access,
            handles: HashMap::new(),
            next_handle: 0,
            bytes_sent: 0,
            peer_addr,
            uuid,
            path: "-".into(),
        }
    }

    fn alloc_handle(&mut self) -> String {
        let h = self.next_handle;
        self.next_handle += 1;
        format!("{h}")
    }

    // -- Path resolution --------------------------------------------------

    /// Strip prefix from an SFTP path, returning the DAV-relative path.
    /// Returns `None` if the path doesn't start with the prefix.
    /// Handles `prefix == "/"` as "no prefix" (all paths match).
    fn strip_prefix(&self, sftp_path: &str) -> Option<String> {
        let prefix = self.access.prefix();

        // Normalize: strip trailing slashes from input path for matching
        let path = sftp_path.trim_end_matches('/');
        let path = if path.is_empty() { "/" } else { path };

        // prefix == "/" means "no prefix" — all paths are under root
        let trimmed_prefix = prefix.trim_end_matches('/');
        if trimmed_prefix.is_empty() {
            return Some(path.to_string());
        }

        if let Some(rest) = path.strip_prefix(trimmed_prefix) {
            if rest.is_empty() {
                Some("/".to_string())
            } else if rest.starts_with('/') {
                Some(rest.to_string())
            } else {
                // e.g. prefix="/dav", path="/davextra" → no match
                None
            }
        } else {
            None
        }
    }

    /// Resolve an SFTP path to a physical filesystem path.
    /// Returns `None` if path is outside prefix or escapes root.
    fn resolve_path(&self, sftp_path: &str) -> Option<PathBuf> {
        let dav_path = self.strip_prefix(sftp_path)?;
        let rel = dav_path.trim_start_matches('/');
        let root = self.access.root();
        let full = if rel.is_empty() {
            root.to_path_buf()
        } else {
            root.join(rel)
        };
        // Canonicalize and verify within root to prevent directory traversal.
        let canonical_root = root.canonicalize().ok()?;
        let canonical = if full.exists() {
            full.canonicalize().ok()?
        } else {
            // For non-existent paths, canonicalize the parent and re-join.
            let parent = full.parent()?;
            if !parent.exists() {
                return None;
            }
            let file_name = full.file_name()?;
            let canonical_parent = parent.canonicalize().ok()?;
            if !canonical_parent.starts_with(&canonical_root) {
                return None;
            }
            canonical_parent.join(file_name)
        };
        if canonical.starts_with(&canonical_root) {
            Some(canonical)
        } else {
            None
        }
    }

    /// Check if an SFTP path is allowed under the current access mode.
    /// Returns the resolved physical path if allowed.
    fn check_access(&self, sftp_path: &str) -> Option<PathBuf> {
        // Normalize trailing slashes
        let path = sftp_path.trim_end_matches('/');
        let path = if path.is_empty() { "/" } else { path };

        match &self.access {
            SftpAccess::FullAccess { .. } => {
                // FullAccess: "/" maps to the prefix root
                if path == "/" {
                    let prefix = self.access.prefix().trim_end_matches('/');
                    if prefix.is_empty() {
                        return Some(self.access.root().to_path_buf());
                    }
                    // "/" in FullAccess with prefix: not directly accessible
                    // (client should use the prefix path)
                    return None;
                }
                self.resolve_path(path)
            }
            SftpAccess::SingleFile {
                dav_path,
                real_path,
                ..
            } => {
                // Validate real_path is within root (defense in depth)
                let canonical_root = self.access.root().canonicalize().ok()?;
                let canonical_real = real_path.canonicalize().ok()?;
                if !canonical_real.starts_with(&canonical_root) {
                    return None;
                }

                // /data.bin is at absolute root, NOT under prefix
                if path == "/data.bin" {
                    return Some(real_path.clone());
                }
                // / (root) is always allowed as virtual directory
                if path == "/" {
                    return Some(self.access.root().to_path_buf());
                }

                let stripped = self.strip_prefix(path)?;

                // Prefix root directory
                if stripped == "/" {
                    return Some(self.access.root().to_path_buf());
                }
                if stripped == *dav_path {
                    return Some(real_path.clone());
                }
                // Check intermediate directories in the original path.
                if dav_path.starts_with(&stripped as &str)
                    && dav_path[stripped.len()..].starts_with('/')
                {
                    return Some(self.access.root().to_path_buf());
                }
                None
            }
        }
    }

    /// Check if an SFTP path is a directory in the current access context.
    fn is_dir(&self, sftp_path: &str) -> bool {
        let path = sftp_path.trim_end_matches('/');
        let path = if path.is_empty() { "/" } else { path };

        match &self.access {
            SftpAccess::FullAccess { .. } => {
                self.resolve_path(path).map(|p| p.is_dir()).unwrap_or(false)
            }
            SftpAccess::SingleFile { dav_path, .. } => {
                if path == "/data.bin" {
                    return false;
                }
                if path == "/" {
                    return true;
                }
                let Some(stripped) = self.strip_prefix(path) else {
                    return false;
                };
                if stripped == "/" {
                    return true;
                }
                // Intermediate path components are virtual directories
                dav_path.starts_with(&stripped as &str)
                    && dav_path[stripped.len()..].starts_with('/')
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal file attributes
// ---------------------------------------------------------------------------

/// Build minimal FileAttributes. Only `size` and `permissions` reflect reality.
fn minimal_attrs(size: u64, is_dir: bool) -> FileAttributes {
    FileAttributes {
        size: Some(size),
        uid: Some(0),
        user: None,
        gid: Some(0),
        group: None,
        permissions: Some(if is_dir { 0o40555 } else { 0o100555 }),
        atime: Some(0),
        mtime: Some(0),
    }
}

/// Build a Name entry for readdir / realpath.
fn make_sftp_file(name: &str, size: u64, is_dir: bool) -> SftpFile {
    let attrs = minimal_attrs(size, is_dir);
    let perm_str = if is_dir { "dr-xr-xr-x" } else { "-r-xr-xr-x" };
    let longname = format!("{perm_str}   1 root     root     {size:>12} Jan  1  1970 {name}");
    SftpFile {
        filename: name.to_string(),
        longname,
        attrs,
    }
}

// ---------------------------------------------------------------------------
// Handler implementation
// ---------------------------------------------------------------------------

impl russh_sftp::server::Handler for SftpHandler {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    // init: use default implementation (returns Version::new())

    // -- Read-only file operations ----------------------------------------

    fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> impl Future<Output = Result<Handle, Self::Error>> + Send {
        // Reject any write flags
        let result = if pflags.intersects(
            OpenFlags::WRITE
                | OpenFlags::CREATE
                | OpenFlags::TRUNCATE
                | OpenFlags::APPEND
                | OpenFlags::EXCLUDE,
        ) {
            Err(StatusCode::PermissionDenied)
        } else {
            (|| {
                // Enforce handle limit
                if self.handles.len() >= MAX_HANDLES {
                    return Err(StatusCode::Failure);
                }
                let physical = self.check_access(&filename).ok_or(StatusCode::NoSuchFile)?;
                if !physical.is_file() {
                    return Err(StatusCode::NoSuchFile);
                }
                let file =
                    std::fs::File::open(&physical).map_err(|_| StatusCode::PermissionDenied)?;
                let handle = self.alloc_handle();
                self.handles.insert(handle.clone(), OpenHandle::File(file));
                // Track the last opened file path for access logging
                self.path = filename;
                Ok(Handle { id, handle })
            })()
        };
        std::future::ready(result)
    }

    fn close(
        &mut self,
        id: u32,
        handle: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let result = if self.handles.remove(&handle).is_some() {
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "".into(),
                language_tag: "en".into(),
            })
        } else {
            Err(StatusCode::NoSuchFile)
        };
        std::future::ready(result)
    }

    fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> impl Future<Output = Result<Data, Self::Error>> + Send {
        use std::io::{Read, Seek, SeekFrom};
        let result = (|| {
            let h = self
                .handles
                .get_mut(&handle)
                .ok_or(StatusCode::NoSuchFile)?;
            let OpenHandle::File(file) = h else {
                return Err(StatusCode::BadMessage);
            };
            file.seek(SeekFrom::Start(offset))
                .map_err(|_| StatusCode::Failure)?;
            let capped_len = len.min(MAX_READ_LEN) as usize;
            let mut buf = vec![0u8; capped_len];
            let n = file.read(&mut buf).map_err(|_| StatusCode::Failure)?;
            if n == 0 {
                return Err(StatusCode::Eof);
            }
            buf.truncate(n);
            self.bytes_sent += n as u64;
            Ok(Data { id, data: buf })
        })();
        std::future::ready(result)
    }

    // -- Stat operations --------------------------------------------------

    fn stat(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Attrs, Self::Error>> + Send {
        let result = self.do_stat(id, &path);
        std::future::ready(result)
    }

    fn lstat(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Attrs, Self::Error>> + Send {
        let result = self.do_stat(id, &path);
        std::future::ready(result)
    }

    fn fstat(
        &mut self,
        id: u32,
        handle: String,
    ) -> impl Future<Output = Result<Attrs, Self::Error>> + Send {
        let result = (|| {
            let h = self.handles.get(&handle).ok_or(StatusCode::NoSuchFile)?;
            match h {
                OpenHandle::File(f) => {
                    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
                    Ok(Attrs {
                        id,
                        attrs: minimal_attrs(size, false),
                    })
                }
                OpenHandle::Dir { .. } => Ok(Attrs {
                    id,
                    attrs: minimal_attrs(0, true),
                }),
            }
        })();
        std::future::ready(result)
    }

    // -- Directory operations ---------------------------------------------

    fn opendir(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Handle, Self::Error>> + Send {
        let result = (|| {
            // Enforce handle limit
            if self.handles.len() >= MAX_HANDLES {
                return Err(StatusCode::Failure);
            }
            let _ = self.check_access(&path).ok_or(StatusCode::NoSuchFile)?;
            if !self.is_dir(&path) {
                return Err(StatusCode::NoSuchFile);
            }
            let entries = self.build_dir_entries(&path)?;
            let handle = self.alloc_handle();
            self.handles.insert(
                handle.clone(),
                OpenHandle::Dir {
                    entries,
                    read: false,
                },
            );
            Ok(Handle { id, handle })
        })();
        std::future::ready(result)
    }

    fn readdir(
        &mut self,
        id: u32,
        handle: String,
    ) -> impl Future<Output = Result<Name, Self::Error>> + Send {
        let result = (|| {
            let h = self
                .handles
                .get_mut(&handle)
                .ok_or(StatusCode::NoSuchFile)?;
            let OpenHandle::Dir { entries, read } = h else {
                return Err(StatusCode::BadMessage);
            };
            if *read {
                return Err(StatusCode::Eof);
            }
            *read = true;
            Ok(Name {
                id,
                files: entries.clone(),
            })
        })();
        std::future::ready(result)
    }

    fn realpath(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Name, Self::Error>> + Send {
        let result = (|| {
            let prefix = self.access.prefix().to_string();
            let resolved = if path.is_empty() || path == "." {
                // Default directory depends on access mode
                match &self.access {
                    SftpAccess::FullAccess { .. } => prefix.clone(),
                    SftpAccess::SingleFile { .. } => "/".to_string(),
                }
            } else if path == "/" {
                "/".to_string()
            } else if !path.starts_with('/') {
                format!("{prefix}/{path}")
            } else {
                path.clone()
            };
            let _ = self.check_access(&resolved).ok_or(StatusCode::NoSuchFile)?;
            let is_dir = self.is_dir(&resolved);
            Ok(Name {
                id,
                files: vec![make_sftp_file(&resolved, 0, is_dir)],
            })
        })();
        std::future::ready(result)
    }

    // -- Write operations (all rejected) ----------------------------------

    fn write(
        &mut self,
        _id: u32,
        _handle: String,
        _offset: u64,
        _data: Vec<u8>,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        std::future::ready(Err(StatusCode::PermissionDenied))
    }

    fn remove(
        &mut self,
        _id: u32,
        _filename: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        std::future::ready(Err(StatusCode::PermissionDenied))
    }

    fn rename(
        &mut self,
        _id: u32,
        _oldpath: String,
        _newpath: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        std::future::ready(Err(StatusCode::PermissionDenied))
    }

    fn mkdir(
        &mut self,
        _id: u32,
        _path: String,
        _attrs: FileAttributes,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        std::future::ready(Err(StatusCode::PermissionDenied))
    }

    fn rmdir(
        &mut self,
        _id: u32,
        _path: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        std::future::ready(Err(StatusCode::PermissionDenied))
    }

    fn setstat(
        &mut self,
        _id: u32,
        _path: String,
        _attrs: FileAttributes,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        std::future::ready(Err(StatusCode::PermissionDenied))
    }

    fn fsetstat(
        &mut self,
        _id: u32,
        _handle: String,
        _attrs: FileAttributes,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        std::future::ready(Err(StatusCode::PermissionDenied))
    }

    fn symlink(
        &mut self,
        _id: u32,
        _linkpath: String,
        _targetpath: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        std::future::ready(Err(StatusCode::OpUnsupported))
    }

    fn readlink(
        &mut self,
        _id: u32,
        _path: String,
    ) -> impl Future<Output = Result<Name, Self::Error>> + Send {
        std::future::ready(Err(StatusCode::OpUnsupported))
    }
}

// ---------------------------------------------------------------------------
// Stat helper
// ---------------------------------------------------------------------------

impl SftpHandler {
    fn do_stat(&self, id: u32, path: &str) -> Result<Attrs, StatusCode> {
        let physical = self.check_access(path).ok_or(StatusCode::NoSuchFile)?;
        let is_dir = self.is_dir(path);

        if is_dir {
            // For directories: just verify it exists (or is a virtual dir)
            Ok(Attrs {
                id,
                attrs: minimal_attrs(0, true),
            })
        } else {
            // For files: verify the physical file actually exists
            let metadata = std::fs::metadata(&physical).map_err(|_| StatusCode::NoSuchFile)?;
            if !metadata.is_file() {
                return Err(StatusCode::NoSuchFile);
            }
            Ok(Attrs {
                id,
                attrs: minimal_attrs(metadata.len(), false),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Directory listing construction
// ---------------------------------------------------------------------------

impl SftpHandler {
    /// Build directory entries for a given SFTP path. Never directly returns
    /// raw filesystem metadata — all attributes are constructed with minimal info.
    fn build_dir_entries(&self, sftp_path: &str) -> Result<Vec<SftpFile>, StatusCode> {
        match &self.access {
            SftpAccess::FullAccess { .. } => self.build_full_access_dir(sftp_path),
            SftpAccess::SingleFile { .. } => self.build_single_file_dir(sftp_path),
        }
    }

    /// FullAccess: list physical directory but construct all attributes.
    fn build_full_access_dir(&self, sftp_path: &str) -> Result<Vec<SftpFile>, StatusCode> {
        let physical = self.resolve_path(sftp_path).ok_or(StatusCode::NoSuchFile)?;
        let read_dir = std::fs::read_dir(&physical).map_err(|_| StatusCode::PermissionDenied)?;

        let mut entries = vec![make_sftp_file(".", 0, true), make_sftp_file("..", 0, true)];

        for entry in read_dir.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();

            // Get file type; skip entry if we can't determine it
            let Ok(ft) = entry.file_type() else {
                continue;
            };

            // Skip symlinks
            if ft.is_symlink() {
                continue;
            }

            let is_dir = ft.is_dir();
            let size = if is_dir {
                0
            } else {
                entry.metadata().map(|m| m.len()).unwrap_or(0)
            };
            entries.push(make_sftp_file(&name, size, is_dir));
        }

        Ok(entries)
    }

    /// SingleFile: construct a virtual directory listing.
    fn build_single_file_dir(&self, sftp_path: &str) -> Result<Vec<SftpFile>, StatusCode> {
        let SftpAccess::SingleFile {
            dav_path,
            real_path,
            prefix,
            ..
        } = &self.access
        else {
            return Err(StatusCode::Failure);
        };

        // Normalize path: trim trailing slashes, treat empty as "/"
        let path = sftp_path.trim_end_matches('/');
        let path = if path.is_empty() { "/" } else { path };

        let file_size = std::fs::metadata(real_path).map(|m| m.len()).unwrap_or(0);

        let mut entries = vec![make_sftp_file(".", 0, true), make_sftp_file("..", 0, true)];

        if path == "/" {
            // Absolute root: show data.bin + the prefix directory
            entries.push(make_sftp_file("data.bin", file_size, false));

            // Add prefix as a directory entry (strip leading /)
            let prefix_dir = prefix.trim_start_matches('/');
            if !prefix_dir.is_empty() {
                entries.push(make_sftp_file(prefix_dir, 0, true));
            } else {
                // No prefix — show first component of dav_path directly
                let first_component = dav_path
                    .trim_start_matches('/')
                    .split('/')
                    .next()
                    .unwrap_or("");
                if !first_component.is_empty() {
                    let rest = &dav_path[1 + first_component.len()..];
                    if rest.is_empty() {
                        entries.push(make_sftp_file(first_component, file_size, false));
                    } else {
                        entries.push(make_sftp_file(first_component, 0, true));
                    }
                }
            }
        } else {
            let stripped = self.strip_prefix(path).ok_or(StatusCode::NoSuchFile)?;

            if stripped == "/" {
                // Prefix root: show first component of dav_path
                let first_component = dav_path
                    .trim_start_matches('/')
                    .split('/')
                    .next()
                    .unwrap_or("");
                if !first_component.is_empty() {
                    let rest = &dav_path[1 + first_component.len()..];
                    if rest.is_empty() {
                        entries.push(make_sftp_file(first_component, file_size, false));
                    } else {
                        entries.push(make_sftp_file(first_component, 0, true));
                    }
                }
            } else {
                // Intermediate directory: show the next path component
                let remaining = dav_path
                    .strip_prefix(stripped.as_str())
                    .and_then(|r| r.strip_prefix('/'))
                    .unwrap_or("");
                let next_component = remaining.split('/').next().unwrap_or("");
                if !next_component.is_empty() {
                    let after_next = &remaining[next_component.len()..];
                    if after_next.is_empty() {
                        entries.push(make_sftp_file(next_component, file_size, false));
                    } else {
                        entries.push(make_sftp_file(next_component, 0, true));
                    }
                }
            }
        }

        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Drop implementation
// ---------------------------------------------------------------------------

impl Drop for SftpHandler {
    fn drop(&mut self) {
        let ip_str = self
            .peer_addr
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "-".into());
        let uuid_str = self.uuid.as_deref().unwrap_or("-");
        tracing::info!(
            "[sftp] {} {} {} {}",
            ip_str,
            self.path,
            self.bytes_sent,
            uuid_str,
        );
        crate::metrics::record_request("sftp");
        crate::metrics::record_bytes_sent("sftp", self.bytes_sent);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strip a URL prefix from a path, returning the remainder.
fn strip_prefix_path(path: &str, prefix: &str) -> String {
    let trimmed = prefix.trim_end_matches('/');
    if let Some(rest) = path.strip_prefix(trimmed) {
        if rest.is_empty() {
            "/".to_string()
        } else if rest.starts_with('/') {
            rest.to_string()
        } else {
            path.to_string()
        }
    } else {
        path.to_string()
    }
}
