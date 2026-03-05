use std::ffi::OsStr;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct PathPolicy {
    allowed_roots: Vec<PathBuf>,
}

#[derive(Debug)]
pub enum PathPolicyError {
    NotFound(PathBuf),
    InvalidPath(PathBuf),
    Forbidden {
        requested: PathBuf,
        resolved: PathBuf,
    },
    Io(std::io::Error),
}

impl std::fmt::Display for PathPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(path) => write!(f, "Path not found: {}", path.display()),
            Self::InvalidPath(path) => write!(f, "Invalid path: {}", path.display()),
            Self::Forbidden {
                requested,
                resolved,
            } => write!(
                f,
                "Path is outside allowed roots: requested={}, resolved={}",
                requested.display(),
                resolved.display()
            ),
            Self::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl std::error::Error for PathPolicyError {}

impl PathPolicyError {
    pub fn is_forbidden(&self) -> bool {
        matches!(self, Self::Forbidden { .. })
    }
}

impl PathPolicy {
    pub fn new(root: PathBuf, allow_link_targets: &[String]) -> anyhow::Result<Self> {
        let canonical_root = canonicalize_existing_dir(&root)?;
        let mut allowed_roots = vec![canonical_root];

        for raw in allow_link_targets {
            let canonical = canonicalize_existing_dir(Path::new(raw))?;
            if !allowed_roots.iter().any(|existing| existing == &canonical) {
                allowed_roots.push(canonical);
            }
        }

        Ok(Self { allowed_roots })
    }

    pub fn allowed_roots(&self) -> &[PathBuf] {
        &self.allowed_roots
    }

    pub fn resolve_existing(&self, path: &Path) -> Result<PathBuf, PathPolicyError> {
        let canonical = path.canonicalize().map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                PathPolicyError::NotFound(path.to_path_buf())
            } else {
                PathPolicyError::Io(err)
            }
        })?;

        self.ensure_allowed(path, canonical)
    }

    pub fn resolve_for_create(&self, path: &Path) -> Result<PathBuf, PathPolicyError> {
        if path.exists() {
            return self.resolve_existing(path);
        }

        let (existing_ancestor, relative_tail) = find_existing_ancestor(path)?;
        let canonical_ancestor = existing_ancestor
            .canonicalize()
            .map_err(PathPolicyError::Io)?;

        let intended = canonical_ancestor.join(relative_tail);
        self.ensure_allowed(path, intended)
    }

    fn ensure_allowed(
        &self,
        requested: &Path,
        resolved: PathBuf,
    ) -> Result<PathBuf, PathPolicyError> {
        if self
            .allowed_roots
            .iter()
            .any(|allowed| resolved.starts_with(allowed))
        {
            Ok(resolved)
        } else {
            Err(PathPolicyError::Forbidden {
                requested: requested.to_path_buf(),
                resolved,
            })
        }
    }
}

fn canonicalize_existing_dir(path: &Path) -> anyhow::Result<PathBuf> {
    if !path.exists() {
        anyhow::bail!("Path '{}' does not exist", path.display());
    }
    if !path.is_dir() {
        anyhow::bail!("Path '{}' is not a directory", path.display());
    }
    Ok(path.canonicalize()?)
}

fn find_existing_ancestor(path: &Path) -> Result<(&Path, PathBuf), PathPolicyError> {
    let mut current = path;
    while !current.exists() {
        current = current
            .parent()
            .ok_or_else(|| PathPolicyError::InvalidPath(path.to_path_buf()))?;
    }

    let relative_tail = path
        .strip_prefix(current)
        .map_err(|_| PathPolicyError::InvalidPath(path.to_path_buf()))?;

    if relative_tail
        .components()
        .any(|component| component.as_os_str() == OsStr::new(""))
    {
        return Err(PathPolicyError::InvalidPath(path.to_path_buf()));
    }

    Ok((current, relative_tail.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dfsnode-path-policy-{name}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn allows_existing_paths_under_allowed_roots() {
        let base = make_temp_dir("allow-existing");
        let root = base.join("root");
        let allowed = base.join("allowed");
        let blocked = base.join("blocked");
        fs::create_dir_all(&root).expect("create root");
        fs::create_dir_all(&allowed).expect("create allowed");
        fs::create_dir_all(&blocked).expect("create blocked");

        let allowed_file = allowed.join("ok.txt");
        let blocked_file = blocked.join("no.txt");
        fs::write(&allowed_file, b"ok").expect("write allowed file");
        fs::write(&blocked_file, b"no").expect("write blocked file");

        let policy = PathPolicy::new(root.clone(), &[allowed.to_string_lossy().to_string()])
            .expect("build policy");

        assert!(policy.resolve_existing(&allowed_file).is_ok());
        assert!(matches!(
            policy.resolve_existing(&blocked_file),
            Err(PathPolicyError::Forbidden { .. })
        ));
    }

    #[test]
    fn create_path_checks_nearest_existing_ancestor() {
        let base = make_temp_dir("create");
        let root = base.join("root");
        let allowed = base.join("allowed");
        let blocked = base.join("blocked");
        fs::create_dir_all(&root).expect("create root");
        fs::create_dir_all(&allowed).expect("create allowed");
        fs::create_dir_all(&blocked).expect("create blocked");

        let policy =
            PathPolicy::new(root, &[allowed.to_string_lossy().to_string()]).expect("build policy");

        let allowed_new = allowed.join("a/b/c/new.txt");
        let blocked_new = blocked.join("x/y/new.txt");

        assert!(policy.resolve_for_create(&allowed_new).is_ok());
        assert!(matches!(
            policy.resolve_for_create(&blocked_new),
            Err(PathPolicyError::Forbidden { .. })
        ));
    }
}
