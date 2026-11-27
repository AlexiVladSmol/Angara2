//! Safe configuration/users file editing with an inter-process lock.
//!
//! All participating tools use the same `<path>.lock` flock and the same
//! read-compare-write sequence. A completed external edit is detected by the
//! content version; a concurrent non-cooperating editor cannot be prevented,
//! which is documented in the administrator guide.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fs2::FileExt;

use crate::version::content_version;

/// Maximum time spent waiting for the cooperative file lock.
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Candidate validation failure.
#[derive(Clone, Debug)]
pub struct CandidateError {
    /// `invalid_candidate` or `restart_required`.
    pub restart_required: bool,
    /// Safe message.
    pub message: String,
    /// Safe field paths.
    pub fields: Vec<String>,
}

impl CandidateError {
    /// Invalid candidate.
    pub fn invalid(message: impl Into<String>, fields: Vec<String>) -> Self {
        Self {
            restart_required: false,
            message: message.into(),
            fields,
        }
    }

    /// Candidate needs a restart.
    pub fn restart(message: impl Into<String>, fields: Vec<String>) -> Self {
        Self {
            restart_required: true,
            message: message.into(),
            fields,
        }
    }
}

/// File error classes mapped to API errors by the writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileErrorKind {
    /// File is missing.
    NotFound,
    /// Expected version is stale.
    Conflict,
    /// Candidate validation failed.
    InvalidCandidate,
    /// Candidate needs a restart.
    RestartRequired,
    /// File type, owner, mode or link count is unsafe.
    Unsafe,
    /// File is too large.
    TooLarge,
    /// Lock acquisition failed.
    Lock,
    /// Other I/O failure.
    Io,
}

/// One safe file-editing failure.
#[derive(Clone, Debug)]
pub struct FileError {
    pub kind: FileErrorKind,
    pub message: String,
    pub fields: Vec<String>,
    pub current_version: Option<String>,
    pub saved: bool,
}

impl FileError {
    fn new(kind: FileErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            fields: Vec::new(),
            current_version: None,
            saved: false,
        }
    }

    fn with_version(mut self, version: String) -> Self {
        self.current_version = Some(version);
        self
    }
}

impl std::fmt::Display for FileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for FileError {}

/// Successful edit result.
#[derive(Clone, Debug)]
pub struct EditOutcome {
    /// New content version.
    pub version: String,
    /// The file was replaced.
    pub saved: bool,
}

/// Reads one file with O_NOFOLLOW and validates its metadata.
pub fn read_checked(
    path: &Path,
    max_bytes: u64,
    allowed_owners: &[u32],
    users_file: bool,
) -> Result<(Vec<u8>, std::fs::Metadata), FileError> {
    let file = open_checked(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| FileError::new(FileErrorKind::Io, "cannot inspect file"))?;
    validate_metadata(&metadata, allowed_owners, users_file)?;
    if metadata.len() > max_bytes {
        return Err(FileError::new(
            FileErrorKind::TooLarge,
            "file exceeds the configured byte limit",
        ));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| FileError::new(FileErrorKind::Io, "cannot read file"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(FileError::new(
            FileErrorKind::TooLarge,
            "file exceeds the configured byte limit",
        ));
    }
    Ok((bytes, metadata))
}

/// Edits one file under the shared lock.
///
/// The mutator receives a parsed `toml_edit` document. The validator receives
/// the complete candidate text and must apply the same production validators
/// used by CLI/startup.
pub fn edit_locked<M, V>(
    path: &Path,
    expected_version: &str,
    max_bytes: u64,
    allowed_owners: &[u32],
    users_file: bool,
    mutate: M,
    validate: V,
) -> Result<EditOutcome, FileError>
where
    M: FnOnce(&mut toml_edit::DocumentMut) -> Result<(), CandidateError>,
    V: FnOnce(&str) -> Result<(), CandidateError>,
{
    let lock_path = lock_path(path);
    let lock = acquire_lock(&lock_path)?;
    let (bytes, metadata) = read_checked(path, max_bytes, allowed_owners, users_file)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| FileError::new(FileErrorKind::Unsafe, "file is not valid UTF-8"))?;
    let current_version = content_version(text.as_bytes());
    if current_version != expected_version {
        return Err(FileError::new(
            FileErrorKind::Conflict,
            "file changed since the form was opened",
        )
        .with_version(current_version));
    }
    let mut document = text
        .parse::<toml_edit::DocumentMut>()
        .map_err(|_| FileError::new(FileErrorKind::InvalidCandidate, "file is not valid TOML"))?;
    mutate(&mut document).map_err(candidate_to_file_error)?;
    let candidate = document.to_string();
    if candidate.len() as u64 > max_bytes {
        return Err(FileError::new(
            FileErrorKind::TooLarge,
            "candidate exceeds the configured byte limit",
        ));
    }
    validate(&candidate).map_err(candidate_to_file_error)?;
    let new_version = content_version(candidate.as_bytes());
    write_atomic(path, &metadata, candidate.as_bytes())?;
    drop(lock);
    Ok(EditOutcome {
        version: new_version,
        saved: true,
    })
}

fn candidate_to_file_error(error: CandidateError) -> FileError {
    let kind = if error.restart_required {
        FileErrorKind::RestartRequired
    } else {
        FileErrorKind::InvalidCandidate
    };
    let mut file_error = FileError::new(kind, error.message);
    file_error.fields = error.fields.into_iter().take(16).collect();
    file_error
}

fn open_checked(path: &Path) -> Result<File, FileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    FileError::new(FileErrorKind::NotFound, "file does not exist")
                } else {
                    FileError::new(FileErrorKind::Io, "cannot open file")
                }
            })
    }
    #[cfg(not(unix))]
    {
        File::open(path).map_err(|_| FileError::new(FileErrorKind::Io, "cannot open file"))
    }
}

fn validate_metadata(
    metadata: &std::fs::Metadata,
    allowed_owners: &[u32],
    users_file: bool,
) -> Result<(), FileError> {
    if !metadata.is_file() {
        return Err(FileError::new(
            FileErrorKind::Unsafe,
            "path must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let forbidden = if users_file { 0o027 } else { 0o022 };
        if metadata.mode() & forbidden != 0 {
            return Err(FileError::new(
                FileErrorKind::Unsafe,
                if users_file {
                    "users file has unsafe permissions"
                } else {
                    "configuration has unsafe permissions"
                },
            ));
        }
        if metadata.nlink() != 1 {
            return Err(FileError::new(
                FileErrorKind::Unsafe,
                "file must not have additional hard links",
            ));
        }
        if !allowed_owners.contains(&metadata.uid()) {
            return Err(FileError::new(
                FileErrorKind::Unsafe,
                "file owner is not root or the configured service owner",
            ));
        }
    }
    Ok(())
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

fn acquire_lock(path: &Path) -> Result<File, FileError> {
    let file = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
        }
        #[cfg(not(unix))]
        {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)
        }
    }
    .map_err(|_| FileError::new(FileErrorKind::Lock, "cannot open the lock file"))?;
    let deadline = Instant::now() + LOCK_TIMEOUT;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(FileError::new(
                        FileErrorKind::Lock,
                        "timed out waiting for the file lock",
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                return Err(FileError::new(
                    FileErrorKind::Lock,
                    "cannot acquire the file lock",
                ));
            }
        }
    }
}

fn write_atomic(path: &Path, original: &std::fs::Metadata, bytes: &[u8]) -> Result<(), FileError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "control".to_owned());
    let mut last_error = None;
    for attempt in 0..16_u32 {
        let temp = parent.join(format!(
            ".{name}.angara-tmp-{}-{attempt}",
            std::process::id()
        ));
        let file = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&temp)
            }
            #[cfg(not(unix))]
            {
                OpenOptions::new().write(true).create_new(true).open(&temp)
            }
        };
        let mut file = match file {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
                continue;
            }
            Err(_) => {
                return Err(FileError::new(
                    FileErrorKind::Io,
                    "cannot create a temporary file",
                ));
            }
        };
        if file.write_all(bytes).is_err() || file.sync_all().is_err() {
            let _ = std::fs::remove_file(&temp);
            return Err(FileError::new(
                FileErrorKind::Io,
                "cannot write or sync the temporary file",
            ));
        }
        drop(file);
        if !preserve_metadata(&temp, original) {
            let _ = std::fs::remove_file(&temp);
            return Err(FileError::new(
                FileErrorKind::Unsafe,
                "cannot preserve file owner or mode",
            ));
        }
        if std::fs::rename(&temp, path).is_err() {
            let _ = std::fs::remove_file(&temp);
            return Err(FileError::new(
                FileErrorKind::Io,
                "cannot replace the file; the previous contents are intact",
            ));
        }
        // The replacement is visible. A failed directory sync means the
        // durability of the rename is unknown, not that the old file survived.
        if let Ok(directory) = File::open(parent)
            && directory.sync_all().is_err()
        {
            let mut error = FileError::new(
                FileErrorKind::Io,
                "file was replaced but the directory sync failed",
            );
            error.saved = true;
            return Err(error);
        }
        return Ok(());
    }
    let _ = last_error;
    Err(FileError::new(
        FileErrorKind::Io,
        "cannot allocate a unique temporary file",
    ))
}

fn preserve_metadata(temp: &Path, original: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let temp_metadata = match std::fs::symlink_metadata(temp) {
            Ok(metadata) => metadata,
            Err(_) => return false,
        };
        if (temp_metadata.uid() != original.uid() || temp_metadata.gid() != original.gid())
            && std::os::unix::fs::chown(temp, Some(original.uid()), Some(original.gid())).is_err()
        {
            return false;
        }
        std::fs::set_permissions(
            temp,
            std::fs::Permissions::from_mode(original.mode() & 0o7777),
        )
        .is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = (temp, original);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn temp_dir(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "angara-files-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn edit_preserves_comments_mode_and_owner_and_detects_conflict() {
        let dir = temp_dir("edit");
        let path = dir.join("users.toml");
        std::fs::write(
            &path,
            "# leading\nversion = 1\n\n[[users]]\n# alice comment\nusername = \"alice\"\npassword_hash = \"a\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let before = std::fs::metadata(&path).unwrap();
        let version = content_version(&std::fs::read(&path).unwrap());

        let outcome = edit_locked(
            &path,
            &version,
            1 << 20,
            &[before.uid()],
            true,
            |document| {
                document["users"]
                    .as_array_of_tables_mut()
                    .unwrap()
                    .get_mut(0)
                    .unwrap()["password_hash"] = toml_edit::value("b");
                Ok(())
            },
            |_| Ok(()),
        )
        .expect("edit");
        assert!(outcome.saved);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# leading"));
        assert!(text.contains("# alice comment"));
        assert!(text.contains("password_hash = \"b\""));
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(before.uid(), after.uid());
        assert_eq!(before.gid(), after.gid());
        assert_eq!(after.mode() & 0o777, 0o640);

        let error = edit_locked(
            &path,
            &version,
            1 << 20,
            &[after.uid()],
            true,
            |_| Ok(()),
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.kind, FileErrorKind::Conflict);
        assert_eq!(
            error.current_version.as_deref(),
            Some(outcome.version.as_str())
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn write_failure_before_rename_keeps_the_old_file() {
        if crate::control_server::effective_uid() == Some(0) {
            return;
        }
        let dir = temp_dir("readonly");
        let path = dir.join("users.toml");
        std::fs::write(&path, "version = 1\nusers = []\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let lock = lock_path(&path);
        File::create(&lock).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let version = content_version(&std::fs::read(&path).unwrap());
        let error = edit_locked(
            &path,
            &version,
            1 << 20,
            &[crate::control_server::effective_uid().unwrap()],
            true,
            |document| {
                document["version"] = toml_edit::value(2);
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(!error.saved);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "version = 1\nusers = []\n"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn validation_failure_keeps_the_old_file() {
        let dir = temp_dir("validate");
        let path = dir.join("angara.toml");
        std::fs::write(&path, "a = 1\n").unwrap();
        let before = std::fs::metadata(&path).unwrap();
        let version = content_version(&std::fs::read(&path).unwrap());
        let error = edit_locked(
            &path,
            &version,
            1 << 20,
            &[before.uid()],
            false,
            |document| {
                document["a"] = toml_edit::value(2);
                Ok(())
            },
            |candidate| {
                if candidate.contains("a = 2") {
                    Err(CandidateError::invalid("bad", vec!["a".to_owned()]))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert_eq!(error.kind, FileErrorKind::InvalidCandidate);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a = 1\n");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
