use anyhow::{bail, Context, Result};
use std::fs::{self, Metadata, OpenOptions};
use std::io::Read;
use std::path::{Component, Path};

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) fn read_text(repo: &Path, relative: &Path) -> Result<String> {
    read_optional_text(repo, relative)?.with_context(|| {
        format!(
            "incomplete analysis: required input missing: {}",
            relative.display()
        )
    })
}

/// True when `relative` names nothing in the working tree: the change removed it.
/// A path that escapes the repository or crosses a symlink is still an error.
pub(crate) fn is_removed_path(repo: &Path, relative: &Path) -> Result<bool> {
    let mut full = repo.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            bail!("incomplete analysis: input path must stay inside the repository");
        };
        full.push(name);
        match fs::symlink_metadata(&full) {
            Ok(metadata) if metadata.is_symlink() => {
                bail!(
                    "incomplete analysis: symlinked input: {}",
                    relative.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error).context("incomplete analysis: inspect input"),
        }
    }
    Ok(false)
}

pub(crate) fn read_optional_text(repo: &Path, relative: &Path) -> Result<Option<String>> {
    let mut full = repo.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            bail!("incomplete analysis: input path must stay inside the repository");
        };
        full.push(name);
        match fs::symlink_metadata(&full) {
            Ok(metadata) if metadata.is_symlink() => {
                bail!(
                    "incomplete analysis: symlinked input: {}",
                    relative.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("incomplete analysis: inspect input"),
        }
    }
    let before = fs::symlink_metadata(&full).context("incomplete analysis: inspect input")?;
    if !before.is_file() || before.len() > MAX_INPUT_BYTES {
        bail!(
            "incomplete analysis: input must be a bounded regular file: {}",
            relative.display()
        );
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(&full)
        .context("incomplete analysis: open input")?;
    if !same_file(&before, &file.metadata()?) {
        bail!("incomplete analysis: input changed before reading");
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("incomplete analysis: read input")?;
    if bytes.len() as u64 != before.len()
        || !same_file(&before, &file.metadata()?)
        || !same_file(&before, &fs::symlink_metadata(&full)?)
    {
        bail!("incomplete analysis: input changed or was truncated while reading");
    }
    String::from_utf8(bytes)
        .map(Some)
        .context("incomplete analysis: input is not UTF-8")
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    let same = right.is_file()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same && left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        same
    }
}
