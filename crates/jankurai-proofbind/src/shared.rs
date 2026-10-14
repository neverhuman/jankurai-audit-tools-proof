use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command as GitProcess;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn resolve_repo_path(repo: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo.join(path)
    }
}

/// One changed path, and whether Git reports the change to it as a deletion.
struct ChangedEntry {
    path: String,
    deleted: bool,
}

/// The change set to analyze: every changed path, sorted and unique, and the
/// subset Git itself reports as deleted. An explicit `changed` list carries no
/// deletion status, so every path in it stays a required input.
pub(crate) struct ChangeSet {
    pub(crate) paths: Vec<String>,
    pub(crate) deleted: BTreeSet<String>,
}

pub(crate) fn resolve_change_set(
    repo: &Path,
    changed: &[PathBuf],
    changed_from: Option<&str>,
) -> Result<ChangeSet> {
    let entries = if let Some(base) = changed_from {
        changed_entries_from_git(repo, base)?
    } else if changed.is_empty() {
        local_changed_entries_from_git(repo)?
    } else {
        changed
            .iter()
            .map(|path| {
                normalize_changed_path(repo, path)
                    .map(|path| ChangedEntry {
                        path,
                        deleted: false,
                    })
                    .with_context(|| {
                        format!(
                            "incomplete analysis: invalid changed path {}",
                            path.display()
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?
    };
    let deleted = entries
        .iter()
        .filter(|entry| entry.deleted)
        .map(|entry| entry.path.clone())
        .collect();
    let mut paths = entries
        .into_iter()
        .map(|entry| entry.path)
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    Ok(ChangeSet { paths, deleted })
}

pub fn resolve_changed_paths<F>(
    repo: &Path,
    changed: &[PathBuf],
    changed_from: Option<&str>,
    include_path: F,
) -> Result<Vec<String>>
where
    F: Fn(&str) -> bool,
{
    Ok(resolve_change_set(repo, changed, changed_from)?
        .paths
        .into_iter()
        .filter(|path| include_path(path))
        .collect())
}

pub fn changed_paths_from_git(repo: &Path, base: &str) -> Result<Vec<String>> {
    Ok(changed_entries_from_git(repo, base)?
        .into_iter()
        .map(|entry| entry.path)
        .collect())
}

/// `git diff --name-status -z <base>...HEAD`, read as `--name-only` would list
/// it (a rename or copy names its destination), with each deletion marked.
fn changed_entries_from_git(repo: &Path, base: &str) -> Result<Vec<ChangedEntry>> {
    let refspec = format!("{base}...HEAD");
    let output = GitProcess::new("git")
        .args([
            "-c",
            "core.fsmonitor=false",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-status",
            "-z",
            refspec.as_str(),
            "--",
        ])
        .current_dir(repo)
        .output()
        .with_context(|| format!("run git diff for {base}"))?;
    if !output.status.success() {
        bail!("incomplete analysis: git diff failed for {base}");
    }
    let text = String::from_utf8(output.stdout)
        .context("incomplete analysis: changed paths are not UTF-8")?;
    let mut fields = text.split('\0').filter(|field| !field.is_empty());
    let mut entries = Vec::new();
    while let Some(status) = fields.next() {
        let kind = status.as_bytes()[0];
        if matches!(kind, b'R' | b'C') {
            fields
                .next()
                .context("incomplete analysis: missing rename source")?;
        }
        let path = fields
            .next()
            .context("incomplete analysis: malformed git diff status")?;
        entries.push(ChangedEntry {
            path: path.to_string(),
            deleted: kind == b'D',
        });
    }
    Ok(entries)
}

pub fn local_changed_paths_from_git(repo: &Path) -> Result<Vec<String>> {
    Ok(local_changed_entries_from_git(repo)?
        .into_iter()
        .map(|entry| entry.path)
        .collect())
}

/// `git status --porcelain=v1 -z`, with each path whose index or working-tree
/// status is a deletion marked (`D `, ` D`, `AD`, `RD`, ...).
fn local_changed_entries_from_git(repo: &Path) -> Result<Vec<ChangedEntry>> {
    let output = GitProcess::new("git")
        .args([
            "-c",
            "core.fsmonitor=false",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ])
        .current_dir(repo)
        .output()
        .context("incomplete analysis: run git status")?;
    if !output.status.success() {
        bail!("incomplete analysis: git status failed");
    }
    let text = String::from_utf8(output.stdout)
        .context("incomplete analysis: changed paths are not UTF-8")?;
    let mut fields = text.split('\0').filter(|field| !field.is_empty());
    let mut entries = Vec::new();
    while let Some(field) = fields.next() {
        let bytes = field.as_bytes();
        if bytes.len() < 4 || bytes[2] != b' ' {
            bail!("incomplete analysis: malformed Git status");
        }
        entries.push(ChangedEntry {
            path: field[3..].to_string(),
            deleted: bytes[..2].contains(&b'D'),
        });
        if bytes[..2]
            .iter()
            .any(|status| matches!(status, b'R' | b'C'))
        {
            fields
                .next()
                .context("incomplete analysis: missing rename source")?;
        }
    }
    Ok(entries)
}

/// The content a deleted path had before the change: at the merge base for
/// `--changed-from <base>` (the side `<base>...HEAD` diffs against), otherwise
/// in the index or, for a staged deletion, at `HEAD`. Classification needs the
/// pre-image so a removed authorization module, policy file or CI script binds
/// the same obligations editing it would. A pre-image Git cannot produce, or
/// one over the input bound, is an incomplete analysis, never an empty file.
pub(crate) fn removed_pre_image(
    repo: &Path,
    path: &str,
    changed_from: Option<&str>,
    max_bytes: u64,
) -> Result<String> {
    let candidates = if let Some(base) = changed_from {
        let merge_base = git_output(repo, &["merge-base", base, "HEAD"])
            .with_context(|| format!("incomplete analysis: no merge base for {base} and HEAD"))?;
        vec![format!("{merge_base}:{path}")]
    } else {
        vec![format!(":0:{path}"), format!("HEAD:{path}")]
    };
    for object in candidates {
        let Some(size) = git_output(repo, &["cat-file", "-s", object.as_str()]) else {
            continue;
        };
        let size: u64 = size
            .parse()
            .context("incomplete analysis: unreadable removed-input size")?;
        if size > max_bytes {
            bail!("incomplete analysis: removed input exceeds the input bound: {path}");
        }
        let output = GitProcess::new("git")
            .args(["cat-file", "blob", object.as_str()])
            .current_dir(repo)
            .output()
            .context("incomplete analysis: run git cat-file")?;
        if !output.status.success() || output.stdout.len() as u64 != size {
            bail!("incomplete analysis: read removed input {path}");
        }
        // Lossy: a removed binary still binds its removal obligation; every
        // marker classification looks for is ASCII.
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    bail!("incomplete analysis: removed input has no pre-image in Git: {path}")
}

pub fn normalize_changed_path(repo: &Path, path: &Path) -> Option<String> {
    let candidate = resolve_repo_path(repo, path);
    let relative = candidate.strip_prefix(repo).ok()?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return None;
    }
    relative.to_str().map(str::to_string)
}

pub fn read_json<T: DeserializeOwned>(path: PathBuf) -> Option<T> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn read_toml<T: DeserializeOwned>(path: PathBuf) -> Option<T> {
    let text = fs::read_to_string(path).ok()?;
    toml::from_str(&text).ok()
}

pub fn prefix_matches(prefix: &str, path: &str) -> bool {
    let prefix = prefix.trim().trim_matches('/');
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

pub fn normalize_prefix(prefix: &str) -> String {
    prefix.trim().trim_end_matches('/').to_string()
}

pub fn git_output(repo: &Path, args: &[&str]) -> Option<String> {
    GitProcess::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

pub fn git_dirty(repo: &Path) -> bool {
    if let Ok(out) = GitProcess::new("git")
        .args(["-c", "core.fsmonitor=false", "status", "--porcelain"])
        .current_dir(repo)
        .output()
    {
        !out.status.success() || !out.stdout.is_empty()
    } else {
        true
    }
}

pub fn unix_seconds() -> String {
    if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
        duration.as_secs().to_string()
    } else {
        "0".into()
    }
}

pub fn elapsed_ms(started: SystemTime) -> u128 {
    if let Ok(duration) = started.elapsed() {
        duration.as_millis()
    } else {
        0
    }
}

pub fn path_symbol(path: &str) -> String {
    if let Some(name) = Path::new(path).file_stem().and_then(|name| name.to_str()) {
        name.to_string()
    } else {
        "file".into()
    }
}

pub fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                ':'
            }
        })
        .collect::<String>()
        .trim_matches(':')
        .to_string()
}

pub fn display_rel(repo: &Path, path: &Path) -> String {
    if let Ok(rel) = path.strip_prefix(repo) {
        rel.to_string_lossy().replace('\\', "/")
    } else {
        path.to_string_lossy().replace('\\', "/")
    }
}
