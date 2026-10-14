//! Site configuration for the governed launcher.
//!
//! The installation root, the Cargo/rustup homes, extra `PATH` directories and
//! the forge URLs differ per site, so they are not compiled in. They are also
//! never read from the caller's environment: the sealed environment exists so
//! that callers cannot choose the tools the auditor runs, and an environment
//! variable is exactly what a caller chooses.
//!
//! Instead the launcher reads one file at a fixed, host-neutral location,
//! [`SITE_CONFIG_PATH`], and trusts it only when it is a regular, single-link
//! file owned by root, writable by nobody else, inside a directory chain that
//! only root controls. Every directory the file names must exist as a physical
//! directory owned by root or the effective user, with no world-writable
//! component on the way to it. The sealed `PATH` always starts with the system
//! directories; the file can only append to it.

use super::filesystem::{read_bounded, require_stable_fd, require_stable_path};
use super::{BoundaryError, Identity, Result};
use serde_json::{Map, Value};
use std::fs::OpenOptions;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

/// The only place production site configuration is read from.
pub(super) const SITE_CONFIG_PATH: &str = "/etc/jankurai/governed-launcher.json";
pub(super) const SITE_SCHEMA: &str = "jankurai.governed-site/v1";
/// The sealed `PATH` always begins with these, in this order.
pub(super) const SYSTEM_PATH: &str = "/usr/bin:/bin";
const MAX_SITE_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_EXTRA_PATH_ENTRIES: usize = 8;
const MAX_URL_BYTES: usize = 512;
const SITE_KEYS: [&str; 7] = [
    "cargo_home",
    "extra_path",
    "manifest_repo",
    "root",
    "rustup_home",
    "schema",
    "source_remote",
];

/// Where site configuration comes from and who may own it.
#[derive(Clone, Debug)]
pub(super) struct SiteSource {
    /// The configuration file.
    pub(super) config_path: PathBuf,
    /// Directory chains are validated from here down. `/` in production.
    pub(super) anchor: PathBuf,
    /// The only owner the configuration file and its directories may have.
    /// Root in production.
    pub(super) config_owner: u32,
    /// The launcher's effective user, who may also own the named directories.
    pub(super) effective_uid: u32,
}

impl SiteSource {
    pub(super) fn production(effective_uid: u32) -> Self {
        Self {
            config_path: PathBuf::from(SITE_CONFIG_PATH),
            anchor: PathBuf::from("/"),
            config_owner: 0,
            effective_uid,
        }
    }
}

/// The site paths handed to the governed auditor as part of its environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SiteEnvironment {
    pub(super) cargo_home: String,
    pub(super) rustup_home: String,
    pub(super) path: String,
}

/// Validated site configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Site {
    pub(super) root: PathBuf,
    pub(super) environment: SiteEnvironment,
    pub(super) source_remote: String,
    pub(super) manifest_repo: String,
}

pub(super) fn load(source: &SiteSource) -> Result<Site> {
    let bytes = read_config(source)?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| BoundaryError("governed site configuration is not valid JSON"))?;
    let object = value.as_object().ok_or(BoundaryError(
        "governed site configuration is not an object",
    ))?;
    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    if keys != SITE_KEYS {
        return Err(BoundaryError(
            "governed site configuration has unexpected fields",
        ));
    }
    if string_field(object, "schema")? != SITE_SCHEMA {
        return Err(BoundaryError(
            "governed site configuration has the wrong schema",
        ));
    }

    let root = normalised_path(string_field(object, "root")?)?;
    let cargo_home = trusted_directory(source, string_field(object, "cargo_home")?)?;
    let rustup_home = trusted_directory(source, string_field(object, "rustup_home")?)?;
    let extra_path = extra_path(source, object)?;
    let mut path = SYSTEM_PATH.to_owned();
    for entry in &extra_path {
        path.push(':');
        path.push_str(entry);
    }

    Ok(Site {
        root: PathBuf::from(root),
        environment: SiteEnvironment {
            cargo_home,
            rustup_home,
            path,
        },
        source_remote: url_field(object, "source_remote")?,
        manifest_repo: url_field(object, "manifest_repo")?,
    })
}

/// Open the configuration without following links, require root ownership and
/// no group/world write on the file and every directory above it, then read it
/// through the held descriptor and confirm nothing changed meanwhile.
fn read_config(source: &SiteSource) -> Result<Vec<u8>> {
    let parent = source
        .config_path
        .parent()
        .ok_or(BoundaryError("governed site configuration has no parent"))?;
    for directory in chain(&source.anchor, parent)? {
        let metadata = std::fs::symlink_metadata(&directory)
            .map_err(|_| BoundaryError("governed site configuration is unavailable"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(BoundaryError(
                "governed site configuration directory is not a physical directory",
            ));
        }
        if metadata.uid() != 0 && metadata.uid() != source.config_owner {
            return Err(BoundaryError(
                "governed site configuration directory has the wrong owner",
            ));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(BoundaryError(
                "governed site configuration directory is writable by others",
            ));
        }
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&source.config_path)
        .map_err(|_| BoundaryError("governed site configuration is unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| BoundaryError("governed site configuration is unavailable"))?;
    let identity = Identity::from(&metadata);
    if !metadata.is_file() {
        return Err(BoundaryError("governed site configuration is not regular"));
    }
    if identity.uid != source.config_owner {
        return Err(BoundaryError(
            "governed site configuration has the wrong owner",
        ));
    }
    if identity.mode & 0o022 != 0 {
        return Err(BoundaryError(
            "governed site configuration is writable by others",
        ));
    }
    if identity.links != 1 {
        return Err(BoundaryError(
            "governed site configuration has an unsafe link count",
        ));
    }
    if identity.length == 0 || identity.length > MAX_SITE_CONFIG_BYTES {
        return Err(BoundaryError(
            "governed site configuration has an invalid size",
        ));
    }
    require_stable_path(&source.config_path, identity)?;
    let bytes = read_bounded(&mut file, MAX_SITE_CONFIG_BYTES)?;
    require_stable_fd(&file, identity)?;
    require_stable_path(&source.config_path, identity)?;
    Ok(bytes)
}

fn extra_path(source: &SiteSource, object: &Map<String, Value>) -> Result<Vec<String>> {
    let entries = object
        .get("extra_path")
        .and_then(Value::as_array)
        .ok_or(BoundaryError("governed site extra_path is not a list"))?;
    if entries.len() > MAX_EXTRA_PATH_ENTRIES {
        return Err(BoundaryError("governed site extra_path is too long"));
    }
    let mut accepted: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let entry = entry.as_str().ok_or(BoundaryError(
            "governed site extra_path entry is not a string",
        ))?;
        let entry = normalised_path(entry)?;
        if SYSTEM_PATH.split(':').any(|system| system == entry)
            || accepted.iter().any(|seen| seen == entry)
        {
            return Err(BoundaryError("governed site extra_path entry is repeated"));
        }
        accepted.push(trusted_directory(source, entry)?);
    }
    Ok(accepted)
}

/// A directory the auditor will trust: normalised, absolute, under the anchor,
/// and physically present with no component that another user could replace.
fn trusted_directory(source: &SiteSource, raw: &str) -> Result<String> {
    let value = normalised_path(raw)?;
    for directory in chain(&source.anchor, Path::new(value))? {
        let metadata = std::fs::symlink_metadata(&directory)
            .map_err(|_| BoundaryError("governed site directory is unavailable"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(BoundaryError(
                "governed site directory is not a physical directory",
            ));
        }
        if metadata.uid() != 0 && metadata.uid() != source.effective_uid {
            return Err(BoundaryError("governed site directory has the wrong owner"));
        }
        if metadata.mode() & 0o002 != 0 {
            return Err(BoundaryError("governed site directory is world writable"));
        }
    }
    Ok(value.to_owned())
}

/// Every directory from `anchor` down to and including `path`.
fn chain(anchor: &Path, path: &Path) -> Result<Vec<PathBuf>> {
    let relative = path
        .strip_prefix(anchor)
        .map_err(|_| BoundaryError("governed site path is outside the trusted anchor"))?;
    let mut current = anchor.to_path_buf();
    let mut directories = vec![current.clone()];
    for component in relative.components() {
        match component {
            Component::Normal(name) => {
                current.push(name);
                directories.push(current.clone());
            }
            _ => return Err(BoundaryError("governed site path is not normalised")),
        }
    }
    Ok(directories)
}

/// Absolute, `/`-separated, no empty, `.` or `..` components, no trailing
/// slash, and no byte that could split a `PATH` or an environment entry.
fn normalised_path(value: &str) -> Result<&str> {
    if !value.starts_with('/') {
        return Err(BoundaryError("governed site path is not absolute"));
    }
    if value
        .bytes()
        .any(|byte| byte == b':' || byte.is_ascii_control())
    {
        return Err(BoundaryError(
            "governed site path has a forbidden character",
        ));
    }
    if value != "/"
        && value[1..]
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(BoundaryError("governed site path is not normalised"));
    }
    Ok(value)
}

fn string_field<'a>(object: &'a Map<String, Value>, key: &'static str) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(BoundaryError("governed site field is not a string"))
}

fn url_field(object: &Map<String, Value>, key: &'static str) -> Result<String> {
    let value = string_field(object, key)?;
    if value.is_empty()
        || value.len() > MAX_URL_BYTES
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(BoundaryError("governed site URL is invalid"));
    }
    Ok(value.to_owned())
}
