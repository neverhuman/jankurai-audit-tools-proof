use super::site::SiteEnvironment;
use super::{BoundaryError, Policy, Result, VerifiedExecutable};
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;

pub(super) fn sealed_copy(bytes: &[u8]) -> Result<File> {
    let name = CString::new("jankurai-governed-executable")
        .map_err(|_| BoundaryError("sealed executable name is invalid"))?;
    // SAFETY: name is a live NUL-terminated CString and flags are valid for memfd_create.
    let descriptor =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if descriptor < 0 {
        return Err(BoundaryError("sealed executable allocation failed"));
    }
    // SAFETY: descriptor is newly created and ownership is transferred exactly once.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    file.write_all(bytes)
        .map_err(|_| BoundaryError("sealed executable write failed"))?;
    file.flush()
        .map_err(|_| BoundaryError("sealed executable flush failed"))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o500))
        .map_err(|_| BoundaryError("sealed executable mode could not be set"))?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: file owns a valid memfd and F_ADD_SEALS consumes only the integer mask.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(BoundaryError("sealed executable could not be sealed"));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| BoundaryError("sealed executable seek failed"))?;
    Ok(file)
}

pub(super) fn exec_sealed(
    verified: VerifiedExecutable,
    policy: &Policy,
    arguments: Vec<OsString>,
) -> Result<()> {
    let mut argv = Vec::with_capacity(arguments.len() + 1);
    argv.push(os_to_cstring(policy.binary_path.as_os_str())?);
    for argument in arguments {
        argv.push(os_to_cstring(&argument)?);
    }
    let mut argv_pointers = argv.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
    argv_pointers.push(std::ptr::null());

    let environment = sealed_environment(&policy.environment)?;
    let mut environment_pointers = environment
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    environment_pointers.push(std::ptr::null());

    // SAFETY: the fd owns a sealed executable image; argv/envp are live NUL-terminated
    // CString arrays with trailing null pointers for the duration of fexecve.
    let result = unsafe {
        libc::fexecve(
            verified.sealed_file.as_raw_fd(),
            argv_pointers.as_ptr(),
            environment_pointers.as_ptr(),
        )
    };
    debug_assert_eq!(result, -1);
    Err(BoundaryError("verified executable launch failed"))
}

/// The complete environment the governed auditor runs with, in a stable
/// alphabetical order: fixed hardening entries plus the Cargo/rustup homes and
/// `PATH` from the root-owned site file (`site::load`), never from the caller.
pub(super) fn sealed_environment(site: &SiteEnvironment) -> Result<Vec<CString>> {
    [
        format!("CARGO_HOME={}", site.cargo_home),
        "CARGO_NET_OFFLINE=true".to_owned(),
        "GIT_CONFIG_GLOBAL=/dev/null".to_owned(),
        "GIT_CONFIG_NOSYSTEM=1".to_owned(),
        "GIT_OPTIONAL_LOCKS=0".to_owned(),
        "GIT_PAGER=cat".to_owned(),
        "GIT_TERMINAL_PROMPT=0".to_owned(),
        "HOME=/nonexistent".to_owned(),
        "JANKURAI_NO_UPDATE_CHECK=1".to_owned(),
        "LANG=C.UTF-8".to_owned(),
        "LC_ALL=C.UTF-8".to_owned(),
        "PAGER=cat".to_owned(),
        format!("PATH={}", site.path),
        format!("RUSTUP_HOME={}", site.rustup_home),
        "TZ=UTC".to_owned(),
    ]
    .into_iter()
    .map(|entry| {
        CString::new(entry.as_bytes()).map_err(|_| BoundaryError("governed environment is invalid"))
    })
    .collect()
}

fn os_to_cstring(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| BoundaryError("argument contains a NUL byte"))
}
