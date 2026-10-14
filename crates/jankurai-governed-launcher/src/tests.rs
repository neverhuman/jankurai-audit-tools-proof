use super::*;
use digest::digest_hex;
use filesystem::validate_regular_identity;
use serde_json::{json, Value};
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::sync::Mutex;
use tempfile::TempDir;

static ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

// Invented site values: the fixtures never name a real installation or forge.
const FIXTURE_SOURCE_REMOTE: &str = "https://forge.example/git/jeryu/jankurai.git";
const FIXTURE_MANIFEST_REPO: &str = "https://forge.example/git/jeryu/jeryu-tool.git";
const FIXTURE_CARGO_HOME: &str = "/opt/governed/cargo";
const FIXTURE_RUSTUP_HOME: &str = "/opt/governed/rustup";
const FIXTURE_PATH: &str = "/usr/bin:/bin:/opt/governed/bin";

fn fixture_site() -> SiteEnvironment {
    SiteEnvironment {
        cargo_home: FIXTURE_CARGO_HOME.to_owned(),
        rustup_home: FIXTURE_RUSTUP_HOME.to_owned(),
        path: FIXTURE_PATH.to_owned(),
    }
}

struct Fixture {
    _temp: TempDir,
    policy: Policy,
}

impl Fixture {
    fn new(binary_bytes: &[u8]) -> Self {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let binary_dir = temp.path().join("bin");
        let receipt_dir = temp.path().join("receipts");
        fs::create_dir(&binary_dir).unwrap();
        fs::create_dir(&receipt_dir).unwrap();
        fs::set_permissions(&binary_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&receipt_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let binary_path = binary_dir.join("jankurai");
        fs::write(&binary_path, binary_bytes).unwrap();
        fs::set_permissions(&binary_path, fs::Permissions::from_mode(0o755)).unwrap();
        let binary_sha256 = digest_hex(binary_bytes);
        let receipt_path = receipt_dir.join("receipt.json");
        let receipt = valid_receipt(&binary_path, &binary_sha256);
        let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
        fs::write(&receipt_path, &receipt_bytes).unwrap();
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();
        let receipt_sha256 = digest_hex(&receipt_bytes);
        Self {
            _temp: temp,
            policy: Policy {
                trusted_root: binary_dir.parent().unwrap().to_path_buf(),
                binary_path,
                binary_sha256,
                receipt_path,
                receipt_sha256,
                source_remote: FIXTURE_SOURCE_REMOTE.to_owned(),
                manifest_repo: FIXTURE_MANIFEST_REPO.to_owned(),
                environment: fixture_site(),
            },
        }
    }
}

fn valid_receipt(binary_path: &Path, binary_sha256: &str) -> Value {
    json!({
        "schema": "jeryu.jankurai-installation/v1",
        "source": {
            "remote": FIXTURE_SOURCE_REMOTE,
            "commit": "4dfbdfa3585f1928d5f996d7b5e14608dff14a03",
            "tag": "v1.6.11-deadlang-precision-split.2",
            "tree": "7e5d501aa6f0ee6ced9a48c6288a9943d0b9573c",
            "archive_sha256": "1aa3d178dec0fbb8d0657dd465ea6fda830ffc4ec1f65560b7b7d1682fd87e69",
            "cargo_lock_sha256": "b9acb981c326226a687d0b6703e4f7ee303148e9e1a6dda1aa03d77988820f6a",
            "verification": "release-authoritative"
        },
        "build": {
            "rustc": "rustc 1.95.0 (59807616e 2026-04-14)",
            "cargo": "cargo 1.95.0 (f2d3ce0bd 2026-03-21)",
            "target_triple": "x86_64-unknown-linux-gnu",
            "mode": "cargo-install-locked-offline-path-v1",
            "cargo_net_offline": true,
            "dedicated_cargo_home": true,
            "git_global_config_disabled": true,
            "git_system_config_disabled": true,
            "git_http_follow_redirects": false,
            "git_terminal_prompt": false,
            "jankurai_update_check": false,
            "network_scope": "local-forge-source-plus-offline-cargo",
            "no_proxy": "127.0.0.1,localhost,::1"
        },
        "binary": {"sha256": binary_sha256, "version_output": "jankurai 1.6.11"},
        "installation": {"path": binary_path, "atomic": true},
        "governance": {
            "status": "governed",
            "manifest_repo": FIXTURE_MANIFEST_REPO,
            "manifest_commit": "aac9336ac369f4d3046a1e0acc9d98c48ce164d1",
            "manifest_tree": "7049feda28cfd95c8657f562b92e8246ceb1cc26",
            "manifest_sha256": "7aaac7f1b8c1543eba5215ec7cd2bf35e0c2411339ed9af1d1a6ace68d2807d8",
            "protected_main": true,
            "protection_policy": "immutable-main-v1"
        },
        "test_mode": false,
        "conclusion": "success"
    })
}

#[test]
fn valid_files_produce_a_write_sealed_exact_copy() {
    let fixture = Fixture::new(b"governed executable bytes");
    let verified = verify_with_hook(&fixture.policy, || {}).unwrap();
    assert_eq!(
        // SAFETY: verified owns a valid memfd and F_GET_SEALS has no pointer argument.
        unsafe { libc::fcntl(verified.sealed_file.as_raw_fd(), libc::F_GET_SEALS) },
        libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE
    );
    assert_eq!(
        require_file_digest(&verified.sealed_file, &fixture.policy.binary_sha256),
        Ok(())
    );
}

#[test]
fn in_process_sha256_matches_standard_vectors() {
    assert_eq!(
        digest_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        digest_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn rejects_symlink_component() {
    let fixture = Fixture::new(b"governed executable bytes");
    let link = fixture._temp.path().join("linked-bin");
    symlink(fixture._temp.path().join("bin"), &link).unwrap();
    let mut policy = fixture.policy.clone();
    policy.binary_path = link.join("jankurai");
    assert!(verify_with_hook(&policy, || {}).is_err());
}

#[test]
fn rejects_hardlinked_binary() {
    let fixture = Fixture::new(b"governed executable bytes");
    fs::hard_link(
        &fixture.policy.binary_path,
        fixture._temp.path().join("alias"),
    )
    .unwrap();
    assert_eq!(
        verify_with_hook(&fixture.policy, || {}).unwrap_err(),
        BoundaryError("governed file has an unsafe link count")
    );
}

#[test]
fn rejects_wrong_file_mode() {
    let fixture = Fixture::new(b"governed executable bytes");
    fs::set_permissions(
        &fixture.policy.binary_path,
        fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    assert_eq!(
        verify_with_hook(&fixture.policy, || {}).unwrap_err(),
        BoundaryError("governed file has the wrong mode")
    );
}

#[test]
fn rejects_wrong_effective_owner() {
    let identity = Identity {
        device: 1,
        inode: 2,
        uid: 2000,
        mode: 0o755,
        links: 1,
        length: 1,
    };
    assert_eq!(
        validate_regular_identity(identity, true, 1000, 0o755, 64).unwrap_err(),
        BoundaryError("governed file has the wrong owner")
    );
}

#[test]
fn rejects_oversized_receipt_before_parsing() {
    let fixture = Fixture::new(b"governed executable bytes");
    fs::write(
        &fixture.policy.receipt_path,
        vec![b'x'; (MAX_RECEIPT_BYTES + 1) as usize],
    )
    .unwrap();
    assert_eq!(
        verify_with_hook(&fixture.policy, || {}).unwrap_err(),
        BoundaryError("governed file has an invalid size")
    );
}

#[test]
fn rejects_atomic_path_replacement_after_open() {
    let fixture = Fixture::new(b"governed executable bytes");
    let original = fixture.policy.binary_path.with_extension("original");
    let replacement = fixture.policy.binary_path.clone();
    let result = verify_with_hook(&fixture.policy, || {
        fs::rename(&replacement, &original).unwrap();
        fs::write(&replacement, b"governed executable bytes").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755)).unwrap();
    });
    assert_eq!(
        result.unwrap_err(),
        BoundaryError("governed path changed during validation")
    );
}

#[test]
fn rejects_same_version_fake_by_digest() {
    let fixture = Fixture::new(b"governed executable bytes");
    fs::write(
        &fixture.policy.binary_path,
        b"#!/bin/sh\nprintf 'jankurai 1.6.11\\n'\n",
    )
    .unwrap();
    assert_eq!(
        verify_with_hook(&fixture.policy, || {}).unwrap_err(),
        BoundaryError("binary digest mismatch")
    );
}

#[test]
fn ambient_path_and_shell_function_markers_are_not_consulted() {
    let _guard = ENVIRONMENT_LOCK.lock().unwrap();
    let fixture = Fixture::new(b"governed executable bytes");
    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", "/definitely/hostile");
    std::env::set_var("BASH_FUNC_sha256sum%%", "() { return 0; }");
    let result = verify_with_hook(&fixture.policy, || {});
    std::env::remove_var("BASH_FUNC_sha256sum%%");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }
    assert!(result.is_ok());
}

#[test]
fn sealed_environment_excludes_caller_tool_and_git_configuration() {
    let environment = execution::sealed_environment(&fixture_site()).unwrap();
    let environment = environment
        .iter()
        .map(|entry| entry.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert_eq!(
        environment,
        vec![
            "CARGO_HOME=/opt/governed/cargo",
            "CARGO_NET_OFFLINE=true",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_CONFIG_NOSYSTEM=1",
            "GIT_OPTIONAL_LOCKS=0",
            "GIT_PAGER=cat",
            "GIT_TERMINAL_PROMPT=0",
            "HOME=/nonexistent",
            "JANKURAI_NO_UPDATE_CHECK=1",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "PAGER=cat",
            "PATH=/usr/bin:/bin:/opt/governed/bin",
            "RUSTUP_HOME=/opt/governed/rustup",
            "TZ=UTC",
        ]
    );
}

#[test]
fn rejects_receipt_tampering_in_a_controlled_installation() {
    let fixture = Fixture::new(b"verified executable fixture");
    fs::write(&fixture.policy.receipt_path, b"{} ").unwrap();
    assert_eq!(
        verify_with_hook(&fixture.policy, || {}).unwrap_err(),
        BoundaryError("receipt digest mismatch")
    );
}

/// Replace the fixture receipt on disk and re-pin its digest in `policy`.
fn rewrite_receipt(policy: &mut Policy, receipt: &Value) {
    let bytes = serde_json::to_vec(receipt).unwrap();
    fs::write(&policy.receipt_path, &bytes).unwrap();
    fs::set_permissions(&policy.receipt_path, fs::Permissions::from_mode(0o600)).unwrap();
    policy.receipt_sha256 = digest_hex(&bytes);
}

#[test]
fn a_declared_forge_must_match_the_receipt_exactly() {
    let fixture = Fixture::new(b"governed executable bytes");
    let mut policy = fixture.policy.clone();
    policy.source_remote = "https://other-forge.example/git/jeryu/jankurai.git".to_owned();
    assert_eq!(
        verify_with_hook(&policy, || {}).unwrap_err(),
        BoundaryError("governed receipt semantic mismatch")
    );
    let mut policy = fixture.policy.clone();
    policy.manifest_repo = "https://other-forge.example/git/jeryu/jeryu-tool.git".to_owned();
    assert_eq!(
        verify_with_hook(&policy, || {}).unwrap_err(),
        BoundaryError("governed receipt semantic mismatch")
    );
}

#[test]
fn an_empty_receipt_remote_is_refused() {
    let fixture = Fixture::new(b"governed executable bytes");
    let mut policy = fixture.policy.clone();
    let mut receipt = valid_receipt(&policy.binary_path, &policy.binary_sha256);
    receipt["source"]["remote"] = json!("");
    rewrite_receipt(&mut policy, &receipt);
    assert_eq!(
        verify_with_hook(&policy, || {}).unwrap_err(),
        BoundaryError("governed receipt semantic mismatch")
    );
}

#[test]
fn a_receipt_for_another_root_names_the_site_mismatch() {
    let fixture = Fixture::new(b"governed executable bytes");
    let mut policy = fixture.policy.clone();
    let receipt = valid_receipt(Path::new("/elsewhere/bin/jankurai"), &policy.binary_sha256);
    rewrite_receipt(&mut policy, &receipt);
    assert_eq!(
        verify_with_hook(&policy, || {}).unwrap_err(),
        BoundaryError("governed receipt installation path does not match the configured root")
    );
}

/// A controlled site: a private anchor directory standing in for `/`, a
/// configuration directory and file, and the directories the file names.
struct SiteFixture {
    temp: TempDir,
    source: SiteSource,
}

impl SiteFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        for directory in ["etc", "root", "cargo", "rustup", "bin"] {
            let path = temp.path().join(directory);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        // SAFETY: geteuid has no arguments, does not dereference memory, and cannot violate aliases.
        let effective_uid = unsafe { libc::geteuid() };
        let fixture = Self {
            source: SiteSource {
                config_path: temp.path().join("etc/governed-launcher.json"),
                anchor: temp.path().to_path_buf(),
                config_owner: effective_uid,
                effective_uid,
            },
            temp,
        };
        fixture.write(&fixture.valid());
        fixture
    }

    fn dir(&self, name: &str) -> String {
        self.temp.path().join(name).to_string_lossy().into_owned()
    }

    fn valid(&self) -> Value {
        json!({
            "schema": site::SITE_SCHEMA,
            "root": self.dir("root"),
            "cargo_home": self.dir("cargo"),
            "rustup_home": self.dir("rustup"),
            "extra_path": [self.dir("bin")],
            "source_remote": FIXTURE_SOURCE_REMOTE,
            "manifest_repo": FIXTURE_MANIFEST_REPO,
        })
    }

    fn write(&self, value: &Value) {
        let path = &self.source.config_path;
        let _ = fs::remove_file(path);
        fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    fn with(&self, key: &str, replacement: Value) -> Result<Site> {
        let mut value = self.valid();
        value[key] = replacement;
        self.write(&value);
        site::load(&self.source)
    }
}

#[test]
fn site_file_supplies_every_site_path() {
    let fixture = SiteFixture::new();
    let site = site::load(&fixture.source).unwrap();
    assert_eq!(site.root, fixture.temp.path().join("root"));
    assert_eq!(site.environment.cargo_home, fixture.dir("cargo"));
    assert_eq!(site.environment.rustup_home, fixture.dir("rustup"));
    assert_eq!(
        site.environment.path,
        format!("/usr/bin:/bin:{}", fixture.dir("bin"))
    );
    let policy = Policy::for_site(site, BINARY_SHA256, RECEIPT_SHA256);
    assert_eq!(
        policy.binary_path,
        fixture.temp.path().join("root/bin/jankurai")
    );
    assert_eq!(
        policy.receipt_path,
        fixture
            .temp
            .path()
            .join("root/receipts/jankurai/sha256")
            .join(format!("{RECEIPT_SHA256}.json"))
    );
    assert_eq!(policy.source_remote, FIXTURE_SOURCE_REMOTE);
    assert_eq!(policy.manifest_repo, FIXTURE_MANIFEST_REPO);
}

/// The held finding on PR #2: caller-set variables chose the sealed PATH and
/// Cargo/rustup homes. They must have no effect on what the auditor gets.
#[test]
fn caller_environment_cannot_select_the_sealed_site_paths() {
    let _guard = ENVIRONMENT_LOCK.lock().unwrap();
    let fixture = SiteFixture::new();
    let hostile = [
        ("JANKURAI_GOVERNED_ROOT", "/definitely/hostile/root"),
        ("JANKURAI_GOVERNED_CARGO_HOME", "/definitely/hostile/cargo"),
        (
            "JANKURAI_GOVERNED_RUSTUP_HOME",
            "/definitely/hostile/rustup",
        ),
        (
            "JANKURAI_GOVERNED_PATH",
            "/definitely/hostile/bin:/usr/bin:/bin",
        ),
        ("CARGO_HOME", "/definitely/hostile/cargo"),
        ("RUSTUP_HOME", "/definitely/hostile/rustup"),
        ("PATH", "/definitely/hostile/bin"),
    ];
    let saved = hostile
        .iter()
        .map(|(name, _)| (*name, std::env::var_os(name)))
        .collect::<Vec<_>>();
    for (name, value) in hostile {
        std::env::set_var(name, value);
    }
    let from_file = site::load(&fixture.source);
    let production = Policy::production();
    for (name, value) in saved {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }

    let site = from_file.unwrap();
    let rendered = format!("{site:?}");
    assert!(!rendered.contains("hostile"), "{rendered}");
    let sealed = execution::sealed_environment(&site.environment).unwrap();
    assert!(sealed
        .iter()
        .all(|entry| !entry.to_string_lossy().contains("hostile")));
    // Production reads only the root-owned file; on a host without one it
    // refuses rather than falling back to the variables above.
    match production {
        Ok(policy) => assert!(!format!("{policy:?}").contains("hostile")),
        Err(error) => assert!(!error.0.contains("JANKURAI_GOVERNED"), "{error}"),
    }
}

#[test]
fn production_reads_one_fixed_root_owned_file() {
    let source = SiteSource::production(1000);
    assert_eq!(
        source.config_path,
        Path::new("/etc/jankurai/governed-launcher.json")
    );
    assert_eq!(source.anchor, Path::new("/"));
    assert_eq!(source.config_owner, 0);
}

#[test]
fn site_file_must_have_the_trusted_owner() {
    let mut fixture = SiteFixture::new();
    fixture.source.config_owner = fixture.source.effective_uid.wrapping_add(1);
    // The fixture's directories are owned by the test user, not the expected
    // owner, so the chain check fires before the file is opened.
    assert_eq!(
        site::load(&fixture.source).unwrap_err(),
        BoundaryError("governed site configuration directory has the wrong owner")
    );
}

#[test]
fn site_file_writable_by_others_is_refused() {
    let fixture = SiteFixture::new();
    for mode in [0o664, 0o646, 0o666] {
        fs::set_permissions(
            &fixture.source.config_path,
            fs::Permissions::from_mode(mode),
        )
        .unwrap();
        assert_eq!(
            site::load(&fixture.source).unwrap_err(),
            BoundaryError("governed site configuration is writable by others"),
            "mode {mode:o}"
        );
    }
}

#[test]
fn site_file_in_a_writable_directory_is_refused() {
    let fixture = SiteFixture::new();
    fs::set_permissions(
        fixture.temp.path().join("etc"),
        fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    assert_eq!(
        site::load(&fixture.source).unwrap_err(),
        BoundaryError("governed site configuration directory is writable by others")
    );
}

#[test]
fn site_file_reached_through_a_symlink_is_refused() {
    let fixture = SiteFixture::new();
    let real = fixture.temp.path().join("etc/real.json");
    fs::rename(&fixture.source.config_path, &real).unwrap();
    symlink(&real, &fixture.source.config_path).unwrap();
    assert_eq!(
        site::load(&fixture.source).unwrap_err(),
        BoundaryError("governed site configuration is unavailable")
    );

    let mut fixture = SiteFixture::new();
    let linked = fixture.temp.path().join("linked-etc");
    symlink(fixture.temp.path().join("etc"), &linked).unwrap();
    fixture.source.config_path = linked.join("governed-launcher.json");
    assert_eq!(
        site::load(&fixture.source).unwrap_err(),
        BoundaryError("governed site configuration directory is not a physical directory")
    );
}

#[test]
fn hardlinked_site_file_is_refused() {
    let fixture = SiteFixture::new();
    fs::hard_link(
        &fixture.source.config_path,
        fixture.temp.path().join("etc/alias.json"),
    )
    .unwrap();
    assert_eq!(
        site::load(&fixture.source).unwrap_err(),
        BoundaryError("governed site configuration has an unsafe link count")
    );
}

#[test]
fn missing_site_file_is_refused() {
    let fixture = SiteFixture::new();
    fs::remove_file(&fixture.source.config_path).unwrap();
    assert_eq!(
        site::load(&fixture.source).unwrap_err(),
        BoundaryError("governed site configuration is unavailable")
    );
}

#[test]
fn site_file_schema_and_fields_are_exact() {
    let fixture = SiteFixture::new();
    assert_eq!(
        fixture.with("schema", json!("other/v1")).unwrap_err(),
        BoundaryError("governed site configuration has the wrong schema")
    );
    assert_eq!(
        fixture
            .with("path", json!("/definitely/hostile"))
            .unwrap_err(),
        BoundaryError("governed site configuration has unexpected fields")
    );
    let mut missing = fixture.valid();
    missing.as_object_mut().unwrap().remove("manifest_repo");
    fixture.write(&missing);
    assert_eq!(
        site::load(&fixture.source).unwrap_err(),
        BoundaryError("governed site configuration has unexpected fields")
    );
    assert_eq!(
        fixture.with("source_remote", json!("")).unwrap_err(),
        BoundaryError("governed site URL is invalid")
    );
    assert_eq!(
        fixture
            .with("source_remote", json!("https://forge.example/a b"))
            .unwrap_err(),
        BoundaryError("governed site URL is invalid")
    );
}

/// A world-writable CARGO_HOME lets any user plant a config.toml with a
/// rustc-wrapper; a world-writable PATH entry lets any user plant `git`.
#[test]
fn world_writable_site_directories_are_refused() {
    for key in ["cargo_home", "rustup_home", "extra_path"] {
        let fixture = SiteFixture::new();
        let open = fixture.temp.path().join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        let open = open.to_string_lossy().into_owned();
        let replacement = if key == "extra_path" {
            json!([open])
        } else {
            json!(open)
        };
        assert_eq!(
            fixture.with(key, replacement).unwrap_err(),
            BoundaryError("governed site directory is world writable"),
            "{key}"
        );
    }
}

#[test]
fn site_directories_below_a_world_writable_parent_are_refused() {
    let fixture = SiteFixture::new();
    let open = fixture.temp.path().join("open");
    fs::create_dir_all(open.join("cargo")).unwrap();
    fs::set_permissions(&open, fs::Permissions::from_mode(0o1777)).unwrap();
    assert_eq!(
        fixture
            .with("cargo_home", json!(open.join("cargo")))
            .unwrap_err(),
        BoundaryError("governed site directory is world writable")
    );
}

#[test]
fn site_directories_must_be_physical_and_present() {
    let fixture = SiteFixture::new();
    let linked = fixture.temp.path().join("linked-cargo");
    symlink(fixture.temp.path().join("cargo"), &linked).unwrap();
    assert_eq!(
        fixture.with("cargo_home", json!(linked)).unwrap_err(),
        BoundaryError("governed site directory is not a physical directory")
    );
    assert_eq!(
        fixture
            .with("rustup_home", json!(fixture.temp.path().join("absent")))
            .unwrap_err(),
        BoundaryError("governed site directory is unavailable")
    );
    assert_eq!(
        fixture
            .with("cargo_home", json!("/definitely/hostile/cargo"))
            .unwrap_err(),
        BoundaryError("governed site path is outside the trusted anchor")
    );
}

#[test]
fn site_paths_must_be_absolute_and_normalised() {
    let fixture = SiteFixture::new();
    let base = fixture.dir("cargo");
    for (value, error) in [
        (
            "relative/cargo".to_owned(),
            "governed site path is not absolute",
        ),
        (
            format!("{base}/../cargo"),
            "governed site path is not normalised",
        ),
        (format!("{base}/./"), "governed site path is not normalised"),
        (format!("{base}//x"), "governed site path is not normalised"),
        (
            format!("{base}:/definitely/hostile"),
            "governed site path has a forbidden character",
        ),
    ] {
        assert_eq!(
            fixture.with("cargo_home", json!(value)).unwrap_err(),
            BoundaryError(error),
            "{value}"
        );
        assert_eq!(
            fixture.with("extra_path", json!([value])).unwrap_err(),
            BoundaryError(error),
            "{value}"
        );
    }
    assert_eq!(
        fixture.with("root", json!("relative/root")).unwrap_err(),
        BoundaryError("governed site path is not absolute")
    );
}

#[test]
fn sealed_path_always_starts_with_the_system_directories() {
    let fixture = SiteFixture::new();
    let site = fixture.with("extra_path", json!([])).unwrap();
    assert_eq!(site.environment.path, "/usr/bin:/bin");
    assert_eq!(
        fixture.with("extra_path", json!(["/usr/bin"])).unwrap_err(),
        BoundaryError("governed site extra_path entry is repeated")
    );
    assert_eq!(
        fixture
            .with("extra_path", json!(vec![fixture.dir("bin"); 2]))
            .unwrap_err(),
        BoundaryError("governed site extra_path entry is repeated")
    );
    assert_eq!(
        fixture
            .with("extra_path", json!(vec![fixture.dir("bin"); 9]))
            .unwrap_err(),
        BoundaryError("governed site extra_path is too long")
    );
}
