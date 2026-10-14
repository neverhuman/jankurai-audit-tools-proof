use super::{BoundaryError, Policy, Result};
use serde_json::Value;

pub(super) fn validate_receipt(bytes: &[u8], policy: &Policy) -> Result<()> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| BoundaryError("governed receipt is not valid JSON"))?;
    expect_string(&value, "/schema", "jeryu.jankurai-installation/v1")?;
    expect_string(&value, "/source/remote", &policy.source_remote)?;
    expect_string(
        &value,
        "/source/commit",
        "4dfbdfa3585f1928d5f996d7b5e14608dff14a03",
    )?;
    expect_string(&value, "/source/tag", "v1.6.11-deadlang-precision-split.2")?;
    expect_string(
        &value,
        "/source/tree",
        "7e5d501aa6f0ee6ced9a48c6288a9943d0b9573c",
    )?;
    expect_string(
        &value,
        "/source/archive_sha256",
        "1aa3d178dec0fbb8d0657dd465ea6fda830ffc4ec1f65560b7b7d1682fd87e69",
    )?;
    expect_string(
        &value,
        "/source/cargo_lock_sha256",
        "b9acb981c326226a687d0b6703e4f7ee303148e9e1a6dda1aa03d77988820f6a",
    )?;
    expect_string(&value, "/source/verification", "release-authoritative")?;
    expect_string(
        &value,
        "/build/rustc",
        "rustc 1.95.0 (59807616e 2026-04-14)",
    )?;
    expect_string(
        &value,
        "/build/cargo",
        "cargo 1.95.0 (f2d3ce0bd 2026-03-21)",
    )?;
    expect_string(&value, "/build/target_triple", "x86_64-unknown-linux-gnu")?;
    expect_string(
        &value,
        "/build/mode",
        "cargo-install-locked-offline-path-v1",
    )?;
    for pointer in [
        "/build/cargo_net_offline",
        "/build/dedicated_cargo_home",
        "/build/git_global_config_disabled",
        "/build/git_system_config_disabled",
        "/build/git_http_follow_redirects",
        "/build/git_terminal_prompt",
        "/build/jankurai_update_check",
    ] {
        let expected = !matches!(
            pointer,
            "/build/git_http_follow_redirects"
                | "/build/git_terminal_prompt"
                | "/build/jankurai_update_check"
        );
        expect_bool(&value, pointer, expected)?;
    }
    expect_string(
        &value,
        "/build/network_scope",
        "local-forge-source-plus-offline-cargo",
    )?;
    expect_string(&value, "/build/no_proxy", "127.0.0.1,localhost,::1")?;
    expect_string(&value, "/binary/sha256", &policy.binary_sha256)?;
    expect_string(&value, "/binary/version_output", "jankurai 1.6.11")?;
    // The pinned receipt names one absolute installation path, so a site
    // whose configured root differs gets a site error, not a semantic one.
    if value.pointer("/installation/path").and_then(Value::as_str)
        != Some(policy.binary_path.to_string_lossy().as_ref())
    {
        return Err(BoundaryError(
            "governed receipt installation path does not match the configured root",
        ));
    }
    expect_bool(&value, "/installation/atomic", true)?;
    expect_string(&value, "/governance/status", "governed")?;
    expect_string(&value, "/governance/manifest_repo", &policy.manifest_repo)?;
    expect_string(
        &value,
        "/governance/manifest_commit",
        "aac9336ac369f4d3046a1e0acc9d98c48ce164d1",
    )?;
    expect_string(
        &value,
        "/governance/manifest_tree",
        "7049feda28cfd95c8657f562b92e8246ceb1cc26",
    )?;
    expect_string(
        &value,
        "/governance/manifest_sha256",
        "7aaac7f1b8c1543eba5215ec7cd2bf35e0c2411339ed9af1d1a6ace68d2807d8",
    )?;
    expect_bool(&value, "/governance/protected_main", true)?;
    expect_string(&value, "/governance/protection_policy", "immutable-main-v1")?;
    expect_bool(&value, "/test_mode", false)?;
    expect_string(&value, "/conclusion", "success")?;
    Ok(())
}

fn expect_string(value: &Value, pointer: &str, expected: &str) -> Result<()> {
    if value.pointer(pointer).and_then(Value::as_str) != Some(expected) {
        return Err(BoundaryError("governed receipt semantic mismatch"));
    }
    Ok(())
}

fn expect_bool(value: &Value, pointer: &str, expected: bool) -> Result<()> {
    if value.pointer(pointer).and_then(Value::as_bool) != Some(expected) {
        return Err(BoundaryError("governed receipt semantic mismatch"));
    }
    Ok(())
}
