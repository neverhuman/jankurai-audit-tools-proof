#!/usr/bin/env bash
# Proves ops/ci/lib.sh resolves the toolchain that builds the governed launcher
# only from the pinned toolchain name inside the root-owned site file's rustup
# home: caller variables (RUSTUP_HOME, CARGO_HOME, JANKURAI_GOVERNED_*,
# GOVERNED_*) change nothing, and an unsafe site file, an untrusted directory
# or a toolchain reporting the wrong version is refused. The fixture stands in
# for `/` with a private anchor directory owned by the test user.
set -euo pipefail

ci_dir="${BASH_SOURCE[0]%/*}"
[[ "$ci_dir" != "${BASH_SOURCE[0]}" ]] || ci_dir=.
source "$ci_dir/lib.sh"
cd "$REPO_ROOT"

/usr/bin/mkdir -p "$REPO_ROOT/target/jankurai"
fixture_root="$(/usr/bin/mktemp -d "$REPO_ROOT/target/jankurai/governed-site-test.XXXXXX")"
cleanup_fixture() {
  case "$fixture_root" in
    "$REPO_ROOT"/target/jankurai/governed-site-test.*)
      /usr/bin/chmod -R u+rwx -- "$fixture_root"
      /usr/bin/rm -rf -- "$fixture_root"
      ;;
    *)
      printf '[ci] refusing unsafe governed-site fixture cleanup\n' >&2
      return 1
      ;;
  esac
}
trap cleanup_fixture EXIT

failures=0
ok()  { printf 'ok: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; failures=$((failures + 1)); }

self="$(/usr/bin/id -u)"
toolchain_bin="$fixture_root/rustup/toolchains/$GOVERNED_RUST_TOOLCHAIN/bin"
config="$fixture_root/etc/governed-launcher.json"

reset_fixture() {
  /usr/bin/chmod -R u+rwx -- "$fixture_root"
  /usr/bin/find "$fixture_root" -mindepth 1 -delete
  /usr/bin/chmod 0700 "$fixture_root"
  /usr/bin/mkdir -p "$fixture_root/etc" "$fixture_root/root" "$fixture_root/cargo" \
    "$fixture_root/hostile/rustup/toolchains/$GOVERNED_RUST_TOOLCHAIN/bin" "$toolchain_bin"
  /usr/bin/chmod -R 0755 "$fixture_root/etc" "$fixture_root/root" "$fixture_root/cargo" \
    "$fixture_root/rustup" "$fixture_root/hostile"
  fake_tool "$toolchain_bin/rustc" "$GOVERNED_RUSTC_VERSION"
  fake_tool "$toolchain_bin/cargo" "$GOVERNED_CARGO_VERSION"
  # A same-version impostor where an ambient RUSTUP_HOME would point.
  fake_tool "$fixture_root/hostile/rustup/toolchains/$GOVERNED_RUST_TOOLCHAIN/bin/rustc" "$GOVERNED_RUSTC_VERSION"
  fake_tool "$fixture_root/hostile/rustup/toolchains/$GOVERNED_RUST_TOOLCHAIN/bin/cargo" "$GOVERNED_CARGO_VERSION"
  write_config "$fixture_root/cargo" "$fixture_root/rustup"
}

fake_tool() {
  /usr/bin/printf '#!/usr/bin/bash\nprintf "%%s\\n" "%s"\n' "$2" >"$1"
  /usr/bin/chmod 0755 "$1"
}

write_config() {
  /usr/bin/rm -f -- "$config"
  /usr/bin/jq -n --arg root "$fixture_root/root" --arg cargo "$1" --arg rustup "$2" '{
    schema: "jankurai.governed-site/v1", root: $root, cargo_home: $cargo,
    rustup_home: $rustup, extra_path: [],
    source_remote: "https://forge.example/git/jeryu/jankurai.git",
    manifest_repo: "https://forge.example/git/jeryu/jeryu-tool.git"}' >"$config"
  /usr/bin/chmod 0644 "$config"
}

# resolve <owner> -- resolve the fixture site in a fresh shell whose
# environment is hostile; prints GOVERNED_CARGO on success.
resolve() {
  /usr/bin/env \
    RUSTUP_HOME="$fixture_root/hostile/rustup" \
    CARGO_HOME="$fixture_root/hostile/cargo" \
    JANKURAI_GOVERNED_RUSTUP_HOME="$fixture_root/hostile/rustup" \
    JANKURAI_GOVERNED_CARGO_HOME="$fixture_root/hostile/cargo" \
    JANKURAI_GOVERNED_ROOT="$fixture_root/hostile" \
    JANKURAI_GOVERNED_PATH="$fixture_root/hostile/bin:/usr/bin:/bin" \
    GOVERNED_RUST_TOOLCHAIN_TARGET="../../hostile" \
    GOVERNED_RUST_TOOLCHAIN="../../hostile" \
    GOVERNED_RUSTUP_HOME="$fixture_root/hostile/rustup" \
    GOVERNED_CARGO="$fixture_root/hostile/cargo" \
    GOVERNED_RUSTC="$fixture_root/hostile/rustc" \
    /usr/bin/bash -c 'source "$1/ops/ci/lib.sh" && resolve_governed_site "$2" "$3" "$4" && printf "%s" "$GOVERNED_CARGO"' \
    resolve "$REPO_ROOT" "$config" "$1" "$fixture_root" 2>/dev/null
}

accepts() {
  local actual
  if actual="$(resolve "$self")" && [[ "$actual" == "$toolchain_bin/cargo" ]]; then
    ok "$1"
  else
    bad "$1: resolved '${actual:-<refused>}'"
  fi
}

refuses() {
  if resolve "${2:-$self}" >/dev/null; then bad "$1: accepted"; else ok "$1"; fi
}

reset_fixture
accepts "caller variables cannot select the governed toolchain"

reset_fixture
/usr/bin/chmod 0664 "$config"
refuses "group-writable site file"

reset_fixture
/usr/bin/chmod 0646 "$config"
refuses "world-writable site file"

reset_fixture
refuses "site file not owned by the required owner" "$((self + 1))"

reset_fixture
/usr/bin/chmod 0775 "$fixture_root/etc"
refuses "site file in a group-writable directory"

reset_fixture
/usr/bin/mv "$config" "$config.real"
/usr/bin/ln -s "$config.real" "$config"
refuses "symlinked site file"

reset_fixture
/usr/bin/ln "$config" "$fixture_root/etc/alias.json"
refuses "hardlinked site file"

reset_fixture
/usr/bin/chmod 0777 "$fixture_root/cargo"
refuses "world-writable cargo home"

reset_fixture
/usr/bin/chmod 0777 "$fixture_root/rustup"
refuses "world-writable rustup home"

reset_fixture
write_config "$fixture_root/cargo" "$fixture_root/rustup/../hostile/rustup"
refuses "rustup home with a parent component"

reset_fixture
write_config "$fixture_root/cargo" "/definitely/outside/the/anchor"
refuses "rustup home outside the anchor"

reset_fixture
fake_tool "$toolchain_bin/rustc" "rustc 1.99.0 (impostor)"
refuses "toolchain reporting the wrong rustc version"

reset_fixture
fake_tool "$toolchain_bin/cargo" "cargo 1.99.0 (impostor)"
refuses "toolchain reporting the wrong cargo version"

reset_fixture
/usr/bin/jq '. + {path: "/definitely/hostile"}' "$config" >"$config.new"
/usr/bin/mv "$config.new" "$config"
/usr/bin/chmod 0644 "$config"
refuses "site file with an unexpected field"

if [[ "$GOVERNED_SITE_CONFIG" == /etc/jankurai/governed-launcher.json ]]; then
  ok "production reads the fixed root-owned site file"
else
  bad "production site file moved to '$GOVERNED_SITE_CONFIG'"
fi

if (( failures > 0 )); then
  printf '[ci] governed site contract: %d failure(s)\n' "$failures" >&2
  exit 1
fi
printf '[ci] governed site contract holds\n'
