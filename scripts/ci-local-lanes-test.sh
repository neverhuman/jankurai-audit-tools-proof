#!/usr/bin/env bash
# Proves scripts/ci-local.sh keeps the family-standard lane contract:
# required, fast, security, audit and gates are accepted in every repository,
# all is an alias of gates, every accepted lane resolves to a script that
# exists, an unknown lane still exits 2, and no argument means required.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

dispatch=scripts/ci-local.sh
failures=0

ok()   { printf 'ok: %s\n' "$1"; }
bad()  { printf 'FAIL: %s\n' "$1" >&2; failures=$((failures + 1)); }
same() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1: expected '$3', got '$2'"; fi; }

mapfile -t accepted < <(bash "$dispatch" --list)

for lane in required fast security audit gates all; do
  if printf '%s\n' "${accepted[@]}" | grep -qxF -- "$lane"; then
    ok "--list accepts $lane"
  else
    bad "--list does not accept the standard lane $lane"
  fi
done

for lane in "${accepted[@]}"; do
  script="$(bash "$dispatch" --which "$lane")"
  if [[ -s "$script" ]]; then
    ok "$lane -> $script"
  else
    bad "lane $lane resolves to '$script', which is not a nonempty file"
  fi
done

same "all is an alias of gates" \
  "$(bash "$dispatch" --which all)" "$(bash "$dispatch" --which gates)"
same "no argument runs the required lane" \
  "$(bash "$dispatch" --which)" "$(bash "$dispatch" --which required)"

# The lanes that run the governed build invoke /usr/bin/bash by absolute path
# because they execute under a sealed PATH, so the dispatcher refuses to start
# a lane on an image that has no /usr/bin/bash.
output=""
status=0
output="$(JANKURAI_TOOLS_SEALED_BASH=/nonexistent/bash \
  bash "$dispatch" required 2>&1)" || status=$?
same "a missing sealed bash exits non-zero" "$((status != 0))" "1"
same "a missing sealed bash explains itself" "$output" \
  "tools-proof requires /usr/bin/bash (sealed PATH by design)"
same "the sealed bash guard leaves --which alone" \
  "$(JANKURAI_TOOLS_SEALED_BASH=/nonexistent/bash bash "$dispatch" --which)" \
  "ops/ci/required.sh"

status=0
bash "$dispatch" definitely-not-a-lane >/dev/null 2>&1 || status=$?
same "an unknown lane exits 2" "$status" "2"

if ((failures)); then
  printf '%s: %d check(s) failed\n' "$0" "$failures" >&2
  exit 1
fi
printf '%s: lane contract holds\n' "$0"
