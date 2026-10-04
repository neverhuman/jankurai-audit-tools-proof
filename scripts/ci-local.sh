#!/usr/bin/env bash
# Local entry point for the CI lanes. Delegates to the exact same
# ops/ci/<lane>.sh scripts the forge CI calls, so local runs
# never drift from CI.
#
# Every repository of the split family accepts the same lane names:
#   required  fast  security  audit  gates  (all is an alias of gates)
# plus the legacy lane names kept for callers that still pass them. With no
# argument the required lane runs, because that is the gate every change has
# to pass. `--list` prints the accepted lanes and `--which [lane]` prints the
# script a lane resolves to, so the contract can be probed without running it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Lane -> script. Aliases point at the script they alias rather than at
# another lane name, so --list and --which can never drift from what the
# dispatcher actually runs.
declare -A lane_script=(
  [required]="ops/ci/required.sh"
  [fast]="ops/ci/fast.sh"
  [security]="ops/ci/security.sh"
  [audit]="ops/ci/audit.sh"
  [gates]="ops/ci/quality-gates.sh"
  [all]="ops/ci/quality-gates.sh"
  [quality-gates]="ops/ci/quality-gates.sh"
  [tool-adoption]="ops/ci/tool-adoption.sh"
  [drift]="ops/ci/contract-drift.sh"
  [contract-drift]="ops/ci/contract-drift.sh"
)

lanes() { printf '%s\n' "${!lane_script[@]}" | sort; }

usage() {
  local accepted
  mapfile -t accepted < <(lanes)
  local IFS='|'
  echo "usage: $0 {${accepted[*]}} | --list | --which [lane]" >&2
}

resolve() {
  local want="$1"
  if [[ -z "${lane_script[$want]:-}" ]]; then
    echo "$0: unknown lane: $want" >&2
    usage
    return 2
  fi
  echo "${lane_script[$want]}"
}

case "${1:-}" in
  --list)  lanes; exit 0 ;;
  --which) resolve "${2:-required}" || exit $?; exit 0 ;;
esac

# Several lanes of this repository invoke /usr/bin/bash by absolute path
# (ops/ci/tool-adoption.sh, ops/ci/changed-fast-audit.sh and the evidence
# scripts they drive). That is deliberate: those lanes run the governed build
# under `/usr/bin/env -i ... PATH=/usr/bin:/bin` (see ops/ci/lib.sh), so the
# sealed PATH is the only PATH the lane may rely on and an ambient `bash`
# earlier on the caller's PATH must never be able to shadow the interpreter.
# Keep the absolute path; on an image without /usr/bin/bash fail here with a
# readable message instead of letting a lane die on a bare "No such file".
# The variable exists so scripts/ci-local-lanes-test.sh can prove the guard;
# it only redirects the existence check, never what a lane executes.
sealed_bash="${JANKURAI_TOOLS_SEALED_BASH:-/usr/bin/bash}"
require_sealed_bash() {
  if [[ ! -x "$sealed_bash" ]]; then
    echo "tools-proof requires /usr/bin/bash (sealed PATH by design)" >&2
    return 1
  fi
}

script="$(resolve "${1:-required}")" || exit $?
require_sealed_bash || exit 1
exec bash "$script"
