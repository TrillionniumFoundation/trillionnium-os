#!/usr/bin/env bash
set -euo pipefail

# Target-side launcher/validator for the non-production conformance binary.
# The caller must arrange the exact reviewed startup capability set (normally
# an isolated Linux capsh/setpriv harness or a disabled Android init service).
# This script never grants capabilities, starts the production daemon, or uses
# ADB; it only validates the machine-readable self/child-exec result.

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BINARY="${1:-$ROOT_DIR/target/debug/trillionnium-agentd-capability-conformance}"

fail() {
  echo "agentd-capability-runtime-conformance: $*" >&2
  exit 1
}

[ -f "$BINARY" ] && [ ! -L "$BINARY" ] && [ -x "$BINARY" ] ||
  fail "conformance binary must be a regular non-symlink executable: $BINARY"

result="$(TRILLIONNIUM_ANDROID_AGENTD_CAPABILITY_HARDENING=1 "$BINARY")" ||
  fail "conformance binary rejected the target capability state"

command -v jq >/dev/null 2>&1 || fail "jq is required to validate the result"
jq -e '
  .schema == "org.trillionnium.agentd-capability-runtime-conformance.v1"
  and .status == "PASS_AGENTD_CAPABILITY_NON_REGAIN"
  and .parent.proc_status.CapEff == "00000000000000e1"
  and .parent.proc_status.CapPrm == "00000000000000e1"
  and .parent.proc_status.CapInh == "0000000000000000"
  and .parent.proc_status.CapBnd == "0000000000000000"
  and .parent.proc_status.CapAmb == "0000000000000000"
  and .parent.securebits.no_root == true
  and .parent.securebits.no_root_locked == true
  and .parent.securebits.no_cap_ambient_raise == true
  and .parent.securebits.no_cap_ambient_raise_locked == true
  and .child.proc_status.CapEff == "0000000000000000"
  and .child.proc_status.CapPrm == "0000000000000000"
  and .child.proc_status.CapInh == "0000000000000000"
  and .child.proc_status.CapBnd == "0000000000000000"
  and .child.proc_status.CapAmb == "0000000000000000"
  and .child.securebits.no_root == true
  and .child.securebits.no_root_locked == true
  and .child.securebits.no_cap_ambient_raise == true
  and .child.securebits.no_cap_ambient_raise_locked == true
' <<<"$result" >/dev/null || fail "runtime conformance JSON violates the exact capability contract"

printf '%s\n' "$result"
