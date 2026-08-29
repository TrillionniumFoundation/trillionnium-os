#!/usr/bin/env bash
# Prepare the accepted W3-A loopback-only device -> owner-host adb-server path.
# This is an owner bootstrap/recovery tool, not an Agent semantic gate and not
# integrated same-turn evidence.
set -euo pipefail

usage() {
  cat <<'EOF'
usage:
  prepare-adb-reverse-v1.sh --serial SERIAL --apply [options]
  prepare-adb-reverse-v1.sh --serial SERIAL --remove [options]

required:
  --serial SERIAL       exact owner-authorized adb serial
  --apply               create/update the reverse mapping
  --remove              remove the exact reverse mapping

options:
  --adb PATH            host adb executable (default: adb from PATH)
  --device-port PORT    device loopback port (default: 15037)
  --host-port PORT      owner-host adb-server port (default: 5037)
  --evidence PATH       write JSON evidence atomically
  --allow-nonloopback-server
                        acknowledge that host adb-server exposure was reviewed;
                        the script still does not configure a network listener
  -h, --help            show this help

The Root Linux client setting emitted on success is:
  ADB_SERVER_SOCKET=tcp:127.0.0.1:<device-port>
EOF
}

ADB=adb
SERIAL=
MODE=
DEVICE_PORT=15037
HOST_PORT=5037
EVIDENCE=
ALLOW_NONLOOPBACK_SERVER=0

while (($#)); do
  case "$1" in
    --serial)
      (($# >= 2)) || { echo "--serial requires a value" >&2; exit 64; }
      SERIAL=$2
      shift 2
      ;;
    --apply|--remove)
      [[ -z "$MODE" ]] || { echo "select exactly one of --apply or --remove" >&2; exit 64; }
      MODE=${1#--}
      shift
      ;;
    --adb)
      (($# >= 2)) || { echo "--adb requires a value" >&2; exit 64; }
      ADB=$2
      shift 2
      ;;
    --device-port)
      (($# >= 2)) || { echo "--device-port requires a value" >&2; exit 64; }
      DEVICE_PORT=$2
      shift 2
      ;;
    --host-port)
      (($# >= 2)) || { echo "--host-port requires a value" >&2; exit 64; }
      HOST_PORT=$2
      shift 2
      ;;
    --evidence)
      (($# >= 2)) || { echo "--evidence requires a value" >&2; exit 64; }
      EVIDENCE=$2
      shift 2
      ;;
    --allow-nonloopback-server)
      ALLOW_NONLOOPBACK_SERVER=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

[[ -n "$SERIAL" ]] || { echo "--serial is required" >&2; exit 64; }
[[ -n "$MODE" ]] || { echo "select exactly one of --apply or --remove" >&2; exit 64; }
if [[ ! "$SERIAL" =~ ^[A-Za-z0-9._:-]{1,128}$ ]] &&
   [[ ! "$SERIAL" =~ ^\[[0-9A-Fa-f:]+\]:[0-9]{1,5}$ ]]; then
  echo "serial is empty or malformed" >&2
  exit 64
fi
for value in "$DEVICE_PORT" "$HOST_PORT"; do
  [[ "$value" =~ ^[0-9]+$ ]] || { echo "ports must be decimal integers" >&2; exit 64; }
  ((value >= 1 && value <= 65535)) || { echo "ports must be in 1..65535" >&2; exit 64; }
done

# Bind every adb invocation in this bootstrap to the explicitly selected host
# server. A caller-provided socket/address/port must not silently redirect
# version, device, or reverse commands to a different server. Use the same
# ADB_SERVER_SOCKET contract as the measured qualification runners; clear the
# alternate Android routing variables so they cannot override this endpoint.
unset ADB_SERVER_PORT ANDROID_ADB_SERVER_PORT ANDROID_ADB_SERVER_ADDRESS
export ADB_SERVER_SOCKET="tcp:127.0.0.1:$HOST_PORT"

command -v "$ADB" >/dev/null 2>&1 || {
  echo "host adb executable is unavailable: $ADB" >&2
  exit 69
}

ADB_VERSION=$("$ADB" version 2>&1) || {
  echo "host adb version probe failed" >&2
  exit 69
}
DEVICES=$("$ADB" devices -l 2>&1) || {
  echo "adb devices -l failed" >&2
  exit 69
}

# Require the exact serial to be present as one adb devices record. The state is
# retained as evidence and may be device, offline or unauthorized; only an
# absent/ambiguous serial is a bootstrap input error.
MATCH_COUNT=$(printf '%s\n' "$DEVICES" | awk -v serial="$SERIAL" '
  $1 == serial { count += 1 }
  END { print count + 0 }
')
[[ "$MATCH_COUNT" == 1 ]] || {
  echo "exact serial is absent or ambiguous in adb devices -l: $SERIAL" >&2
  exit 66
}

# Parse the local-address column emitted by `ss -ltnH`.  Linux normally
# renders IPv6 endpoints as `[::1]:PORT`, but some builds omit the brackets;
# splitting at the final colon handles both forms.  Keep this deliberately
# strict: an address we cannot parse is not evidence of a safe listener.
listener_is_loopback() {
  local endpoint=$1
  local host
  local port

  if [[ "$endpoint" =~ ^\[([^][]+)\]:([0-9]+)$ ]]; then
    host=${BASH_REMATCH[1]}
    port=${BASH_REMATCH[2]}
  elif [[ "$endpoint" =~ ^(.+):([0-9]+)$ ]]; then
    host=${BASH_REMATCH[1]}
    port=${BASH_REMATCH[2]}
  else
    return 2
  fi

  # Strip a Linux interface scope (for example, `%lo`) before classifying an
  # IPv6 address. `ss -n` emits canonical addresses, so accept the canonical
  # and fully expanded spellings of IPv6 loopback plus IPv4-mapped loopback.
  if [[ "$host" == *%* ]]; then
    host=${host%%\%*}
  fi
  host=${host,,}
  [[ "$port" == "$HOST_PORT" ]] || return 2
  case "$host" in
    127.*|::1|0:0:0:0:0:0:0:1|0000:0000:0000:0000:0000:0000:0000:0001|\
    ::ffff:127.*|0:0:0:0:0:ffff:7f00:*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

require_ss() {
  command -v ss >/dev/null 2>&1 || {
    echo "ss is required to verify the host adb-server listener" >&2
    return 69
  }
}

check_host_listener() {
  require_ss || return $?

  local output
  if ! output=$(ss -ltnH "sport = :$HOST_PORT" 2>&1); then
    echo "host listener probe failed: $output" >&2
    return 69
  fi
  [[ -n "$output" ]] || {
    echo "host adb-server listener is not observable on port $HOST_PORT" >&2
    return 77
  }

  local listener
  local local_address
  local listener_status
  local listener_count=0
  while IFS= read -r listener; do
    [[ -z "${listener//[[:space:]]/}" ]] && continue
    local_address=$(awk 'NF >= 4 { print $4; exit }' <<<"$listener")
    [[ -n "$local_address" ]] || {
      echo "host listener probe returned an unparsable record" >&2
      return 69
    }
    if listener_is_loopback "$local_address"; then
      ((listener_count += 1))
      continue
    else
      listener_status=$?
    fi
    if [[ "$listener_status" -eq 2 ]]; then
      echo "host listener probe returned an unexpected endpoint: $local_address" >&2
      return 69
    fi
    ((listener_count += 1))
    if [[ "$ALLOW_NONLOOPBACK_SERVER" != 1 ]]; then
      echo "host port $HOST_PORT has a non-loopback listener; review and pass --allow-nonloopback-server explicitly" >&2
      return 77
    fi
  done <<<"$output"
  ((listener_count > 0)) || {
    echo "host adb-server listener is not observable on port $HOST_PORT" >&2
    return 77
  }
  HOST_LISTENERS=$output
}

# Start (or attach to) the explicitly selected host server before checking its
# listener.  Checking only before this call misses a server that adb launches
# here and would make the loopback exposure test fail open.
require_ss || exit $?
if ! "$ADB" start-server >/dev/null 2>&1; then
  echo "adb start-server failed" >&2
  exit 69
fi
check_host_listener
REMOTE="tcp:$DEVICE_PORT"
LOCAL="tcp:$HOST_PORT"

case "$MODE" in
  apply)
    # Replace only the exact requested mapping. No target serial is inferred.
    "$ADB" -s "$SERIAL" reverse --remove "$REMOTE" >/dev/null 2>&1 || true
    "$ADB" -s "$SERIAL" reverse "$REMOTE" "$LOCAL"
    ;;
  remove)
    "$ADB" -s "$SERIAL" reverse --remove "$REMOTE"
    ;;
esac

REVERSE_LIST=$("$ADB" -s "$SERIAL" reverse --list 2>&1) || {
  echo "failed to read reverse mapping after $MODE" >&2
  exit 69
}

if [[ "$MODE" == apply ]]; then
  printf '%s\n' "$REVERSE_LIST" | awk -v remote="$REMOTE" -v local="$LOCAL" '
    $2 == remote && $3 == local { found = 1 }
    END { exit(found ? 0 : 1) }
  ' || {
    echo "exact reverse mapping is not observable after apply" >&2
    exit 70
  }
fi

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ADB_SERVER_SOCKET="tcp:127.0.0.1:$DEVICE_PORT"
printf 'ADB_SERVER_SOCKET=%s\n' "$ADB_SERVER_SOCKET"

if [[ -n "$EVIDENCE" ]]; then
  command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required to write JSON evidence" >&2
    exit 69
  }
  evidence_parent=$(dirname -- "$EVIDENCE")
  mkdir -p -- "$evidence_parent"
  tmp=$(mktemp "$evidence_parent/.owner-open-adb-evidence.XXXXXX")
  trap 'rm -f -- "$tmp"' EXIT
  export TIMESTAMP SERIAL MODE DEVICE_PORT HOST_PORT ADB_SERVER_SOCKET
  export ADB_VERSION DEVICES REVERSE_LIST HOST_LISTENERS
  python3 - "$tmp" <<'PY'
import json
import os
from pathlib import Path
import sys

path = Path(sys.argv[1])
value = {
    "schema": "org.trillionnium.owner-open.adb-reverse-bootstrap-evidence.v1",
    "observed_at": os.environ["TIMESTAMP"],
    "serial": os.environ["SERIAL"],
    "mode": os.environ["MODE"],
    "device_loopback_port": int(os.environ["DEVICE_PORT"]),
    "host_adb_server_port": int(os.environ["HOST_PORT"]),
    "adb_server_socket": os.environ["ADB_SERVER_SOCKET"],
    "host_adb_version_raw": os.environ["ADB_VERSION"],
    "devices_raw": os.environ["DEVICES"],
    "reverse_list_raw": os.environ["REVERSE_LIST"],
    "host_listener_raw": os.environ.get("HOST_LISTENERS", ""),
    "integrated_codex_turn_proven": False,
    "physical_effect_proven": False,
    "release_evidence": False,
}
encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
with path.open("w", encoding="utf-8") as handle:
    handle.write(encoded)
    handle.flush()
    os.fsync(handle.fileno())
PY
  chmod 0600 "$tmp"
  mv -f -- "$tmp" "$EVIDENCE"
  if command -v sync >/dev/null 2>&1; then
    sync -f "$EVIDENCE" 2>/dev/null || true
    sync -f "$evidence_parent" 2>/dev/null || true
  fi
  trap - EXIT
fi
