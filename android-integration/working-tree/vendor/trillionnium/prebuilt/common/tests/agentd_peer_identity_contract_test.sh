#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ANDROID_ROOT=$(cd "$(dirname "$0")/../../../../.." && pwd)
AUTHORITY="$ANDROID_ROOT/packages/apps/TrillionniumAiAuthority"
POLICY="$AUTHORITY/src/org/trillionnium/aiauthority/GatewayPeerPolicy.java"
IDENTITY="$AUTHORITY/src/org/trillionnium/aiauthority/GatewayPeerIdentity.java"
GATEWAY="$AUTHORITY/src/org/trillionnium/aiauthority/AgentGatewayServer.java"
PREBUILT_BP="$ANDROID_ROOT/vendor/trillionnium/prebuilt/common/Android.bp"
PRODUCT_MK="$ANDROID_ROOT/vendor/trillionnium/config/common.mk"
WRAPPER="$ANDROID_ROOT/vendor/trillionnium/prebuilt/common/bin/trillionniumd.sh"
ROOTLINUX_RUNNER="$ANDROID_ROOT/vendor/trillionnium/prebuilt/common/bin/trillionnium-root-linux-run.sh"
MANIFEST="$ANDROID_ROOT/vendor/trillionnium/prebuilt/common/linux/manifest.txt"
AGENTD_TE="$ANDROID_ROOT/device/trillionnium/sepolicy/common/private/trillionnium_agentd.te"
AUTHORITY_TE="$ANDROID_ROOT/device/trillionnium/sepolicy/common/private/trillionnium_aiauthority.te"
VERIFIED_TE="$ANDROID_ROOT/device/trillionnium/sepolicy/common/private/trillionnium_verified_data_exec.te"
FILE_CONTEXTS="$ANDROID_ROOT/device/trillionnium/sepolicy/common/private/file_contexts"
FILE_TYPES="$ANDROID_ROOT/device/trillionnium/sepolicy/common/private/file.te"
INIT_RC="$ANDROID_ROOT/vendor/trillionnium/prebuilt/common/etc/init/init.trillionnium-system_ext.rc"
EXTRACTOR="$ANDROID_ROOT/vendor/trillionnium/prebuilt/common/tests/agentd_payload_extract_verify.sh"
RECEIPT_STAGE_MATERIALIZER="$ANDROID_ROOT/vendor/trillionnium/prebuilt/common/tools/trillionnium_receipt_stage_materialize.py"

# Tradefed runs the installed test from an isolated directory.  Resolve the
# explicitly packaged data inputs there instead of depending on a source-tree
# checkout or ANDROID_BUILD_TOP.
if [[ ! -f "$POLICY" ]]; then
    TEST_DIR=$(cd "$(dirname "$0")" && pwd)
    find_one() {
        local name=$1
        local match
        mapfile -t matches < <(find "$TEST_DIR" -type f -name "$name" -print)
        if [[ ${#matches[@]} -ne 1 ]]; then
            echo "expected exactly one packaged peer-identity input named $name" >&2
            exit 1
        fi
        match=${matches[0]}
        printf '%s\n' "$match"
    }
    POLICY=$(find_one GatewayPeerPolicy.java)
    IDENTITY=$(find_one GatewayPeerIdentity.java)
    GATEWAY=$(find_one AgentGatewayServer.java)
    PREBUILT_BP=$(find_one Android.bp)
    PRODUCT_MK=$(find_one common.mk)
    WRAPPER=$(find_one trillionniumd.sh)
    ROOTLINUX_RUNNER=$(find_one trillionnium-root-linux-run.sh)
    MANIFEST=$(find_one manifest.txt)
    AGENTD_TE=$(find_one trillionnium_agentd.te)
    AUTHORITY_TE=$(find_one trillionnium_aiauthority.te)
    VERIFIED_TE=$(find_one trillionnium_verified_data_exec.te)
    FILE_CONTEXTS=$(find_one file_contexts)
    FILE_TYPES=$(find_one file.te)
    INIT_RC=$(find_one init.trillionnium-system_ext.rc)
    EXTRACTOR=$(find_one agentd_payload_extract_verify.sh)
    RECEIPT_STAGE_MATERIALIZER=$(find_one trillionnium_receipt_stage_materialize.py)
fi

python3 - "$POLICY" "$IDENTITY" "$GATEWAY" "$PREBUILT_BP" "$PRODUCT_MK" "$WRAPPER" "$ROOTLINUX_RUNNER" \
    "$MANIFEST" "$AGENTD_TE" "$AUTHORITY_TE" "$VERIFIED_TE" \
    "$FILE_CONTEXTS" "$FILE_TYPES" "$INIT_RC" "$EXTRACTOR" \
    "$RECEIPT_STAGE_MATERIALIZER" <<'PY'
import pathlib
import re
import sys

(
    policy_path,
    identity_path,
    gateway_path,
    prebuilt_bp_path,
    product_mk_path,
    wrapper_path,
    rootlinux_runner_path,
    manifest_path,
    agentd_te_path,
    authority_te_path,
    verified_te_path,
    file_contexts_path,
    file_types_path,
    init_rc_path,
    extractor_path,
    receipt_stage_materializer_path,
) = map(pathlib.Path, sys.argv[1:])

for path in (
    policy_path,
    identity_path,
    gateway_path,
    prebuilt_bp_path,
    product_mk_path,
    wrapper_path,
    rootlinux_runner_path,
    manifest_path,
    agentd_te_path,
    authority_te_path,
    verified_te_path,
    file_contexts_path,
    file_types_path,
    init_rc_path,
    extractor_path,
):
    if not path.is_file():
        raise SystemExit(f"missing peer-identity contract input: {path}")

policy = policy_path.read_text(encoding="utf-8")
identity = identity_path.read_text(encoding="utf-8")
gateway = gateway_path.read_text(encoding="utf-8")
prebuilt_bp = prebuilt_bp_path.read_text(encoding="utf-8")
receipt_stage_materializer = receipt_stage_materializer_path.read_text(
    encoding="utf-8"
)
product_mk = product_mk_path.read_text(encoding="utf-8")
wrapper = wrapper_path.read_text(encoding="utf-8")
rootlinux_runner = rootlinux_runner_path.read_text(encoding="utf-8")
agentd_te = agentd_te_path.read_text(encoding="utf-8")
authority_te = authority_te_path.read_text(encoding="utf-8")
verified_te = verified_te_path.read_text(encoding="utf-8")
file_contexts = file_contexts_path.read_text(encoding="utf-8")
file_types = file_types_path.read_text(encoding="utf-8")
init_rc = init_rc_path.read_text(encoding="utf-8")
extractor = extractor_path.read_text(encoding="utf-8")


def require(condition, reason):
    if not condition:
        raise SystemExit(reason)


def java_string(name):
    match = re.search(rf"\b{name}\s*=\s*\"([^\"]+)\"\s*;", policy, re.DOTALL)
    require(match is not None, f"missing Java peer policy constant: {name}")
    return match.group(1)


def shell_value(name):
    match = re.search(rf"(?m)^{name}=([^\n]+)$", wrapper)
    require(match is not None, f"missing wrapper peer policy constant: {name}")
    value = match.group(1)
    defaulted = re.fullmatch(r"\$\{[A-Z0-9_]+:-([^}]+)\}", value)
    return defaulted.group(1) if defaulted else value


manifest = {}
for line in manifest_path.read_text(encoding="utf-8").splitlines():
    if not line or line.startswith("#"):
        continue
    require("=" in line, "malformed payload manifest line")
    key, value = line.split("=", 1)
    require(key and value and key not in manifest, f"duplicate/empty manifest field: {key}")
    manifest[key] = value

expected_hash = java_string("ENTRYPOINT_SHA256")
expected_epoch = java_string("POLICY_EPOCH")
expected_path = java_string("ENTRYPOINT_PATH")
expected_label = java_string("ENTRYPOINT_SELINUX_LABEL")
expected_domain = java_string("SELINUX_DOMAIN")
require(expected_hash == shell_value("DAEMON_PAYLOAD_SHA256"),
        "Authority/wrapper daemon digest mismatch")
require(expected_hash == manifest.get("agentd_payload_sha256"),
        "Authority/manifest daemon digest mismatch")
require(expected_epoch == shell_value("AGENTD_PEER_IDENTITY_POLICY_EPOCH"),
        "Authority/wrapper peer policy epoch mismatch")
require(expected_epoch == manifest.get("agentd_peer_identity_policy_epoch"),
        "Authority/manifest peer policy epoch mismatch")
require(expected_path == shell_value("DAEMON_SIGNED_SOURCE"),
        "Authority/wrapper signed daemon source mismatch")
require(expected_path == manifest.get("agentd_signed_source"),
        "Authority/manifest signed daemon source mismatch")
require(expected_label == shell_value("DAEMON_PAYLOAD_CONTEXT"),
        "Authority/wrapper daemon label mismatch")
require(expected_label == manifest.get("agentd_payload_selinux_label"),
        "Authority/manifest daemon label mismatch")
require(manifest.get("agentd_payload_owner") == "0:0"
        and manifest.get("agentd_payload_mode") == "0755",
        "manifest daemon owner/mode contract mismatch")
require(expected_domain == "u:r:trillionnium_agentd:s0",
        "Authority accepts an unexpected final daemon domain")

for marker in (
    "SELinux.isSELinuxEnabled()",
    "SELinux.isSELinuxEnforced()",
    "Credentials verified = socket.getPeerCredentials()",
    "SELinux.getPeerContext(fd)",
    "credentials.getPid() != verified.getPid()",
    "GatewayPeerPolicy.SELINUX_DOMAIN.equals(peerContext)",
):
    require(marker in identity, f"missing kernel socket identity marker: {marker}")
require(not re.search(r"/proc/|attr/current|processStartTime|requireStatusCredentials", identity),
        "Authority app identity path still reads non-app /proc")

auth_offset = gateway.find("GatewayPeerIdentity.capture(")
read_offset = gateway.find("reader.readLine()")
require(auth_offset >= 0 and read_offset >= 0 and auth_offset < read_offset,
        "gateway authenticates its peer after reading caller bytes")
require("type trillionnium_agentd_launcher, domain, coredomain;" in agentd_te,
        "short-lived agentd launcher domain is absent")
require(re.search(
    r"domain_auto_trans\(\s*init\s*,\s*trillionnium_agentd_exec\s*,\s*"
    r"trillionnium_agentd_launcher\s*\)", agentd_te, re.DOTALL),
    "init does not enter the launcher domain")
require(re.search(
    r"domain_auto_trans\(\s*trillionnium_agentd_launcher\s*,\s*"
    r"trillionnium_agentd_payload_exec\s*,\s*trillionnium_agentd\s*\)",
    agentd_te, re.DOTALL),
    "exact payload does not enter the final daemon domain")
require(re.search(
    r"allow\s+trillionnium_agentd_launcher\s+trillionnium_agentd:process2\s+"
    r"nosuid_transition\s*;", agentd_te, re.DOTALL),
    "nosuid daemon bind cannot enter the final daemon domain")
require(re.search(
    r"neverallow\s+\{\s*domain\s+-trillionnium_agentd_launcher\s*\}\s+"
    r"trillionnium_agentd:process2\s+\*;", agentd_te, re.DOTALL),
    "foreign domains are not barred from the final daemon process2 edge")
require(re.search(
    r"neverallow\s+trillionnium_agentd_launcher\s+\{\s*domain\s+"
    r"-trillionnium_agentd\s*\}:process2\s+\*;", agentd_te, re.DOTALL),
    "launcher process2 permissions are not confined to the final daemon")
require("init_daemon_domain(trillionnium_agentd)" not in agentd_te,
        "init can bypass the verified launcher-to-payload transition")
require("typeattribute trillionnium_agentd mlstrustedsubject;" in agentd_te
        and "typeattribute trillionnium_agentd_launcher mlstrustedsubject;" not in agentd_te,
        "launcher inherited the final daemon MCS trust")
require("net_domain(trillionnium_agentd_launcher)" not in agentd_te,
        "launcher inherited long-lived network authority")
for target in ("shell_exec", "toolbox_exec", "trillionnium_rootlinux_exec"):
    require(not re.search(
        rf"(?m)^allow\s+trillionnium_agentd\s+{target}:file\s+.*"
        rf"\b(execute|execute_no_trans|rx_file_perms)\b", agentd_te),
        f"product adds a broad final-daemon launcher allow: {target}")
require("platform policy" in agentd_te and "baseline system_file execute" in agentd_te,
        "policy overclaims removal of the coredomain system-file baseline")

require(re.search(
    r"neverallow\s+\{\s*domain\s+-trillionnium_agentd_launcher\s*\}\s+"
    r"trillionnium_agentd:process\s+transition", agentd_te, re.DOTALL),
    "final daemon transition source set is not closed")
require(re.search(
    r"allow\s+trillionnium_agentd\s+trillionnium_codex_agent:process2\s+\{\s*nnp_transition\s+"
    r"nosuid_transition\s*\};", agentd_te, re.DOTALL),
    "Codex NNP/nosuid transition is not authorized exactly")
require(re.search(
    r"neverallow\s+\{\s*domain\s+-trillionnium_agentd\s*\}\s+"
    r"trillionnium_codex_agent:process2\s+"
    r"\*;", agentd_te, re.DOTALL),
    "Codex process2 transition source set is not closed")
require(re.search(
    r"neverallow\s+\{\s*domain\s+-trillionnium_agentd_launcher\s+"
    r"-trillionnium_agentd\s+(?:userdebug_or_eng\(`-overlay_remounter'\)\s+)?"
    r"\}\s+trillionnium_agentd_payload_exec:file\s+"
    r"no_x_file_perms", verified_te, re.DOTALL),
    "payload executable source set is not closed")
require(re.search(
    r"neverallow\s+\{\s*domain\s+-trillionnium_agentd\s*\}\s+"
    r"trillionnium_agentd_payload_exec:file\s+entrypoint", verified_te, re.DOTALL),
    "payload entrypoint target set is not closed")
require(re.search(
    r"neverallow\s+\{\s*domain\s+(?:userdebug_or_eng\(`-overlay_remounter'\)\s+)?"
    r"\}\s+verified_data_exec_type:file\s+\{[^}]*"
    r"append[^}]*write[^}]*\}", verified_te, re.DOTALL),
    "verified payload bytes are mutable while trusted")
require(re.search(
    r"/\(system_ext\|system/system_ext\)/bin/trillionnium-agentd-payload\s+"
    r"u:object_r:trillionnium_agentd_payload_exec:s0", file_contexts),
    "exact system_ext daemon payload file_context binding is absent")
require(not re.search(
    r"/data/trillionnium/root-linux/rootfs/usr/bin/trillionniumd\s+--\s+"
    r"u:object_r:trillionnium_agentd_payload_exec:s0", file_contexts),
    "mutable archive member can acquire the final-domain entrypoint label")
require(re.search(
    r"type\s+trillionnium_agentd_payload_exec\s*,[^;]*\bexec_type\b[^;]*"
    r"\bsystem_file_type\b[^;]*\bverified_data_exec_type\b[^;]*;",
    file_types), "payload type is not an immutable system entrypoint")

source = shell_value("DAEMON_SIGNED_SOURCE")
target = shell_value("DAEMON_PAYLOAD")
unmount_line = f"umount {target}"
restore_line = f"restorecon {target}"
bind_line = f"mount none {source} {target} bind"
remount_line = f"mount none {source} {target} remount bind ro nosuid nodev"


def property_block(expression):
    match = re.search(
        rf"(?ms)^on property:{re.escape(expression)}\n(.*?)(?=^on |^service |\Z)",
        init_rc,
    )
    require(match is not None, f"missing init lifecycle block: {expression}")
    return match.group(1)


prepare = property_block("sys.trillionnium.rootlinux.prepare=1")
require(unmount_line in prepare and restore_line in prepare
        and prepare.index(unmount_line) < prepare.index(restore_line),
        "bootstrap preparation does not unmount and declassify daemon target")
activation = property_block("sys.trillionnium.rootlinux.prepare=0")
for marker in (unmount_line, restore_line, bind_line, remount_line):
    require(marker in activation, f"incomplete daemon bind lifecycle: {marker}")
require(activation.index(unmount_line) < activation.index(restore_line)
        < activation.index(bind_line) < activation.index(remount_line),
        "unsafe daemon bind lifecycle ordering")
require("sys.trillionnium.rootlinux.daemon" not in init_rc,
        "retired manual daemon property remains in production init")

for marker in (
    'name: "trillionnium-agentd-payload-verified"',
    'srcs: ["linux/rootfs-essential-extract.tar.zst"]',
    '"trillionnium-agentd-payload-extract-verify"',
    '$(location trillionnium-agentd-payload-extract-verify)',
    'fa4c321cdc7dd2907c8e5677b902a7f35973bf4e284a43228a611a2dd623c60f',
    expected_hash,
    'name: "trillionnium-agentd-payload"',
    'srcs: [":trillionnium-agentd-payload-verified"]',
    'system_ext_specific: true',
    'check_elf_files: false',
):
    require(marker in prebuilt_bp, f"missing fail-closed system_ext payload module: {marker}")
rootfs_module_match = re.search(
    r'(?ms)^(?:prebuilt_etc|trillionnium_p01_prebuilt_etc)\s*\{\s*'
    r'name:\s*"trillionnium-root-linux-rootfs-essential",'
    r'(?P<body>.*?)^\}',
    prebuilt_bp,
)
require(rootfs_module_match is not None,
        "rootfs archive prebuilt module is absent")
require(re.search(
    r'required:\s*\[\s*"trillionnium-agentd-payload",?\s*\]',
    rootfs_module_match.group("body")),
    "rootfs archive can bypass the verified Direct-ID daemon dependency")
for marker in (
    'sha256sum "$input"',
    "read -r archive_sha256 _",
    'tar -xOf - "$archive_member"',
    'sha256sum "$tmp"',
    "read -r payload_sha256 _",
):
    require(marker in extractor, f"shared payload extractor lacks: {marker}")
require(re.search(r"(?m)^\s*trillionnium-agentd-payload\s*\\$", product_mk),
        "system_ext daemon payload is absent from the product graph")

require("allow trillionnium_agentd trillionnium_aiauthority:unix_stream_socket" in authority_te,
        "final daemon cannot reach Authority")
require("neverallow trillionnium_agentd_launcher trillionnium_aiauthority:unix_stream_socket connectto;"
        in authority_te, "launcher can impersonate the final Authority peer")
require(not re.search(
    r"(?m)^allow\s+trillionnium_agentd_launcher\s+"
    r"trillionnium_aiauthority:unix_stream_socket", authority_te),
    "launcher has an explicit Authority gateway allow")
require(re.search(
    r"allow\s+trillionnium_agentd_launcher\s+\{\s*"
    r"trillionnium_codex_agent_exec\s+"
    r"trillionnium_agent_system_api_exec\s+"
    r"trillionnium_agent_accessibility_exec\s+"
    r"trillionnium_agent_adb_exec\s+"
    r"trillionnium_agent_shell_exec\s+"
    r"trillionnium_agent_system_api_operation_replay_sync_exec\s*\}"
    r":file\s+r_file_perms;", agentd_te),
    "launcher cannot read the exact signed provider/tool entrypoint closure")
require(re.search(
    r"neverallow\s+trillionnium_agentd_launcher\s+\{\s*"
    r"trillionnium_codex_agent_exec\s+"
    r"trillionnium_agent_system_api_exec\s+"
    r"trillionnium_agent_accessibility_exec\s+"
    r"trillionnium_agent_adb_exec\s+"
    r"trillionnium_agent_shell_exec\s+"
    r"trillionnium_agent_system_api_operation_replay_sync_exec\s*\}"
    r":file\s+\{\s*entrypoint\s+execute\s+execute_no_trans\s*\};",
    agentd_te),
    "launcher Codex/tool read boundary does not explicitly forbid execution")
require(re.search(
    r"allow\s+trillionnium_agentd_launcher\s+"
    r"trillionnium_direct_tool_call_allocator_file:dir\s+"
    r"\{\s*getattr\s+search\s*\};",
    agentd_te),
    "launcher cannot authenticate allocator directory metadata")
require(re.search(
    r"neverallow\s+trillionnium_agentd_launcher\s+\{[^}]*"
    r"trillionnium_direct_tool_call_allocator_file[^}]*\}:dir\s+"
    r"\{[^}]*create[^}]*write[^}]*\};",
    agentd_te, re.S),
    "launcher allocator metadata boundary does not forbid directory writes")
require("allow trillionnium_agentd trillionnium_agentd_launcher:fd use;" in agentd_te,
        "final daemon cannot consume the exact launcher-owned ELF descriptor")
require(re.search(
    r"neverallow\s+\{\s*domain\s+-trillionnium_agentd\s+"
    r"-trillionnium_agentd_launcher\s+-crash_dump\s+-heapprofd\s+"
    r"-mediaprovider_app\s+-tombstoned\s+-traced_perf\s*\}\s+"
    r"trillionnium_agentd_launcher:fd\s+use;", agentd_te),
    "launcher-owned descriptors are not closed beyond platform diagnostics")

verify_offset = wrapper.find(
    'verify_data_exec "$DAEMON_PAYLOAD" "$DAEMON_PAYLOAD_SHA256" 755')
bind_verify_offset = wrapper.find(
    'verify_signed_bind "$DAEMON_SIGNED_SOURCE" "$DAEMON_PAYLOAD"')
manifest_offset = wrapper.find("verify_runtime_manifest_binding ||")
exec_offset = wrapper.rfind('exec /system_ext/bin/trillionnium-root-linux-run')
require(0 <= bind_verify_offset < verify_offset < exec_offset
        and 0 <= manifest_offset < exec_offset,
        "wrapper can enter the payload before digest/manifest verification")
require("manifest_value agentd_peer_identity_policy_epoch" in wrapper,
        "wrapper does not authenticate the peer policy epoch in the signed manifest")
require(
    "export TRILLIONNIUM_AGENT_API_SOCKET=/run/trillionnium/agent-api-v2.sock" in wrapper,
    "wrapper does not pin the no-fallback Agent API UDS v2 socket",
)
require("agent-api-v1.sock" not in wrapper,
        "wrapper retains the incompatible Agent API UDS v1 socket")
for marker in (
    "stat -c '%d:%i' \"$source\"",
    "stat -c '%d:%i' \"$target\"",
    "stat -c '%u:%g' \"$source\"",
    "stat -c '%u:%g' \"$target\"",
    "stat -c '%a' \"$source\"",
    "stat -c '%a' \"$target\"",
    "stat -c '%C' \"$source\"",
    "stat -c '%C' \"$target\"",
    'sha256sum "$source"',
    'sha256sum "$target"',
):
    require(marker in wrapper, f"daemon bind verifier lacks exact pair check: {marker}")
require('[ -f "$source" ] || return 1' in wrapper,
        "daemon bind verifier does not require a regular signed source")
require('[ -x "$source" ]' not in wrapper,
        "launcher verifier probes provider execute permission before transition")
require('[ -x "${ROOTFS}/bin/sh" ]' not in rootlinux_runner,
        "root-linux runner probes shell execute permission in the launcher domain")
require("stat -c '%u:%g' \"$source\")\" = \"0:2000\"" in wrapper,
        "daemon bind verifier does not pin the system_ext root:shell owner")
require('expected_owner="${5:-0:0}"' in wrapper,
        "generic data verifier lacks a fail-closed default owner")
require(re.search(
    r'verify_data_exec\s+"\$DAEMON_PAYLOAD"\s+"\$DAEMON_PAYLOAD_SHA256"\s+'
    r'755\s+\\\s*"\$DAEMON_PAYLOAD_CONTEXT"\s+0:2000\s+\|\|', wrapper),
    "daemon payload verifier does not require the system_ext root:shell owner")
require('manifest_value agentd_payload_owner)" = "0:2000"' in wrapper,
        "wrapper manifest binding does not pin the system_ext root:shell owner")
require('"agentd_payload_owner": "0:2000"' in receipt_stage_materializer,
        "P01 manifest derivation does not record the system_ext root:shell owner")

print("PASS: exact system_ext agentd identity source contract; artifact/device HOLD")
PY
