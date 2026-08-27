#!/system/bin/sh
#
# Materialize the built-in Trillionnium root Linux payload from read-only
# system_ext archives into /data. This is intentionally idempotent and manual:
# start it through init or run it as root when the operator wants the payload
# prepared.

set -eu
umask 077

ARCHIVE_DIR="${TRILLIONNIUM_ROOT_LINUX_ARCHIVE_DIR:-/system_ext/etc/trillionnium/linux}"
DATA_DIR="${TRILLIONNIUM_ROOT_LINUX_DATA_DIR:-/data/trillionnium/root-linux}"
ROOTFS="${TRILLIONNIUM_ROOT_LINUX_ROOTFS:-${DATA_DIR}/rootfs}"
STAGING="${DATA_DIR}/.staging"
ROOTFS_BACKUP="${DATA_DIR}/rootfs.previous"
STAMP="${DATA_DIR}/stamp"
STAMP_TMP="${DATA_DIR}/stamp.staging"
STAMP_BACKUP="${DATA_DIR}/stamp.previous"
LOG_FILE="${DATA_DIR}/bootstrap.log"
LOCK_FILE="${DATA_DIR}/.bootstrap.lock"
AGENT_PROVISION_DIR="${TRILLIONNIUM_AGENT_PROVISION_DIR:-/data/trillionnium/agent-provision}"
CODEX_AUTH_INBOX="${AGENT_PROVISION_DIR}/codex-auth.json"
SIGNED_AGENT_MANIFEST_DIR="${TRILLIONNIUM_SIGNED_AGENT_MANIFEST_DIR:-/system_ext/etc/trillionnium/agents}"
CODEX_AGENT_MANIFEST="${SIGNED_AGENT_MANIFEST_DIR}/agent-codex-direct-v1.json"
STATE_CONTEXT_MAX_BYTES=134217728
STATE_REPLAY_MAX_BYTES=67108864
STATE_AUDIT_MAX_BYTES=134217728
STATE_HIGH_WATER_MAX_BYTES=4194304
STATE_MAX_FILES=5000
STAGED_CODEX_INBOX=0
CURRENT_SOURCES_VERIFIED=0
PAYLOAD_CONTRACT_BRANCH=legacy_v6

ROOTFS_ARCHIVE="${ARCHIVE_DIR}/rootfs-essential-extract.tar.zst"
ROOTFS_PACKAGE_CONTRACT="${ARCHIVE_DIR}/rootfs-contract.v6.json"
ROOTFS_PACKAGE_RECEIPT="${ARCHIVE_DIR}/trillionnium-rootfs-codex-v6.receipt.json"
ROOTFS_COMMON_ARTIFACT_SET="${ARCHIVE_DIR}/common-codex-rootfs-artifact-set.v2.json"
ROOTFS_FRESH_BASE_RECEIPT="${ARCHIVE_DIR}/minimal-bookworm-arm64.receipt.json"
ROOTFS_FRESH_BASE_SBOM="${ARCHIVE_DIR}/minimal-bookworm-arm64.spdx.json"
ROOTFS_PACKAGE_CONTRACT_SHA256=9843127fdcd1bca761e3ce42f87dc1fa89ba12875a8410b37e22016d5dc7873b
ROOTFS_PACKAGE_RECEIPT_SHA256=4c57daa0d9d2c180e712eb2ad94996d835b15742c7cc699cdc49d803d788d96e
ROOTFS_COMMON_ARTIFACT_SET_SHA256=012c3bfcd67ce0ba64c2e1852a99bd5240ac2aef28c3c10c41dd507cc8250c9e
ROOTFS_FRESH_BASE_RECEIPT_SHA256=a1777fbc37ca7bf83333e67f0ec8042726c1c5d7933998f1fda56e68124edaa5
ROOTFS_FRESH_BASE_SBOM_SHA256=93662fa0447fa1ddfd192f3bae79db05d21eb09c34a07deb9acecc984070fe36
ROOTFS_FRESH_BASE_RECEIPT_BYTES=""
ROOTFS_FRESH_BASE_SBOM_BYTES=""
ROOTFS_DPKG_PACKAGE_COUNT=35
ROOTFS_DPKG_STATUS_SHA256=8460a2d43ad922776b001caae5ee42547ccb4c92a8f198bfda4356d53cc63f66
ROOTFS_ARCHIVE_DIRECTORY_COUNT=265
ROOTFS_ARCHIVE_PAYLOAD_DIRECTORY_MODE=0555
ROOTFS_ARCHIVE_DAEMON_SHA256=c6065d4be5dc4815f37cb9064dc846ca7d58b65f0fceaca1641459b7b120937f
ROOTFS_ARCHIVE_REPLAY_SYNC_SHA256=44acea820d7ce25684bd461c4a6cfdb94f84862e73321068cd58a204aa02bbd3
ROOTFS_ARCHIVE_SYSTEM_API_SHA256=43aa395ef79f172b7dd07d938d6f03fa7f5e84e92be78d1f7b79c097428510b1
ROOTFS_ARCHIVE_ACCESSIBILITY_SHA256=983e8ccb571c909a4bda4db58da70af0ef7118c6c89d4cd27c6c8f0adb168e8c
ROOTFS_ARCHIVE_CODEX_LAUNCHER_SHA256=edcf9d31da8b48d29575115a7242691c1337174edf42573b7274b652a4cd571c
ROOTFS_ARCHIVE_AGENT_MANIFEST_SHA256=fb6e2b53f1c08e95aa8f860c60d70b2c21e8ac565faa0dd1f52233485ac69f80
ROOTFS_RAW_TAR_SHA256=e21ff00db1353c812c151a6555f9e2d66012cc0f5c7fd37ebc893d40eaf627d0
ROOTFS_FILTERED_TAR_SHA256=0b692358b1099e2165a92ce3cdbd9d0be318f719ac77312af499a241882cec0b
ROOTFS_RAW_TAR_SIZE=70676480
ROOTFS_FILTERED_TAR_SIZE=70676480
ROOTFS_ARCHIVE_BYTES=""
ROOTFS_TAR_STAGING_FILTER_SCHEMA=org.trillionnium.rootfs-tar-staging-filter.v1
ROOTFS_TAR_STAGING_FILTER_SOURCE_SHA256=dc48c9ce97f1e64a62e45d00350b44801adb7cc0f60f8666b1d5e87696ce6092
ROOTFS_EMPTY_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
ROOTFS_APT_SOURCES_SHA256=122e34d08b2e72fb1160d6fda02157bf07c25d42ef714cba66782e0437c069bb
ROOTFS_PASSWD_SHA256=461a76b6b52e84fe0b2939fb0a1e7f95eb146a5802ae6993faf8bcdac7233a9b
ROOTFS_GROUP_SHA256=0cc1a09e6a22f2c31ef0279e880f5e53bfb9fc86eb4a57fa8bfcbcd6ad72fc41
ROOTFS_NSSWITCH_SHA256=eec30745bade42a3f3f792e4d4192e57d2bcfe8e472433b1de426fe39a39cddb
ROOTFS_SHELLS_SHA256=c98472a3b09dd76183f945ce25393c5bc6fc84509fbb50ae6aa99b6cd0a5909d
ROOTFS_RESOLV_CONF_SHA256=6e0022b6503dab3e5b1e4af99eec3cf7e24bbf7629a3736f137b249bc65e50ce
ROOTFS_HOSTS_SHA256=b876a0bbaf79de9251f3a3fe579089941661875e453c2a2d1d21c58738680ed7
ROOTFS_SHADOW_SHA256=86effed0fd79c2ec9130d2c8227f05f33196f5eb81c56832c60ef1524b01833f
ROOTFS_GSHADOW_SHA256=0c914338e0b2f66bbffa079f9cad744943bb01aba477c8ec56cb4d4aff9a82f2
ROOTFS_POLICY_RC_D_SHA256=c2bcd9decf63ff2c0d9f473f38bc3607900530aad80f99139855d56678456230
CODEX_INTEGRITY_LAUNCHER_SHA256="${TRILLIONNIUM_CODEX_INTEGRITY_LAUNCHER_SHA256:-edcf9d31da8b48d29575115a7242691c1337174edf42573b7274b652a4cd571c}"
P01_AGENTD_SOURCE="${TRILLIONNIUM_P01_AGENTD_SOURCE:-/system_ext/etc/trillionnium/p01-userdebug/trillionnium-agentd-materialization}"
P01_AGENTD_SHA256=""
CODEX_RUNTIME_ROOTFS_PATH="usr/lib/trillionnium/agents/codex/0.144.1/aarch64-unknown-linux-musl/bin/codex.real"
BOOTSTRAP_LAYOUT_VERSION="essential-codex-v2-headless-immutable-agentd-runtime"
MANIFEST_FILE="${ARCHIVE_DIR}/manifest.txt"
SYSTEM_MANIFEST_FILE="${TRILLIONNIUM_ROOT_LINUX_SYSTEM_MANIFEST_FILE:-/system_ext/etc/trillionnium/linux/manifest.txt}"
ROOTFS_SHA256_FALLBACK="fa4c321cdc7dd2907c8e5677b902a7f35973bf4e284a43228a611a2dd623c60f"
USERDEBUG_ROOTFS_PACKAGE_CONTRACT_SCHEMA=org.trillionnium.rootfs-package.contract.v9
USERDEBUG_ROOTFS_PACKAGE_RECEIPT_SCHEMA=org.trillionnium.rootfs-package.receipt.v9
USERDEBUG_ROOTFS_COMMON_ARTIFACT_SET_SCHEMA=org.trillionnium.common-codex-rootfs-artifact-set.v5
USERDEBUG_ROOTFS_PACKAGE_CONTRACT_PATH=/system_ext/etc/trillionnium/linux/rootfs-package.contract.v9.json
USERDEBUG_ROOTFS_PACKAGE_RECEIPT_PATH=/system_ext/etc/trillionnium/linux/rootfs-package-receipt.json
USERDEBUG_ROOTFS_COMMON_ARTIFACT_SET_PATH=/system_ext/etc/trillionnium/linux/common-codex-rootfs-artifact-set.v5.json
USERDEBUG_ROOTFS_FRESH_BASE_RECEIPT_SCHEMA=org.trillionnium.root-linux.minimal-bookworm-receipt.v1
USERDEBUG_ROOTFS_FRESH_BASE_SBOM_SCHEMA=SPDX-2.3
USERDEBUG_ROOTFS_FRESH_BASE_RECEIPT_PATH=/system_ext/etc/trillionnium/linux/minimal-bookworm-arm64.receipt.json
USERDEBUG_ROOTFS_FRESH_BASE_SBOM_PATH=/system_ext/etc/trillionnium/linux/minimal-bookworm-arm64.spdx.json
USERDEBUG_RECEIPT_STAGE_SCHEMA=org.trillionnium.android.receipt-stage.v1
USERDEBUG_RECEIPT_STAGE_PATH=/system_ext/etc/trillionnium/p01-userdebug/receipt-stage.v1.json
USERDEBUG_RECEIPT_STAGE_CUSTODY_PATH=/system_ext/etc/trillionnium/p01-userdebug/receipt-stage-custody.v1.json

TOYBOX="${TRILLIONNIUM_ROOT_LINUX_TOYBOX:-/system/bin/toybox}"
# Android's toybox build intentionally does not carry the awk applet on this
# product.  Keep the parser pinned to the standalone system binary instead of
# invoking `toybox awk` (which silently turned a valid manifest into the
# generic "malformed" error during early boot).  The override is used only by
# host-side contract tests; the init service uses the immutable /system path.
AWK="${TRILLIONNIUM_ROOT_LINUX_AWK:-/system/bin/awk}"
ZSTD="${TRILLIONNIUM_ROOT_LINUX_ZSTD:-/system_ext/bin/zstd}"
TAR_STAGING_FILTER="${TRILLIONNIUM_ROOT_LINUX_TAR_STAGING_FILTER:-/system_ext/bin/trillionnium_rootfs_tar_staging_filter}"
TAR_STAGING_FILTER_IDENTITY="${TRILLIONNIUM_ROOT_LINUX_TAR_STAGING_FILTER_IDENTITY:-${ARCHIVE_DIR}/rootfs-tar-staging-filter.identity.v1}"
CHCON="${TRILLIONNIUM_ROOT_LINUX_CHCON:-}"
GENERIC_ROOTFS_CONTEXT=u:object_r:trillionnium_rootlinux_data_file:s0
CURRENT_STEP="script_init"

log() {
    /system/bin/log -t trillionnium_root_linux "$*" 2>/dev/null || true
    echo "$*"
}

set_step() {
    CURRENT_STEP="$1"
    log "step: $CURRENT_STEP"
}

on_exit() {
    rc="$?"
    if [ "$rc" -ne 0 ]; then
        set +e
        # Do not guess at rollback from process-local flags.  SIGKILL or power
        # loss cannot run this trap, so every publish edge is represented by
        # fixed on-disk slots and reconciled under the next process's lock.
        # Preserving those slots also prevents an error path from deleting the
        # only copy of migrated allowlisted state.
        log "transaction artifacts preserved for locked restart reconciliation"
        log "ERROR: bootstrap aborted rc=$rc step=${CURRENT_STEP:-unknown}"
    fi
}

trap on_exit EXIT

fail() {
    log "ERROR: $*"
    exit 1
}

sha256() {
    sum_line="$("$TOYBOX" sha256sum "$1")"
    set -- $sum_line
    echo "$1"
}

verify_installed_agent_manifest() {
    root="$1"
    name="$2"
    expected_identity="$3"
    source="${SIGNED_AGENT_MANIFEST_DIR}/${name}"
    target="${root}/etc/trillionnium/agents/${name}"
    [ -f "$source" ] && [ ! -L "$source" ] || return 1
    [ -f "$target" ] && [ ! -L "$target" ] || return 1
    [ "$($TOYBOX stat -c '%u:%g:%a' "$target")" = "0:0:444" ] || return 1
    [ "$(sha256 "$source")" = "$(sha256 "$target")" ] || return 1
    identity_pattern="\"identity_key_sha256\": \"${expected_identity}\""
    [ "$($TOYBOX grep -F -c "$identity_pattern" "$source")" = 1 ] &&
        [ "$($TOYBOX grep -F -c "$identity_pattern" "$target")" = 1 ]
}

verify_installed_agent_manifests() {
    verify_installed_agent_manifest "$1" agent-codex-direct-v1.json \
        "$CODEX_INTEGRITY_LAUNCHER_SHA256"
}

verify_agentd_direct_identity() {
    root="$1"
    daemon="${root}/usr/bin/trillionniumd"
    [ -f "$daemon" ] && [ ! -L "$daemon" ] || return 1
    "$TOYBOX" grep -a -F -q agent-codex-direct-v1 "$daemon"
}

verify_rootfs_regular() {
    local path="$1"
    local expected_sha256="$2"
    local expected_mode="$3"
    local expected_owner="${4:-0:0}"
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    [ "$($TOYBOX stat -c '%u:%g:%a' "$path")" = \
        "${expected_owner}:${expected_mode}" ] || return 1
    [ "$(sha256 "$path")" = "$expected_sha256" ]
}

verify_rootfs_directory() {
    local path="$1"
    local expected_mode="$2"
    local expected_owner="${3:-0:0}"
    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    [ "$("$TOYBOX" stat -c '%u:%g:%a' "$path")" = \
        "${expected_owner}:${expected_mode}" ]
}

prepare_agent_direct_tool_targets() {
    root="$1"
    verify_rootfs_directory "${root}/usr/local" 555 ||
        fail "archive-owned /usr/local directory is missing or changed"
    verify_rootfs_directory "${root}/usr/local/bin" 555 ||
        fail "archive-owned /usr/local/bin directory is missing or changed"
    verify_rootfs_regular \
        "${root}/usr/local/bin/trillionnium-agent-system-api" \
        "$ROOTFS_ARCHIVE_SYSTEM_API_SHA256" 555 ||
        fail "archive-owned System API tool is missing or changed"
    verify_rootfs_regular \
        "${root}/usr/local/bin/trillionnium-agent-accessibility" \
        "$ROOTFS_ARCHIVE_ACCESSIBILITY_SHA256" 555 ||
        fail "archive-owned Accessibility tool is missing or changed"
    materialize_adb_bind_placeholder "$root"
}

prepare_codex_runtime_target() {
    root="$1"
    for relative in \
        usr/lib/trillionnium \
        usr/lib/trillionnium/agents \
        usr/lib/trillionnium/agents/codex \
        usr/lib/trillionnium/agents/codex/0.144.1 \
        usr/lib/trillionnium/agents/codex/0.144.1/aarch64-unknown-linux-musl \
        usr/lib/trillionnium/agents/codex/0.144.1/aarch64-unknown-linux-musl/bin; do
        verify_rootfs_directory "${root}/${relative}" 555 ||
            fail "archive-owned Codex runtime directory is missing or changed: /$relative"
    done
    target="${root}/${CODEX_RUNTIME_ROOTFS_PATH}"
    verify_rootfs_regular "$target" "$ROOTFS_EMPTY_SHA256" 555 &&
        [ "$($TOYBOX stat -c %s "$target")" = 0 ] ||
        fail "archive-owned Codex runtime bind placeholder is missing or changed"
}

install_signed_agent_manifests() {
    root="$1"
    target_dir="${root}/etc/trillionnium/agents"
    for relative in etc etc/trillionnium etc/trillionnium/agents; do
        verify_rootfs_directory "${root}/${relative}" 555 ||
            fail "archive AgentManifest directory is missing or changed: /$relative"
    done
    for source in "$CODEX_AGENT_MANIFEST"; do
        [ -f "$source" ] && [ ! -L "$source" ] ||
            fail "signed AgentManifest missing or unsafe: $source"
        name="${source##*/}"
        target="${target_dir}/${name}"
        [ -f "$target" ] && [ ! -L "$target" ] ||
            fail "archive AgentManifest target is missing or unsafe: $name"
        if [ "$(sha256 "$source")" != "$(sha256 "$target")" ]; then
            [ -n "$P01_AGENTD_SHA256" ] ||
                fail "common archive AgentManifest differs from signed source: $name"
            require_staging_in_place_overlay_target "$target"
            chmod 0600 "$target" ||
                fail "cannot thaw P01 AgentManifest target: $name"
            "$TOYBOX" cp "$source" "$target" ||
                fail "cannot overlay P01 signed AgentManifest: $name"
            test_kill_after_boundary materialize.p01_manifest.overlay
            chown 0:0 "$target" || fail "cannot own signed AgentManifest: $name"
            chmod 0444 "$target" || fail "cannot freeze signed AgentManifest: $name"
            fsync_path "$target" materialize.p01_manifest.file_fsync
        fi
    done
    [ "$($TOYBOX stat -c '%u:%g:%a' "$target_dir")" = "0:0:555" ] ||
        fail "archive AgentManifest directory is not immutable"
    verify_installed_agent_manifests "$root" ||
        fail "installed AgentManifests do not match signed system sources"
}

sync_filesystems() {
    if "$TOYBOX" sync 2>/dev/null; then
        return 0
    fi
    sync || fail "filesystem sync unavailable"
}

publish_rootlinux_prepare_complete() {
    local property=sys.trillionnium.rootlinux.prepare
    local expected=0
    local attempt=1
    local max_attempts=5
    local observed=""

    set_step "publish prepared Root Linux property"
    while [ "$attempt" -le "$max_attempts" ]; do
        if setprop "$property" "$expected" 2>/dev/null; then
            observed="$(getprop "$property" 2>/dev/null)" || observed=""
            if [ "$observed" = "$expected" ]; then
                log "published and read back ${property}=${expected}"
                return 0
            fi
        else
            observed=""
        fi

        log "prepare property publish attempt ${attempt}/${max_attempts} failed: observed=${observed:-unavailable}"
        if [ "$attempt" -lt "$max_attempts" ]; then
            "$TOYBOX" sleep 1 || fail "cannot wait before retrying prepare property publication"
        fi
        attempt=$((attempt + 1))
    done

    fail "cannot publish and read back ${property}=${expected} after ${max_attempts} attempts"
}

test_kill_after_boundary() {
    local boundary="$1"
    local requested="${TRILLIONNIUM_BOOTSTRAP_TEST_KILL_AFTER:-}"
    [ -n "$requested" ] || return 0
    case "$DATA_DIR" in
        /tmp/trillionnium-bootstrap-transaction-test.*/*|\
        /data/local/tmp/trillionnium-bootstrap-transaction-test.*/*) ;;
        *) fail "test fault injection is restricted to a dedicated test directory" ;;
    esac
    [ "$requested" = "$boundary" ] || return 0
    log "TEST: killing bootstrap after durable boundary: $boundary"
    kill -KILL "$$"
    # SIGKILL cannot return, but keep a fail-closed guard for unusual shells.
    exit 137
}

path_parent() {
    local path="$1"
    local parent="${path%/*}"
    [ "$parent" != "$path" ] || parent=.
    [ -n "$parent" ] || parent=/
    echo "$parent"
}

fsync_path() {
    local path="$1"
    local boundary="$2"
    local help
    [ -e "$path" ] && [ ! -L "$path" ] || fail "cannot fsync unsafe path: $path"
    if ! "$TOYBOX" fsync "$path" 2>/dev/null; then
        # The Android/device toybox always has fsync.  The host-only toybox
        # used by migration unit tests does not; permit only that missing-
        # applet case to fall back to a stronger whole-filesystem sync.
        help="$("$TOYBOX" fsync --help 2>&1 || true)"
        case "$help" in
            *"Unknown command fsync"*) sync_filesystems ;;
            *) fail "fsync failed for $path" ;;
        esac
    fi
    test_kill_after_boundary "$boundary"
}

fsync_open_descriptor() {
    local descriptor="$1"
    local boundary="$2"
    local help sync_failed=0
    # This primitive is deliberately not a general fd/path escape hatch. The
    # credential file or home directory is opened while root-owned, then its
    # exact fd is inherited as stdin by toybox fsync so the post-chown inode
    # can be flushed without a DAC-gated path reopen.
    case "${descriptor}:${boundary}" in
        8:state.codex_home.chown)
            "$TOYBOX" fsync - <&8 2>/dev/null || sync_failed=1
            ;;
        9:state.codex_auth.chown)
            "$TOYBOX" fsync - <&9 2>/dev/null || sync_failed=1
            ;;
        *) fail "open-descriptor fsync is outside the credential transfer allowlist" ;;
    esac
    if [ "$sync_failed" = 1 ]; then
        help="$($TOYBOX fsync --help 2>&1 || true)"
        case "$help" in
            *"Unknown command fsync"*) sync_filesystems ;;
            *) fail "fsync failed for a staged Codex ownership-transfer descriptor" ;;
        esac
    fi
    test_kill_after_boundary "$boundary"
}

require_staging_rootfs_path() {
    local root="$1"
    [ "$root" = "${STAGING}/rootfs" ] ||
        fail "staging mutation attempted outside the unpublished rootfs"
    [ -d "$root" ] && [ ! -L "$root" ] ||
        fail "staging rootfs is missing or unsafe"
}

require_staging_in_place_overlay_target() {
    local target="$1"
    require_staging_rootfs_path "${STAGING}/rootfs"
    case "$target" in
        "${STAGING}/rootfs/usr/bin/trillionniumd"|\
        "${STAGING}/rootfs/etc/trillionnium/agents/agent-codex-direct-v1.json") ;;
        *) fail "staging file is outside the exact in-place overlay allowlist: $target" ;;
    esac
    [ -f "$target" ] && [ ! -L "$target" ] &&
        [ "$($TOYBOX stat -c '%u:%g:%h' "$target")" = "0:0:1" ] ||
        fail "in-place overlay target inode is unsafe: $target"
}

staging_test_owner() {
    if [ "${TRILLIONNIUM_BOOTSTRAP_ADB_PLACEHOLDER_TEST_ONLY:-0}" = 1 ]; then
        case "$DATA_DIR" in
            /tmp/trillionnium-bootstrap-transaction-test.*/*) ;;
            *) fail "ADB placeholder test owner is restricted to a dedicated test directory" ;;
        esac
        echo "${TRILLIONNIUM_BOOTSTRAP_TEST_EXPECTED_UID:-0}:${TRILLIONNIUM_BOOTSTRAP_TEST_EXPECTED_GID:-0}"
    else
        echo 0:0
    fi
}

create_staging_regular_no_replace() {
    local target="$1"
    local expected_mode="$2"
    local expected_uid="$3"
    local expected_gid="$4"
    local boundary="$5"
    local content_kind="$6"
    shift 6
    local parent source_dir source name expected_sha expected_size

    ensure_in_staging_rootfs "$target"
    parent="$(path_parent "$target")"
    ensure_in_staging_rootfs "$parent"
    [ -d "$parent" ] && [ ! -L "$parent" ] ||
        fail "no-replace target parent is missing or unsafe: $parent"
    [ ! -e "$target" ] && [ ! -L "$target" ] ||
        fail "no-replace target already exists: $target"
    name="${target##*/}"
    case "$name" in
        ''|.|..|*/*) fail "invalid no-replace target basename" ;;
    esac
    source_dir="${STAGING}/.no-replace-${boundary}.$$"
    [ ! -e "$source_dir" ] && [ ! -L "$source_dir" ] ||
        fail "no-replace source directory already exists"
    mkdir "$source_dir" || fail "cannot create private no-replace source directory"
    chmod 0700 "$source_dir" || fail "cannot secure no-replace source directory"
    source="${source_dir}/${name}"
    case "$content_kind" in
        empty) : >"$source" ;;
        lines) printf '%s\n' "$@" >"$source" ;;
        *) fail "invalid no-replace content kind" ;;
    esac
    chown "${expected_uid}:${expected_gid}" "$source" ||
        fail "cannot own no-replace source: $name"
    chmod "0${expected_mode}" "$source" ||
        fail "cannot freeze no-replace source: $name"
    expected_sha="$(sha256 "$source")"
    expected_size="$($TOYBOX stat -c %s "$source")"

    # Toybox cpio's regular-file extractor uses
    # O_CREAT|O_WRONLY|O_EXCL|O_NOFOLLOW. Copy-pass therefore gives the shell
    # materializer a no-replace/no-follow creation primitive without granting
    # DAC_OVERRIDE or exposing a writable live-rootfs directory.
    (
        cd "$source_dir"
        printf '%s\n' "$name" | "$TOYBOX" cpio -p "$parent" >/dev/null
    ) || fail "cannot publish no-replace staging file: $target"
    test_kill_after_boundary "${boundary}.file_created"
    # Copy-pass honors the process umask when it creates the O_EXCL target.
    # Converge the already no-follow/no-replace inode to its exact reviewed
    # metadata before measuring or syncing it; CHOWN+FOWNER are sufficient.
    chown "${expected_uid}:${expected_gid}" "$target" ||
        fail "cannot own published no-replace staging file: $target"
    chmod "0${expected_mode}" "$target" ||
        fail "cannot freeze published no-replace staging file: $target"
    verify_rootfs_regular "$target" "$expected_sha" "$expected_mode" \
        "${expected_uid}:${expected_gid}" &&
        [ "$($TOYBOX stat -c %s "$target")" = "$expected_size" ] &&
        [ "$($TOYBOX stat -c %h "$target")" = 1 ] ||
        fail "published no-replace staging file differs: $target"
    fsync_path "$target" "${boundary}.file_fsync"
    fsync_path "$parent" "${boundary}.parent_fsync"
    rm -f "$source" || fail "cannot remove no-replace source: $name"
    rmdir "$source_dir" || fail "cannot remove no-replace source directory"
}

thaw_staging_directory() {
    local root="$1"
    local relative="$2"
    local boundary="$3"
    local path="${root}/${relative}"
    local expected_owner
    require_staging_rootfs_path "$root"
    case "$relative" in
        etc|usr/sbin|usr/local/bin) ;;
        *) fail "staging directory is outside the exact thaw allowlist: /$relative" ;;
    esac
    ensure_in_staging_rootfs "$path"
    expected_owner="$(staging_test_owner)"
    [ -d "$path" ] && [ ! -L "$path" ] &&
        [ "$($TOYBOX stat -c '%u:%g:%a' "$path")" = "${expected_owner}:555" ] ||
        fail "immutable staging directory cannot be thawed: /$relative"
    chmod 0755 "$path" || fail "cannot thaw staging directory: /$relative"
    [ "$($TOYBOX stat -c '%u:%g:%a' "$path")" = "${expected_owner}:755" ] ||
        fail "staging directory thaw did not take effect: /$relative"
    fsync_path "$path" "${boundary}.parent_thawed"
}

refreeze_staging_directory() {
    local root="$1"
    local relative="$2"
    local boundary="$3"
    local path="${root}/${relative}"
    local expected_owner
    require_staging_rootfs_path "$root"
    case "$relative" in
        etc|usr/sbin|usr/local/bin) ;;
        *) fail "staging directory is outside the exact refreeze allowlist: /$relative" ;;
    esac
    ensure_in_staging_rootfs "$path"
    expected_owner="$(staging_test_owner)"
    [ -d "$path" ] && [ ! -L "$path" ] &&
        [ "$($TOYBOX stat -c '%u:%g:%a' "$path")" = "${expected_owner}:755" ] ||
        fail "staging directory is outside the exact thaw contract: /$relative"
    chmod 0555 "$path" || fail "cannot refreeze staging directory: /$relative"
    [ "$($TOYBOX stat -c '%u:%g:%a' "$path")" = "${expected_owner}:555" ] ||
        fail "staging directory refreeze did not take effect: /$relative"
    test_kill_after_boundary "${boundary}.parent_refrozen"
    fsync_path "$path" "${boundary}.parent_refreeze_fsync"
}

fresh_v2_adb_placeholder_layout_matches() {
    local root="$1"
    local parent="${root}/usr/local/bin"
    local target="${parent}/trillionnium-agent-adb"
    local expected_owner="0:0"
    if [ "${TRILLIONNIUM_BOOTSTRAP_ADB_PLACEHOLDER_TEST_ONLY:-0}" = 1 ]; then
        expected_owner="$(staging_test_owner)"
    fi
    [ -d "$parent" ] && [ ! -L "$parent" ] &&
        [ "$($TOYBOX stat -c '%u:%g:%a' "$parent")" = "${expected_owner}:555" ] &&
        verify_rootfs_regular "$target" "$ROOTFS_EMPTY_SHA256" 555 \
            "$expected_owner" &&
        [ "$($TOYBOX stat -c '%u:%g:%a:%s:%h' "$target")" = \
            "${expected_owner}:555:0:1" ]
}

fresh_v2_p01_replay_placeholder_layout_matches() {
    local root="$1"
    local target="${root}/usr/local/bin/trillionnium-system-api-device-conformance-replay-sync"
    if [ -z "$P01_AGENTD_SHA256" ]; then
        [ ! -e "$target" ] && [ ! -L "$target" ]
        return
    fi
    verify_rootfs_regular "$target" "$ROOTFS_EMPTY_SHA256" 555 &&
        [ "$($TOYBOX stat -c '%u:%g:%a:%s:%h' "$target")" = \
            "0:0:555:0:1" ]
}

materialize_adb_bind_placeholder() {
    local root="$1"
    local relative=usr/local/bin
    local target="${root}/${relative}/trillionnium-agent-adb"
    local owner uid gid
    require_staging_rootfs_path "$root"
    owner="$(staging_test_owner)"
    uid="${owner%:*}"
    gid="${owner#*:}"
    thaw_staging_directory "$root" "$relative" materialize.adb_placeholder
    create_staging_regular_no_replace "$target" 555 "$uid" "$gid" \
        materialize.adb_placeholder empty
    if [ -n "$P01_AGENTD_SHA256" ]; then
        create_staging_regular_no_replace \
            "${root}/${relative}/trillionnium-system-api-device-conformance-replay-sync" \
            555 0 0 materialize.p01_replay_placeholder empty
    fi
    refreeze_staging_directory "$root" "$relative" materialize.adb_placeholder
    fresh_v2_adb_placeholder_layout_matches "$root" ||
        fail "standalone ADB bind placeholder did not refreeze exactly"
    fresh_v2_p01_replay_placeholder_layout_matches "$root" ||
        fail "P01 replay-sync bind placeholder did not refreeze exactly"
}

rename_path_durable() {
    local source="$1"
    local destination="$2"
    local boundary="$3"
    local source_parent destination_parent
    source_parent="$(path_parent "$source")"
    destination_parent="$(path_parent "$destination")"
    mv "$source" "$destination" || fail "rename failed: $source -> $destination"
    log "transaction rename: $source -> $destination"
    test_kill_after_boundary "${boundary}.rename"
    if [ "$source_parent" = "$destination_parent" ]; then
        fsync_path "$destination_parent" "${boundary}.parent_fsync"
    else
        fsync_path "$source_parent" "${boundary}.source_parent_fsync"
        fsync_path "$destination_parent" "${boundary}.destination_parent_fsync"
    fi
}

remove_file_durable() {
    local path="$1"
    local boundary="$2"
    local parent
    [ -e "$path" ] || [ -L "$path" ] || return 0
    [ -f "$path" ] && [ ! -L "$path" ] || fail "refusing unsafe file cleanup: $path"
    parent="$(path_parent "$path")"
    log "removing verified transaction file orphan: $path"
    rm -f "$path" || fail "cannot remove transaction file: $path"
    fsync_path "$parent" "${boundary}.parent_fsync"
}

remove_generated_tree() {
    local path="$1"
    local boundary="$2"
    local parent
    case "$path" in
        "$STAGING"|"${DATA_DIR}"/.staging.*|"${DATA_DIR}"/.rollback-new.*|\
        "$ROOTFS_BACKUP") ;;
        *) return 1 ;;
    esac
    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    parent="$(path_parent "$path")"
    log "removing verified generated rootfs orphan: $path"
    "$TOYBOX" rm -rf "$path" || return 1
    fsync_path "$parent" "${boundary}.parent_fsync"
}

declassify_retired_rootfs() {
    local path="$1"
    case "$path" in
        "$ROOTFS_BACKUP") ;;
        *) return 1 ;;
    esac
    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    normalize_retired_private_boundaries "$path" || return 1
    # Exact executable labels are assigned only at the live rootfs path.  Once
    # an old tree has atomically moved to the fixed backup name, remove every
    # specialised label before cleanup.  Policy permits this one-way
    # declassification only to the short-lived bootstrap domain; labelled
    # executable bytes themselves can never be written or unlinked.
    if [ -n "$CHCON" ]; then
        "$CHCON" -h -R "$GENERIC_ROOTFS_CONTEXT" "$path"
    else
        "$TOYBOX" chcon -h -R "$GENERIC_ROOTFS_CONTEXT" "$path"
    fi
    chmod -R u+w "$path" || return 1
}

normalize_retired_private_directory_tree() {
    local path="$1"
    local child
    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    chown 0:0 "$path" || return 1
    chmod 0700 "$path" || return 1
    for child in "$path"/* "$path"/.[!.]* "$path"/..?*; do
        if [ ! -e "$child" ] && [ ! -L "$child" ]; then
            continue
        fi
        if [ -L "$child" ] || [ -f "$child" ] || [ -S "$child" ]; then
            continue
        fi
        [ -d "$child" ] || return 1
        normalize_retired_private_directory_tree "$child" || return 1
    done
}

normalize_retired_private_boundaries() {
    local root="$1"
    local relative path
    for relative in \
        /var/lib/trillionnium/agents/codex/home \
        /var/lib/trillionnium/agents/openclaw/home; do
        path="${root}${relative}"
        if [ ! -e "$path" ] && [ ! -L "$path" ]; then
            continue
        fi
        ensure_no_symlink_components "$root" "$relative"
        normalize_retired_private_directory_tree "$path" || return 1
    done
}

manifest_value_file() {
    local file="$1"
    local key="$2"
    local line value found=0
    [ -f "$file" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            "$key"=*)
                value="${line#*=}"
                [ -n "$value" ] || return 1
                found=$((found + 1))
                ;;
        esac
    done < "$file"
    [ "$found" = 1 ] || return 1
    echo "$value"
}

verify_payload_manifest_file_syntax() {
    local file="$1"
    [ -f "$file" ] && [ ! -L "$file" ] || return 1
    [ -x "$AWK" ] || return 1
    "$AWK" -F= '
        NF < 2 || $1 == "" || length(substr($0, length($1) + 2)) == 0 || seen[$1]++ {
            exit 1
        }
        END { if (NR == 0) exit 1 }
    ' "$file"
}

tar_staging_filter_identity_value() {
    local key="$1"
    [ "$($TOYBOX grep -c "^${key}=" "$TAR_STAGING_FILTER_IDENTITY")" = 1 ] ||
        return 1
    manifest_value_file "$TAR_STAGING_FILTER_IDENTITY" "$key"
}

verify_tar_staging_filter_identity() {
    local actual_sha256 claimed_sha256 claimed_size claimed_variants
    [ -f "$TAR_STAGING_FILTER_IDENTITY" ] &&
        [ ! -L "$TAR_STAGING_FILTER_IDENTITY" ] || return 1
    [ "$($TOYBOX stat -c '%u:%g:%a:%h' "$TAR_STAGING_FILTER_IDENTITY")" = \
        "0:0:644:1" ] || return 1
    [ "$(tar_staging_filter_identity_value schema)" = \
        org.trillionnium.rootfs-tar-staging-filter.identity.v1 ] || return 1
    [ "$(tar_staging_filter_identity_value path)" = \
        /system_ext/bin/trillionnium_rootfs_tar_staging_filter ] || return 1
    [ "$(tar_staging_filter_identity_value owner)" = 0:2000 ] &&
        [ "$(tar_staging_filter_identity_value mode)" = 0755 ] || return 1
    [ "$(tar_staging_filter_identity_value selinux_label)" = \
        u:object_r:trillionnium_rootlinux_exec:s0 ] || return 1
    [ "$(tar_staging_filter_identity_value source_sha256)" = \
        "$ROOTFS_TAR_STAGING_FILTER_SOURCE_SHA256" ] || return 1
    claimed_variants="$(tar_staging_filter_identity_value build_variants)" ||
        return 1
    case ",${claimed_variants}," in
        *",${BUILD_TYPE},"*) ;;
        *) return 1 ;;
    esac
    claimed_sha256="$(tar_staging_filter_identity_value sha256)" ||
        return 1
    validate_hex_token "$claimed_sha256" 64 ||
        return 1
    claimed_size="$(tar_staging_filter_identity_value size)" ||
        return 1
    case "$claimed_size" in
        ''|*[!0-9]*|0) return 1 ;;
    esac
    [ -f "$TAR_STAGING_FILTER" ] && [ ! -L "$TAR_STAGING_FILTER" ] || return 1
    [ "$($TOYBOX stat -c '%u:%g:%a:%s:%h' "$TAR_STAGING_FILTER")" = \
        "0:2000:755:${claimed_size}:1" ] || return 1
    [ "$($TOYBOX stat -c '%C' "$TAR_STAGING_FILTER")" = \
        u:object_r:trillionnium_rootlinux_exec:s0 ] || return 1
    actual_sha256="$(sha256 "$TAR_STAGING_FILTER")" ||
        return 1
    [ "$actual_sha256" = "$claimed_sha256" ]
}

manifest_value() {
    manifest_value_file "$MANIFEST_FILE" "$1"
}

system_manifest_value() {
    manifest_value_file "$SYSTEM_MANIFEST_FILE" "$1"
}

payload_rootfs_sha256() {
    override="$1"

    if [ "$PAYLOAD_CONTRACT_BRANCH" = userdebug_v9 ]; then
        [ -z "$override" ] ||
            fail "userdebug v9 rootfs digest cannot be overridden outside the staged manifest"
        payload_manifest_value rootfs_archive_sha256
        return 0
    fi
    if [ -n "$override" ]; then
        echo "$override"
        return 0
    fi
    manifest_value rootfs_archive_sha256 || \
        system_manifest_value rootfs_archive_sha256 || \
        echo "$ROOTFS_SHA256_FALLBACK"
}

reject_mobian_package_contract() {
    # Mobian .deb/package images are host-side candidate artifacts.  Android's
    # production materializer accepts only the self-contained essential rootfs
    # with the measured Codex runtime. Keep legacy inputs from
    # silently changing the effective runtime when an old profile or manifest
    # is supplied.
    [ -z "${TRILLIONNIUM_ROOT_LINUX_PACKAGE_SHA256:-}" ] ||
        fail "Mobian package inputs are not accepted by the Android headless bootstrap"
    for candidate_manifest in "$MANIFEST_FILE" "$SYSTEM_MANIFEST_FILE"; do
        [ -f "$candidate_manifest" ] || continue
        if "$TOYBOX" grep -Eq '^(package_|gui_baseline_)' \
                "$candidate_manifest"; then
            fail "Mobian package fields are not accepted in Android payload manifests"
        fi
    done
}

verify_bootstrap_layout_contract() {
    manifest_layout="$(payload_manifest_value bootstrap_layout || true)"
    [ "$manifest_layout" = "$BOOTSTRAP_LAYOUT_VERSION" ] ||
        fail "payload bootstrap layout mismatch: ${manifest_layout:-missing}"
}

payload_manifest_value() {
    if [ "$PAYLOAD_CONTRACT_BRANCH" = userdebug_v9 ]; then
        # The userdebug manifest is a receipt-stage output.  Mixing even one
        # field from a second manifest would recreate two independent roots of
        # authority, so this branch deliberately has no fallback.
        manifest_value "$1"
        return
    fi
    manifest_value "$1" || system_manifest_value "$1"
}

require_userdebug_sha256_field() {
    local key="$1"
    local value
    value="$(manifest_value "$key")" ||
        fail "userdebug v9 manifest field is absent: $key"
    validate_hex_token "$value" 64 ||
        fail "userdebug v9 manifest digest is malformed: $key"
    [ "$value" != 0000000000000000000000000000000000000000000000000000000000000000 ] ||
        fail "userdebug v9 manifest digest is all-zero: $key"
    echo "$value"
}

require_userdebug_positive_decimal_field() {
    local key="$1"
    local value
    value="$(manifest_value "$key")" ||
        fail "userdebug v9 manifest field is absent: $key"
    case "$value" in
        ''|*[!0-9]*|0) fail "userdebug v9 manifest positive decimal is malformed: $key" ;;
    esac
    echo "$value"
}

configure_userdebug_v9_contract() {
    # Production installs one stage-derived manifest at this exact logical
    # source.  A distinct fallback path is rejected even if its current bytes
    # happen to match: equality today does not make two authorities one.
    [ "$MANIFEST_FILE" = "$SYSTEM_MANIFEST_FILE" ] ||
        fail "userdebug v9 requires one root-linux manifest authority"
    [ "$($TOYBOX stat -c '%a:%h' "$MANIFEST_FILE" 2>/dev/null)" = 644:1 ] ||
        fail "userdebug v9 root-linux manifest metadata mismatch"
    [ "$(manifest_value p01_product_variant)" = userdebug ] ||
        fail "userdebug product requires the exact P01 manifest selector"
    [ "$(manifest_value android_receipt_stage_schema)" = \
        "$USERDEBUG_RECEIPT_STAGE_SCHEMA" ] ||
        fail "userdebug root-linux manifest is not receipt-stage v1 derived"
    [ "$(manifest_value android_receipt_stage_path)" = \
        "$USERDEBUG_RECEIPT_STAGE_PATH" ] ||
        fail "userdebug receipt-stage evidence path mismatch"
    [ "$(manifest_value android_receipt_stage_custody_path)" = \
        "$USERDEBUG_RECEIPT_STAGE_CUSTODY_PATH" ] ||
        fail "userdebug receipt-stage custody path mismatch"
    [ "$(manifest_value rootfs_archive)" = rootfs-current.tar.zst ] ||
        fail "userdebug v9 rootfs archive path mismatch"
    [ "$(manifest_value rootfs_package_contract_schema)" = \
        "$USERDEBUG_ROOTFS_PACKAGE_CONTRACT_SCHEMA" ] ||
        fail "userdebug v9 packaging contract schema mismatch"
    [ "$(manifest_value rootfs_package_contract_path)" = \
        "$USERDEBUG_ROOTFS_PACKAGE_CONTRACT_PATH" ] ||
        fail "userdebug v9 packaging contract path mismatch"
    [ "$(manifest_value rootfs_package_receipt_schema)" = \
        "$USERDEBUG_ROOTFS_PACKAGE_RECEIPT_SCHEMA" ] ||
        fail "userdebug v9 packaging receipt schema mismatch"
    [ "$(manifest_value rootfs_package_receipt_path)" = \
        "$USERDEBUG_ROOTFS_PACKAGE_RECEIPT_PATH" ] ||
        fail "userdebug v9 packaging receipt path mismatch"
    [ "$(manifest_value rootfs_common_artifact_set_schema)" = \
        "$USERDEBUG_ROOTFS_COMMON_ARTIFACT_SET_SCHEMA" ] ||
        fail "userdebug v9 common artifact-set schema mismatch"
    [ "$(manifest_value rootfs_common_artifact_set_path)" = \
        "$USERDEBUG_ROOTFS_COMMON_ARTIFACT_SET_PATH" ] ||
        fail "userdebug v9 common artifact-set path mismatch"
    [ "$(manifest_value rootfs_fresh_base_receipt_schema)" = \
        "$USERDEBUG_ROOTFS_FRESH_BASE_RECEIPT_SCHEMA" ] ||
        fail "userdebug v9 fresh-base receipt schema mismatch"
    [ "$(manifest_value rootfs_fresh_base_receipt_path)" = \
        "$USERDEBUG_ROOTFS_FRESH_BASE_RECEIPT_PATH" ] ||
        fail "userdebug v9 fresh-base receipt path mismatch"
    [ "$(manifest_value rootfs_fresh_base_sbom_schema)" = \
        "$USERDEBUG_ROOTFS_FRESH_BASE_SBOM_SCHEMA" ] ||
        fail "userdebug v9 fresh-base SBOM schema mismatch"
    [ "$(manifest_value rootfs_fresh_base_sbom_path)" = \
        "$USERDEBUG_ROOTFS_FRESH_BASE_SBOM_PATH" ] ||
        fail "userdebug v9 fresh-base SBOM path mismatch"
    [ "$(manifest_value rootfs_tar_staging_filter_schema)" = \
        org.trillionnium.rootfs-tar-staging-filter.v1 ] ||
        fail "userdebug v9 Android tar-filter schema mismatch"

    ROOTFS_ARCHIVE="${ARCHIVE_DIR}/rootfs-current.tar.zst"
    ROOTFS_PACKAGE_CONTRACT="${ARCHIVE_DIR}/rootfs-package.contract.v9.json"
    ROOTFS_PACKAGE_RECEIPT="${ARCHIVE_DIR}/rootfs-package-receipt.json"
    ROOTFS_COMMON_ARTIFACT_SET="${ARCHIVE_DIR}/common-codex-rootfs-artifact-set.v5.json"
    ROOTFS_PACKAGE_CONTRACT_SHA256="$(require_userdebug_sha256_field rootfs_package_contract_sha256)"
    ROOTFS_PACKAGE_RECEIPT_SHA256="$(require_userdebug_sha256_field rootfs_package_receipt_sha256)"
    ROOTFS_COMMON_ARTIFACT_SET_SHA256="$(require_userdebug_sha256_field rootfs_common_artifact_set_sha256)"
    ROOTFS_SHA256="$(require_userdebug_sha256_field rootfs_archive_sha256)"
    ROOTFS_ARCHIVE_BYTES="$(require_userdebug_positive_decimal_field rootfs_archive_bytes)"
    ROOTFS_RAW_TAR_SHA256="$(require_userdebug_sha256_field rootfs_raw_tar_sha256)"
    ROOTFS_FILTERED_TAR_SHA256="$(require_userdebug_sha256_field rootfs_filtered_tar_sha256)"
    ROOTFS_RAW_TAR_SIZE="$(require_userdebug_positive_decimal_field rootfs_raw_tar_size)"
    ROOTFS_FILTERED_TAR_SIZE="$(require_userdebug_positive_decimal_field rootfs_filtered_tar_size)"
    ROOTFS_TAR_STAGING_FILTER_SCHEMA="$(manifest_value rootfs_tar_staging_filter_schema)"
    ROOTFS_TAR_STAGING_FILTER_SOURCE_SHA256="$(require_userdebug_sha256_field rootfs_tar_staging_filter_source_sha256)"
    ROOTFS_FRESH_BASE_RECEIPT_SHA256="$(require_userdebug_sha256_field rootfs_fresh_base_receipt_sha256)"
    ROOTFS_FRESH_BASE_SBOM_SHA256="$(require_userdebug_sha256_field rootfs_fresh_base_sbom_sha256)"
    ROOTFS_FRESH_BASE_RECEIPT_BYTES="$(require_userdebug_positive_decimal_field rootfs_fresh_base_receipt_bytes)"
    ROOTFS_FRESH_BASE_SBOM_BYTES="$(require_userdebug_positive_decimal_field rootfs_fresh_base_sbom_bytes)"
    ROOTFS_DPKG_PACKAGE_COUNT="$(require_userdebug_positive_decimal_field rootfs_dpkg_package_count)"
    ROOTFS_DPKG_STATUS_SHA256="$(require_userdebug_sha256_field rootfs_dpkg_status_sha256)"
    ROOTFS_ARCHIVE_DIRECTORY_COUNT="$(require_userdebug_positive_decimal_field rootfs_archive_directory_count)"
    [ "$ROOTFS_FILTERED_TAR_SIZE" = "$ROOTFS_RAW_TAR_SIZE" ] ||
        fail "userdebug v9 tar filter changed the receipt-bound stream size"
    ROOTFS_ARCHIVE_PAYLOAD_DIRECTORY_MODE="$(manifest_value rootfs_archive_payload_directory_mode)" ||
        fail "userdebug v9 archive directory mode is absent"
    [ "$ROOTFS_ARCHIVE_PAYLOAD_DIRECTORY_MODE" = 0555 ] ||
        fail "userdebug v9 archive directory mode mismatch"
    ROOTFS_ARCHIVE_DAEMON_SHA256="$(require_userdebug_sha256_field root_linux_archive_daemon_sha256)"
    ROOTFS_ARCHIVE_REPLAY_SYNC_SHA256="$(require_userdebug_sha256_field root_linux_archive_replay_sync_sha256)"
    ROOTFS_ARCHIVE_SYSTEM_API_SHA256="$(require_userdebug_sha256_field root_linux_archive_system_api_sha256)"
    ROOTFS_ARCHIVE_ACCESSIBILITY_SHA256="$(require_userdebug_sha256_field root_linux_archive_accessibility_sha256)"
    ROOTFS_ARCHIVE_CODEX_LAUNCHER_SHA256="$(require_userdebug_sha256_field root_linux_archive_codex_launcher_sha256)"
    ROOTFS_ARCHIVE_AGENT_MANIFEST_SHA256="$(require_userdebug_sha256_field root_linux_archive_agent_manifest_sha256)"
    CODEX_INTEGRITY_LAUNCHER_SHA256="$(require_userdebug_sha256_field codex_integrity_launcher_sha256)"
    P01_AGENTD_SHA256="$(require_userdebug_sha256_field agentd_payload_sha256)"
    [ "$(manifest_value agentd_build_variants)" = userdebug ] ||
        fail "P01 Agent API daemon build variant mismatch"
    [ "$(manifest_value public_release_allowed)" = false ] ||
        fail "userdebug v9 manifest overclaims release authority"
}

manifest_has_p01_selector() {
    local file="$1"
    manifest_value_file "$file" p01_product_variant >/dev/null 2>&1
}

select_payload_contract_branch_for_build_type() {
    BUILD_TYPE="$1"
    case "$BUILD_TYPE" in
        userdebug)
            PAYLOAD_CONTRACT_BRANCH=userdebug_v9
            P01_PRODUCT_VARIANT=userdebug
            configure_userdebug_v9_contract
            ;;
        user|eng)
            PAYLOAD_CONTRACT_BRANCH=legacy_v6
            P01_PRODUCT_VARIANT=""
            ! manifest_has_p01_selector "$MANIFEST_FILE" ||
                fail "$BUILD_TYPE product forbids the P01 userdebug manifest selector"
            if [ "$SYSTEM_MANIFEST_FILE" != "$MANIFEST_FILE" ]; then
                ! manifest_has_p01_selector "$SYSTEM_MANIFEST_FILE" ||
                    fail "$BUILD_TYPE product forbids the P01 userdebug system-manifest selector"
            fi
            ROOTFS_SHA256="$(payload_rootfs_sha256 "${TRILLIONNIUM_ROOT_LINUX_ROOTFS_SHA256:-}")"
            ;;
        *) fail "unsupported Android build type: ${BUILD_TYPE:-missing}" ;;
    esac
}

verify_fresh_v2_manifest_contract() {
    case "$PAYLOAD_CONTRACT_BRANCH" in
        userdebug_v9)
            [ "$(payload_manifest_value rootfs_package_contract_schema)" = \
                "$USERDEBUG_ROOTFS_PACKAGE_CONTRACT_SCHEMA" ] &&
                [ "$(payload_manifest_value rootfs_package_contract_sha256)" = \
                    "$ROOTFS_PACKAGE_CONTRACT_SHA256" ] ||
                fail "rootfs v9 packaging contract identity drifted"
            [ "$(payload_manifest_value rootfs_package_receipt_schema)" = \
                "$USERDEBUG_ROOTFS_PACKAGE_RECEIPT_SCHEMA" ] &&
                [ "$(payload_manifest_value rootfs_package_receipt_sha256)" = \
                    "$ROOTFS_PACKAGE_RECEIPT_SHA256" ] ||
                fail "rootfs v9 packaging receipt identity drifted"
            [ "$(payload_manifest_value rootfs_common_artifact_set_schema)" = \
                "$USERDEBUG_ROOTFS_COMMON_ARTIFACT_SET_SCHEMA" ] &&
                [ "$(payload_manifest_value rootfs_common_artifact_set_sha256)" = \
                    "$ROOTFS_COMMON_ARTIFACT_SET_SHA256" ] ||
                fail "rootfs v9 common artifact-set identity drifted"
            [ "$(payload_manifest_value rootfs_archive_bytes)" = \
                "$ROOTFS_ARCHIVE_BYTES" ] &&
                [ "$(payload_manifest_value rootfs_archive_sha256)" = \
                    "$ROOTFS_SHA256" ] ||
                fail "rootfs v9 archive identity drifted"
            [ "$(payload_manifest_value rootfs_raw_tar_size)" = \
                "$ROOTFS_RAW_TAR_SIZE" ] &&
                [ "$(payload_manifest_value rootfs_raw_tar_sha256)" = \
                    "$ROOTFS_RAW_TAR_SHA256" ] &&
                [ "$(payload_manifest_value rootfs_filtered_tar_size)" = \
                    "$ROOTFS_FILTERED_TAR_SIZE" ] &&
                [ "$(payload_manifest_value rootfs_filtered_tar_sha256)" = \
                    "$ROOTFS_FILTERED_TAR_SHA256" ] ||
                fail "rootfs v9 tar-stream identity drifted"
            [ "$(payload_manifest_value rootfs_fresh_base_receipt_schema)" = \
                "$USERDEBUG_ROOTFS_FRESH_BASE_RECEIPT_SCHEMA" ] &&
                [ "$(payload_manifest_value rootfs_fresh_base_receipt_bytes)" = \
                    "$ROOTFS_FRESH_BASE_RECEIPT_BYTES" ] &&
                [ "$(payload_manifest_value rootfs_fresh_base_receipt_sha256)" = \
                    "$ROOTFS_FRESH_BASE_RECEIPT_SHA256" ] &&
                [ "$(payload_manifest_value rootfs_fresh_base_sbom_schema)" = \
                    "$USERDEBUG_ROOTFS_FRESH_BASE_SBOM_SCHEMA" ] &&
                [ "$(payload_manifest_value rootfs_fresh_base_sbom_bytes)" = \
                    "$ROOTFS_FRESH_BASE_SBOM_BYTES" ] &&
                [ "$(payload_manifest_value rootfs_fresh_base_sbom_sha256)" = \
                    "$ROOTFS_FRESH_BASE_SBOM_SHA256" ] ||
                fail "rootfs v9 fresh-base evidence identity drifted"
            ;;
        legacy_v6)
            [ "$(payload_manifest_value rootfs_package_contract_schema)" = \
                org.trillionnium.rootfs-package.contract.v6 ] ||
                fail "rootfs v6 packaging contract schema mismatch"
            [ "$(payload_manifest_value rootfs_package_contract_sha256)" = \
                "$ROOTFS_PACKAGE_CONTRACT_SHA256" ] ||
                fail "rootfs v6 packaging contract digest mismatch"
            [ "$(payload_manifest_value rootfs_package_receipt_schema)" = \
                org.trillionnium.rootfs-package.receipt.v6 ] ||
                fail "rootfs v6 packaging receipt schema mismatch"
            [ "$(payload_manifest_value rootfs_package_receipt_sha256)" = \
                "$ROOTFS_PACKAGE_RECEIPT_SHA256" ] ||
                fail "rootfs v6 packaging receipt digest mismatch"
            [ "$(payload_manifest_value rootfs_common_artifact_set_sha256)" = \
                "$ROOTFS_COMMON_ARTIFACT_SET_SHA256" ] ||
                fail "common Codex artifact-set digest mismatch"
            [ "$(payload_manifest_value rootfs_fresh_base_receipt_sha256)" = \
                "$ROOTFS_FRESH_BASE_RECEIPT_SHA256" ] ||
                fail "fresh minimal base receipt digest mismatch"
            [ "$(payload_manifest_value rootfs_fresh_base_sbom_sha256)" = \
                "$ROOTFS_FRESH_BASE_SBOM_SHA256" ] ||
                fail "fresh minimal base SBOM digest mismatch"
            ;;
        *) fail "rootfs payload contract branch was not selected" ;;
    esac
    [ "$(payload_manifest_value rootfs_dpkg_package_count)" = \
        "$ROOTFS_DPKG_PACKAGE_COUNT" ] ||
        fail "fresh minimal package count mismatch"
    [ "$(payload_manifest_value rootfs_dpkg_status_sha256)" = \
        "$ROOTFS_DPKG_STATUS_SHA256" ] ||
        fail "fresh minimal dpkg status digest mismatch"
    [ "$(payload_manifest_value rootfs_directory_layout)" = \
        non_usrmerge_real_bin_sbin_lib ] ||
        fail "fresh rootfs directory layout mismatch"
    [ "$(payload_manifest_value rootfs_carrier_directory_owner)" = 0:0 ] &&
        [ "$(payload_manifest_value rootfs_carrier_directory_mode)" = 0755 ] ||
        fail "fresh rootfs carrier directory contract mismatch"
    [ "$(payload_manifest_value rootfs_archive_directory_count)" = \
        "$ROOTFS_ARCHIVE_DIRECTORY_COUNT" ] &&
        [ "$(payload_manifest_value rootfs_archive_payload_directory_mode)" = \
            "$ROOTFS_ARCHIVE_PAYLOAD_DIRECTORY_MODE" ] ||
        fail "fresh rootfs archive directory contract mismatch"
    [ "$(payload_manifest_value rootfs_tar_staging_filter_schema)" = \
        "$ROOTFS_TAR_STAGING_FILTER_SCHEMA" ] ||
        fail "rootfs tar staging filter schema mismatch"
    [ "$(payload_manifest_value rootfs_tar_staging_filter_path)" = \
        /system_ext/bin/trillionnium_rootfs_tar_staging_filter ] ||
        fail "rootfs tar staging filter path mismatch"
    [ "$(payload_manifest_value rootfs_tar_staging_filter_identity_path)" = \
        /system_ext/etc/trillionnium/linux/rootfs-tar-staging-filter.identity.v1 ] ||
        fail "rootfs tar staging filter identity path mismatch"
    [ "$(payload_manifest_value rootfs_tar_staging_filter_source_sha256)" = \
        "$ROOTFS_TAR_STAGING_FILTER_SOURCE_SHA256" ] ||
        fail "rootfs tar staging filter source digest mismatch"
    [ "$(payload_manifest_value rootfs_tar_staging_filter_owner)" = 0:2000 ] &&
        [ "$(payload_manifest_value rootfs_tar_staging_filter_mode)" = 0755 ] ||
        fail "rootfs tar staging filter installed metadata mismatch"
    [ "$(payload_manifest_value rootfs_tar_staging_filter_identity_owner)" = 0:0 ] &&
        [ "$(payload_manifest_value rootfs_tar_staging_filter_identity_mode)" = 0644 ] ||
        fail "rootfs tar staging filter receipt metadata mismatch"
    [ "$(payload_manifest_value rootfs_raw_tar_sha256)" = \
        "$ROOTFS_RAW_TAR_SHA256" ] &&
        [ "$(payload_manifest_value rootfs_filtered_tar_sha256)" = \
            "$ROOTFS_FILTERED_TAR_SHA256" ] ||
        fail "rootfs tar staging stream digest mismatch"
    [ "$(payload_manifest_value rootfs_tar_staging_filter_transform)" = \
        265_directory_headers_0555_to_0755_only ] ||
        fail "rootfs tar staging filter transform mismatch"
    [ "$(payload_manifest_value rootfs_top_level_directory_owner)" = 0:0 ] ||
        fail "fresh rootfs top-level owner mismatch"
    [ "$(payload_manifest_value rootfs_top_level_directory_mode)" = 0555 ] ||
        fail "fresh rootfs top-level mode mismatch"
    [ "$(payload_manifest_value rootfs_staging_parent_thaw_allowlist)" = \
        /etc,/usr/sbin,/usr/local/bin ] ||
        fail "fresh rootfs staging thaw allowlist mismatch"
    [ "$(payload_manifest_value rootfs_staging_in_place_overlay_allowlist)" = \
        /usr/bin/trillionniumd,/etc/trillionnium/agents/agent-codex-direct-v1.json ] ||
        fail "fresh rootfs in-place overlay allowlist mismatch"
    [ "$(payload_manifest_value rootfs_materialized_runtime_directories)" = \
        /proc:0:0:0700,/run/trillionnium:0:0:0750,/tmp:0:0:1777,/var/lib/trillionnium:0:0:0711 ] ||
        fail "fresh rootfs runtime directory allowlist mismatch"
    [ "$(payload_manifest_value rootfs_materialized_readonly_config_modes)" = \
        /etc/resolv.conf:0:0:0444,/etc/hosts:0:0:0444,/etc/shadow:0:42:0440,/etc/gshadow:0:42:0440,/usr/sbin/policy-rc.d:0:0:0555 ] ||
        fail "fresh rootfs readonly config mode contract mismatch"
    [ "$(payload_manifest_value rootfs_empty_placeholder_sha256)" = \
        "$ROOTFS_EMPTY_SHA256" ] &&
        [ "$(payload_manifest_value rootfs_bind_placeholder_mode)" = 0555 ] ||
        fail "fresh rootfs placeholder contract mismatch"
    for binding in \
        "rootfs_materialized_resolv_conf_sha256:$ROOTFS_RESOLV_CONF_SHA256" \
        "rootfs_materialized_hosts_sha256:$ROOTFS_HOSTS_SHA256" \
        "rootfs_materialized_shadow_sha256:$ROOTFS_SHADOW_SHA256" \
        "rootfs_materialized_gshadow_sha256:$ROOTFS_GSHADOW_SHA256" \
        "rootfs_materialized_policy_rc_d_sha256:$ROOTFS_POLICY_RC_D_SHA256"; do
        key="${binding%%:*}"
        expected="${binding#*:}"
        [ "$(payload_manifest_value "$key")" = "$expected" ] ||
            fail "fresh rootfs materialized file binding mismatch: $key"
    done
    [ "$(payload_manifest_value rootfs_bin_sh_symlink_target)" = dash ] ||
        fail "fresh rootfs /bin/sh contract mismatch"
    [ "$(payload_manifest_value rootfs_usr_bin_touch_symlink_target)" = \
        ../../bin/touch ] ||
        fail "fresh rootfs /usr/bin/touch contract mismatch"
    [ "$(payload_manifest_value rootfs_loader_symlink_path)" = \
        /lib/ld-linux-aarch64.so.1 ] ||
        fail "fresh rootfs loader alias path mismatch"
    [ "$(payload_manifest_value rootfs_loader_symlink_target)" = \
        aarch64-linux-gnu/ld-linux-aarch64.so.1 ] ||
        fail "fresh rootfs loader alias target mismatch"
    [ "$(payload_manifest_value root_linux_archive_owned_roles)" = \
        daemon,replay_sync,system_api,accessibility,codex_launcher ] ||
        fail "fresh rootfs archive ownership mismatch"
    [ "$(payload_manifest_value root_linux_standalone_transaction_roles)" = adb ] ||
        fail "fresh rootfs standalone ownership mismatch"
    for binding in \
        "root_linux_archive_daemon_sha256:$ROOTFS_ARCHIVE_DAEMON_SHA256" \
        "root_linux_archive_replay_sync_sha256:$ROOTFS_ARCHIVE_REPLAY_SYNC_SHA256" \
        "root_linux_archive_system_api_sha256:$ROOTFS_ARCHIVE_SYSTEM_API_SHA256" \
        "root_linux_archive_accessibility_sha256:$ROOTFS_ARCHIVE_ACCESSIBILITY_SHA256" \
        "root_linux_archive_codex_launcher_sha256:$ROOTFS_ARCHIVE_CODEX_LAUNCHER_SHA256"; do
        key="${binding%%:*}"
        expected="${binding#*:}"
        [ "$(payload_manifest_value "$key")" = "$expected" ] ||
            fail "fresh rootfs archive artifact binding mismatch: $key"
    done
    if [ "$PAYLOAD_CONTRACT_BRANCH" = userdebug_v9 ]; then
        [ "$(payload_manifest_value root_linux_archive_agent_manifest_sha256)" = \
            "$ROOTFS_ARCHIVE_AGENT_MANIFEST_SHA256" ] ||
            fail "rootfs v9 archive AgentManifest binding mismatch"
    fi
}

verify_archive() {
    archive="$1"
    expected="$2"
    [ -f "$archive" ] || fail "missing archive: $archive"
    actual="$(sha256 "$archive")"
    [ "$actual" = "$expected" ] || fail "sha256 mismatch for $archive: $actual"
}

verify_payload_source_file_quiet() {
    local source="$1"
    local expected_sha256="$2"
    local expected_bytes="${3:-}"
    local metadata actual
    [ -f "$source" ] && [ ! -L "$source" ] || return 1
    metadata="$($TOYBOX stat -c '%a:%s:%h' "$source" 2>/dev/null)" || return 1
    case "$metadata" in
        644:*:1) ;;
        *) return 1 ;;
    esac
    if [ -n "$expected_bytes" ]; then
        [ "$metadata" = "644:${expected_bytes}:1" ] || return 1
    fi
    actual="$(sha256 "$source" 2>/dev/null)" || return 1
    [ "$actual" = "$expected_sha256" ]
}

verify_payload_json_evidence_quiet() {
    local source="$1"
    local expected_sha256="$2"
    local expected_schema="$3"
    local expected_bytes="${4:-}"
    verify_payload_source_file_quiet \
        "$source" "$expected_sha256" "$expected_bytes" || return 1
    "$TOYBOX" grep -F -q "\"schema\": \"${expected_schema}\"" "$source"
}

verify_payload_json_marker_quiet() {
    local source="$1"
    local expected_sha256="$2"
    local marker="$3"
    local expected_bytes="${4:-}"
    verify_payload_source_file_quiet \
        "$source" "$expected_sha256" "$expected_bytes" || return 1
    "$TOYBOX" grep -F -q "$marker" "$source"
}

verify_selected_rootfs_evidence_quiet() {
    local binding source expected
    verify_payload_source_file_quiet \
        "$ROOTFS_ARCHIVE" "$ROOTFS_SHA256" "$ROOTFS_ARCHIVE_BYTES" || return 1
    case "$PAYLOAD_CONTRACT_BRANCH" in
        userdebug_v9)
            verify_payload_json_evidence_quiet \
                "$ROOTFS_PACKAGE_CONTRACT" \
                "$ROOTFS_PACKAGE_CONTRACT_SHA256" \
                "$USERDEBUG_ROOTFS_PACKAGE_CONTRACT_SCHEMA" || return 1
            verify_payload_json_evidence_quiet \
                "$ROOTFS_PACKAGE_RECEIPT" \
                "$ROOTFS_PACKAGE_RECEIPT_SHA256" \
                "$USERDEBUG_ROOTFS_PACKAGE_RECEIPT_SCHEMA" || return 1
            verify_payload_json_evidence_quiet \
                "$ROOTFS_COMMON_ARTIFACT_SET" \
                "$ROOTFS_COMMON_ARTIFACT_SET_SHA256" \
                "$USERDEBUG_ROOTFS_COMMON_ARTIFACT_SET_SCHEMA" || return 1
            verify_payload_json_evidence_quiet \
                "$ROOTFS_FRESH_BASE_RECEIPT" \
                "$ROOTFS_FRESH_BASE_RECEIPT_SHA256" \
                "$USERDEBUG_ROOTFS_FRESH_BASE_RECEIPT_SCHEMA" \
                "$ROOTFS_FRESH_BASE_RECEIPT_BYTES" || return 1
            verify_payload_json_marker_quiet \
                "$ROOTFS_FRESH_BASE_SBOM" \
                "$ROOTFS_FRESH_BASE_SBOM_SHA256" \
                "\"spdxVersion\": \"${USERDEBUG_ROOTFS_FRESH_BASE_SBOM_SCHEMA}\"" \
                "$ROOTFS_FRESH_BASE_SBOM_BYTES"
            ;;
        legacy_v6)
            for binding in \
                "$ROOTFS_PACKAGE_CONTRACT:$ROOTFS_PACKAGE_CONTRACT_SHA256" \
                "$ROOTFS_PACKAGE_RECEIPT:$ROOTFS_PACKAGE_RECEIPT_SHA256" \
                "$ROOTFS_COMMON_ARTIFACT_SET:$ROOTFS_COMMON_ARTIFACT_SET_SHA256" \
                "$ROOTFS_FRESH_BASE_RECEIPT:$ROOTFS_FRESH_BASE_RECEIPT_SHA256" \
                "$ROOTFS_FRESH_BASE_SBOM:$ROOTFS_FRESH_BASE_SBOM_SHA256"; do
                source="${binding%%:*}"
                expected="${binding#*:}"
                verify_payload_source_file_quiet "$source" "$expected" || return 1
            done
            ;;
        *) return 1 ;;
    esac
}

create_staging_tar_slot() {
    local path="$1"
    local metadata
    case "$path" in
        "${STAGING}/rootfs.raw.tar"|"${STAGING}/rootfs.directory-writable.tar") ;;
        *) fail "tar staging slot is outside the fixed allowlist: $path" ;;
    esac
    [ "$($TOYBOX stat -c '%u:%g:%a' "$STAGING")" = "0:0:700" ] ||
        fail "tar staging parent is not root-owned 0700"
    [ ! -e "$path" ] && [ ! -L "$path" ] ||
        fail "tar staging slot already exists: $path"
    (umask 077; set -C; : >"$path") 2>/dev/null ||
        fail "cannot create no-clobber tar staging slot: $path"
    metadata="$($TOYBOX stat -c '%u:%g:%a:%s:%h' "$path")"
    [ "$metadata" = "0:0:600:0:1" ] ||
        fail "tar staging slot metadata is unsafe: $path"
}

verify_staging_tar_slot() {
    local path="$1"
    local expected_identity="$2"
    local expected_size="$3"
    [ -f "$path" ] && [ ! -L "$path" ] &&
        [ "$($TOYBOX stat -c '%d:%i' "$path")" = "$expected_identity" ] &&
        [ "$($TOYBOX stat -c '%u:%g:%a:%s:%h' "$path")" = \
            "0:0:600:${expected_size}:1" ]
}

verify_extracted_writable_archive_directories() {
    local root="${STAGING}/rootfs"
    local inventory count relative metadata
    inventory="$("$TOYBOX" find "$root" -xdev -type d \
        -printf '%P|%U:%G:%m\n')" || return 1
    count="$(printf '%s\n' "$inventory" | "$TOYBOX" wc -l)"
    [ "$count" = "$ROOTFS_ARCHIVE_DIRECTORY_COUNT" ] || return 1
    printf '%s\n' "$inventory" | while IFS='|' read -r relative metadata; do
        [ -n "$metadata" ] && [ "$metadata" = "0:0:755" ] || return 1
    done
}

refreeze_extracted_archive_directories() {
    local root="${STAGING}/rootfs"
    local inventory count relative metadata
    verify_extracted_writable_archive_directories ||
        fail "filtered archive did not extract with the receipt-bound writable directory count"
    "$TOYBOX" find "$root" -xdev -depth -mindepth 1 -type d \
        -exec "$TOYBOX" chmod 0555 '{}' + ||
        fail "cannot refreeze extracted archive directories"
    [ "$($TOYBOX stat -c '%u:%g:%a' "$root")" = "0:0:755" ] ||
        fail "rootfs carrier directory did not remain root-owned 0755"
    inventory="$("$TOYBOX" find "$root" -xdev -mindepth 1 -type d \
        -printf '%P|%U:%G:%m\n')" ||
        fail "cannot inventory refrozen archive directories"
    count="$(printf '%s\n' "$inventory" | "$TOYBOX" wc -l)"
    [ "$count" = "$((ROOTFS_ARCHIVE_DIRECTORY_COUNT - 1))" ] ||
        fail "refrozen archive directory count differs"
    printf '%s\n' "$inventory" | while IFS='|' read -r relative metadata; do
        [ -n "$relative" ] && [ "$metadata" = "0:0:555" ] || return 1
    done || fail "archive payload directory did not refreeze root-owned 0555"
    sync_filesystems
    test_kill_after_boundary extract.archive_directories.refrozen
    fsync_path "$root" extract.archive_directories.root_fsync
}

extract_archive() {
    local archive="$1"
    local name="${archive##*/}"
    local raw="${STAGING}/rootfs.raw.tar"
    local filtered="${STAGING}/rootfs.directory-writable.tar"
    local raw_identity filtered_identity
    [ "$archive" = "$ROOTFS_ARCHIVE" ] ||
        fail "fresh-v2 extractor accepts only the pinned rootfs archive"
    log "extracting $name through the authenticated directory-mode filter"
    create_staging_tar_slot "$raw"
    raw_identity="$($TOYBOX stat -c '%d:%i' "$raw")"
    if ! "$ZSTD" -dc "$archive" >"$raw"; then
        fail "cannot decompress the verified rootfs archive"
    fi
    verify_staging_tar_slot "$raw" "$raw_identity" "$ROOTFS_RAW_TAR_SIZE" ||
        fail "decompressed rootfs tar slot changed identity or size"
    [ "$(sha256 "$raw")" = "$ROOTFS_RAW_TAR_SHA256" ] ||
        fail "decompressed rootfs tar digest mismatch"
    fsync_path "$raw" extract.raw_tar.file_fsync

    create_staging_tar_slot "$filtered"
    filtered_identity="$($TOYBOX stat -c '%d:%i' "$filtered")"
    if ! "$TAR_STAGING_FILTER" <"$raw" >"$filtered"; then
        fail "rootfs tar directory-mode filter rejected the archive"
    fi
    verify_staging_tar_slot \
        "$filtered" "$filtered_identity" "$ROOTFS_FILTERED_TAR_SIZE" ||
        fail "filtered rootfs tar slot changed identity or size"
    [ "$(sha256 "$filtered")" = "$ROOTFS_FILTERED_TAR_SHA256" ] ||
        fail "filtered rootfs tar digest mismatch"
    fsync_path "$filtered" extract.filtered_tar.file_fsync
    remove_file_durable "$raw" extract.raw_tar.cleanup

    "$TOYBOX" tar --restrict -xpof "$filtered" -m \
        --exclude=./data* --exclude=data* -C "${STAGING}/rootfs" ||
        fail "cannot extract the filtered fresh-v2 rootfs tar"
    verify_extracted_writable_archive_directories ||
        fail "filtered fresh-v2 archive directory contract mismatch"
    refreeze_extracted_archive_directories
    remove_file_durable "$filtered" extract.filtered_tar.cleanup
}

install_p01_agentd_overlay() {
    [ -n "$P01_AGENTD_SHA256" ] || return 0
    local target="${STAGING}/rootfs/usr/bin/trillionniumd"
    [ -f "$P01_AGENTD_SOURCE" ] && [ ! -L "$P01_AGENTD_SOURCE" ] || \
        fail "P01 Agent API daemon source is missing or unsafe"
    [ "$($TOYBOX stat -c '%u:%g:%a' "$P01_AGENTD_SOURCE")" = "0:0:644" ] || \
        fail "P01 Agent API daemon source metadata mismatch"
    [ "$(sha256 "$P01_AGENTD_SOURCE")" = "$P01_AGENTD_SHA256" ] || \
        fail "P01 Agent API daemon source digest mismatch"
    [ -f "$target" ] && [ ! -L "$target" ] || \
        fail "P01 Agent API daemon target is missing or unsafe"
    require_staging_in_place_overlay_target "$target"
    chmod 0600 "$target" || fail "cannot unfreeze P01 Agent API daemon target"
    "$TOYBOX" cp "$P01_AGENTD_SOURCE" "$target" || \
        fail "cannot install P01 Agent API daemon"
    test_kill_after_boundary materialize.p01_agentd.overlay
    chown 0:0 "$target" || fail "cannot own P01 Agent API daemon"
    chmod 0555 "$target" || fail "cannot freeze P01 Agent API daemon"
    [ "$(sha256 "$target")" = "$P01_AGENTD_SHA256" ] || \
        fail "installed P01 Agent API daemon digest mismatch"
    fsync_path "$target" materialize.p01_agentd.file_fsync
    verify_agentd_direct_identity "${STAGING}/rootfs" || \
        fail "installed P01 Agent API daemon identity mismatch"
}

provision_codex_credential() {
    local target_root="$1"
    local consume_inbox="${2:-0}"
    local size codex_home codex_tmp codex_tmp_identity home_created=0
    [ -d "$target_root" ] && [ ! -L "$target_root" ] || \
        fail "credential target rootfs is not a real directory"
    codex_home="${target_root}/var/lib/trillionnium/agents/codex/home"
    ensure_no_symlink_components "$target_root" "/var/lib/trillionnium/agents/codex/home/auth.json"
    ensure_state_directory "${target_root}/var/lib/trillionnium" 0 0 0711
    ensure_state_directory "${target_root}/var/lib/trillionnium/agents" 0 0 0711
    ensure_state_directory "${target_root}/var/lib/trillionnium/agents/codex" 0 0 0711
    if [ -e "$codex_home" ] || [ -L "$codex_home" ]; then
        [ -d "$codex_home" ] && [ ! -L "$codex_home" ] &&
            [ "$($TOYBOX stat -c '%u:%g:%a' "$codex_home")" = "5901:5901:700" ] ||
            fail "existing Codex home metadata is unsafe"
        [ ! -e "$CODEX_AUTH_INBOX" ] && [ ! -L "$CODEX_AUTH_INBOX" ] ||
            fail "Codex credential refresh requires a fresh atomic rootfs transaction"
        return 0
    fi
    mkdir "$codex_home" || fail "cannot create staged Codex home"
    chown 0:0 "$codex_home" || fail "cannot own staged Codex home"
    chmod 0700 "$codex_home" || fail "cannot secure staged Codex home"
    home_created=1
    if [ ! -e "$CODEX_AUTH_INBOX" ] && [ ! -L "$CODEX_AUTH_INBOX" ]; then
        exec 8<"$codex_home" || fail "cannot pin empty staged Codex home descriptor"
        fsync_path "$codex_home" state.codex_home.empty_fsync
        chown 5901:5901 "$codex_home" || fail "cannot transfer staged Codex home"
        [ "$($TOYBOX stat -c '%u:%g:%a' "$codex_home")" = "5901:5901:700" ] ||
            fail "empty staged Codex home transfer did not converge"
        fsync_open_descriptor 8 state.codex_home.chown
        exec 8<&-
        fsync_path "${target_root}/var/lib/trillionnium/agents/codex" \
            state.codex_home.parent_fsync
        test_kill_after_boundary state.codex_home.transferred
        return 0
    fi
    [ -f "$CODEX_AUTH_INBOX" ] && [ ! -L "$CODEX_AUTH_INBOX" ] ||
        fail "Codex credential inbox is not a regular no-follow file"
    [ "$($TOYBOX stat -c '%u:%g:%a:%h' "$CODEX_AUTH_INBOX")" = "0:0:600:1" ] ||
        fail "Codex credential inbox metadata is unsafe"
    size="$(wc -c < "$CODEX_AUTH_INBOX")"
    case "$size" in
        ''|*[!0-9]*) fail "invalid Codex credential inbox size" ;;
    esac
    [ "$size" -gt 0 ] && [ "$size" -le 1048576 ] || \
        fail "Codex credential inbox is outside the bounded size contract"
    json_file_is_valid "$CODEX_AUTH_INBOX" || \
        fail "Codex credential inbox is not valid bounded JSON"
    "$TOYBOX" grep -q '"auth_mode"' "$CODEX_AUTH_INBOX" || \
        fail "Codex credential inbox is missing auth_mode"
    "$TOYBOX" grep -q '"tokens"' "$CODEX_AUTH_INBOX" || \
        fail "Codex credential inbox is missing tokens"
    codex_tmp="${codex_home}/.auth.json.tmp.$$"
    cp "$CODEX_AUTH_INBOX" "$codex_tmp" || fail "cannot copy staged Codex credential"
    chmod 0600 "$codex_tmp" || fail "cannot secure staged Codex credential"
    codex_tmp_identity="$($TOYBOX stat -c '%d:%i:%h:%u:%g:%a' "$codex_tmp")"
    [ "$codex_tmp_identity" = \
        "$($TOYBOX stat -c '%d:%i' "$codex_tmp"):1:0:0:600" ] ||
        fail "staged Codex credential inode identity is unsafe"
    fsync_path "$codex_tmp" state.codex_auth.file_fsync
    exec 9<>"$codex_tmp" || fail "cannot pin staged Codex credential descriptor"
    chown 5901:5901 "$codex_tmp" || fail "cannot transfer staged Codex credential"
    [ "$($TOYBOX stat -c '%d:%i:%h:%u:%g:%a' "$codex_tmp")" = \
        "${codex_tmp_identity%:0:0:600}:5901:5901:600" ] ||
        fail "staged Codex credential inode changed during transfer"
    fsync_open_descriptor 9 state.codex_auth.chown
    exec 9>&-
    rename_path_durable "$codex_tmp" "${codex_home}/auth.json" \
        state.codex_auth
    [ "$home_created" = 1 ] || fail "Codex home transfer state is inconsistent"
    exec 8<"$codex_home" || fail "cannot pin populated staged Codex home descriptor"
    chown 5901:5901 "$codex_home" || fail "cannot transfer staged Codex home"
    [ "$($TOYBOX stat -c '%u:%g:%a' "$codex_home")" = "5901:5901:700" ] ||
        fail "staged Codex home transfer did not converge"
    fsync_open_descriptor 8 state.codex_home.chown
    exec 8<&-
    fsync_path "${target_root}/var/lib/trillionnium/agents/codex" \
        state.codex_home.parent_fsync
    test_kill_after_boundary state.codex_home.transferred
    if [ "$consume_inbox" = "1" ]; then
        rm -f "$CODEX_AUTH_INBOX"
    else
        STAGED_CODEX_INBOX=1
    fi
    log "provisioned built-in Codex credential into the isolated Agent home"
}

json_read_byte() {
    if IFS= read -r JSON_BYTE <&3; then
        JSON_EOF=0
    else
        JSON_BYTE=""
        JSON_EOF=1
    fi
}

json_skip_whitespace() {
    while [ "$JSON_EOF" = 0 ]; do
        case "$JSON_BYTE" in
            09|0a|0d|20) json_read_byte ;;
            *) return 0 ;;
        esac
    done
}

json_consume_utf8_continuation() {
    case "$JSON_BYTE" in
        8[0-9a-f]|9[0-9a-f]|a[0-9a-f]|b[0-9a-f]) json_read_byte ;;
        *) return 1 ;;
    esac
}

json_parse_string() {
    local index
    [ "$JSON_EOF" = 0 ] && [ "$JSON_BYTE" = 22 ] || return 1
    JSON_STRING_HEX=""
    JSON_STRING_SIMPLE=1
    json_read_byte
    while [ "$JSON_EOF" = 0 ]; do
        case "$JSON_BYTE" in
            22)
                json_read_byte
                return 0
                ;;
            5c)
                JSON_STRING_SIMPLE=0
                json_read_byte
                [ "$JSON_EOF" = 0 ] || return 1
                case "$JSON_BYTE" in
                    22|2f|5c|62|66|6e|72|74) json_read_byte ;;
                    75)
                        index=0
                        while [ "$index" -lt 4 ]; do
                            json_read_byte
                            [ "$JSON_EOF" = 0 ] || return 1
                            case "$JSON_BYTE" in
                                [0-9a-f][0-9a-f]) ;;
                                *) return 1 ;;
                            esac
                            index=$((index + 1))
                        done
                        json_read_byte
                        ;;
                    *) return 1 ;;
                esac
                ;;
            0[0-9a-f]|1[0-9a-f]) return 1 ;;
            [2-6][0-9a-f]|7[0-9a-e])
                if [ "$JSON_CAPTURE_STRING" = 1 ] &&
                        [ "$JSON_STRING_SIMPLE" = 1 ]; then
                    if [ "${#JSON_STRING_HEX}" -lt 64 ]; then
                        JSON_STRING_HEX="${JSON_STRING_HEX}${JSON_BYTE}"
                    else
                        JSON_STRING_SIMPLE=0
                    fi
                fi
                json_read_byte
                ;;
            c[2-9a-f]|d[0-9a-f])
                JSON_STRING_SIMPLE=0
                json_read_byte
                json_consume_utf8_continuation || return 1
                ;;
            e0)
                JSON_STRING_SIMPLE=0
                json_read_byte
                case "$JSON_BYTE" in a[0-9a-f]|b[0-9a-f]) json_read_byte ;; *) return 1 ;; esac
                json_consume_utf8_continuation || return 1
                ;;
            e[1-9a-c]|e[e-f])
                JSON_STRING_SIMPLE=0
                json_read_byte
                json_consume_utf8_continuation || return 1
                json_consume_utf8_continuation || return 1
                ;;
            ed)
                JSON_STRING_SIMPLE=0
                json_read_byte
                case "$JSON_BYTE" in 8[0-9a-f]|9[0-9a-f]) json_read_byte ;; *) return 1 ;; esac
                json_consume_utf8_continuation || return 1
                ;;
            f0)
                JSON_STRING_SIMPLE=0
                json_read_byte
                case "$JSON_BYTE" in 9[0-9a-f]|a[0-9a-f]|b[0-9a-f]) json_read_byte ;; *) return 1 ;; esac
                json_consume_utf8_continuation || return 1
                json_consume_utf8_continuation || return 1
                ;;
            f[1-3])
                JSON_STRING_SIMPLE=0
                json_read_byte
                json_consume_utf8_continuation || return 1
                json_consume_utf8_continuation || return 1
                json_consume_utf8_continuation || return 1
                ;;
            f4)
                JSON_STRING_SIMPLE=0
                json_read_byte
                case "$JSON_BYTE" in 8[0-9a-f]) json_read_byte ;; *) return 1 ;; esac
                json_consume_utf8_continuation || return 1
                json_consume_utf8_continuation || return 1
                ;;
            *) return 1 ;;
        esac
    done
    return 1
}

json_parse_number() {
    if [ "$JSON_BYTE" = 2d ]; then
        json_read_byte
        [ "$JSON_EOF" = 0 ] || return 1
    fi
    case "$JSON_BYTE" in
        30) json_read_byte ;;
        3[1-9])
            while [ "$JSON_EOF" = 0 ]; do
                case "$JSON_BYTE" in 3[0-9]) json_read_byte ;; *) break ;; esac
            done
            ;;
        *) return 1 ;;
    esac
    if [ "$JSON_EOF" = 0 ] && [ "$JSON_BYTE" = 2e ]; then
        json_read_byte
        [ "$JSON_EOF" = 0 ] || return 1
        case "$JSON_BYTE" in 3[0-9]) ;; *) return 1 ;; esac
        while [ "$JSON_EOF" = 0 ]; do
            case "$JSON_BYTE" in 3[0-9]) json_read_byte ;; *) break ;; esac
        done
    fi
    if [ "$JSON_EOF" = 0 ]; then
        case "$JSON_BYTE" in
            45|65)
                json_read_byte
                [ "$JSON_EOF" = 0 ] || return 1
                case "$JSON_BYTE" in 2b|2d) json_read_byte ;; esac
                [ "$JSON_EOF" = 0 ] || return 1
                case "$JSON_BYTE" in 3[0-9]) ;; *) return 1 ;; esac
                while [ "$JSON_EOF" = 0 ]; do
                    case "$JSON_BYTE" in 3[0-9]) json_read_byte ;; *) break ;; esac
                done
                ;;
        esac
    fi
}

json_parse_literal() {
    local expected
    for expected in "$@"; do
        [ "$JSON_EOF" = 0 ] && [ "$JSON_BYTE" = "$expected" ] || return 1
        json_read_byte
    done
}

json_parse_array() {
    [ "$JSON_BYTE" = 5b ] || return 1
    json_read_byte
    json_skip_whitespace
    if [ "$JSON_EOF" = 0 ] && [ "$JSON_BYTE" = 5d ]; then
        json_read_byte
        return 0
    fi
    while :; do
        json_parse_value || return 1
        json_skip_whitespace
        [ "$JSON_EOF" = 0 ] || return 1
        case "$JSON_BYTE" in
            5d) json_read_byte; return 0 ;;
            2c) json_read_byte; json_skip_whitespace ;;
            *) return 1 ;;
        esac
    done
}

json_parse_object() {
    [ "$JSON_BYTE" = 7b ] || return 1
    json_read_byte
    json_skip_whitespace
    if [ "$JSON_EOF" = 0 ] && [ "$JSON_BYTE" = 7d ]; then
        json_read_byte
        return 0
    fi
    while :; do
        if [ "$JSON_DEPTH" = 1 ]; then
            JSON_CAPTURE_STRING=1
        else
            JSON_CAPTURE_STRING=0
        fi
        json_parse_string || return 1
        if [ "$JSON_DEPTH" = 1 ] && [ "$JSON_STRING_SIMPLE" = 1 ]; then
            case "$JSON_STRING_HEX" in
                617574685f6d6f6465)
                    JSON_TOP_AUTH_MODE_COUNT=$((JSON_TOP_AUTH_MODE_COUNT + 1))
                    [ "$JSON_TOP_AUTH_MODE_COUNT" = 1 ] || return 1
                    ;;
                746f6b656e73)
                    JSON_TOP_TOKENS_COUNT=$((JSON_TOP_TOKENS_COUNT + 1))
                    [ "$JSON_TOP_TOKENS_COUNT" = 1 ] || return 1
                    ;;
            esac
        fi
        json_skip_whitespace
        [ "$JSON_EOF" = 0 ] && [ "$JSON_BYTE" = 3a ] || return 1
        json_read_byte
        json_parse_value || return 1
        json_skip_whitespace
        [ "$JSON_EOF" = 0 ] || return 1
        case "$JSON_BYTE" in
            7d) json_read_byte; return 0 ;;
            2c) json_read_byte; json_skip_whitespace ;;
            *) return 1 ;;
        esac
    done
}

json_parse_value() {
    local result=1
    JSON_DEPTH=$((JSON_DEPTH + 1))
    [ "$JSON_DEPTH" -le 64 ] || {
        JSON_DEPTH=$((JSON_DEPTH - 1))
        return 1
    }
    json_skip_whitespace
    if [ "$JSON_EOF" = 0 ]; then
        case "$JSON_BYTE" in
            22) JSON_CAPTURE_STRING=0; json_parse_string && result=0 ;;
            2d|3[0-9]) json_parse_number && result=0 ;;
            5b) json_parse_array && result=0 ;;
            66) json_parse_literal 66 61 6c 73 65 && result=0 ;;
            6e) json_parse_literal 6e 75 6c 6c && result=0 ;;
            74) json_parse_literal 74 72 75 65 && result=0 ;;
            7b) json_parse_object && result=0 ;;
        esac
    fi
    JSON_DEPTH=$((JSON_DEPTH - 1))
    return "$result"
}

json_file_is_valid() {
    local path="$1"
    local hex_path="${STAGING}/.codex-auth-json.hex.$$"
    local input_size token_count hex_identity result=1
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    [ -d "$STAGING" ] && [ ! -L "$STAGING" ] &&
        [ "$($TOYBOX stat -c '%u:%g:%a' "$STAGING")" = "0:0:700" ] || return 1
    [ ! -e "$hex_path" ] && [ ! -L "$hex_path" ] || return 1
    ( umask 077; set -C; : >"$hex_path" ) || return 1
    [ "$($TOYBOX stat -c '%u:%g:%a:%h' "$hex_path")" = "0:0:600:1" ] || {
        rm -f "$hex_path"
        return 1
    }
    hex_identity="$($TOYBOX stat -c '%d:%i:%h:%u:%g:%a' "$hex_path")"
    if "$TOYBOX" xxd -p -c 1 "$path" >"$hex_path" &&
            [ "$($TOYBOX stat -c '%d:%i:%h:%u:%g:%a' "$hex_path")" = "$hex_identity" ]; then
        input_size="$(wc -c <"$path")"
        token_count="$(wc -l <"$hex_path")"
        if [ "$input_size" = "$token_count" ]; then
            exec 3<"$hex_path"
            JSON_BYTE=""
            JSON_EOF=0
            JSON_DEPTH=0
            JSON_CAPTURE_STRING=0
            JSON_STRING_HEX=""
            JSON_STRING_SIMPLE=0
            JSON_TOP_AUTH_MODE_COUNT=0
            JSON_TOP_TOKENS_COUNT=0
            json_read_byte
            json_skip_whitespace
            if [ "$JSON_EOF" = 0 ] && [ "$JSON_BYTE" = 7b ] &&
                    json_parse_value; then
                json_skip_whitespace
                [ "$JSON_EOF" = 1 ] &&
                    [ "$JSON_TOP_AUTH_MODE_COUNT" = 1 ] &&
                    [ "$JSON_TOP_TOKENS_COUNT" = 1 ] && result=0
            fi
            exec 3<&-
        fi
    fi
    rm -f "$hex_path" || return 1
    return "$result"
}

mode_allowed() {
    local candidate="$1"
    local allowed="$2"
    case ",${allowed}," in
        *,"${candidate}",*) return 0 ;;
        *) return 1 ;;
    esac
}

ensure_no_symlink_components() {
    local root="$1"
    local absolute_path="$2"
    local relative_path current old_ifs component
    case "$absolute_path" in
        /*) relative_path="${absolute_path#/}" ;;
        *) fail "state path must be absolute inside rootfs: $absolute_path" ;;
    esac
    current="$root"
    old_ifs="$IFS"
    IFS=/
    set -- $relative_path
    IFS="$old_ifs"
    for component in "$@"; do
        [ -n "$component" ] || fail "empty state path component"
        [ "$component" != "." ] && [ "$component" != ".." ] || \
            fail "unsafe state path component"
        current="${current}/${component}"
        [ ! -L "$current" ] || fail "state path contains symlink: $current"
    done
}

ensure_state_directory() {
    local path="$1"
    local uid="$2"
    local gid="$3"
    local mode="$4"
    local current_metadata current_owner current_mode expected_mode
    if [ -e "$path" ] || [ -L "$path" ]; then
        [ ! -L "$path" ] && [ -d "$path" ] || \
            fail "state directory is not a real directory: $path"
    else
        mkdir "$path" || fail "cannot create state directory: $path"
    fi
    current_metadata="$("$TOYBOX" stat -c '%u:%g:%a' "$path" 2>/dev/null)" || \
        fail "cannot stat state directory: $path"
    current_owner="${current_metadata%:*}"
    current_mode="${current_metadata##*:}"
    expected_mode="${mode#0}"
    if [ "$current_owner" != "${uid}:${gid}" ]; then
        chown "${uid}:${gid}" "$path" || fail "cannot chown state directory: $path"
    fi
    if [ "$current_mode" != "$expected_mode" ]; then
        chmod "$mode" "$path" || fail "cannot chmod state directory: $path"
    fi
}

prepare_state_parent() {
    local root="$1"
    local absolute_path="$2"
    local parent="${absolute_path%/*}"
    local target relative old_ifs component
    ensure_no_symlink_components "$root" "$parent"
    target="$root"
    relative="${parent#/}"
    old_ifs="$IFS"
    IFS=/
    set -- $relative
    IFS="$old_ifs"
    for component in "$@"; do
        target="${target}/${component}"
        if [ -e "$target" ] || [ -L "$target" ]; then
            [ ! -L "$target" ] && [ -d "$target" ] || \
                fail "state parent is not a real directory: $target"
        else
            mkdir "$target" || fail "cannot create state parent: $target"
            chown 0:0 "$target" || fail "cannot chown state parent: $target"
            chmod 0700 "$target" || fail "cannot chmod state parent: $target"
        fi
    done
}

validate_state_file() {
    local path="$1"
    local max_bytes="$2"
    local expected_uid="$3"
    local expected_gid="$4"
    local allowed_modes="$5"
    local uid gid mode size
    [ ! -L "$path" ] && [ -f "$path" ] || fail "state file is not regular: $path"
    [ "$("$TOYBOX" stat -c %h "$path")" = "1" ] || \
        fail "state file has unexpected hard links: $path"
    uid="$("$TOYBOX" stat -c %u "$path")"
    gid="$("$TOYBOX" stat -c %g "$path")"
    mode="$("$TOYBOX" stat -c %a "$path")"
    size="$("$TOYBOX" stat -c %s "$path")"
    case "$size" in ''|*[!0-9]*) fail "invalid state file size: $path" ;; esac
    [ "$uid" = "$expected_uid" ] && [ "$gid" = "$expected_gid" ] || \
        fail "state file owner mismatch: $path"
    mode_allowed "$mode" "$allowed_modes" || fail "state file mode mismatch: $path mode=$mode"
    [ "$size" -gt 0 ] && [ "$size" -le "$max_bytes" ] || \
        fail "state file is outside bounded size contract: $path size=$size"
}

copy_state_file() {
    local old_root="$1"
    local source_path="$2"
    local new_root="$3"
    local destination_path="$4"
    local max_bytes="$5"
    local expected_uid="$6"
    local expected_gid="$7"
    local allowed_modes="$8"
    local destination_mode="$9"
    local source="${old_root}${source_path}"
    local destination="${new_root}${destination_path}"
    local temporary
    if [ ! -e "$source" ] && [ ! -L "$source" ]; then
        return 0
    fi
    ensure_no_symlink_components "$old_root" "$source_path"
    validate_state_file "$source" "$max_bytes" "$expected_uid" "$expected_gid" "$allowed_modes"
    prepare_state_parent "$new_root" "$destination_path"
    [ ! -e "$destination" ] && [ ! -L "$destination" ] || \
        fail "signed payload unexpectedly contains runtime state: $destination"
    temporary="${destination}.migrate.$$"
    [ ! -e "$temporary" ] && [ ! -L "$temporary" ] || \
        fail "state migration temporary path already exists"
    "$TOYBOX" cp "$source" "$temporary" || fail "cannot stage state file: $source"
    chown "${expected_uid}:${expected_gid}" "$temporary" || \
        fail "cannot chown staged state file: $temporary"
    chmod "$destination_mode" "$temporary" || \
        fail "cannot chmod staged state file: $temporary"
    validate_state_file "$temporary" "$max_bytes" "$expected_uid" "$expected_gid" \
        "$destination_mode"
    [ "$(sha256 "$source")" = "$(sha256 "$temporary")" ] || \
        fail "state migration digest mismatch: $source"
    rename_path_durable "$temporary" "$destination" state.allowlisted_file
    log "migrated allowlisted state metadata: $destination_path"
}

prepare_agent_tool_mount_target() {
    local root="$1"
    # Operation journals and daemon-authored binding inboxes live on the
    # persistent Android-owned /data/trillionnium/agent-tools tree.  The
    # Root-Linux image carries only this root-owned mount point; init bind
    # mounts the persistent tree after bootstrap has stopped every Agent.
    # Keeping the leaves out of the replaceable rootfs avoids copying private
    # UID-owned journals during an OTA and keeps DAC_READ_SEARCH out of this
    # bootstrap domain.
    ensure_no_symlink_components "$root" "/var/lib/trillionnium/agent-tools"
    ensure_state_directory "${root}/var/lib/trillionnium" 0 0 0711
    ensure_state_directory "${root}/var/lib/trillionnium/agent-tools" 0 0 0711
}

prepare_proc_mount_target() {
    local root="$1"
    ensure_no_symlink_components "$root" "/proc"
    ensure_state_directory "${root}/proc" 0 0 0700
}

# One-release OTA migration: move only the two former external provider state
# roots to fixed quarantine names. This operation never recursively traverses
# provider-controlled content, refuses every symlink boundary, and leaves the
# bytes recoverable for an explicit later retention decision. UID/GID 5902 is
# a retired tombstone and must not be reused while these quarantines may exist.
quarantine_retired_provider_path() {
    local source="$1"
    local destination="$2"
    local parent
    case "${source}:${destination}" in
        /data/trillionnium/agent-tools/state/openclaw:/data/trillionnium/agent-tools/state/.retired-openclaw-v1|\
        /data/trillionnium/agent-tools/inbox/openclaw:/data/trillionnium/agent-tools/inbox/.retired-openclaw-v1) ;;
        *) fail "retired provider quarantine path is outside the fixed allowlist" ;;
    esac
    parent="${source%/*}"
    if [ ! -e "$source" ] && [ ! -L "$source" ] && \
        [ ! -e "$destination" ] && [ ! -L "$destination" ]; then
        return 0
    fi
    [ -d "$parent" ] && [ ! -L "$parent" ] || \
        fail "retired provider quarantine parent is missing or unsafe: $parent"
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        [ -d "$destination" ] && [ ! -L "$destination" ] || \
            fail "retired provider quarantine destination is unsafe: $destination"
        [ ! -e "$source" ] && [ ! -L "$source" ] || \
            fail "retired provider source and quarantine both exist"
        return 0
    fi
    [ -e "$source" ] || [ -L "$source" ] || return 0
    [ -d "$source" ] && [ ! -L "$source" ] || \
        fail "retired provider source is not a no-follow directory: $source"
    rename_path_durable "$source" "$destination" retired_provider.quarantine
    chmod 0700 "$destination" || \
        fail "cannot secure retired provider quarantine: $destination"
}

quarantine_retired_provider_state() {
    quarantine_retired_provider_path \
        /data/trillionnium/agent-tools/state/openclaw \
        /data/trillionnium/agent-tools/state/.retired-openclaw-v1
    quarantine_retired_provider_path \
        /data/trillionnium/agent-tools/inbox/openclaw \
        /data/trillionnium/agent-tools/inbox/.retired-openclaw-v1
}

reject_retired_provider_payload() {
    local root="$1"
    local relative candidate
    for relative in \
        usr/bin/openclaw \
        usr/libexec/trillionnium-openclaw \
        etc/trillionnium/agents/agent-openclaw-direct-v1.json \
        var/lib/trillionnium/agents/openclaw; do
        candidate="${root}/${relative}"
        [ ! -e "$candidate" ] && [ ! -L "$candidate" ] || \
            fail "Codex-only rootfs contains retired provider path: $relative"
    done
}

validate_hex_token() {
    local token="$1"
    local expected_length="$2"
    [ "${#token}" -eq "$expected_length" ] || return 1
    case "$token" in
        *[!0-9a-f]*) return 1 ;;
        *) return 0 ;;
    esac
}

context_memory_file_contract() {
    local relative="$1"
    local token
    CONTEXT_FILE_MAX=0
    CONTEXT_FILE_EXACT=0
    CONTEXT_FILE_ENCRYPTED=0
    case "$relative" in
        memory-key.envelope.json)
            CONTEXT_FILE_MAX=8192
            ;;
        ui-replay-archive.json)
            CONTEXT_FILE_MAX=262144
            ;;
        metadata.json)
            CONTEXT_FILE_MAX=4194304
            ;;
        agent-data-grants.enc)
            CONTEXT_FILE_MAX=2097280
            CONTEXT_FILE_ENCRYPTED=1
            ;;
        ephemeral-contexts.enc)
            CONTEXT_FILE_MAX=26738816
            CONTEXT_FILE_ENCRYPTED=1
            ;;
        authority-key-pin.json|execution-payload-integrity.json)
            CONTEXT_FILE_MAX=65536
            ;;
        payloads/memory-*.enc)
            token="${relative#payloads/memory-}"
            token="${token%.enc}"
            validate_hex_token "$token" 64 || return 1
            CONTEXT_FILE_MAX=131072
            CONTEXT_FILE_ENCRYPTED=1
            ;;
        ui-replay/*.json)
            token="${relative#ui-replay/}"
            token="${token%.json}"
            validate_hex_token "$token" 64 || return 1
            CONTEXT_FILE_MAX=16384
            ;;
        ui-replay-outcomes/*.enc)
            token="${relative#ui-replay-outcomes/}"
            token="${token%.enc}"
            validate_hex_token "$token" 64 || return 1
            CONTEXT_FILE_MAX=262272
            CONTEXT_FILE_ENCRYPTED=1
            ;;
        execution-payloads/execution-payload-*.enc)
            token="${relative#execution-payloads/execution-payload-}"
            token="${token%.enc}"
            validate_hex_token "$token" 64 || return 1
            CONTEXT_FILE_MAX=32768
            CONTEXT_FILE_ENCRYPTED=1
            ;;
        execution-payload-quarantine/invalid-entry-*)
            token="${relative#execution-payload-quarantine/invalid-entry-}"
            validate_hex_token "$token" 64 || return 1
            CONTEXT_FILE_MAX=32768
            ;;
        *) return 1 ;;
    esac
    return 0
}

migrate_context_memory() {
    local old_root="$1"
    local new_root="$2"
    local source="${old_root}/var/lib/trillionnium/context-memory"
    local destination="${new_root}/var/lib/trillionnium/context-memory"
    local list count total item relative target size parent temporary
    if [ ! -e "$source" ] && [ ! -L "$source" ]; then
        return 0
    fi
    ensure_no_symlink_components "$old_root" "/var/lib/trillionnium/context-memory"
    [ ! -L "$source" ] && [ -d "$source" ] || \
        fail "context-memory state root is not a real directory"
    [ "$("$TOYBOX" stat -c %u "$source")" = "0" ] && \
        [ "$("$TOYBOX" stat -c %g "$source")" = "0" ] && \
        [ "$("$TOYBOX" stat -c %a "$source")" = "700" ] || \
        fail "context-memory state root owner or mode mismatch"
    prepare_state_parent "$new_root" "/var/lib/trillionnium/context-memory/item"
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        [ ! -L "$destination" ] && [ -d "$destination" ] || \
            fail "staged context-memory root is not a real directory"
        if [ -n "$("$TOYBOX" find "$destination" -mindepth 1 -print -quit 2>/dev/null)" ]; then
            fail "signed payload unexpectedly contains context-memory runtime state"
        fi
    else
        mkdir "$destination" || fail "cannot create staged context-memory root"
    fi
    chown 0:0 "$destination"
    chmod 0700 "$destination"
    list="${STAGING}/.context-memory-list.$$"
    "$TOYBOX" find "$source" -print >"$list" || fail "cannot inventory context-memory state"
    count=0
    total=0
    while IFS= read -r item || [ -n "$item" ]; do
        [ "$item" != "$source" ] || continue
        relative="${item#${source}/}"
        [ "$relative" != "$item" ] && [ -n "$relative" ] || \
            fail "context-memory path escaped source root"
        case "$relative" in
            *[!A-Za-z0-9._/-]*) fail "context-memory path contains unsupported characters" ;;
            ../*|*/../*|*/..|.|..) fail "context-memory path traversal denied" ;;
        esac
        count=$((count + 1))
        [ "$count" -le "$STATE_MAX_FILES" ] || fail "context-memory file count exceeded"
        [ ! -L "$item" ] || fail "context-memory symlink denied: $relative"
        target="${destination}/${relative}"
        if [ -d "$item" ]; then
            case "$relative" in
                payloads|ui-replay|ui-replay-outcomes|execution-payloads|execution-payload-quarantine) ;;
                *) fail "unrecognized context-memory directory denied: $relative" ;;
            esac
            [ "$("$TOYBOX" stat -c %u "$item")" = "0" ] && \
                [ "$("$TOYBOX" stat -c %g "$item")" = "0" ] && \
                [ "$("$TOYBOX" stat -c %a "$item")" = "700" ] || \
                fail "context-memory directory owner or mode mismatch: $relative"
            [ ! -e "$target" ] && [ ! -L "$target" ] || \
                fail "duplicate staged context-memory directory: $relative"
            mkdir "$target" || fail "cannot stage context-memory directory: $relative"
            chown 0:0 "$target"
            chmod 0700 "$target"
        elif [ -f "$item" ]; then
            context_memory_file_contract "$relative" || \
                fail "unrecognized context-memory file denied: $relative"
            validate_state_file "$item" "$CONTEXT_FILE_MAX" 0 0 600
            size="$("$TOYBOX" stat -c %s "$item")"
            if [ "$CONTEXT_FILE_EXACT" -gt 0 ] && [ "$size" -ne "$CONTEXT_FILE_EXACT" ]; then
                fail "context-memory exact file size mismatch: $relative"
            fi
            if [ "$CONTEXT_FILE_ENCRYPTED" = "1" ] && [ "$size" -lt 40 ]; then
                fail "encrypted context-memory file is shorter than nonce and tag: $relative"
            fi
            total=$((total + size))
            [ "$total" -le "$STATE_CONTEXT_MAX_BYTES" ] || \
                fail "context-memory total size exceeded"
            parent="${target%/*}"
            [ -d "$parent" ] && [ ! -L "$parent" ] || \
                fail "context-memory staged parent missing: $relative"
            temporary="${target}.migrate.$$"
            "$TOYBOX" cp "$item" "$temporary" || \
                fail "cannot stage context-memory file: $relative"
            chown 0:0 "$temporary"
            chmod 0600 "$temporary"
            validate_state_file "$temporary" "$CONTEXT_FILE_MAX" 0 0 600
            [ "$(sha256 "$item")" = "$(sha256 "$temporary")" ] || \
                fail "context-memory migration digest mismatch: $relative"
            rename_path_durable "$temporary" "$target" state.context_memory_file
        else
            fail "context-memory special file denied: $relative"
        fi
    done <"$list"
    rm -f "$list"
    log "migrated encrypted context-memory state files=$count bytes=$total"
}

migrate_audit_state() {
    local old_root="$1"
    local new_root="$2"
    local legacy="/root/.local/state/trillionnium-os/audit.sqlite"
    local current="/var/lib/trillionnium/state/trillionnium-os/audit.sqlite"
    local legacy_present=0
    local current_present=0
    local source suffix
    if [ -e "${old_root}${legacy}" ] || [ -L "${old_root}${legacy}" ]; then
        legacy_present=1
    fi
    if [ -e "${old_root}${current}" ] || [ -L "${old_root}${current}" ]; then
        current_present=1
    fi
    [ $((legacy_present + current_present)) -le 1 ] || \
        fail "ambiguous audit state exists at legacy and current paths"
    [ "$legacy_present" = "1" ] && source="$legacy" || source="$current"
    [ "$legacy_present" = "1" ] || [ "$current_present" = "1" ] || return 0
    copy_state_file "$old_root" "$source" "$new_root" "$current" \
        "$STATE_AUDIT_MAX_BYTES" 0 0 "600,640,644" 600
    for suffix in -wal -shm -journal; do
        copy_state_file "$old_root" "${source}${suffix}" "$new_root" "${current}${suffix}" \
            "$STATE_AUDIT_MAX_BYTES" 0 0 "600,640,644" 600
    done
}

migrate_agent_api_replay_state() {
    local old_root="$1"
    local new_root="$2"
    local legacy="/var/lib/trillionnium/agent-api-replay.json"
    local current="/var/lib/trillionnium/state/trillionnium-os/agent-api-replay.json"
    local legacy_present=0
    local current_present=0
    local source
    if [ -e "${old_root}${legacy}" ] || [ -L "${old_root}${legacy}" ]; then
        legacy_present=1
    fi
    if [ -e "${old_root}${current}" ] || [ -L "${old_root}${current}" ]; then
        current_present=1
    fi
    [ $((legacy_present + current_present)) -le 1 ] || \
        fail "ambiguous Agent API replay state exists at legacy and current paths"
    [ "$legacy_present" = "1" ] && source="$legacy" || source="$current"
    [ "$legacy_present" = "1" ] || [ "$current_present" = "1" ] || return 0
    copy_state_file "$old_root" "$source" "$new_root" "$current" \
        "$STATE_REPLAY_MAX_BYTES" 0 0 600 600
}

migrate_high_water_state() {
    local old_root="$1"
    local new_root="$2"
    local relative="/var/lib/trillionnium/direct-operation-custody/high-water-authority-v2"
    local source="${old_root}${relative}"
    local list item name count
    if [ ! -e "$source" ] && [ ! -L "$source" ]; then
        return 0
    fi
    ensure_no_symlink_components "$old_root" "$relative"
    [ ! -L "$source" ] && [ -d "$source" ] || \
        fail "high-water authority state root is not a real directory"
    [ "$($TOYBOX stat -c '%u:%g:%a' "$source")" = "0:0:700" ] || \
        fail "high-water authority state root owner or mode mismatch"
    list="${STAGING}/.high-water-state-list.$$"
    "$TOYBOX" find "$source" -maxdepth 1 -print >"$list" || \
        fail "cannot inventory high-water authority state"
    count=0
    while IFS= read -r item || [ -n "$item" ]; do
        [ "$item" != "$source" ] || continue
        name="${item##*/}"
        count=$((count + 1))
        [ "$count" -le 1 ] || fail "high-water authority state contains extra entries"
        [ "$name" = "authority-state-v2.json" ] || \
            fail "unrecognized high-water authority state denied: $name"
        [ ! -L "$item" ] && [ -f "$item" ] || \
            fail "high-water authority state is not a regular file"
    done <"$list"
    rm -f "$list"
    copy_state_file "$old_root" "${relative}/authority-state-v2.json" \
        "$new_root" "${relative}/authority-state-v2.json" \
        "$STATE_HIGH_WATER_MAX_BYTES" 0 0 600 600
}

migrate_allowlisted_state() {
    local old_root="$1"
    local new_root="$2"
    local codex_home
    [ -d "$new_root" ] && [ ! -L "$new_root" ] || \
        fail "state migration destination rootfs is not a real directory"
    if [ -e "$old_root" ] || [ -L "$old_root" ]; then
        [ -d "$old_root" ] && [ ! -L "$old_root" ] || \
            fail "state migration source rootfs is not a real directory"
    else
        return 0
    fi
    log "migrating strict allowlist of Agent credentials and OS control-plane state"
    # Never cross the UID 5901-owned 0700 boundary from the bootstrap domain.
    # Credentials are reprovisioned only through the root-owned bounded inbox,
    # which keeps DAC override/read-search out of the production TCB.
    codex_home="${old_root}/var/lib/trillionnium/agents/codex/home"
    if [ -e "$codex_home" ] || [ -L "$codex_home" ]; then
        log "Codex credential state intentionally not migrated; signed inbox reprovisioning required"
    fi
    reject_retired_provider_payload "$new_root"
    migrate_context_memory "$old_root" "$new_root"
    migrate_agent_api_replay_state "$old_root" "$new_root"
    migrate_audit_state "$old_root" "$new_root"
    migrate_high_water_state "$old_root" "$new_root"
    sync_filesystems
    log "allowlisted state migration staged and synced"
}

if [ "${TRILLIONNIUM_BOOTSTRAP_MIGRATION_ONLY:-0}" = "1" ]; then
    migration_old="${TRILLIONNIUM_BOOTSTRAP_MIGRATION_OLD_ROOT:-}"
    migration_new="${TRILLIONNIUM_BOOTSTRAP_MIGRATION_NEW_ROOT:-}"
    [ -n "$migration_old" ] && [ -n "$migration_new" ] || \
        fail "migration-only mode requires explicit old and new roots"
    case "${migration_old}:${migration_new}" in
        /tmp/*:/tmp/*|/data/local/tmp/*:/data/local/tmp/*) ;;
        *) fail "migration-only roots must remain in an explicit test directory" ;;
    esac
    STAGING="${TRILLIONNIUM_BOOTSTRAP_MIGRATION_SCRATCH:-${migration_new}}"
    migrate_allowlisted_state "$migration_old" "$migration_new"
    exit 0
fi

ensure_no_android_data_tree() {
    # The Android /data tree is outside the rootfs contract. If a payload archive
    # accidentally carries top-level ./data entries, stop before hardening would
    # traverse data/local and cross into system_data_file policy.
    if [ -e "${STAGING}/rootfs/data" ] || [ -L "${STAGING}/rootfs/data" ]; then
        fail "rootfs payload unexpectedly contains top-level /data"
    fi
}

verify_fresh_v2_archive_layout() {
    root="${STAGING}/rootfs"
    [ "$($TOYBOX stat -c '%u:%g:%a' "$root")" = "0:0:755" ] ||
        fail "fresh rootfs carrier directory ownership or mode mismatch"
    for relative in \
        bin sbin lib etc etc/apt etc/trillionnium etc/trillionnium/agents \
        usr usr/bin usr/sbin usr/local usr/local/bin \
        usr/lib/trillionnium usr/lib/trillionnium/agents \
        usr/lib/trillionnium/agents/codex \
        usr/lib/trillionnium/agents/codex/0.144.1 \
        usr/lib/trillionnium/agents/codex/0.144.1/aarch64-unknown-linux-musl \
        usr/lib/trillionnium/agents/codex/0.144.1/aarch64-unknown-linux-musl/bin; do
        path="${root}/${relative}"
        [ -d "$path" ] && [ ! -L "$path" ] ||
            fail "fresh rootfs /$relative is not a real directory"
        [ "$($TOYBOX stat -c '%u:%g:%a' "$path")" = "0:0:555" ] ||
            fail "fresh rootfs /$relative ownership or mode mismatch"
    done
    [ -L "${root}/bin/sh" ] && [ "$(readlink "${root}/bin/sh")" = dash ] ||
        fail "fresh rootfs /bin/sh relative symlink mismatch"
    verify_rootfs_regular "${root}/bin/dash" \
        15fc4c72f49c86639a383121eec6fbdbcd32ec9d03db915cb3096928295e1a17 555 ||
        fail "fresh rootfs /bin/dash mismatch"
    verify_rootfs_regular "${root}/bin/touch" \
        866e7f7d08fc061d62dc5ba5c88785f0ecbcd3eebf3a533ea29b38a462622c42 555 ||
        fail "fresh rootfs /bin/touch mismatch"
    [ -L "${root}/usr/bin/touch" ] &&
        [ "$(readlink "${root}/usr/bin/touch")" = ../../bin/touch ] ||
        fail "fresh rootfs /usr/bin/touch relative symlink mismatch"
    [ -L "${root}/lib/ld-linux-aarch64.so.1" ] &&
        [ "$(readlink "${root}/lib/ld-linux-aarch64.so.1")" = \
            aarch64-linux-gnu/ld-linux-aarch64.so.1 ] ||
        fail "fresh rootfs loader relative symlink mismatch"
    verify_rootfs_regular \
        "${root}/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" \
        17538b8f9889a470c061f69a8fea8124da89627311cd16546c133a89f09056df 555 ||
        fail "fresh rootfs loader mismatch"
    verify_rootfs_regular "${root}/lib/aarch64-linux-gnu/libc.so.6" \
        e4ac8ae1d81e4865e3aadedb962879cf9415903b3f2ba81ec75e9962b86ab8b0 555 ||
        fail "fresh rootfs libc mismatch"
    verify_rootfs_regular "${root}/lib/aarch64-linux-gnu/libm.so.6" \
        3c4cb3be0b974edf05f023f85ab15107fb5afc2687163593d0d4cf8e80c17b39 444 ||
        fail "fresh rootfs libm mismatch"
    verify_rootfs_regular "${root}/lib/aarch64-linux-gnu/libgcc_s.so.1" \
        046856f95f4636f1fc7c3a12bf4f3cd5634c2fc5145c3fdf7395d4f349fa69c7 444 ||
        fail "fresh rootfs libgcc_s mismatch"
    for legacy in \
        usr/lib/ld-linux-aarch64.so.1 \
        usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 \
        usr/lib/aarch64-linux-gnu/libc.so.6 \
        usr/lib/aarch64-linux-gnu/libm.so.6 \
        usr/lib/aarch64-linux-gnu/libgcc_s.so.1; do
        [ ! -e "${root}/${legacy}" ] && [ ! -L "${root}/${legacy}" ] ||
            fail "legacy usrmerge runtime path is forbidden: /$legacy"
    done
    verify_rootfs_regular "${root}/usr/bin/trillionniumd" \
        "$ROOTFS_ARCHIVE_DAEMON_SHA256" 555 ||
        fail "archive-owned Agent daemon mismatch"
    verify_rootfs_regular \
        "${root}/usr/local/bin/trillionnium-system-api-replay-sync" \
        "$ROOTFS_ARCHIVE_REPLAY_SYNC_SHA256" 555 ||
        fail "archive-owned replay-sync mismatch"
    verify_rootfs_regular \
        "${root}/usr/local/bin/trillionnium-agent-system-api" \
        "$ROOTFS_ARCHIVE_SYSTEM_API_SHA256" 555 ||
        fail "archive-owned System API tool mismatch"
    verify_rootfs_regular \
        "${root}/usr/local/bin/trillionnium-agent-accessibility" \
        "$ROOTFS_ARCHIVE_ACCESSIBILITY_SHA256" 555 ||
        fail "archive-owned Accessibility tool mismatch"
    verify_rootfs_regular \
        "${root}/usr/lib/trillionnium/agents/codex/0.144.1/aarch64-unknown-linux-musl/bin/codex" \
        "$ROOTFS_ARCHIVE_CODEX_LAUNCHER_SHA256" 555 ||
        fail "archive-owned Codex launcher mismatch"
    verify_rootfs_regular "${root}/${CODEX_RUNTIME_ROOTFS_PATH}" \
        "$ROOTFS_EMPTY_SHA256" 555 ||
        fail "archive-owned Codex runtime placeholder mismatch"
    verify_rootfs_regular \
        "${root}/etc/trillionnium/agents/agent-codex-direct-v1.json" \
        "$ROOTFS_ARCHIVE_AGENT_MANIFEST_SHA256" 444 ||
        fail "archive-owned AgentManifest mismatch"
    verify_rootfs_regular "${root}/etc/apt/sources.list" \
        "$ROOTFS_APT_SOURCES_SHA256" 444 ||
        fail "archive apt sources mismatch"
    verify_rootfs_regular "${root}/etc/passwd" "$ROOTFS_PASSWD_SHA256" 444 ||
        fail "archive passwd mismatch"
    verify_rootfs_regular "${root}/etc/group" "$ROOTFS_GROUP_SHA256" 444 ||
        fail "archive group mismatch"
    verify_rootfs_regular "${root}/etc/nsswitch.conf" \
        "$ROOTFS_NSSWITCH_SHA256" 444 ||
        fail "archive nsswitch mismatch"
    verify_rootfs_regular "${root}/etc/shells" "$ROOTFS_SHELLS_SHA256" 444 ||
        fail "archive shells mismatch"
    [ -L "${root}/etc/alternatives/awk" ] &&
        [ "$(readlink "${root}/etc/alternatives/awk")" = ../../usr/bin/mawk ] &&
        [ -L "${root}/usr/bin/awk" ] &&
        [ "$(readlink "${root}/usr/bin/awk")" = ../../etc/alternatives/awk ] ||
        fail "archive awk alternatives mismatch"
}

restore_existing_labels() {
    for path in "$@"; do
        [ -e "$path" ] || continue
        restorecon "$path" || fail "cannot restore rootlinux label: $path"
    done
}

restore_rootlinux_top_labels() {
    restore_existing_labels /data/trillionnium "$DATA_DIR" "$ROOTFS" "$STAMP" "$LOG_FILE" "$STAGING" "${STAGING}/rootfs"
}

ensure_in_staging_rootfs() {
    path="$1"
    root="${STAGING}/rootfs"
    case "$path" in
        "$root"|"$root"/*) ;;
        *) fail "refusing to touch path outside staging rootfs: $path" ;;
    esac
}

verify_materialized_readonly_config_contract() {
    local root="$1"
    local relative
    for relative in \
        etc etc/apt etc/trillionnium etc/trillionnium/agents \
        usr usr/bin usr/sbin usr/local usr/local/bin \
        usr/lib/trillionnium usr/lib/trillionnium/agents \
        usr/lib/trillionnium/agents/codex \
        usr/lib/trillionnium/agents/codex/0.144.1 \
        usr/lib/trillionnium/agents/codex/0.144.1/aarch64-unknown-linux-musl \
        usr/lib/trillionnium/agents/codex/0.144.1/aarch64-unknown-linux-musl/bin; do
        verify_rootfs_directory "${root}/${relative}" 555 || return 1
    done
    verify_rootfs_regular "${root}/etc/apt/sources.list" \
        "$ROOTFS_APT_SOURCES_SHA256" 444 || return 1
    verify_rootfs_regular "${root}/etc/passwd" "$ROOTFS_PASSWD_SHA256" 444 || return 1
    verify_rootfs_regular "${root}/etc/group" "$ROOTFS_GROUP_SHA256" 444 || return 1
    verify_rootfs_regular "${root}/etc/nsswitch.conf" \
        "$ROOTFS_NSSWITCH_SHA256" 444 || return 1
    verify_rootfs_regular "${root}/etc/shells" "$ROOTFS_SHELLS_SHA256" 444 || return 1
    verify_rootfs_regular "${root}/etc/resolv.conf" \
        "$ROOTFS_RESOLV_CONF_SHA256" 444 || return 1
    verify_rootfs_regular "${root}/etc/hosts" "$ROOTFS_HOSTS_SHA256" 444 || return 1
    verify_rootfs_regular "${root}/etc/shadow" "$ROOTFS_SHADOW_SHA256" 440 "0:42" ||
        return 1
    verify_rootfs_regular "${root}/etc/gshadow" "$ROOTFS_GSHADOW_SHA256" 440 "0:42" ||
        return 1
    verify_rootfs_regular "${root}/usr/sbin/policy-rc.d" \
        "$ROOTFS_POLICY_RC_D_SHA256" 555 || return 1
    fresh_v2_adb_placeholder_layout_matches "$root" || return 1
    [ -L "${root}/etc/alternatives/awk" ] &&
        [ "$(readlink "${root}/etc/alternatives/awk")" = ../../usr/bin/mawk ] &&
        [ -L "${root}/usr/bin/awk" ] &&
        [ "$(readlink "${root}/usr/bin/awk")" = ../../etc/alternatives/awk ]
}

verify_materialized_directory_mode_contract() {
    local root="$1"
    local inventory relative metadata binding
    inventory="$("$TOYBOX" find "$root" -xdev \
        \( -path "${root}/proc" -o -path "${root}/tmp" -o \
           -path "${root}/run/trillionnium" -o \
           -path "${root}/var/lib/trillionnium" \) -prune -o \
        -type d -printf '%P|%U:%G:%m\n')" || return 1
    printf '%s\n' "$inventory" | while IFS='|' read -r relative metadata; do
        [ -n "$metadata" ] || return 1
        if [ -z "$relative" ]; then
            [ "$metadata" = "0:0:755" ] || return 1
            continue
        fi
        [ "$metadata" = "0:0:555" ] || return 1
    done || return 1
    for binding in \
        proc:0:0:700 \
        run/trillionnium:0:0:750 \
        tmp:0:0:1777 \
        var/lib/trillionnium:0:0:711 \
        var/lib/trillionnium/agent-tools:0:0:711 \
        var/lib/trillionnium/agents:0:0:711 \
        var/lib/trillionnium/agents/codex:0:0:711 \
        var/lib/trillionnium/agents/codex/home:5901:5901:700; do
        relative="${binding%%:*}"
        metadata="${binding#*:}"
        verify_rootfs_directory "${root}/${relative}" "${metadata##*:}" \
            "${metadata%:*}" || return 1
    done
    for relative in \
        var/lib/trillionnium/context-memory \
        var/lib/trillionnium/context-memory/payloads \
        var/lib/trillionnium/context-memory/ui-replay \
        var/lib/trillionnium/context-memory/ui-replay-outcomes \
        var/lib/trillionnium/context-memory/execution-payloads \
        var/lib/trillionnium/context-memory/execution-payload-quarantine \
        var/lib/trillionnium/state \
        var/lib/trillionnium/state/trillionnium-os \
        var/lib/trillionnium/direct-operation-custody \
        var/lib/trillionnium/direct-operation-custody/high-water-authority-v2; do
        [ ! -e "${root}/${relative}" ] && [ ! -L "${root}/${relative}" ] && continue
        verify_rootfs_directory "${root}/${relative}" 700 || return 1
    done
}

harden_rootfs() {
    local root="${STAGING}/rootfs"
    require_staging_rootfs_path "$root"
    log "materializing the closed fresh-v2 runtime mutation allowlist"

    # The archive SHA and member contract make package-owned configuration
    # immutable input. Verify these files exactly instead of rewriting them.
    verify_rootfs_regular "${root}/etc/apt/sources.list" \
        "$ROOTFS_APT_SOURCES_SHA256" 444 ||
        fail "archive apt sources differ from the fresh-v2 contract"
    verify_rootfs_regular "${root}/etc/passwd" "$ROOTFS_PASSWD_SHA256" 444 ||
        fail "archive passwd differs from the fresh-v2 contract"
    verify_rootfs_regular "${root}/etc/group" "$ROOTFS_GROUP_SHA256" 444 ||
        fail "archive group differs from the fresh-v2 contract"
    verify_rootfs_regular "${root}/etc/nsswitch.conf" \
        "$ROOTFS_NSSWITCH_SHA256" 444 ||
        fail "archive nsswitch differs from the fresh-v2 contract"
    verify_rootfs_regular "${root}/etc/shells" "$ROOTFS_SHELLS_SHA256" 444 ||
        fail "archive shells differs from the fresh-v2 contract"
    [ -L "${root}/etc/alternatives/awk" ] &&
        [ "$(readlink "${root}/etc/alternatives/awk")" = ../../usr/bin/mawk ] &&
        [ -L "${root}/usr/bin/awk" ] &&
        [ "$(readlink "${root}/usr/bin/awk")" = ../../etc/alternatives/awk ] ||
        fail "archive awk alternatives differ from the fresh-v2 contract"

    # Only five absent, deterministic non-state files are added. Their two
    # exact parent directories are writable only while the unpublished staging
    # rootfs is being updated, and every file is O_EXCL/O_NOFOLLOW published,
    # fsynced, measured, and stripped of owner write before the parent refreeze.
    set_step "materialize immutable rootfs config"
    thaw_staging_directory "$root" etc materialize.rootfs_config
    create_staging_regular_no_replace "${root}/etc/resolv.conf" 444 0 0 \
        materialize.rootfs_config.resolv lines \
        "# Trillionnium Android-hosted rootfs DNS" \
        "nameserver 1.1.1.1" \
        "nameserver 8.8.8.8" \
        "options timeout:2 attempts:3"
    create_staging_regular_no_replace "${root}/etc/hosts" 444 0 0 \
        materialize.rootfs_config.hosts lines \
        "127.0.0.1 localhost" \
        "::1 localhost ip6-localhost ip6-loopback"
    create_staging_regular_no_replace "${root}/etc/shadow" 440 0 42 \
        materialize.rootfs_config.shadow lines \
        "root:*:19793:0:99999:7:::" \
        "daemon:*:19793:0:99999:7:::" \
        "bin:*:19793:0:99999:7:::" \
        "sys:*:19793:0:99999:7:::" \
        "sync:*:19793:0:99999:7:::" \
        "games:*:19793:0:99999:7:::" \
        "man:*:19793:0:99999:7:::" \
        "lp:*:19793:0:99999:7:::" \
        "mail:*:19793:0:99999:7:::" \
        "news:*:19793:0:99999:7:::" \
        "uucp:*:19793:0:99999:7:::" \
        "proxy:*:19793:0:99999:7:::" \
        "www-data:*:19793:0:99999:7:::" \
        "backup:*:19793:0:99999:7:::" \
        "list:*:19793:0:99999:7:::" \
        "irc:*:19793:0:99999:7:::" \
        "_apt:*:19793:0:99999:7:::" \
        "nobody:*:19793:0:99999:7:::"
    create_staging_regular_no_replace "${root}/etc/gshadow" 440 0 42 \
        materialize.rootfs_config.gshadow lines \
        "root:*::" \
        "shadow:*::" \
        "nogroup:*::"
    refreeze_staging_directory "$root" etc materialize.rootfs_config

    thaw_staging_directory "$root" usr/sbin materialize.policy_rc_d
    create_staging_regular_no_replace "${root}/usr/sbin/policy-rc.d" 555 0 0 \
        materialize.policy_rc_d lines \
        "#!/bin/sh" \
        "exit 101"
    refreeze_staging_directory "$root" usr/sbin materialize.policy_rc_d

    # These are the only non-read-only runtime mount/scratch directories in the
    # base skeleton. Persistent state below /var/lib/trillionnium is handled by
    # the separate no-follow state migration and credential contracts.
    chmod 0750 "${root}/run/trillionnium" ||
        fail "cannot set the runtime socket directory mode"
    chmod 1777 "${root}/tmp" || fail "cannot set the runtime tmp mode"
    [ "$($TOYBOX stat -c '%u:%g:%a' "${root}/run/trillionnium")" = "0:0:750" ] ||
        fail "runtime socket directory mode mismatch"
    [ "$($TOYBOX stat -c '%u:%g:%a' "${root}/tmp")" = "0:0:1777" ] ||
        fail "runtime tmp directory mode mismatch"
    fsync_path "${root}/run/trillionnium" materialize.runtime_run.mode_fsync
    fsync_path "${root}/tmp" materialize.runtime_tmp.mode_fsync

    verify_materialized_readonly_config_contract "$root" ||
        fail "fresh-v2 materialized readonly config contract mismatch"
}

rootfs_dpkg_status_sane() {
    local root="$1"
    local status_file="${root}/var/lib/dpkg/status"
    local package_count
    [ -s "$status_file" ] && [ ! -L "$status_file" ] || return 1
    package_count="$("$TOYBOX" grep -c '^Package: ' "$status_file" 2>/dev/null)" || \
        package_count=0
    [ "$package_count" -gt 0 ] && [ "$package_count" -le 1000 ]
}

rootfs_dpkg_status_matches_current_contract() {
    local root="$1"
    local status_file="${root}/var/lib/dpkg/status"
    local package package_count
    rootfs_dpkg_status_sane "$root" || return 1
    package_count="$("$TOYBOX" grep -c '^Package: ' "$status_file" 2>/dev/null)" || \
        package_count=0
    [ "$package_count" = "$ROOTFS_DPKG_PACKAGE_COUNT" ] || return 1
    [ "$(sha256 "$status_file")" = "$ROOTFS_DPKG_STATUS_SHA256" ] || return 1
    for package in \
        base-files base-passwd ca-certificates coreutils dash debconf \
        debianutils diffutils dpkg findutils gcc-12-base grep gzip libacl1 \
        libattr1 libbz2-1.0 libc-bin libc6 libcrypt1 libdebconfclient0 \
        libgcc-s1 libgmp10 liblzma5 libmd0 libpcre2-8-0 libselinux1 \
        libssl3 libstdc++6 libzstd1 mawk openssl perl-base sed tar zlib1g; do
        [ "$("$TOYBOX" grep -F -x -c "Package: $package" "$status_file")" = 1 ] || \
            return 1
    done
    ! "$TOYBOX" grep -Eiq \
        '^Package: (phosh|gnome-shell|xwayland|squeekboard|mobian|trillionnium-command-center)$' \
        "$status_file"
}

verify_configured_dpkg_status() {
    local status_file="${STAGING}/rootfs/var/lib/dpkg/status"
    local package_count
    rootfs_dpkg_status_matches_current_contract "${STAGING}/rootfs" || \
        fail "configured rootfs does not match the exact 35-package contract"
    package_count="$("$TOYBOX" grep -c '^Package: ' "$status_file" 2>/dev/null)" || \
        package_count=0
    log "configured dpkg status packages=$package_count"
}

stamp_value() {
    local path="$1"
    local size links lines metadata value
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    size="$("$TOYBOX" stat -c %s "$path" 2>/dev/null)" || return 1
    links="$("$TOYBOX" stat -c %h "$path" 2>/dev/null)" || return 1
    lines="$("$TOYBOX" wc -l <"$path" 2>/dev/null)" || return 1
    metadata="$("$TOYBOX" stat -c '%u:%g:%a' "$path" 2>/dev/null)" || return 1
    case "$size" in ''|*[!0-9]*) return 1 ;; esac
    [ "$size" -gt 0 ] && [ "$size" -le 4096 ] && [ "$links" = 1 ] && \
        [ "$lines" = 1 ] && [ "$metadata" = "0:0:600" ] || return 1
    value="$("$TOYBOX" cat "$path" 2>/dev/null)" || return 1
    [ -n "$value" ] || return 1
    echo "$value"
}

stamp_matches_payload() {
    local value
    value="$(stamp_value "$1")" || return 1
    [ "$value" = "$PAYLOAD_KEY" ]
}

stamp_has_payload_contract() {
    local path="$1"
    local receipt field value
    local seen_layout=0 seen_bootstrap=0 seen_rootfs=0
    local seen_package=0 seen_codex=0
    receipt="$(stamp_value "$path")" || return 1
    set -f
    set -- $receipt
    set +f
    [ "$#" -ge 4 ] && [ "$#" -le 5 ] || return 1
    for field in "$@"; do
        value="${field#*=}"
        [ "$value" != "$field" ] && [ -n "$value" ] || return 1
        case "$field" in
            layout=*)
                [ "$seen_layout" = 0 ] || return 1
                [ "${#value}" -le 128 ] || return 1
                case "$value" in *[!A-Za-z0-9._-]*) return 1 ;; esac
                seen_layout=1
                ;;
            bootstrap=*)
                [ "$seen_bootstrap" = 0 ] && validate_hex_token "$value" 64 || return 1
                seen_bootstrap=1
                ;;
            rootfs=*)
                [ "$seen_rootfs" = 0 ] && validate_hex_token "$value" 64 || return 1
                seen_rootfs=1
                ;;
            package=*)
                [ "$seen_package" = 0 ] && validate_hex_token "$value" 64 || return 1
                seen_package=1
                ;;
            codex_manifest=*)
                [ "$seen_codex" = 0 ] && validate_hex_token "$value" 64 || return 1
                seen_codex=1
                ;;
            *) return 1 ;;
        esac
    done
    [ "$seen_layout" = 1 ] && [ "$seen_bootstrap" = 1 ] && \
        [ "$seen_rootfs" = 1 ] && [ "$seen_codex" = 1 ]
}

verify_complete_rootfs_skeleton() {
    local root="$1"
    [ -d "$root" ] && [ ! -L "$root" ] || return 1
    executable_mode_is_canonical "${root}/bin/sh" || return 1
    executable_mode_is_canonical "${root}/usr/bin/trillionniumd" && \
        [ ! -L "${root}/usr/bin/trillionniumd" ] || return 1
    rootfs_dpkg_status_sane "$root"
}

fresh_v2_installed_layout_matches() {
    local root="$1"
    local relative path expected_agentd_sha256
    for relative in bin sbin lib; do
        path="${root}/${relative}"
        [ -d "$path" ] && [ ! -L "$path" ] || return 1
        [ "$("$TOYBOX" stat -c '%u:%g:%a' "$path")" = "0:0:555" ] || return 1
    done
    [ -L "${root}/bin/sh" ] && [ "$(readlink "${root}/bin/sh")" = dash ] || return 1
    verify_rootfs_regular "${root}/bin/dash" \
        15fc4c72f49c86639a383121eec6fbdbcd32ec9d03db915cb3096928295e1a17 555 || \
        return 1
    verify_rootfs_regular "${root}/bin/touch" \
        866e7f7d08fc061d62dc5ba5c88785f0ecbcd3eebf3a533ea29b38a462622c42 555 || \
        return 1
    [ -L "${root}/usr/bin/touch" ] && \
        [ "$(readlink "${root}/usr/bin/touch")" = ../../bin/touch ] || return 1
    [ -L "${root}/lib/ld-linux-aarch64.so.1" ] && \
        [ "$(readlink "${root}/lib/ld-linux-aarch64.so.1")" = \
            aarch64-linux-gnu/ld-linux-aarch64.so.1 ] || return 1
    verify_rootfs_regular \
        "${root}/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" \
        17538b8f9889a470c061f69a8fea8124da89627311cd16546c133a89f09056df 555 || \
        return 1
    verify_rootfs_regular "${root}/lib/aarch64-linux-gnu/libc.so.6" \
        e4ac8ae1d81e4865e3aadedb962879cf9415903b3f2ba81ec75e9962b86ab8b0 555 || \
        return 1
    verify_rootfs_regular "${root}/lib/aarch64-linux-gnu/libm.so.6" \
        3c4cb3be0b974edf05f023f85ab15107fb5afc2687163593d0d4cf8e80c17b39 444 || \
        return 1
    verify_rootfs_regular "${root}/lib/aarch64-linux-gnu/libgcc_s.so.1" \
        046856f95f4636f1fc7c3a12bf4f3cd5634c2fc5145c3fdf7395d4f349fa69c7 444 || \
        return 1
    for relative in \
        usr/lib/ld-linux-aarch64.so.1 \
        usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 \
        usr/lib/aarch64-linux-gnu/libc.so.6 \
        usr/lib/aarch64-linux-gnu/libm.so.6 \
        usr/lib/aarch64-linux-gnu/libgcc_s.so.1; do
        [ ! -e "${root}/${relative}" ] && [ ! -L "${root}/${relative}" ] || return 1
    done
    expected_agentd_sha256="$ROOTFS_ARCHIVE_DAEMON_SHA256"
    [ -z "$P01_AGENTD_SHA256" ] || expected_agentd_sha256="$P01_AGENTD_SHA256"
    verify_rootfs_regular "${root}/usr/bin/trillionniumd" \
        "$expected_agentd_sha256" 555 || return 1
    verify_rootfs_regular \
        "${root}/usr/local/bin/trillionnium-system-api-replay-sync" \
        "$ROOTFS_ARCHIVE_REPLAY_SYNC_SHA256" 555 || return 1
    verify_rootfs_regular \
        "${root}/usr/local/bin/trillionnium-agent-system-api" \
        "$ROOTFS_ARCHIVE_SYSTEM_API_SHA256" 555 || return 1
    verify_rootfs_regular \
        "${root}/usr/local/bin/trillionnium-agent-accessibility" \
        "$ROOTFS_ARCHIVE_ACCESSIBILITY_SHA256" 555 || return 1
    verify_rootfs_regular \
        "${root}/usr/lib/trillionnium/agents/codex/0.144.1/aarch64-unknown-linux-musl/bin/codex" \
        "$ROOTFS_ARCHIVE_CODEX_LAUNCHER_SHA256" 555 || return 1
    verify_rootfs_regular "${root}/${CODEX_RUNTIME_ROOTFS_PATH}" \
        "$ROOTFS_EMPTY_SHA256" 555 || return 1
    verify_materialized_readonly_config_contract "$root" || return 1
    verify_materialized_directory_mode_contract "$root" || return 1
    fresh_v2_p01_replay_placeholder_layout_matches "$root" || return 1
    rootfs_dpkg_status_matches_current_contract "$root"
}

executable_mode_is_canonical() {
    local path="$1"
    local mode
    [ -f "$path" ] || return 1
    mode="$($TOYBOX stat -L -c %a "$path" 2>/dev/null)" || return 1
    case "$mode" in
        555|755) return 0 ;;
        *) return 1 ;;
    esac
}

verify_complete_pair() {
    local root="$1"
    local stamp_path="$2"
    verify_complete_rootfs_skeleton "$root" && \
        stamp_has_payload_contract "$stamp_path"
}

verify_current_rootfs() {
    local root="$1"
    verify_complete_rootfs_skeleton "$root" && \
        fresh_v2_installed_layout_matches "$root" && \
        verify_agentd_direct_identity "$root" && \
        [ -f "${root}/${CODEX_RUNTIME_ROOTFS_PATH}" ] && \
        [ ! -L "${root}/${CODEX_RUNTIME_ROOTFS_PATH}" ] && \
        [ "$($TOYBOX stat -c '%u:%g:%a:%s' "${root}/${CODEX_RUNTIME_ROOTFS_PATH}")" = \
            "0:0:555:0" ] && \
        verify_installed_agent_manifests "$root"
}

verify_current_pair() {
    local root="$1"
    local stamp_path="$2"
    stamp_matches_payload "$stamp_path" && verify_current_rootfs "$root"
}

verify_current_sources_quiet() {
    verify_selected_rootfs_evidence_quiet || return 1
    verify_payload_source_file_quiet \
        "$CODEX_AGENT_MANIFEST" "$CODEX_AGENT_MANIFEST_SHA256" || return 1
    verify_tar_staging_filter_identity
}

ensure_current_sources_verified() {
    [ "$CURRENT_SOURCES_VERIFIED" = 1 ] && return 0
    verify_current_sources_quiet || \
        fail "current archive/manifest inputs are incomplete during transaction recovery"
    CURRENT_SOURCES_VERIFIED=1
    log "verified current archive/manifest inputs for transaction recovery"
}

slot_exists() {
    [ -e "$1" ] || [ -L "$1" ]
}

normalize_legacy_transaction_artifacts() {
    local candidate count legacy_staging legacy_stamp legacy_stamp_backup legacy_rollback
    legacy_staging=
    legacy_stamp=
    legacy_stamp_backup=
    legacy_rollback=

    count=0
    for candidate in "${DATA_DIR}"/.staging.*; do
        slot_exists "$candidate" || continue
        count=$((count + 1))
        legacy_staging="$candidate"
    done
    [ "$count" -le 1 ] || fail "ambiguous legacy staging transaction artifacts"

    count=0
    for candidate in "${DATA_DIR}"/.stamp.*; do
        slot_exists "$candidate" || continue
        case "${candidate##*/}" in .stamp.previous.*) continue ;; esac
        count=$((count + 1))
        legacy_stamp="$candidate"
    done
    [ "$count" -le 1 ] || fail "ambiguous legacy staged stamp artifacts"

    count=0
    for candidate in "${DATA_DIR}"/.stamp.previous.*; do
        slot_exists "$candidate" || continue
        count=$((count + 1))
        legacy_stamp_backup="$candidate"
    done
    [ "$count" -le 1 ] || fail "ambiguous legacy stamp backup artifacts"

    count=0
    for candidate in "${DATA_DIR}"/.rollback-new.*; do
        slot_exists "$candidate" || continue
        count=$((count + 1))
        legacy_rollback="$candidate"
    done
    [ "$count" -le 1 ] || fail "ambiguous legacy rollback rootfs artifacts"

    if [ -n "$legacy_staging" ]; then
        [ -d "$legacy_staging" ] && [ ! -L "$legacy_staging" ] || \
            fail "legacy staging artifact is unsafe"
        ! slot_exists "$STAGING" || fail "legacy and fixed staging slots both exist"
        rename_path_durable "$legacy_staging" "$STAGING" \
            reconcile.legacy_staging
    fi
    if [ -n "$legacy_stamp" ]; then
        [ -f "$legacy_stamp" ] && [ ! -L "$legacy_stamp" ] || \
            fail "legacy staged stamp artifact is unsafe"
        ! slot_exists "$STAMP_TMP" || fail "legacy and fixed staged stamps both exist"
        rename_path_durable "$legacy_stamp" "$STAMP_TMP" \
            reconcile.legacy_staged_stamp
    fi
    if [ -n "$legacy_stamp_backup" ]; then
        [ -f "$legacy_stamp_backup" ] && [ ! -L "$legacy_stamp_backup" ] || \
            fail "legacy stamp backup artifact is unsafe"
        ! slot_exists "$STAMP_BACKUP" || fail "legacy and fixed stamp backups both exist"
        rename_path_durable "$legacy_stamp_backup" "$STAMP_BACKUP" \
            reconcile.legacy_stamp_backup
    fi
    if [ -n "$legacy_rollback" ]; then
        [ -d "$legacy_rollback" ] && [ ! -L "$legacy_rollback" ] || \
            fail "legacy rollback rootfs artifact is unsafe"
        if slot_exists "$STAGING"; then
            [ -d "$STAGING" ] && [ ! -L "$STAGING" ] && \
                [ -z "$("$TOYBOX" find "$STAGING" -mindepth 1 -print -quit 2>/dev/null)" ] || \
                fail "legacy rollback and nonempty fixed staging slots both exist"
        else
            mkdir "$STAGING" || fail "cannot create fixed staging slot for legacy rollback"
            fsync_path "$DATA_DIR" reconcile.legacy_rollback.mkdir_parent_fsync
        fi
        rename_path_durable "$legacy_rollback" "${STAGING}/rootfs" \
            reconcile.legacy_rollback
    fi
}

transaction_artifacts_present() {
    slot_exists "$STAGING" || slot_exists "$ROOTFS_BACKUP" || \
        slot_exists "$STAMP_TMP" || slot_exists "$STAMP_BACKUP"
}

retire_rootfs_backup() {
    local reason="$1"
    local backup="$ROOTFS_BACKUP"
    slot_exists "$backup" || return 0
    [ -d "$backup" ] && [ ! -L "$backup" ] || \
        fail "rootfs backup slot is unsafe"
    log "retiring rootfs.previous after selecting complete $reason pair"
    declassify_retired_rootfs "$backup" || \
        fail "cannot declassify rootfs.previous during reconciliation"
    remove_generated_tree "$backup" cleanup.rootfs_backup || \
        fail "cannot remove retired rootfs.previous during reconciliation"
}

discard_staging_artifact() {
    local reason="$1"
    slot_exists "$STAGING" || return 0
    [ -d "$STAGING" ] && [ ! -L "$STAGING" ] || \
        fail "staging transaction slot is unsafe"
    if slot_exists "${STAGING}/rootfs"; then
        [ -d "${STAGING}/rootfs" ] && [ ! -L "${STAGING}/rootfs" ] || \
            fail "staged rootfs artifact is unsafe"
        ! slot_exists "$ROOTFS_BACKUP" || \
            fail "cannot retire staged orphan while rootfs.previous is occupied"
        log "isolating staged rootfs orphan after selecting complete $reason pair"
        rename_path_durable "${STAGING}/rootfs" "$ROOTFS_BACKUP" \
            cleanup.staged_rootfs
        retire_rootfs_backup "$reason"
    fi
    remove_generated_tree "$STAGING" cleanup.staging || \
        fail "cannot remove empty staging transaction slot"
}

cleanup_selected_pair_artifacts() {
    local reason="$1"
    # Free rootfs.previous before retiring a staged root that may have carried
    # live executable labels in a partially rolled-back legacy transaction.
    retire_rootfs_backup "$reason"
    remove_file_durable "$STAMP_BACKUP" cleanup.stamp_backup
    # Retire the staged receipt before a rejected staged tree is moved through
    # rootfs.previous for bounded declassification.  Otherwise a second crash
    # could make that cleanup tombstone look paired with stamp.staging.
    remove_file_durable "$STAMP_TMP" cleanup.staged_stamp
    discard_staging_artifact "$reason"
}

finish_live_current_rootfs() {
    ensure_current_sources_verified
    verify_current_rootfs "$ROOTFS" && stamp_matches_payload "$STAMP_TMP" || \
        fail "cannot finish an unverified current rootfs/staged-stamp pair"

    if slot_exists "$STAMP"; then
        ! slot_exists "$STAMP_BACKUP" || \
            fail "live and backup stamps both occupy the old-pair slot"
        verify_complete_pair "$ROOTFS_BACKUP" "$STAMP" || \
            fail "live stamp is not paired with rootfs.previous"
        rename_path_durable "$STAMP" "$STAMP_BACKUP" publish.old_stamp
    elif slot_exists "$STAMP_BACKUP"; then
        verify_complete_pair "$ROOTFS_BACKUP" "$STAMP_BACKUP" || \
            fail "stamp.previous is not paired with rootfs.previous"
    elif slot_exists "$ROOTFS_BACKUP"; then
        fail "rootfs.previous has no complete old stamp pair"
    fi

    rename_path_durable "$STAMP_TMP" "$STAMP" publish.new_stamp
    verify_current_pair "$ROOTFS" "$STAMP" || \
        fail "published current rootfs/stamp pair failed verification"
    log "selected complete new rootfs/stamp pair during reconciliation"
    cleanup_selected_pair_artifacts new
}

publish_staged_current_rootfs() {
    ensure_current_sources_verified
    verify_current_pair "${STAGING}/rootfs" "$STAMP_TMP" || \
        fail "staged rootfs/stamp pair is not a complete current candidate"

    if slot_exists "$ROOTFS"; then
        ! slot_exists "$ROOTFS_BACKUP" || \
            fail "live and backup rootfs slots are both occupied before publish"
        verify_complete_pair "$ROOTFS" "$STAMP" || \
            fail "refusing to replace an incomplete live rootfs/stamp pair"
        rename_path_durable "$ROOTFS" "$ROOTFS_BACKUP" publish.old_rootfs
    elif slot_exists "$ROOTFS_BACKUP"; then
        if ! verify_complete_pair "$ROOTFS_BACKUP" "$STAMP" && \
                ! verify_complete_pair "$ROOTFS_BACKUP" "$STAMP_BACKUP"; then
            fail "rootfs.previous has no complete old stamp pair"
        fi
    elif slot_exists "$STAMP" || slot_exists "$STAMP_BACKUP"; then
        fail "stamp exists without an old rootfs during initial publication"
    fi

    rename_path_durable "${STAGING}/rootfs" "$ROOTFS" publish.new_rootfs
    finish_live_current_rootfs
}

restore_previous_pair() {
    local old_stamp
    if verify_complete_pair "$ROOTFS_BACKUP" "$STAMP_BACKUP"; then
        old_stamp="$STAMP_BACKUP"
    elif verify_complete_pair "$ROOTFS_BACKUP" "$STAMP"; then
        old_stamp="$STAMP"
    else
        fail "rootfs.previous has no verifiable stamp pair to restore"
    fi

    if slot_exists "$ROOTFS"; then
        if slot_exists "$STAGING"; then
            [ -d "$STAGING" ] && [ ! -L "$STAGING" ] && \
                [ -z "$("$TOYBOX" find "$STAGING" -mindepth 1 -print -quit 2>/dev/null)" ] || \
                fail "cannot isolate live rootfs into occupied staging slot"
        else
            mkdir "$STAGING" || fail "cannot create staging slot for old-pair restore"
            fsync_path "$DATA_DIR" reconcile.restore_staging.mkdir_parent_fsync
        fi
        rename_path_durable "$ROOTFS" "${STAGING}/rootfs" \
            reconcile.reject_live_rootfs
    fi

    rename_path_durable "$ROOTFS_BACKUP" "$ROOTFS" reconcile.restore_old_rootfs
    if [ "$old_stamp" = "$STAMP_BACKUP" ]; then
        if slot_exists "$STAMP"; then
            if slot_exists "$STAMP_TMP"; then
                remove_file_durable "$STAMP" reconcile.reject_live_stamp
            else
                rename_path_durable "$STAMP" "$STAMP_TMP" \
                    reconcile.reject_live_stamp
            fi
        fi
        rename_path_durable "$STAMP_BACKUP" "$STAMP" reconcile.restore_old_stamp
    fi
    verify_complete_pair "$ROOTFS" "$STAMP" || \
        fail "restored old rootfs/stamp pair failed completeness verification"
    log "selected complete old rootfs/stamp pair during reconciliation"
    # Make the rejection of the staged current stamp durable before reusing
    # rootfs.previous as the bounded declassification path for the rejected
    # tree.  This ordering lets a restart distinguish that cleanup tombstone
    # from the genuine old rootfs retained during publication.
    remove_file_durable "$STAMP_TMP" cleanup.rejected_stamp
    discard_staging_artifact old
}

reconcile_rootfs_transaction() {
    local sources_valid=0
    normalize_legacy_transaction_artifacts
    transaction_artifacts_present || return 0
    log "reconciling persistent rootfs transaction slots"
    if verify_current_sources_quiet; then
        CURRENT_SOURCES_VERIFIED=1
        sources_valid=1
    else
        log "current archive/manifest inputs are not valid; new candidate cannot be selected"
    fi

    if [ "$sources_valid" = 1 ] && verify_current_pair "$ROOTFS" "$STAMP"; then
        log "reconciliation found a complete committed new pair"
        cleanup_selected_pair_artifacts new
        return 0
    fi
    if [ "$sources_valid" = 1 ] && verify_current_rootfs "$ROOTFS" && \
            stamp_matches_payload "$STAMP_TMP"; then
        finish_live_current_rootfs
        return 0
    fi
    if [ "$sources_valid" = 1 ] && \
            verify_current_pair "${STAGING}/rootfs" "$STAMP_TMP"; then
        publish_staged_current_rootfs
        return 0
    fi

    # During old-pair cleanup the rejected new tree may already have moved
    # through rootfs.previous, but its staged stamp is durably gone first.  A
    # live complete pair with no stamp.previous and without the simultaneous
    # rootfs.previous+stamp.staging publish topology is therefore the selected
    # prior pair, not an invitation to swap in an unrelated orphan.
    if verify_complete_pair "$ROOTFS" "$STAMP" && \
            ! slot_exists "$STAMP_BACKUP" && \
            { ! slot_exists "$ROOTFS_BACKUP" || ! slot_exists "$STAMP_TMP"; }; then
        log "selected complete old rootfs/stamp pair after interrupted restore; retiring only verified generated orphans"
        cleanup_selected_pair_artifacts old
        return 0
    fi

    if verify_complete_pair "$ROOTFS_BACKUP" "$STAMP_BACKUP" || \
            verify_complete_pair "$ROOTFS_BACKUP" "$STAMP"; then
        restore_previous_pair
        return 0
    fi
    if verify_complete_pair "$ROOTFS" "$STAMP_BACKUP"; then
        ! slot_exists "$STAMP" || \
            fail "restored rootfs has both live and backup stamp candidates"
        rename_path_durable "$STAMP_BACKUP" "$STAMP" reconcile.restore_old_stamp
        verify_complete_pair "$ROOTFS" "$STAMP" || \
            fail "restored old pair failed after stamp recovery"
        log "selected complete old rootfs/stamp pair after interrupted restore"
        cleanup_selected_pair_artifacts old
        return 0
    fi
    if ! slot_exists "$ROOTFS" && ! slot_exists "$STAMP" && \
            ! slot_exists "$ROOTFS_BACKUP" && ! slot_exists "$STAMP_BACKUP"; then
        log "no prior rootfs/stamp pair exists; retiring incomplete initial-install artifacts"
        discard_staging_artifact initial
        remove_file_durable "$STAMP_TMP" cleanup.initial_staged_stamp
        return 0
    fi
    fail "no complete old or new rootfs/stamp pair can be selected; preserving all slots"
}

require_complete_migration_source() {
    if ! slot_exists "$ROOTFS" && ! slot_exists "$STAMP"; then
        return 0
    fi
    slot_exists "$ROOTFS" && slot_exists "$STAMP" || \
        fail "state migration source is a missing rootfs/stamp half-pair"
    if stamp_matches_payload "$STAMP"; then
        ensure_current_sources_verified
        # Installed runtime remeasurement may fail because the mutable /data
        # tree was damaged.  Rebuild it from the authenticated current
        # archives, but migrate only the strict validated state allowlist from
        # a structurally complete rootfs/stamp pair.  A missing or half rootfs
        # never reaches migration.
        verify_complete_pair "$ROOTFS" "$STAMP" || \
            fail "state migration source is an incomplete current rootfs/stamp pair"
    else
        verify_complete_pair "$ROOTFS" "$STAMP" || \
            fail "state migration source is an incomplete previous pair"
    fi
}

set_step "prepare rootlinux data directory"
mkdir -p "$DATA_DIR"
chmod 0755 /data/trillionnium "$DATA_DIR" ||
    fail "cannot secure rootlinux data directories"
[ "$($TOYBOX stat -c %a /data/trillionnium)" = 755 ] &&
    [ "$($TOYBOX stat -c %a "$DATA_DIR")" = 755 ] ||
    fail "rootlinux data directory mode did not converge"
restore_rootlinux_top_labels
[ -d "$DATA_DIR" ] && [ ! -L "$DATA_DIR" ] || \
    fail "rootlinux data directory is not a real directory"
[ -x "$TOYBOX" ] || fail "missing toybox: $TOYBOX"
if [ -e "$LOCK_FILE" ] || [ -L "$LOCK_FILE" ]; then
    [ ! -L "$LOCK_FILE" ] && [ -f "$LOCK_FILE" ] || \
        fail "bootstrap lock path is not regular"
else
    : >"$LOCK_FILE" || fail "cannot create bootstrap lock"
fi
chown 0:0 "$LOCK_FILE" || fail "cannot own bootstrap lock"
chmod 0600 "$LOCK_FILE" || fail "cannot secure bootstrap lock"
[ "$($TOYBOX stat -c '%u:%g:%a:%h' "$LOCK_FILE")" = "0:0:600:1" ] ||
    fail "bootstrap lock metadata did not converge"
exec 0<>"$LOCK_FILE"
"$TOYBOX" flock -xn 0 || fail "another rootlinux bootstrap instance is active"
if [ -e "$LOG_FILE" ] || [ -L "$LOG_FILE" ]; then
    [ ! -L "$LOG_FILE" ] && [ -f "$LOG_FILE" ] || fail "bootstrap log path is not regular"
    log_size="$("$TOYBOX" stat -c %s "$LOG_FILE")"
    case "$log_size" in ''|*[!0-9]*) fail "invalid bootstrap log size" ;; esac
    if [ "$log_size" -gt 4194304 ]; then
        previous_log="${DATA_DIR}/bootstrap.log.previous"
        if [ -e "$previous_log" ] || [ -L "$previous_log" ]; then
            [ ! -L "$previous_log" ] && [ -f "$previous_log" ] || \
                fail "previous bootstrap log path is not regular"
            rm -f "$previous_log" || fail "cannot remove bounded previous bootstrap log"
        fi
        rename_path_durable "$LOG_FILE" "$previous_log" bootstrap.log_rotate
        chmod 0600 "$previous_log" || fail "cannot secure previous bootstrap log"
    fi
fi
exec >>"$LOG_FILE" 2>&1
chmod 0600 "$LOG_FILE" || fail "cannot secure bootstrap log"

set_step "bootstrap start"
log "bootstrap start: archive_dir=$ARCHIVE_DIR data_dir=$DATA_DIR rootfs=$ROOTFS"

[ -x "$ZSTD" ] || fail "missing zstd: $ZSTD"
[ -x "$TOYBOX" ] || fail "missing toybox: $TOYBOX"
[ -x "$TAR_STAGING_FILTER" ] ||
    fail "missing authenticated tar staging filter: $TAR_STAGING_FILTER"

set_step "read payload manifest"
verify_payload_manifest_file_syntax "$MANIFEST_FILE" ||
    fail "payload manifest has malformed, empty, or duplicate fields"
if [ "$SYSTEM_MANIFEST_FILE" != "$MANIFEST_FILE" ]; then
    verify_payload_manifest_file_syntax "$SYSTEM_MANIFEST_FILE" ||
        fail "system payload manifest has malformed, empty, or duplicate fields"
fi
BUILD_TYPE="$(getprop ro.build.type 2>/dev/null)" ||
    fail "cannot read Android build type"
select_payload_contract_branch_for_build_type "$BUILD_TYPE"
reject_mobian_package_contract
verify_bootstrap_layout_contract
verify_fresh_v2_manifest_contract
verify_tar_staging_filter_identity ||
    fail "tar staging filter target does not match its generated target-ELF receipt"
BOOTSTRAP_SHA256="$(sha256 "$0")"
[ -f "$CODEX_AGENT_MANIFEST" ] && [ ! -L "$CODEX_AGENT_MANIFEST" ] ||
    fail "signed Codex AgentManifest is missing or unsafe"
CODEX_AGENT_MANIFEST_SHA256="$(sha256 "$CODEX_AGENT_MANIFEST")"
PAYLOAD_KEY="layout=${BOOTSTRAP_LAYOUT_VERSION} bootstrap=${BOOTSTRAP_SHA256} rootfs=${ROOTFS_SHA256} codex_manifest=${CODEX_AGENT_MANIFEST_SHA256}"
log "payload key: $PAYLOAD_KEY"

set_step "verify immutable payload evidence"
ensure_current_sources_verified

set_step "reconcile persistent rootfs transaction"
reconcile_rootfs_transaction

set_step "quarantine retired provider state"
quarantine_retired_provider_state

set_step "check existing payload stamp"
if verify_current_pair "$ROOTFS" "$STAMP" &&
        [ ! -e "$CODEX_AUTH_INBOX" ] && [ ! -L "$CODEX_AUTH_INBOX" ]; then
    prepare_agent_tool_mount_target "$ROOTFS"
    prepare_proc_mount_target "$ROOTFS"
    log "already prepared: $PAYLOAD_KEY"
    publish_rootlinux_prepare_complete
    exit 0
fi
if verify_current_pair "$ROOTFS" "$STAMP"; then
    [ -f "$CODEX_AUTH_INBOX" ] && [ ! -L "$CODEX_AUTH_INBOX" ] ||
        fail "Codex credential inbox is unsafe"
    log "Codex credential inbox requires a fresh atomic rootfs transaction"
fi

set_step "verify state migration source pair"
require_complete_migration_source

set_step "extract payload archives"
[ ! -e "$STAGING" ] && [ ! -L "$STAGING" ] || \
    fail "bootstrap staging path already exists"
mkdir -p "${STAGING}/rootfs"
[ -d "$STAGING" ] && [ ! -L "$STAGING" ] && \
    [ -d "${STAGING}/rootfs" ] && [ ! -L "${STAGING}/rootfs" ] || \
    fail "bootstrap staging path is not a real directory"
[ "$($TOYBOX stat -c '%u:%g:%a' "$STAGING")" = "0:0:700" ] &&
    [ "$($TOYBOX stat -c '%u:%g:%a' "${STAGING}/rootfs")" = "0:0:700" ] ||
    fail "bootstrap staging carrier is not root-owned 0700"
restore_rootlinux_top_labels
# The essential archive is the complete Android runtime rootfs.  Mobian package
# candidates are deliberately outside the Android product graph, so no package
# layer may precede or overwrite this release-specific Agent API payload.
extract_archive "$ROOTFS_ARCHIVE"
set_step "verify fresh v2 archive layout"
verify_fresh_v2_archive_layout
install_p01_agentd_overlay
reject_retired_provider_payload "${STAGING}/rootfs"
ensure_no_android_data_tree
prepare_codex_runtime_target "${STAGING}/rootfs"
prepare_agent_direct_tool_targets "${STAGING}/rootfs"
harden_rootfs
set_step "install signed AgentManifests"
install_signed_agent_manifests "${STAGING}/rootfs"
set_step "verify dpkg status"
verify_configured_dpkg_status

set_step "prepare explicit writable rootfs state roots"
prepare_agent_tool_mount_target "${STAGING}/rootfs"
prepare_proc_mount_target "${STAGING}/rootfs"

set_step "migrate allowlisted persistent state"
migrate_allowlisted_state "$ROOTFS" "${STAGING}/rootfs"
provision_codex_credential "${STAGING}/rootfs" 0

set_step "verify final materialized rootfs contract"
verify_current_rootfs "${STAGING}/rootfs" ||
    fail "staged rootfs does not satisfy the final fresh-v2 contract"

set_step "verify rootfs entrypoints"
[ -e "${STAGING}/rootfs/bin/sh" ] || fail "extracted rootfs is missing /bin/sh"
executable_mode_is_canonical "${STAGING}/rootfs/usr/bin/trillionniumd" || \
    fail "extracted rootfs is missing Agent API daemon"

set_step "publish prepared rootfs"
echo "$PAYLOAD_KEY" >"$STAMP_TMP" || fail "cannot stage rootfs payload stamp"
chmod 0600 "$STAMP_TMP" || fail "cannot secure staged rootfs payload stamp"
fsync_path "$STAMP_TMP" publish.staged_stamp.file_fsync
sync_filesystems
test_kill_after_boundary publish.staged_tree.filesystems_sync
publish_staged_current_rootfs
if [ "$STAGED_CODEX_INBOX" = "1" ]; then
    remove_file_durable "$CODEX_AUTH_INBOX" commit.codex_inbox || \
        log "warning: committed Codex credential inbox remains"
fi
chmod 0600 "$LOG_FILE" || fail "cannot secure bootstrap log"
restore_rootlinux_top_labels

log "bootstrap complete: $PAYLOAD_KEY"
publish_rootlinux_prepare_complete
