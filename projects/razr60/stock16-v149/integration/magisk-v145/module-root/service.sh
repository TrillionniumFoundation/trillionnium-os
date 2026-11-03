#!/system/bin/sh
set -eu
MODDIR=${0%/*}
[ "$(/system/bin/getenforce)" = Enforcing ]
[ "$(/system/bin/getprop ro.build.version.sdk)" = 36 ]
[ "$(/system/bin/getprop ro.build.fingerprint)" = motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys ]
# No task, retry, USB, adbd or server management is performed here.
[ "$(/system/bin/id -u)" = 0 ]
umask 077
for module_flag in disable remove; do
    [ ! -e "$MODDIR/$module_flag" ] && [ ! -L "$MODDIR/$module_flag" ]
done
/system/bin/sha256sum -c "$MODDIR/mounted-files.sha256"
# Preserve dedicated labels on the two owned payload directories after magic mounts.
# Directory binding remains before all startup-property publication.
[ "$(readlink /proc/self/ns/mnt)" = "$(readlink /proc/1/ns/mnt)" ]
for name in rootlinux owner-open; do
    source=$MODDIR/system/system_ext/etc/trillionnium/$name
    target=/system_ext/etc/trillionnium/$name
    [ -d "$source" ] && [ ! -L "$source" ]
    [ -d "$target" ] && [ ! -L "$target" ]
    observed=$(/system/bin/ls -Zd "$source")
    [ "${observed%% *}" = u:object_r:trillionnium_owner_open_payload_file:s0 ]
    if [ "$(stat -c '%d:%i' "$source")" != "$(stat -c '%d:%i' "$target")" ]; then
        # An existing mount at this exact target is unknown; never stack over it.
        [ -z "$(awk -v target="$target" '$5 == target {print $0}' /proc/1/mountinfo)" ]
        /data/adb/magisk/busybox mount -o bind "$source" "$target"
        if ! /data/adb/magisk/busybox mount -o remount,bind,ro,nosuid,nodev,noexec "$source" "$target"; then
            /system/bin/umount "$target"
            exit 80
        fi
    fi
    flags=$(awk -v target="$target" '$5 == target {print $6}' /proc/1/mountinfo)
    for flag in ro nosuid nodev noexec; do
        case ,$flags, in *,$flag,*) ;; *) exit 81 ;; esac
    done
done
check_context() {
    context_line=$(/system/bin/ls -Zd "$1") || return 1
    context_word=${context_line%% *}
    [ "$context_word" = "$2" ]
}
# Failure or an unsupported ls context format leaves payload_ready=0.
check_context /system_ext/bin/trillionnium-owner-open-bootstrap u:object_r:trillionnium_owner_open_bootstrap_exec:s0
check_context /system_ext/bin/trillionnium-owner-open-ingress u:object_r:trillionnium_owner_open_ingress_exec:s0
check_context /system_ext/bin/trillionnium-owner-open-emergency-stop u:object_r:trillionnium_owner_open_emergency_stop_exec:s0
check_context /system_ext/etc/trillionnium/rootlinux u:object_r:trillionnium_owner_open_payload_file:s0
check_context /system_ext/etc/trillionnium/owner-open u:object_r:trillionnium_owner_open_payload_file:s0
check_context /data/trillionnium/owner-open/state u:object_r:trillionnium_owner_open_state_file:s0
current=$(/system/bin/getprop ro.trillionnium.owner_open.profile)
[ -z "$current" ] || [ "$current" = leap-stock16-codex-host-relay-v1 ]

# Missing/unknown native state is a hold, never an invented false observation.
STATE=/data/trillionnium/owner-open/state
[ -d "$STATE" ] && [ ! -L "$STATE" ]
[ "$(readlink -f "$STATE")" = "$STATE" ]
[ "$(stat -c '%u:%g:%a' "$STATE")" = 0:0:700 ]
[ "$(/system/bin/getprop trillionnium.owner_open.data_ready)" = 1 ]

# Return0=stopped,1=positively observed absent,2=observation failed.
# Listing also detects a dangling symlink/directory with the exact stop name.
inhibit_state() {
    inhibit_entries=$(/system/bin/ls -a1 "$STATE") || return 2
    if printf '%s\n' "$inhibit_entries" | /system/bin/grep -Fxq emergency-stop; then
        return 0
    else
        inhibit_grep_status=$?
        [ "$inhibit_grep_status" = 1 ] || return 2
    fi
    inhibit_property=$(/system/bin/getprop sys.trillionnium.owner_open.stop) || return 2
    case "$inhibit_property" in ''|0) return 1 ;; *) return 0 ;; esac
}
require_not_inhibited() {
    if inhibit_state; then
        echo HEPTA_BOOT_STOPPED_MARKER_OR_STOP_REQUEST_RETAINED
        return 1
    else
        inhibit_status=$?
        [ "$inhibit_status" = 1 ] || return 2
    fi
}
if require_not_inhibited; then
    :
else
    initial_inhibit_status=$?
    # Explicit stop is a successful hold; unknown observation remains failure.
    [ "$initial_inhibit_status" = 1 ] && exit 0
    exit 70
fi

# Re-read after validation. Read-only ro.enabled is one boot's startup ticket.
enabled=$(/system/bin/getprop ro.trillionnium.owner_open.enabled)
case "$enabled" in
    true)
        [ "$current" = leap-stock16-codex-host-relay-v1 ]
        [ "$(/system/bin/getprop trillionnium.owner_open.payload_ready)" = 1 ]
        echo HEPTA_BOOT_ALREADY_ENABLED_CONFIG_VALIDATED_NO_RESTART
        exit 0
        ;;
    '') ;;
    *) echo HEPTA_BOOT_ENABLE_STATE_UNKNOWN_HOLD; exit 70 ;;
esac
[ "$(/system/bin/getprop trillionnium.owner_open.payload_ready)" = 0 ]
[ "$(/system/bin/getprop trillionnium.owner_open.verified)" = 0 ]
[ "$(/system/bin/getprop trillionnium.owner_open.mount_ready)" = 0 ]
[ "$(/system/bin/getprop trillionnium.owner_open.ready)" = 0 ]

# Keep all previous attempts. A current-boot conflict is HOLD, not a retry.
boot_id=$(/system/bin/cat /proc/sys/kernel/random/boot_id)
printf '%s\n' "$boot_id" | /system/bin/grep -Eq '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
HISTORY=/data/adb/trillionnium-hepta-autostart
[ ! -L "$HISTORY" ]
if [ ! -e "$HISTORY" ]; then
    /system/bin/mkdir -m 700 "$HISTORY"
fi
[ -d "$HISTORY" ] && [ "$(readlink -f "$HISTORY")" = "$HISTORY" ]
[ "$(stat -c '%u:%g:%a' "$HISTORY")" = 0:0:700 ]
CLAIM=$HISTORY/$boot_id
if ! /system/bin/mkdir -m 700 "$CLAIM"; then
    echo HEPTA_BOOT_ATTEMPT_EXISTS_OR_CREATE_UNKNOWN_NO_RETRY
    exit 70
fi
# These are new private metadata files, not backend state/tasks/sessions.
write_once() {
    ( set -C; printf '%s\n' "$2" > "$CLAIM/$1" )
}
finish_attempt() {
    attempt_exit_status=$?
    trap - EXIT
    if ! write_once exit-code "$attempt_exit_status"; then
        [ "$attempt_exit_status" != 0 ] || attempt_exit_status=82
    fi
    exit "$attempt_exit_status"
}
trap finish_attempt EXIT
write_once intent 'guarded-startup-properties-only; no task or retry'

# No lifecycle script clears a stop marker, old task, PID file or diagnostic.
require_not_inhibited
[ "$(/system/bin/getprop ro.trillionnium.owner_open.enabled)" = '' ]
if [ "$current" = '' ]; then
    /system/bin/setprop ro.trillionnium.owner_open.profile leap-stock16-codex-host-relay-v1
fi
[ "$(/system/bin/getprop ro.trillionnium.owner_open.profile)" = leap-stock16-codex-host-relay-v1 ]
require_not_inhibited
[ "$(/system/bin/getprop ro.trillionnium.owner_open.enabled)" = '' ]
/system/bin/setprop trillionnium.owner_open.payload_ready 1
[ "$(/system/bin/getprop trillionnium.owner_open.payload_ready)" = 1 ]
require_not_inhibited
[ "$(/system/bin/getprop ro.trillionnium.owner_open.enabled)" = '' ]
/system/bin/setprop ro.trillionnium.owner_open.enabled true
[ "$(/system/bin/getprop ro.trillionnium.owner_open.enabled)" = true ]
write_once startup-requested 'profile/payload_ready/ro.enabled published; init owns verification/start'
echo HEPTA_BOOT_STARTUP_REQUESTED_NATIVE_READINESS_NOT_YET_CLAIMED
