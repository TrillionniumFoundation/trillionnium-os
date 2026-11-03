#!/system/bin/sh
# Candidate v150 phone-only startup. No task submission, retries, ADB, or mounts.
set -eu
umask 077
MODDIR=${0%/*}
BB=/data/adb/magisk/busybox
SYS=/system/bin
STATE=/data/trillionnium/owner-open/state
HISTORY=/data/adb/trillionnium-hepta-phone-local-v150
ROOT=/data/trillionnium/owner-open/root
CLAIM=
STOPPING=0
[ "$($SYS/id -u)" = 0 ]
[ "$($SYS/getenforce)" = Enforcing ]
[ "$($SYS/getprop ro.build.version.sdk)" = 36 ]
[ "$($SYS/getprop ro.build.fingerprint)" = motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys ]
[ -x "$BB" ]
[ -d "$MODDIR" ] && [ ! -L "$MODDIR" ]
for flag in disable remove; do
    [ ! -e "$MODDIR/$flag" ] && [ ! -L "$MODDIR/$flag" ]
    [ ! -e /data/adb/modules/trillionnium_hepta_stock16_v143/$flag ] && [ ! -L /data/adb/modules/trillionnium_hepta_stock16_v143/$flag ]
done
# Unsealed source candidates MUST fail closed. The seal is produced only after review.
[ -f "$MODDIR/SEALED" ] && [ ! -L "$MODDIR/SEALED" ]
[ "$($SYS/cat "$MODDIR/SEALED")" = HEPTA_PHONE_LOCAL_V150_INPUTS_BOUND ]
[ -f "$MODDIR/module-inputs.sha256" ] && [ ! -L "$MODDIR/module-inputs.sha256" ]
[ -f "$MODDIR/payload-inputs.sha256" ] && [ ! -L "$MODDIR/payload-inputs.sha256" ]
[ -f "$MODDIR/role_guard.sh" ] && [ ! -L "$MODDIR/role_guard.sh" ]
[ "$($SYS/stat -c '%u:%g' "$MODDIR")" = 0:0 ]
[ "$($SYS/stat -c '%a' "$MODDIR")" = 700 ]
cd "$MODDIR"
$SYS/sha256sum -c module-inputs.sha256
$SYS/sha256sum -c payload-inputs.sha256
for role in model sidecar provider; do
    [ -f "$MODDIR/launch-$role.sh" ] && [ ! -L "$MODDIR/launch-$role.sh" ]
done
[ -d "$STATE" ] && [ ! -L "$STATE" ]
[ "$($SYS/readlink -f "$STATE")" = "$STATE" ]
[ "$($SYS/stat -c '%u:%g:%a' "$STATE")" = 0:0:700 ]
[ -d "$ROOT" ] && [ ! -L "$ROOT" ]

inhibited() {
    # Unknown observations are inhibited. Never remove either stop source.
    listing=$($SYS/ls -a1 "$STATE") || return 0
    if printf '%s\n' "$listing" | $BB grep -Fxq emergency-stop; then
        return 0
    else
        found=$?
        [ "$found" = 1 ] || return 0
    fi
    property=$($SYS/getprop sys.trillionnium.owner_open.stop) || return 0
    case "$property" in ''|0) ;; *) return 0 ;; esac
    for flag in disable remove; do
        [ ! -e "$MODDIR/$flag" ] && [ ! -L "$MODDIR/$flag" ] || return 0
        [ ! -e /data/adb/modules/trillionnium_hepta_stock16_v143/$flag ] && [ ! -L /data/adb/modules/trillionnium_hepta_stock16_v143/$flag ] || return 0
    done
    return 1
}
require_running_allowed() {
    if inhibited; then return 1; fi
    [ "$($SYS/getprop ro.trillionnium.owner_open.profile)" = leap-stock16-codex-host-relay-v1 ]
}
# The native profile is intentionally still legacy in this runtime-only phase.
# Do not set properties to pretend the native bootstrap supports phone_local.
elapsed=0
while :; do
    if inhibited; then exit 70; fi
    startup_profile=$($SYS/getprop ro.trillionnium.owner_open.profile) || exit 70
    case "$startup_profile" in ''|leap-stock16-codex-host-relay-v1) ;; *) exit 70 ;; esac
    if [ "$startup_profile" = leap-stock16-codex-host-relay-v1 ] &&
       [ "$($SYS/getprop sys.boot_completed)" = 1 ] &&
       [ "$($SYS/getprop trillionnium.owner_open.ready)" = 1 ] &&
       [ "$($SYS/getprop trillionnium.owner_open.mount_ready)" = 1 ]; then break; fi
    [ "$elapsed" -lt 120 ] || exit 71
    $BB sleep 1
    elapsed=$((elapsed + 1))
done
boot_id=$($SYS/cat /proc/sys/kernel/random/boot_id)
printf '%s\n' "$boot_id" | $BB grep -Eq '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
[ ! -L "$HISTORY" ]
if [ ! -e "$HISTORY" ]; then $SYS/mkdir -m 700 "$HISTORY"; fi
[ -d "$HISTORY" ] && [ "$($SYS/readlink -f "$HISTORY")" = "$HISTORY" ]
[ "$($SYS/stat -c '%u:%g:%a' "$HISTORY")" = 0:0:700 ]
CLAIM=$HISTORY/$boot_id
# Existing/unknown claims are retained, never treated as permission to restart.
$SYS/mkdir -m 700 "$CLAIM" || exit 72
write_once() {
    ( set -C; printf '%s\n' "$2" > "$CLAIM/$1" )
}
write_once intent 'phone-only-services; no task, model prompt, effect, automatic resume, or redispatch'
write_once native-profile leap-stock16-codex-host-relay-v1
write_once runtime-location phone_local
write_once module-path "$MODDIR"
write_once start-utc "$($SYS/date -u +%Y-%m-%dT%H:%M:%SZ)"
# Identity is PID:pgrp:session:starttime. Parse after the final comm parenthesis.
identity() {
    role_pid=$1
    [ "$role_pid" -gt 1 ] || return 1
    stat_line=$($SYS/cat "/proc/$role_pid/stat") || return 1
    stat_tail=${stat_line##*) }
    printf '%s\n' "$stat_tail" | $BB awk -v pid="$role_pid" '{ if ($1 == "Z") exit 2; print pid ":" $3 ":" $4 ":" $20 }'
}
identity_live() {
    role=$1
    [ -f "$CLAIM/$role.identity" ] || return 1
    expected=$($SYS/cat "$CLAIM/$role.identity") || return 1
    role_pid=${expected%%:*}
    actual=$(identity "$role_pid") || return 1
    [ "$actual" = "$expected" ]
}
terminate_role() {
    role=$1
    if [ ! -f "$CLAIM/$role.identity" ]; then
        if [ -f "$CLAIM/$role.spawn-pid" ]; then
            write_once "$role.stop" 'spawn occurred without verified process identity; cleanup UNKNOWN and no retry' || :
            return 1
        fi
        return 0
    fi
    expected=$($SYS/cat "$CLAIM/$role.identity")
    role_pid=${expected%%:*}
    if ! identity_live "$role"; then
        write_once "$role.stop" 'leader already absent or identity unknown; descendants NOT proven absent' || :
        return 1
    fi
    # Groups were verified pgrp=session=leader PID before admission.
    $BB kill -TERM -- "-$role_pid" || :
    count=0
    while identity_live "$role" && [ "$count" -lt 12 ]; do
        $BB sleep 1
        count=$((count + 1))
    done
    if identity_live "$role"; then
        $BB kill -KILL -- "-$role_pid" || :
        write_once "$role.stop" 'forced group kill requested; effect cleanup NOT proven by service hook' || :
        return 1
    fi
    write_once "$role.stop" 'owned leader exited after TERM; task/descendant receipts require independent verification' || :
    return 0
}
stop_owned() {
    [ "$STOPPING" = 0 ] || return
    STOPPING=1
    # Stop admission before tools/model. Provider and sidecar own actual effect cancellation.
    for role in provider sidecar model; do terminate_role "$role" || :; done
}
finish() {
    result=$?
    trap - EXIT INT TERM HUP
    stop_owned
    write_once exit-code "$result" || :
    write_once terminal-scope 'startup supervisor terminal only; no business success or full effect-quiescence claim' || :
    exit "$result"
}
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
PARENT_ID=$(identity "$$")
write_once supervisor.identity "$PARENT_ID"

start_role() {
    role=$1
    require_running_allowed || return 1
    write_once "$role.spawn-intent" 'own-session guard only; no application before identity admission'
    "$BB" setsid "$BB" sh "$MODDIR/role_guard.sh" "$CLAIM" "$role" "$PARENT_ID" >"$CLAIM/$role.stdout" 2>"$CLAIM/$role.stderr" &
    role_pid=$!
    write_once "$role.spawn-pid" "$role_pid"
    count=0
    captured=
    while [ "$count" -lt 40 ]; do
        if [ -f "$CLAIM/$role.identity" ] && [ ! -L "$CLAIM/$role.identity" ]; then
            captured=$($SYS/cat "$CLAIM/$role.identity") || captured=
            case "$captured" in "$role_pid:$role_pid:$role_pid:"*)
                if identity_live "$role"; then break; fi
                ;;
            esac
        fi
        $BB kill -0 "$role_pid" 2>/dev/null || return 1
        $BB sleep 0.1
        count=$((count + 1))
    done
    case "$captured" in "$role_pid:$role_pid:$role_pid:"*) ;; *) return 1 ;; esac
    identity_live "$role" || return 1
    require_running_allowed || return 1
    # Only this exact, already-recorded group can cross the exec barrier.
    write_once "$role.admit" "$captured"
    write_once "$role.started" "$($SYS/date -u +%Y-%m-%dT%H:%M:%SZ)"
}
# Services may become listeners at different times; no health prompt is auto-issued.
start_role model
start_role sidecar
start_role provider
write_once services-started 'process identities only; model health/socket permissions/business/boot qualification still independent'
while :; do
    require_running_allowed || exit 73
    for role in model sidecar provider; do identity_live "$role" || exit 74; done
    $BB sleep 1
done
