#!/system/bin/sh
# Candidate v150-r6 phone-only startup. No task submission, retries, ADB, or mounts.
set -eu
umask 077
MODDIR=${0%/*}
BB=/data/adb/magisk/busybox
SYS=/system/bin
STATE=/data/trillionnium/owner-open/state
HISTORY=/data/adb/trillionnium-hepta-phone-local-v150-r6-r1
ROOT=/data/trillionnium/owner-open/root
CLAIM=
STOPPING=0
PRIOR_R1=/data/adb/modules/trillionnium_hepta_phone_local_v150
PRIOR_R3=/data/adb/modules/trillionnium_hepta_phone_local_v150_r3
PRIOR_R4=/data/adb/modules/trillionnium_hepta_phone_local_v150_r4
PRIOR_R5=/data/adb/modules/trillionnium_hepta_phone_local_v150_r5
PRIOR_R5_R3=/data/adb/modules/trillionnium_hepta_phone_local_v150_r5_r3
EXECUTOR_DATA=/data/trillionnium/owner-open/state/phone-local-v150/executor-r6
EXECUTOR_LOG_ROOT=$EXECUTOR_DATA/module-history-r6-r1
EXECUTOR_LOGDIR=
previous_release_disabled() {
    [ -d "$PRIOR_R5_R3" ] && [ ! -L "$PRIOR_R5_R3" ] || return 1
    [ -f "$PRIOR_R5_R3/disable" ] && [ ! -L "$PRIOR_R5_R3/disable" ] || return 1
    [ -d "$PRIOR_R5" ] && [ ! -L "$PRIOR_R5" ] || return 1
    [ -f "$PRIOR_R5/disable" ] && [ ! -L "$PRIOR_R5/disable" ] || return 1
    # R4 must remain present with its real disable marker; never remove old files.
    [ -d "$PRIOR_R4" ] && [ ! -L "$PRIOR_R4" ] || return 1
    [ -f "$PRIOR_R4/disable" ] && [ ! -L "$PRIOR_R4/disable" ] || return 1
    for prior_dir in "$PRIOR_R1" "$PRIOR_R3"; do
        [ ! -L "$prior_dir" ] || return 1
        if [ ! -e "$prior_dir" ]; then continue; fi
        [ -d "$prior_dir" ] || return 1
        prior_disabled=0
        for prior_flag in disable remove; do
            if [ -f "$prior_dir/$prior_flag" ] && [ ! -L "$prior_dir/$prior_flag" ]; then
                prior_disabled=1
                break
            fi
        done
        [ "$prior_disabled" = 1 ] || return 1
    done
    return 0
}
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
previous_release_disabled || exit 70
# Unsealed source candidates MUST fail closed. The seal is produced only after review.
[ -f "$MODDIR/SEALED" ] && [ ! -L "$MODDIR/SEALED" ]
[ "$($SYS/cat "$MODDIR/SEALED")" = HEPTA_PHONE_LOCAL_V150_R6_R1_REVIEWED_INPUTS_BOUND ]
[ -f "$MODDIR/module-inputs.sha256" ] && [ ! -L "$MODDIR/module-inputs.sha256" ]
[ -f "$MODDIR/payload-inputs.sha256" ] && [ ! -L "$MODDIR/payload-inputs.sha256" ]
[ -f "$MODDIR/role_guard.sh" ] && [ ! -L "$MODDIR/role_guard.sh" ]
for required in activation_gate.sh role_identity_probe.sh role-expectations.tsv; do
    [ -f "$MODDIR/$required" ] && [ ! -L "$MODDIR/$required" ]
done
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
    previous_release_disabled || return 0
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
    [ "$($SYS/getenforce)" = Enforcing ] || return 1
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
# Deliberately closed until the exact reviewed retirement proof and resolution,
# original R4 process retirement and a fresh no-unresolved ledger scan are bound.
# This gate never writes a resolution, deletes claims or contacts the old executor.
"$BB" sh "$MODDIR/activation_gate.sh" startup
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
write_once model-qualification 'PENDING_NEW_NONCE_FOR_V150_R6; old health is historical only'
write_once business-qualification 'NOT_QUALIFIED; executor IPC/shell is not public App permission proof'
write_once worker-qualification 'NOT_OBSERVED; only original executed-worker receipts prove runtime context/credentials'
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
    $BB kill -TERM "-$role_pid" || :
    count=0
    while identity_live "$role" && [ "$count" -lt 12 ]; do
        $BB sleep 1
        count=$((count + 1))
    done
    if identity_live "$role"; then
        $BB kill -KILL "-$role_pid" || :
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
    # A second stop source must not interrupt the existing bounded role cleanup.
    trap '' INT TERM HUP
    trap - EXIT
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

# No relabelling here. Installation supplies the reviewed private label.
executor_label_exact() {
    label_line=$($SYS/ls -Zd "$1") || return 1
    printf '%s\n' "$label_line" | "$BB" awk -v p="$1" '
      NF != 2 { exit 1 }
      $1 != "u:object_r:trillionnium_owner_open_phone_executor_data_file:s0" { exit 1 }
      $2 != p { exit 1 }
      { n++ }
      END { if (n != 1) exit 1 }'
}
prepare_executor_logs() {
    for path in "$EXECUTOR_DATA" "$EXECUTOR_LOG_ROOT"; do
        [ -d "$path" ] && [ ! -L "$path" ] || return 1
        [ "$($SYS/readlink -f "$path")" = "$path" ] || return 1
        [ "$($SYS/stat -c '%u:%g:%a' "$path")" = 0:0:700 ] || return 1
        executor_label_exact "$path" || return 1
    done
    EXECUTOR_LOGDIR=$EXECUTOR_LOG_ROOT/$boot_id
    $SYS/mkdir -m 700 "$EXECUTOR_LOGDIR" || return 1
    [ "$($SYS/stat -c '%u:%g:%a' "$EXECUTOR_LOGDIR")" = 0:0:700 ] || return 1
    executor_label_exact "$EXECUTOR_LOGDIR" || return 1
    for name in sidecar.stdout sidecar.stderr; do
        ( set -C; : > "$EXECUTOR_LOGDIR/$name" ) || return 1
        [ -f "$EXECUTOR_LOGDIR/$name" ] && [ ! -L "$EXECUTOR_LOGDIR/$name" ] || return 1
        [ "$($SYS/stat -c '%u:%g:%a:%h' "$EXECUTOR_LOGDIR/$name")" = 0:0:600:1 ] || return 1
        executor_label_exact "$EXECUTOR_LOGDIR/$name" || return 1
    done
    write_once sidecar-log-directory "$EXECUTOR_LOGDIR"
}
wait_role_exec_identity() {
    checked_role=$1
    checked_count=0
    checked_output=
    while [ "$checked_count" -lt 50 ]; do
        identity_live "$checked_role" || return 1
        require_running_allowed || return 1
        if checked_output=$("$BB" sh "$MODDIR/role_identity_probe.sh" "$CLAIM" "$checked_role" startup 2>&1); then
            write_once "$checked_role.exec-identity" "$checked_output"
            return 0
        fi
        $BB sleep 0.1
        checked_count=$((checked_count + 1))
    done
    write_once "$checked_role.exec-identity-failure" "$checked_output" || :
    return 1
}

start_role() {
    role=$1
    require_running_allowed || return 1
    write_once "$role.spawn-intent" 'own-session guard only; no application before identity admission'
    if [ "$role" = sidecar ]; then
        [ -n "$EXECUTOR_LOGDIR" ]
        log_out=$EXECUTOR_LOGDIR/sidecar.stdout
        log_err=$EXECUTOR_LOGDIR/sidecar.stderr
    else
        log_out=$CLAIM/$role.stdout
        log_err=$CLAIM/$role.stderr
    fi
    "$BB" setsid "$BB" sh "$MODDIR/role_guard.sh" "$CLAIM" "$role" "$PARENT_ID" >"$log_out" 2>"$log_err" &
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
    wait_role_exec_identity "$role" || return 1
    write_once "$role.started" "$($SYS/date -u +%Y-%m-%dT%H:%M:%SZ)"
}
# Services may become listeners at different times; no health prompt is auto-issued.
prepare_executor_logs
start_role model
start_role sidecar
start_role provider
write_once services-started 'post-exec process identity/domain/NNP only; new health, native IPC, worker execution, public App permissions and cold boot remain independent'
while :; do
    require_running_allowed || exit 73
    for role in model sidecar provider; do
        identity_live "$role" || exit 74
        "$BB" sh "$MODDIR/role_identity_probe.sh" "$CLAIM" "$role" monitor >/dev/null 2>&1 || exit 75
    done
    $BB sleep 1
done
