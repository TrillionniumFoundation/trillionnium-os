#!/system/bin/sh
# Own-session startup barrier. No application is executed before parent admission.
set -eu
umask 077
BB=/data/adb/magisk/busybox
SYS=/system/bin
MODDIR=${0%/*}
CLAIM=$1
ROLE=$2
PARENT_ID=$3
PRIOR_R1=/data/adb/modules/trillionnium_hepta_phone_local_v150
PRIOR_R3=/data/adb/modules/trillionnium_hepta_phone_local_v150_r3
PRIOR_R4=/data/adb/modules/trillionnium_hepta_phone_local_v150_r4
PRIOR_R5=/data/adb/modules/trillionnium_hepta_phone_local_v150_r5
PRIOR_R5_R3=/data/adb/modules/trillionnium_hepta_phone_local_v150_r5_r3
PRIOR_R6_R1=/data/adb/modules/trillionnium_hepta_phone_local_v150_r6_r1
PRIOR_R6_R2=/data/adb/modules/trillionnium_hepta_phone_local_v150_r6_r2
previous_release_disabled() {
    [ -d "$PRIOR_R6_R2" ] && [ ! -L "$PRIOR_R6_R2" ] || return 1
    [ -f "$PRIOR_R6_R2/disable" ] && [ ! -L "$PRIOR_R6_R2/disable" ] || return 1
    [ -d "$PRIOR_R6_R1" ] && [ ! -L "$PRIOR_R6_R1" ] || return 1
    [ -f "$PRIOR_R6_R1/disable" ] && [ ! -L "$PRIOR_R6_R1/disable" ] || return 1
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
case "$ROLE" in model|sidecar|provider) ;; *) exit 80 ;; esac
case "$CLAIM" in /data/adb/trillionnium-hepta-phone-local-v150-r7-r1/*) ;; *) exit 80 ;; esac
[ -d "$CLAIM" ] && [ ! -L "$CLAIM" ]
[ "$($SYS/stat -c '%u:%g:%a' "$CLAIM")" = 0:0:700 ]
[ "$($SYS/id -u)" = 0 ]
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
identity() {
    role_pid=$1
    [ "$role_pid" -gt 1 ] || return 1
    stat_line=$($SYS/cat "/proc/$role_pid/stat") || return 1
    stat_tail=${stat_line##*) }
    printf '%s\n' "$stat_tail" | $BB awk -v pid="$role_pid" '{ if ($1 == "Z") exit 2; print pid ":" $3 ":" $4 ":" $20 }'
}
parent_live() {
    parent_pid=${PARENT_ID%%:*}
    actual=$(identity "$parent_pid") || return 1
    [ "$actual" = "$PARENT_ID" ]
}
allowed() {
    previous_release_disabled || return 1
    parent_live || return 1
    for flag in disable remove; do
        [ ! -e "$MODDIR/$flag" ] && [ ! -L "$MODDIR/$flag" ] || return 1
        [ ! -e /data/adb/modules/trillionnium_hepta_stock16_v143/$flag ] && [ ! -L /data/adb/modules/trillionnium_hepta_stock16_v143/$flag ] || return 1
    done
    listing=$($SYS/ls -a1 /data/trillionnium/owner-open/state) || return 1
    if printf '%s\n' "$listing" | $BB grep -Fxq emergency-stop; then return 1; else absent=$?; [ "$absent" = 1 ] || return 1; fi
    stop=$($SYS/getprop sys.trillionnium.owner_open.stop) || return 1
    case "$stop" in ''|0) ;; *) return 1 ;; esac
    return 0
}
own_id=$(identity "$$")
case "$own_id" in "$$:$$:$$:"*) ;; *) exit 81 ;; esac
allowed || exit 82
# File is never overwritten. Parent must read and compare this exact identity.
( set -C; printf '%s\n' "$own_id" > "$CLAIM/$ROLE.identity" )
count=0
while [ "$count" -lt 50 ]; do
    allowed || exit 82
    if [ -f "$CLAIM/$ROLE.admit" ] && [ ! -L "$CLAIM/$ROLE.admit" ]; then
        [ "$($SYS/cat "$CLAIM/$ROLE.admit")" = "$own_id" ] || exit 83
        allowed || exit 82
        "$BB" sh "$MODDIR/activation_gate.sh" admission "$CLAIM" "$ROLE" || exit 85
        exec "$BB" sh "$MODDIR/launch-$ROLE.sh"
    fi
    $BB sleep 0.1
    count=$((count + 1))
done
exit 84
