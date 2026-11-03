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
PRIOR=/data/adb/modules/trillionnium_hepta_phone_local_v150
previous_release_disabled() {
    # This checks only the old release's inhibition marker. Root must separately
    # prove all old owned roles quiescent before installing this release.
    [ ! -L "$PRIOR" ] || return 1
    if [ ! -e "$PRIOR" ]; then return 0; fi
    [ -d "$PRIOR" ] || return 1
    for prior_flag in disable remove; do
        if [ -f "$PRIOR/$prior_flag" ] && [ ! -L "$PRIOR/$prior_flag" ]; then return 0; fi
    done
    return 1
}
case "$ROLE" in model|sidecar|provider) ;; *) exit 80 ;; esac
case "$CLAIM" in /data/adb/trillionnium-hepta-phone-local-v150-r2/*) ;; *) exit 80 ;; esac
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
        exec "$BB" sh "$MODDIR/launch-$ROLE.sh"
    fi
    $BB sleep 0.1
    count=$((count + 1))
done
exit 84
