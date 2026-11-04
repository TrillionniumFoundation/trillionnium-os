#!/system/bin/sh
# Read-only post-exec probe. No signal, task, socket or policy operation.
set -eu
umask 077
BB=/data/adb/magisk/busybox
SYS=/system/bin
MODDIR=${0%/*}
CLAIM=$1
ROLE=$2
MODE=$3
case "$ROLE" in model|sidecar|provider) ;; *) exit 78 ;; esac
case "$MODE" in startup|monitor) ;; *) exit 78 ;; esac
case "$CLAIM" in /data/adb/trillionnium-hepta-phone-local-v150-r7-r1/*) ;; *) exit 78 ;; esac
[ -d "$CLAIM" ] && [ ! -L "$CLAIM" ]
[ "$($SYS/stat -c '%u:%g:%a' "$CLAIM")" = 0:0:700 ]
[ -f "$MODDIR/role-expectations.tsv" ] && [ ! -L "$MODDIR/role-expectations.tsv" ]
row=$("$BB" awk -F '\t' -v r="$ROLE" '$1 == r { if (NF != 7) exit 1; n++; print } END { if (n != 1) exit 1 }' "$MODDIR/role-expectations.tsv")
IFS="$(printf '\t')" read -r found_role expected_exe expected_sha expected_context expected_uid expected_gid expected_nnp <<EOF
$row
EOF
[ "$found_role" = "$ROLE" ]
[ "$expected_uid:$expected_gid:$expected_nnp" = 0:0:0 ]
case "$ROLE" in
    sidecar)
        [ "$expected_exe" = /data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-sidecar-r6 ]
        [ "$expected_context" = u:r:trillionnium_owner_open_phone_executor:s0 ]
        ;;
    model|provider)
        [ "$expected_context" = u:r:magisk:s0 ]
        ;;
esac
printf '%s\n' "$expected_sha" | "$BB" grep -Eq '^[0-9a-f]{64}$'
[ -f "$CLAIM/$ROLE.identity" ] && [ ! -L "$CLAIM/$ROLE.identity" ]
expected_id=$($SYS/cat "$CLAIM/$ROLE.identity")
pid=${expected_id%%:*}
case "$pid" in ''|*[!0-9]*) exit 78 ;; esac
[ "$pid" -gt 1 ]
identity() {
    line=$($SYS/cat "/proc/$pid/stat") || return 1
    tail=${line##*) }
    printf '%s\n' "$tail" | "$BB" awk -v p="$pid" '{ if ($1 == "Z") exit 1; if ($3 != p || $4 != p) exit 1; print p ":" $3 ":" $4 ":" $20 }'
}
[ "$(identity)" = "$expected_id" ]
[ "$($SYS/getenforce)" = Enforcing ]
[ "$($SYS/cat "/proc/$pid/attr/current")" = "$expected_context" ]
[ "$($SYS/readlink "/proc/$pid/exe")" = "$expected_exe" ]
status=$($SYS/cat "/proc/$pid/status")
printf '%s\n' "$status" | "$BB" awk '
  $1=="Uid:" { if (NF!=5 || $2!=0 || $3!=0 || $4!=0 || $5!=0) exit 1; u++ }
  $1=="Gid:" { if (NF!=5 || $2!=0 || $3!=0 || $4!=0 || $5!=0) exit 1; g++ }
  $1=="NoNewPrivs:" { if (NF!=2 || $2!=0) exit 1; n++ }
  END { if (u!=1 || g!=1 || n!=1) exit 1 }'
if [ "$MODE" = startup ]; then
    digest=$($SYS/sha256sum "/proc/$pid/exe")
    actual_sha=${digest%% *}
    [ "$actual_sha" = "$expected_sha" ]
fi
[ "$(identity)" = "$expected_id" ]
[ "$($SYS/cat "/proc/$pid/attr/current")" = "$expected_context" ]
[ "$($SYS/readlink "/proc/$pid/exe")" = "$expected_exe" ]
printf 'role=%s identity=%s context=%s uid=0 gid=0 nnp=0 exe=%s mode=%s\n' "$ROLE" "$expected_id" "$expected_context" "$expected_exe" "$MODE"
