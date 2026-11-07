#!/system/bin/sh
# Read-only predecessor gate. Missing directories require reviewed archive pins.
set -eu
umask 077
BB=/data/adb/magisk/busybox
SYS=/system/bin
MODDIR=${0%/*}
MODULES=/data/adb/modules
ARCHIVES=/data/trillionnium/owner-open/state/phone-local-v150/module-archives-r10-r1
REGISTRY=$MODDIR/prior-modules.tsv
[ "$#" = 0 ]
[ "$("$SYS/id" -u)" = 0 ]
[ -d "$MODULES" ] && [ ! -L "$MODULES" ]
[ "$("$SYS/readlink" -f "$MODULES")" = "$MODULES" ]
[ -f "$REGISTRY" ] && [ ! -L "$REGISTRY" ]
[ "$("$SYS/stat" -c '%u:%g:%a:%h' "$REGISTRY")" = 0:0:600:1 ]
[ "$("$SYS/stat" -c '%s' "$REGISTRY")" -le 8192 ]
registry_before=$("$SYS/stat" -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$REGISTRY")
"$BB" awk -F '\t' 'NF!=6 || seen[$1]++ {exit 1} {n++} END {if(n!=12)exit 1}' "$REGISTRY"
for module in trillionnium_hepta_phone_local_v150 \
    trillionnium_hepta_phone_local_v150_r3 \
    trillionnium_hepta_phone_local_v150_r4 \
    trillionnium_hepta_phone_local_v150_r5 \
    trillionnium_hepta_phone_local_v150_r5_r3 \
    trillionnium_hepta_phone_local_v150_r6_r1 \
    trillionnium_hepta_phone_local_v150_r6_r2 \
    trillionnium_hepta_phone_local_v150_r7_r1 \
    trillionnium_hepta_phone_local_v150_r7_r2 \
    trillionnium_hepta_phone_local_v150_r7_r3 \
    trillionnium_hepta_phone_local_v150_r9_r1 \
    trillionnium_hepta_phone_local_v150_r9_r2; do
    row=$("$BB" awk -F '\t' -v id="$module" '$1==id {print;n++} END {if(n!=1)exit 1}' "$REGISTRY")
    IFS="$(printf '\t')" read -r name mode tar_bytes tar_sha index_bytes index_sha <<EOF
$row
EOF
    [ "$name" = "$module" ]
    prior=$MODULES/$module
    [ ! -L "$prior" ]
    case "$mode" in
        disabled)
            [ "$tar_bytes:$tar_sha:$index_bytes:$index_sha" = '-:-:-:-' ]
            [ -d "$prior" ] && [ "$("$SYS/readlink" -f "$prior")" = "$prior" ]
            [ "$("$SYS/stat" -c '%u:%g' "$prior")" = 0:0 ]
            [ -f "$prior/disable" ] && [ ! -L "$prior/disable" ]
            [ "$("$SYS/stat" -c '%u:%g:%h' "$prior/disable")" = 0:0:1 ]
            ;;
        archived)
            # The index is produced by archive_module.py from a complete,
            # disabled, stable snapshot. Both artifacts are separately sealed.
            [ ! -e "$prior" ]
            printf '%s\n' "$tar_bytes" "$index_bytes" | "$BB" grep -Eqv '^[1-9][0-9]*$' && exit 76
            [ "$tar_bytes" -le 134217728 ] && [ "$index_bytes" -le 2097152 ]
            printf '%s\n' "$tar_sha" "$index_sha" | "$BB" grep -Eqv '^[0-9a-f]{64}$' && exit 76
            [ -d "$ARCHIVES" ] && [ ! -L "$ARCHIVES" ]
            [ "$("$SYS/readlink" -f "$ARCHIVES")" = "$ARCHIVES" ]
            [ "$("$SYS/stat" -c '%u:%g:%a' "$ARCHIVES")" = 0:0:700 ]
            for kind in tar json; do
                path=$ARCHIVES/$module.$kind
                [ -f "$path" ] && [ ! -L "$path" ]
                [ "$("$SYS/stat" -c '%u:%g:%a:%h' "$path")" = 0:0:600:1 ]
                before=$("$SYS/stat" -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$path")
                if [ "$kind" = tar ]; then expected_bytes=$tar_bytes; expected_sha=$tar_sha
                else expected_bytes=$index_bytes; expected_sha=$index_sha; fi
                [ "$("$SYS/stat" -c '%s' "$path")" = "$expected_bytes" ]
                digest=$("$SYS/sha256sum" "$path")
                [ "${digest%% *}" = "$expected_sha" ]
                [ "$("$SYS/stat" -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$path")" = "$before" ]
            done
            ;;
        *) exit 76 ;;
    esac
done
[ "$("$SYS/stat" -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$REGISTRY")" = "$registry_before" ]
