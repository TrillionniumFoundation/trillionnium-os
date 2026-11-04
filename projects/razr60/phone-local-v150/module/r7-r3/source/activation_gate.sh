#!/system/bin/sh
# Read-only current-boot activation. No policy load, listener, task, effect or resolution write.
set -eu
umask 077
BB=/data/adb/magisk/busybox
SYS=/system/bin
MODDIR=${0%/*}
ROOT=/data/trillionnium/owner-open/root
BASE=/data/trillionnium/owner-open/state/phone-local-v150
MODE=${1-}
case "$MODE" in
    startup) [ "$#" = 1 ] ;;
    admission)
        [ "$#" = 3 ]
        case "$2" in /data/adb/trillionnium-hepta-phone-local-v150-r7-r3/*) ;; *) exit 78 ;; esac
        case "$3" in model|sidecar|provider) ;; *) exit 78 ;; esac
        ;;
    *) exit 78 ;;
esac
[ "$("$SYS/id" -u)" = 0 ]
[ "$("$SYS/getenforce")" = Enforcing ]
for f in activation-inputs.tsv activation-artifacts.sha256 retired-groups.tsv; do
    [ -f "$MODDIR/$f" ] && [ ! -L "$MODDIR/$f" ]
    [ "$("$SYS/stat" -c '%u:%g:%a:%h' "$MODDIR/$f")" = 0:0:600:1 ]
done
(cd "$MODDIR" && "$SYS/sha256sum" -c activation-artifacts.sha256)
row=$("$BB" awk -F '\t' 'NF!=2 {exit 1} {n++; print} END {if(n!=1)exit 1}' "$MODDIR/activation-inputs.tsv")
IFS="$(printf '\t')" read -r expected_boot expected_live_policy <<EOF
$row
EOF
printf '%s\n' "$expected_boot" | "$BB" grep -Eq '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
printf '%s\n' "$expected_live_policy" | "$BB" grep -Eq '^[0-9a-f]{64}$'
[ "$("$SYS/cat" /proc/sys/kernel/random/boot_id)" = "$expected_boot" ]
policy_digest=$("$SYS/sha256sum" /sys/fs/selinux/policy)
[ "${policy_digest%% *}" = "$expected_live_policy" ]
# Keys stay in their existing private files. No key bytes or key digests are
# embedded, logged, or emitted. Compare only file identity/permissions and equality.
model_key=/data/local/tmp/hepta-phone-local-v150-r1/state/api.key
provider_key=$BASE/private/llama-api.key
for key_path in "$model_key" "$provider_key"; do
    [ -f "$key_path" ] && [ ! -L "$key_path" ]
    [ "$("$SYS/readlink" -f "$key_path")" = "$key_path" ]
    key_size=$("$SYS/stat" -c '%s' "$key_path")
    [ "$key_size" -gt 0 ] && [ "$key_size" -le 4096 ]
done
[ "$("$SYS/stat" -c '%u:%a:%h' "$model_key")" = 2000:600:1 ]
[ "$("$SYS/stat" -c '%u:%a:%h' "$provider_key")" = 0:600:1 ]
model_key_identity=$("$SYS/stat" -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$model_key")
provider_key_identity=$("$SYS/stat" -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$provider_key")
"$SYS/cmp" "$model_key" "$provider_key" >/dev/null 2>&1
[ "$("$SYS/stat" -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$model_key")" = "$model_key_identity" ]
[ "$("$SYS/stat" -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$provider_key")" = "$provider_key_identity" ]
# The GNU helper below performs the same thirty-group census with explicit kernel errno handling.
exact_label() {
    observed=$("$SYS/ls" -Zd "$1")
    printf '%s\n' "$observed" | "$BB" awk -v p="$1" -v c="$2" 'NF!=2 || $1!=c || $2!=p {exit 1} {n++} END {if(n!=1)exit 1}'
}
exact_label /data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-sidecar-r6 u:object_r:trillionnium_owner_open_phone_executor_exec:s0
exact_label /data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-worker-r6 u:object_r:trillionnium_owner_open_phone_worker_exec:s0
for d in "$BASE/executor-r6" "$BASE/executor-r6/module-history-r7-r3"; do
    [ -d "$d" ] && [ ! -L "$d" ]
    [ "$("$SYS/readlink" -f "$d")" = "$d" ]
    [ "$("$SYS/stat" -c '%u:%g:%a' "$d")" = 0:0:700 ]
    exact_label "$d" u:object_r:trillionnium_owner_open_phone_executor_data_file:s0
done
# This existing audited Python source takes a shared read-only ledger lock and
# validates the exact original retirement plus every existing intent resolution.
# It does not create claims, resolve anything, call a socket or execute an effect.
exec "$BB" timeout -s TERM -k 2 4 "$BB" env -i \
    PATH=/usr/bin:/bin:/usr/libexec/trillionnium \
    PYTHONPATH=/usr/libexec/trillionnium/owner-open PYTHONHOME=/usr \
    PYTHONDONTWRITEBYTECODE=1 \
    LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu \
    LANG=C.UTF-8 LC_ALL=C.UTF-8 TMPDIR=/var/lib/trillionnium/owner-open/tmp \
    NO_COLOR=1 TERM=dumb \
    "$BB" chroot "$ROOT" /usr/bin/python3 -B \
    /var/lib/trillionnium/owner-open/phone-local-v150/module-r7-activation-r3/proc_and_original_gate.py --check-and-chain
