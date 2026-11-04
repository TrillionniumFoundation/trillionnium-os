#!/system/bin/sh
# Root-only resource observation. No writes, signals, sockets or model queries.
set -u
SYS=/system/bin
BB=/data/adb/magisk/busybox
CLAIM=/data/adb/trillionnium-hepta-phone-local-v150-r7-r2/<INSTANCE_UUID_REQUIRED>
emit_file() {
    label=$1
    path=$2
    encoded=$("$SYS/base64" "$path" 2>&1)
    code=$?
    packed=$(printf '%s' "$encoded" | "$SYS/base64" | "$SYS/tr" -d '\r\n')
    printf 'F\t%s\t%s\t%s\n' "$label" "$code" "$packed"
}
emit_command() {
    label=$1
    shift
    value=$("$@" 2>&1)
    code=$?
    packed=$(printf '%s' "$value" | "$SYS/base64" | "$SYS/tr" -d '\r\n')
    printf 'C\t%s\t%s\t%s\n' "$label" "$code" "$packed"
}
printf 'HEPTA_RESOURCE_SAMPLE_V1\n'
emit_file boot_id /proc/sys/kernel/random/boot_id
emit_file uptime.begin /proc/uptime
emit_command utc.begin "$SYS/date" -u +%Y-%m-%dT%H:%M:%SZ
emit_file services_started "$CLAIM/services-started"
BASE=/data/trillionnium/owner-open/state/phone-local-v150
emit_command binding.source_seal.sha256 "$SYS/sha256sum" "$BASE/provider-r7/SOURCE-SEAL-v150-r7.json"
emit_command binding.config.sha256 "$SYS/sha256sum" "$BASE/local-config-r7.json"
emit_command binding.daily.sha256 "$SYS/sha256sum" "$BASE/provider-r7/source/daily_phone_local.py"
emit_command binding.module.sha256 "$SYS/sha256sum" /data/adb/modules/trillionnium_hepta_phone_local_v150_r7_r2/MODULE-MANIFEST-v150-r7-r2.json
emit_file binding.ready "$BASE/provider-state/ready.json"
emit_command clk_tck "$BB" chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -c 'import os; print(os.sysconf("SC_CLK_TCK"))'
for role in model sidecar provider; do
    emit_file "$role.identity.begin" "$CLAIM/$role.identity"
    emit_command "$role.identity_stat.begin" "$SYS/stat" -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$CLAIM/$role.identity"
    ident=$("$SYS/cat" "$CLAIM/$role.identity" 2>/dev/null)
    case "$ident" in ''|*[!0-9:]*) continue ;; esac
    old_ifs=$IFS
    IFS=:
    read -r pid pgid sid ticks extra <<EOF
$ident
EOF
    IFS=$old_ifs
    [ -n "$pid" ] && [ -n "$pgid" ] && [ -n "$sid" ] && [ -n "$ticks" ] && [ -z "$extra" ] || continue
    [ "$pid" -gt 1 ] 2>/dev/null || continue
    emit_file "$role.proc_stat.begin" "/proc/$pid/stat"
    actual=$("$BB" awk '{pid=$1;tail=$0;sub(/^.*\) /,"",tail);n=split(tail,a,/ +/);if(n<20)exit 1;print pid ":" a[3] ":" a[4] ":" a[20]}' "/proc/$pid/stat" 2>/dev/null)
    [ "$actual" = "$ident" ] || continue
    emit_file "$role.status" "/proc/$pid/status"
    emit_file "$role.context" "/proc/$pid/attr/current"
    emit_command "$role.executable" "$SYS/readlink" "/proc/$pid/exe"
    emit_file "$role.proc_stat.end" "/proc/$pid/stat"
    emit_file "$role.identity.end" "$CLAIM/$role.identity"
    emit_command "$role.identity_stat.end" "$SYS/stat" -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$CLAIM/$role.identity"
done
emit_file meminfo /proc/meminfo
for attr in temp capacity current_now voltage_now; do
    emit_file "battery.$attr" "/sys/class/power_supply/battery/$attr"
done
emit_file uptime.end /proc/uptime
emit_command utc.end "$SYS/date" -u +%Y-%m-%dT%H:%M:%SZ
printf 'END\t0\n'
