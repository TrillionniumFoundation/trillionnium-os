#!/system/bin/sh
# Fixed component parent ownership only. Sourcing does not launch anything.
BB=/data/adb/magisk/busybox
SYS=/system/bin
CODE=/data/local/tmp/hepta-component-parent-r6-r2
STATEBASE=/data/trillionnium/owner-open/state/phone-local-v150
JOURNAL=$STATEBASE/executor-r6-component-01
PRIOR_RUN=$JOURNAL/owner-supervisor-r1
RUN=$JOURNAL/owner-supervisor-r2
PARENT_BIN=/data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-sidecar-r6
WORKER_BIN=/data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-worker-r6
PARENT_SHA=8595f99cf8d0f39ec2a45f85f1250745c158ea504d2d0520cd83791f28bdb976
WORKER_SHA=49fb74f8798194c63d5e510c0ed81604d64a55e1df84822d9457ae4110cab6da
PARENT_CONTEXT=u:r:trillionnium_owner_open_phone_executor:s0
DATA_CONTEXT=u:object_r:trillionnium_owner_open_phone_executor_data_file:s0
MAGISK_CONTEXT=u:r:magisk:s0

write_once() {
    ( set -C; printf '%s\n' "$2" > "$RUN/$1" )
}
identity() {
    identity_pid=$1
    case "$identity_pid" in ''|*[!0-9]*) return 1 ;; esac
    [ "$identity_pid" -gt 1 ] || return 1
    identity_line=$($SYS/cat "/proc/$identity_pid/stat") || return 1
    identity_tail=${identity_line##*) }
    printf '%s\n' "$identity_tail" | "$BB" awk -v p="$identity_pid" '
      NF < 20 || $1 == "Z" { exit 1 }
      { print p ":" $3 ":" $4 ":" $20 }'
}
exact_identity() {
    expected_identity=$1
    expected_pid=${expected_identity%%:*}
    observed_identity=$(identity "$expected_pid") || return 1
    [ "$observed_identity" = "$expected_identity" ]
}
private_directory() {
    [ -d "$1" ] && [ ! -L "$1" ] || return 1
    [ "$($SYS/readlink -f "$1")" = "$1" ] || return 1
    [ "$($SYS/stat -c '%u:%g:%a' "$1")" = 0:0:700 ] || return 1
}
exact_label() {
    label_line=$($SYS/ls -Zd "$1") || return 1
    printf '%s\n' "$label_line" | "$BB" awk -v p="$1" -v c="$2" '
      NF != 2 || $1 != c || $2 != p { exit 1 }
      { n++ } END { if(n != 1) exit 1 }'
}
data_label() { exact_label "$1" "$DATA_CONTEXT"; }
old_releases_off() {
    [ -d /data/adb/modules/trillionnium_hepta_phone_local_v150_r4 ] &&
    [ ! -L /data/adb/modules/trillionnium_hepta_phone_local_v150_r4 ] &&
    [ -f /data/adb/modules/trillionnium_hepta_phone_local_v150_r4/disable ] &&
    [ ! -L /data/adb/modules/trillionnium_hepta_phone_local_v150_r4/disable ] || return 1
    for old in /data/adb/modules/trillionnium_hepta_phone_local_v150 /data/adb/modules/trillionnium_hepta_phone_local_v150_r3; do
        [ ! -L "$old" ] || return 1
        if [ ! -e "$old" ]; then continue; fi
        [ -d "$old" ] || return 1
        if [ -f "$old/disable" ] && [ ! -L "$old/disable" ]; then continue; fi
        if [ -f "$old/remove" ] && [ ! -L "$old/remove" ]; then continue; fi
        return 1
    done
}
allowed() {
    [ "$($SYS/getenforce)" = Enforcing ] || return 1
    old_releases_off || return 1
    [ ! -e "$RUN/STOP" ] && [ ! -L "$RUN/STOP" ] || return 1
    [ ! -e /data/trillionnium/owner-open/state/emergency-stop ] &&
    [ ! -L /data/trillionnium/owner-open/state/emergency-stop ] || return 1
    stop_value=$($SYS/getprop sys.trillionnium.owner_open.stop) || return 1
    case "$stop_value" in ''|0) ;; *) return 1 ;; esac
    for f in disable remove; do
        [ ! -e /data/adb/modules/trillionnium_hepta_stock16_v143/$f ] &&
        [ ! -L /data/adb/modules/trillionnium_hepta_stock16_v143/$f ] || return 1
    done
}
root_nnp0() {
    check_status=$($SYS/cat "/proc/$1/status") || return 1
    printf '%s\n' "$check_status" | "$BB" awk '
      $1=="Uid:" { if(NF!=5 || $2!=0 || $3!=0 || $4!=0 || $5!=0) exit 1; u++ }
      $1=="Gid:" { if(NF!=5 || $2!=0 || $3!=0 || $4!=0 || $5!=0) exit 1; g++ }
      $1=="NoNewPrivs:" { if(NF!=2 || $2!=0) exit 1; n++ }
      END { if(u!=1 || g!=1 || n!=1) exit 1 }'
}
verify_prior_records() {
    private_directory "$PRIOR_RUN" && data_label "$PRIOR_RUN" || return 1
    prior_listing=$("$SYS/ls" -A "$PRIOR_RUN") || return 1
    [ "$prior_listing" = "$(printf '%s\n' boot-id group-census-1.stderr group-census-1.stdout group-census-2.stderr group-census-2.stdout intent parent.admit parent.exec-identity-failure parent.forced-group-kill parent.identity parent.retirement parent.signal-skipped parent.spawn-intent parent.spawn-pid parent.stop-reason parent.wait-intent parent.wait-observed parent.wait-return-code parent.wait.stderr parent.wait.stdout persistence-limit retirement-scope start-utc supervisor.exit-code supervisor.identity supervisor.terminal-scope)" ] || return 1
    for prior_name in boot-id group-census-1.stderr group-census-1.stdout group-census-2.stderr group-census-2.stdout intent parent.admit parent.exec-identity-failure parent.forced-group-kill parent.identity parent.retirement parent.signal-skipped parent.spawn-intent parent.spawn-pid parent.stop-reason parent.wait-intent parent.wait-observed parent.wait-return-code parent.wait.stderr parent.wait.stdout persistence-limit retirement-scope start-utc supervisor.exit-code supervisor.identity supervisor.terminal-scope; do
        prior_path=$PRIOR_RUN/$prior_name
        [ -f "$prior_path" ] && [ ! -L "$prior_path" ] || return 1
        [ "$($SYS/readlink -f "$prior_path")" = "$prior_path" ] || return 1
        [ "$($SYS/stat -c '%u:%g:%a:%h' "$prior_path")" = 0:0:600:1 ] || return 1
        data_label "$prior_path" || return 1
    done
    [ "$($SYS/cat "$PRIOR_RUN/parent.identity")" = 28581:28581:28581:7547479 ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN/supervisor.identity")" = 28473:28473:28473:7547409 ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN/parent.wait-observed")" = 1 ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN/parent.wait-return-code")" = 1 ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN/supervisor.exit-code")" = 84 ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN/parent.forced-group-kill")" = 0 ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN/parent.retirement")" = PARENT_CHILD_JOINED_ORIGINAL_GROUP_AND_SESSION_ABSENT ] || return 1
    [ "$($SYS/cat /proc/sys/kernel/random/boot_id)" = "$($SYS/cat "$PRIOR_RUN/boot-id")" ] || return 1
    [ ! -e "$PRIOR_RUN/parent.started" ] && [ ! -L "$PRIOR_RUN/parent.started" ] || return 1
}
verify_prior_groups_absent() {
    # Read only. Never signal any old PID or group, even if a number is reused.
    [ ! -e /proc/28473 ] && [ ! -e /proc/28581 ] || return 1
    prior_members=$("$BB" awk '
        {
            pid=$1;tail=$0
            sub(/^.*\) /,"",tail)
            n=split(tail,a,/ +/)
            if(n<20) {bad=1;next}
            if(a[3]==28473 || a[4]==28473 || a[3]==28581 || a[4]==28581)
                print pid ":" a[3] ":" a[4] ":" a[20] ":state=" a[1]
        }
        END {if(bad) exit 2}
    ' /proc/[0-9]*/stat) || return 1
    [ -z "$prior_members" ] || return 1
}
verify_fixed_inputs() {
    private_directory "$CODE" || return 1
    for owned_source in common.sh child_guard.sh observe_parent.sh supervise_parent.sh; do
        [ -f "$CODE/$owned_source" ] && [ ! -L "$CODE/$owned_source" ] || return 1
        [ "$($SYS/stat -c '%u:%g:%a:%h' "$CODE/$owned_source")" = 0:0:600:1 ] || return 1
    done
    for owned_bin_dir in /data/local/tmp/hepta-phone-executor-v150-r6 /data/local/tmp/hepta-phone-executor-v150-r6/bin; do
        [ -d "$owned_bin_dir" ] && [ ! -L "$owned_bin_dir" ] || return 1
        [ "$($SYS/readlink -f "$owned_bin_dir")" = "$owned_bin_dir" ] || return 1
        case "$($SYS/stat -c '%u:%g:%a' "$owned_bin_dir")" in 0:0:755|0:0:555) ;; *) return 1 ;; esac
    done
    [ -f "$CODE/SHA256SUMS" ] && [ ! -L "$CODE/SHA256SUMS" ] || return 1
    [ "$($SYS/stat -c '%u:%g:%a:%h' "$CODE/SHA256SUMS")" = 0:0:600:1 ] || return 1
    verify_prior_records || return 1
    (cd "$CODE" && "$SYS/sha256sum" -c SHA256SUMS) || return 1
    for executable in "$PARENT_BIN" "$WORKER_BIN"; do
        [ -f "$executable" ] && [ ! -L "$executable" ] || return 1
        [ "$($SYS/readlink -f "$executable")" = "$executable" ] || return 1
        case "$($SYS/stat -c '%u:%g:%a:%h' "$executable")" in 0:0:755:1|0:0:555:1) ;; *) return 1 ;; esac
    done
    # Consume both fixed binary pins independently of the external SUMS inventory.
    [ "$($SYS/stat -c '%s' "$PARENT_BIN")" = 965824 ] || return 1
    [ "$($SYS/stat -c '%s' "$WORKER_BIN")" = 296096 ] || return 1
    parent_digest=$($SYS/sha256sum "$PARENT_BIN") || return 1
    worker_digest=$($SYS/sha256sum "$WORKER_BIN") || return 1
    [ "${parent_digest%% *}" = "$PARENT_SHA" ] || return 1
    [ "${worker_digest%% *}" = "$WORKER_SHA" ] || return 1
    exact_label "$PARENT_BIN" u:object_r:trillionnium_owner_open_phone_executor_exec:s0 || return 1
    exact_label "$WORKER_BIN" u:object_r:trillionnium_owner_open_phone_worker_exec:s0 || return 1
    private_directory "$JOURNAL" && data_label "$JOURNAL" || return 1
}
verify_initial_journal() {
    # This journal contains the immutable zero-action r1 startup failure only.
    # No actions, server.lock, r2 claim, symlink, or extra entry is accepted.
    private_directory "$JOURNAL" && data_label "$JOURNAL" || return 1
    [ "$($SYS/stat -c '%d:%i' "$JOURNAL")" = 65086:138921 ] || return 1
    journal_listing=$("$SYS/ls" -A "$JOURNAL") || return 1
    [ "$journal_listing" = "$(printf '%s\n' owner-supervisor-r1 parent.stderr parent.stdout)" ] || return 1
    [ ! -e "$JOURNAL/actions" ] && [ ! -L "$JOURNAL/actions" ] || return 1
    [ ! -e "$JOURNAL/server.lock" ] && [ ! -L "$JOURNAL/server.lock" ] || return 1
    verify_prior_groups_absent || return 1
    verify_initial_parent_logs
}
verify_initial_parent_logs() {
    for log_name in parent.stdout parent.stderr; do
        case "$log_name" in
            parent.stdout) log_inode=139075; log_size=1082; log_sha=28f7b29bc3341bc4985d4a0d1ddef7629f1f5213d6bb204755a8b9555a2d1535 ;;
            parent.stderr) log_inode=138589; log_size=2210; log_sha=6608b208897a584f32c022570560f98297137eba0e36462690155886140beff9 ;;
        esac
        log_path=$JOURNAL/$log_name
        [ -f "$log_path" ] && [ ! -L "$log_path" ] || return 1
        [ "$($SYS/readlink -f "$log_path")" = "$log_path" ] || return 1
        [ "$($SYS/stat -c '%d:%i:%u:%g:%a:%h:%s' "$log_path")" = "65086:$log_inode:0:0:600:1:$log_size" ] || return 1
        log_digest=$($SYS/sha256sum "$log_path") || return 1
        [ "${log_digest%% *}" = "$log_sha" ] || return 1
        data_label "$log_path" || return 1
    done
}
uptime_seconds() {
    "$BB" awk '{ if (NF < 1 || $1 !~ /^[0-9]+[.][0-9]+$/) exit 1; printf "%.0f\n",int($1) }' /proc/uptime
}
