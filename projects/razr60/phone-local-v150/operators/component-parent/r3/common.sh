#!/system/bin/sh
# Fixed component parent ownership only. Sourcing does not launch anything.
BB=/data/adb/magisk/busybox
SYS=/system/bin
CODE=/data/local/tmp/hepta-component-parent-r6-r3
STATEBASE=/data/trillionnium/owner-open/state/phone-local-v150
JOURNAL=$STATEBASE/executor-r6-component-01
PRIOR_RUN=$JOURNAL/owner-supervisor-r1
PRIOR_RUN2=$JOURNAL/owner-supervisor-r2
RUN=$JOURNAL/owner-supervisor-r3
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
verify_prior_r2_records() {
    # Original r2 reached identity-ready, accepted no action, then joined cleanly.
    # All 32 original bytes/inodes remain evidence; none is opened for write.
    private_directory "$PRIOR_RUN2" && data_label "$PRIOR_RUN2" || return 1
    [ "$($SYS/stat -c '%d:%i' "$PRIOR_RUN")" = 65086:137786 ] || return 1
    [ "$($SYS/stat -c '%d:%i' "$PRIOR_RUN2")" = 65086:135611 ] || return 1
    r2_listing=$("$SYS/ls" -A "$PRIOR_RUN2") || return 1
    [ "$r2_listing" = "$(printf '%s\n' boot-id group-census-1.stderr group-census-1.stdout group-census-2.stderr group-census-2.stdout intent parent.admit parent.exec-identity parent.forced-group-kill parent.identity parent.journal parent.pre-stop-identity parent.retirement parent.spawn-intent parent.spawn-pid parent.started parent.stderr parent.stdout parent.stop-reason parent.term-request-rc parent.wait-intent parent.wait-observed parent.wait-return-code parent.wait.stderr parent.wait.stdout persistence-limit retirement-scope start-utc supervisor.exit-code supervisor.identity supervisor.start-uptime-seconds supervisor.terminal-scope)" ] || return 1
    for r2_name in boot-id group-census-1.stderr group-census-1.stdout group-census-2.stderr group-census-2.stdout intent parent.admit parent.exec-identity parent.forced-group-kill parent.identity parent.journal parent.pre-stop-identity parent.retirement parent.spawn-intent parent.spawn-pid parent.started parent.stderr parent.stdout parent.stop-reason parent.term-request-rc parent.wait-intent parent.wait-observed parent.wait-return-code parent.wait.stderr parent.wait.stdout persistence-limit retirement-scope start-utc supervisor.exit-code supervisor.identity supervisor.start-uptime-seconds supervisor.terminal-scope; do
        r2_path=$PRIOR_RUN2/$r2_name
        [ -f "$r2_path" ] && [ ! -L "$r2_path" ] || return 1
        [ "$($SYS/readlink -f "$r2_path")" = "$r2_path" ] || return 1
        case "$r2_name" in
            boot-id) r2_expected='65086:138211:0:0:600:1:37' ;;
            group-census-1.stderr) r2_expected='65086:136201:0:0:600:1:0' ;;
            group-census-1.stdout) r2_expected='65086:136160:0:0:600:1:0' ;;
            group-census-2.stderr) r2_expected='65086:137764:0:0:600:1:0' ;;
            group-census-2.stdout) r2_expected='65086:135602:0:0:600:1:0' ;;
            intent) r2_expected='65086:139581:0:0:600:1:112' ;;
            parent.admit) r2_expected='65086:139354:0:0:600:1:23' ;;
            parent.exec-identity) r2_expected='65086:138897:0:0:600:1:206' ;;
            parent.forced-group-kill) r2_expected='65086:138409:0:0:600:1:2' ;;
            parent.identity) r2_expected='65086:138158:0:0:600:1:23' ;;
            parent.journal) r2_expected='65086:136042:0:0:600:1:78' ;;
            parent.pre-stop-identity) r2_expected='65086:138959:0:0:600:1:23' ;;
            parent.retirement) r2_expected='65086:139234:0:0:600:1:54' ;;
            parent.spawn-intent) r2_expected='65086:138656:0:0:600:1:77' ;;
            parent.spawn-pid) r2_expected='65086:136255:0:0:600:1:5' ;;
            parent.started) r2_expected='65086:127709:0:0:600:1:133' ;;
            parent.stderr) r2_expected='65086:137583:0:0:600:1:0' ;;
            parent.stdout) r2_expected='65086:137557:0:0:600:1:8176' ;;
            parent.stop-reason) r2_expected='65086:137829:0:0:600:1:30' ;;
            parent.term-request-rc) r2_expected='65086:138584:0:0:600:1:2' ;;
            parent.wait-intent) r2_expected='65086:138501:0:0:600:1:37' ;;
            parent.wait-observed) r2_expected='65086:138444:0:0:600:1:2' ;;
            parent.wait-return-code) r2_expected='65086:139106:0:0:600:1:2' ;;
            parent.wait.stderr) r2_expected='65086:131980:0:0:600:1:0' ;;
            parent.wait.stdout) r2_expected='65086:138558:0:0:600:1:0' ;;
            persistence-limit) r2_expected='65086:138433:0:0:600:1:149' ;;
            retirement-scope) r2_expected='65086:122737:0:0:600:1:177' ;;
            start-utc) r2_expected='65086:135441:0:0:600:1:21' ;;
            supervisor.exit-code) r2_expected='65086:137650:0:0:600:1:3' ;;
            supervisor.identity) r2_expected='65086:139679:0:0:600:1:23' ;;
            supervisor.start-uptime-seconds) r2_expected='65086:138153:0:0:600:1:6' ;;
            supervisor.terminal-scope) r2_expected='65086:136068:0:0:600:1:108' ;;
            *) return 1 ;;
        esac
        [ "$($SYS/stat -c '%d:%i:%u:%g:%a:%h:%s' "$r2_path")" = "$r2_expected" ] || return 1
        data_label "$r2_path" || return 1
    done
    [ "$($SYS/cat "$PRIOR_RUN2/parent.identity")" = 8803:8803:8803:7732883 ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN2/supervisor.identity")" = 8319:8319:8319:7732678 ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN2/parent.admit")" = 8803:8803:8803:7732883 ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN2/parent.wait-observed")" = 1 ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN2/parent.wait-return-code")" = 0 ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN2/supervisor.exit-code")" = 89 ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN2/parent.stop-reason")" = absolute_600s_component_lease ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN2/parent.forced-group-kill")" = 0 ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN2/parent.term-request-rc")" = 0 ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN2/parent.retirement")" = PARENT_CHILD_JOINED_ORIGINAL_GROUP_AND_SESSION_ABSENT ] || return 1
    [ "$($SYS/cat "$PRIOR_RUN2/parent.journal")" = "$JOURNAL" ] || return 1
    [ "$($SYS/cat /proc/sys/kernel/random/boot_id)" = "$($SYS/cat "$PRIOR_RUN2/boot-id")" ] || return 1
    for r2_empty in group-census-1.stderr group-census-1.stdout group-census-2.stderr group-census-2.stdout parent.stderr parent.wait.stderr parent.wait.stdout; do
        [ ! -s "$PRIOR_RUN2/$r2_empty" ] || return 1
    done
}
verify_prior_groups_absent() {
    # Read only. Never signal any old PID or group, even if a number is reused.
    [ ! -e /proc/28473 ] && [ ! -e /proc/28581 ] &&
    [ ! -e /proc/8319 ] && [ ! -e /proc/8803 ] || return 1
    prior_members=$("$BB" awk '
        {
            pid=$1;tail=$0
            sub(/^.*\) /,"",tail)
            n=split(tail,a,/ +/)
            if(n<20) {bad=1;next}
            if(a[3]==28473 || a[4]==28473 || a[3]==28581 || a[4]==28581 ||
               a[3]==8319 || a[4]==8319 || a[3]==8803 || a[4]==8803)
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
    verify_prior_r2_records || return 1
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
    # Preserve r1 failed startup and r2 ready/zero-action clean retirement.
    # Reuse only the exact existing empty actions directory and zero-byte lock.
    private_directory "$JOURNAL" && data_label "$JOURNAL" || return 1
    [ "$($SYS/stat -c '%d:%i' "$JOURNAL")" = 65086:138921 ] || return 1
    journal_listing=$("$SYS/ls" -A "$JOURNAL") || return 1
    [ "$journal_listing" = "$(printf '%s\n' actions owner-supervisor-r1 owner-supervisor-r2 parent.stderr parent.stdout server.lock)" ] || return 1
    private_directory "$JOURNAL/actions" && data_label "$JOURNAL/actions" || return 1
    [ "$($SYS/stat -c '%d:%i' "$JOURNAL/actions")" = 65086:138829 ] || return 1
    action_entries=$("$SYS/ls" -A "$JOURNAL/actions") || return 1
    [ -z "$action_entries" ] || return 1
    lock_path=$JOURNAL/server.lock
    [ -f "$lock_path" ] && [ ! -L "$lock_path" ] || return 1
    [ "$($SYS/readlink -f "$lock_path")" = "$lock_path" ] || return 1
    [ "$($SYS/stat -c '%d:%i:%u:%g:%a:%h:%s' "$lock_path")" = 65086:127107:0:0:600:1:0 ] || return 1
    data_label "$lock_path" || return 1
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
