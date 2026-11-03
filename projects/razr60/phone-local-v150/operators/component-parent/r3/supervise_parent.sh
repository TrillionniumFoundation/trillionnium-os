#!/system/bin/sh
# Explicit one-use parent supervisor. Never starts a provider/model or sends a task.
set -eu
umask 077
if [ "$#" != 1 ] || [ "$1" != --execute-component-parent-once ]; then
    printf '%s\n' 'REVIEW_ONLY: explicit --execute-component-parent-once required; no process launched'
    exit 78
fi
. /data/local/tmp/hepta-component-parent-r6-r3/common.sh
[ "$($SYS/id -u)" = 0 ]
[ "$($SYS/cat /proc/$$/attr/current)" = "$MAGISK_CONTEXT" ]
root_nnp0 "$$"
[ "$($SYS/getprop ro.build.version.sdk)" = 36 ]
[ "$($SYS/getprop ro.trillionnium.owner_open.profile)" = leap-stock16-codex-host-relay-v1 ]
verify_fixed_inputs
allowed
# Accept only the exact r1 failure and r2 zero-action clean retirement.
verify_initial_journal || exit 79
# Fixed new directory is the one-use supervisor claim. Never erase/recreate it.
"$SYS/mkdir" -m 700 "$RUN"
private_directory "$RUN"
data_label "$RUN"
CHILD_PID=
CHILD_ID=
JOINED=0
WAIT_RESULT=unknown
FORCED=0
STOPPING=0
STOP_REASON=not_requested
RETIREMENT=UNKNOWN

census_owned_group() {
    census_number=$1
    # Complete readable /proc snapshot is required; any race/read error is UNKNOWN.
    # This covers the parent's original group/session, not separate worker sessions.
    if ( set -C
         "$BB" awk -v target="$CHILD_PID" '
           {
             pid=$1; tail=$0
             sub(/^.*\) /,"",tail)
             n=split(tail,a,/ +/)
             if(n<20) {bad=1; next}
             if(a[3]==target || a[4]==target)
                 print pid ":" a[3] ":" a[4] ":" a[20] ":state=" a[1]
           }
           END {if(bad) exit 2}
         ' /proc/[0-9]*/stat >"$RUN/group-census-$census_number.stdout" 2>"$RUN/group-census-$census_number.stderr"
    ); then
        [ ! -s "$RUN/group-census-$census_number.stdout" ] &&
        [ ! -s "$RUN/group-census-$census_number.stderr" ]
    else
        return 1
    fi
}
stop_and_join() {
    [ "$STOPPING" = 0 ] || return
    STOPPING=1
    [ -n "$CHILD_PID" ] || return
    write_once parent.stop-reason "$STOP_REASON" || :
    if [ -n "$CHILD_ID" ] && exact_identity "$CHILD_ID"; then
        write_once parent.pre-stop-identity "$CHILD_ID" || :
        if "$BB" kill -TERM "-$CHILD_PID"; then term_rc=0; else term_rc=$?; fi
        write_once parent.term-request-rc "$term_rc" || :
        stop_count=0
        while exact_identity "$CHILD_ID" && [ "$stop_count" -lt 12 ]; do
            "$BB" sleep 1
            stop_count=$((stop_count + 1))
        done
        if exact_identity "$CHILD_ID"; then
            FORCED=1
            if "$BB" kill -KILL "-$CHILD_PID"; then kill_rc=0; else kill_rc=$?; fi
            write_once parent.kill-request-rc "$kill_rc" || :
        fi
    else
        write_once parent.signal-skipped 'leader absent/identity unknown; do not signal a possibly reused group' || :
    fi
    # This is the shell that forked CHILD_PID. Do not move wait to a subshell.
    write_once parent.wait-intent "actual shell wait for own child $CHILD_PID" || :
    if wait "$CHILD_PID" >"$RUN/parent.wait.stdout" 2>"$RUN/parent.wait.stderr"; then
        WAIT_RESULT=0
        JOINED=1
    else
        WAIT_RESULT=$?
        # 127 is ambiguous with shell 'not a child'; do not invent join evidence.
        if [ "$WAIT_RESULT" != 127 ]; then JOINED=1; fi
    fi
    write_once parent.wait-return-code "$WAIT_RESULT" || :
    write_once parent.wait-observed "$JOINED" || :
    write_once parent.forced-group-kill "$FORCED" || :
    if [ "$JOINED" = 1 ] && census_owned_group 1; then
        "$BB" sleep 0.2
        if census_owned_group 2; then
            RETIREMENT=PARENT_CHILD_JOINED_ORIGINAL_GROUP_AND_SESSION_ABSENT
        fi
    fi
    write_once parent.retirement "$RETIREMENT" || :
    write_once retirement-scope 'Own parent child and its original group/session only. Separate worker sessions require original r6 receipt+independent census. Forced termination never proves business outcome.' || :
}
finish() {
    finish_rc=$?
    trap - EXIT
    trap '' INT TERM HUP
    stop_and_join
    if [ "$finish_rc" = 0 ] && [ "$RETIREMENT" != PARENT_CHILD_JOINED_ORIGINAL_GROUP_AND_SESSION_ABSENT ]; then finish_rc=75; fi
    if [ "$finish_rc" = 0 ] && [ "$FORCED" != 0 ]; then finish_rc=76; fi
    write_once supervisor.exit-code "$finish_rc" || :
    write_once supervisor.terminal-scope 'Supervisor exit is not native turn.end, worker/effect cleanup, component success or business qualification.' || :
    printf 'component_parent_supervisor exit=%s parent_wait=%s parent_joined=%s retirement=%s\n' "$finish_rc" "$WAIT_RESULT" "$JOINED" "$RETIREMENT"
    exit "$finish_rc"
}
trap finish EXIT
trap 'STOP_REASON=signal_TERM; exit 143' TERM
trap 'STOP_REASON=signal_INT; exit 130' INT
trap 'STOP_REASON=signal_HUP; exit 129' HUP
SUPERVISOR_ID=$(identity "$$")
case "$SUPERVISOR_ID" in "$$:$$:$$:"*) ;; *) STOP_REASON=supervisor_requires_own_session; exit 81 ;; esac
write_once supervisor.identity "$SUPERVISOR_ID"
write_once boot-id "$($SYS/cat /proc/sys/kernel/random/boot_id)"
write_once intent 'One explicitly authorized component parent. No automatic restart, no task submission, no model or UI operation.'
write_once persistence-limit 'Files are exclusively created and closed; no claim of filesystem fsync durability or cold-boot qualification. Root retains original evidence copies.'
write_once start-utc "$($SYS/date -u +%Y-%m-%dT%H:%M:%SZ)"
# Preserve all r1/r2 records and logs byte for byte. New output belongs to r3 only.
verify_initial_parent_logs
for name in parent.stdout parent.stderr; do
    (set -C; : >"$RUN/$name")
    [ "$($SYS/stat -c '%u:%g:%a:%h:%s' "$RUN/$name")" = 0:0:600:1:0 ]
    data_label "$RUN/$name"
done
write_once parent.spawn-intent 'Own-session guard. Application cannot exec until exact supervisor admission.'
"$BB" setsid "$SYS/sh" "$CODE/child_guard.sh" "$SUPERVISOR_ID" >>"$RUN/parent.stdout" 2>>"$RUN/parent.stderr" &
CHILD_PID=$!
write_once parent.spawn-pid "$CHILD_PID"
count=0
while [ "$count" -lt 40 ]; do
    allowed || { STOP_REASON=inhibited_before_admission; exit 82; }
    if [ -f "$RUN/parent.identity" ] && [ ! -L "$RUN/parent.identity" ]; then
        candidate=$($SYS/cat "$RUN/parent.identity") || candidate=
        case "$candidate" in "$CHILD_PID:$CHILD_PID:$CHILD_PID:"*)
            if exact_identity "$candidate"; then CHILD_ID=$candidate; break; fi
            ;;
        esac
    fi
    "$BB" sleep 0.1
    count=$((count + 1))
done
[ -n "$CHILD_ID" ] || { STOP_REASON=guard_identity_not_verified; exit 83; }
allowed || { STOP_REASON=inhibited_before_admission; exit 82; }
write_once parent.admit "$CHILD_ID"
count=0
exec_verified=0
while [ "$count" -lt 50 ]; do
    exact_identity "$CHILD_ID" || break
    allowed || { STOP_REASON=inhibited_waiting_exec; exit 82; }
    if exec_identity=$("$SYS/sh" "$CODE/observe_parent.sh" startup 2>&1); then
        write_once parent.exec-identity "$exec_identity"
        exec_verified=1
        break
    fi
    "$BB" sleep 0.1
    count=$((count + 1))
done
[ "$exec_verified" = 1 ] || { write_once parent.exec-identity-failure "${exec_identity-unknown}" || :; STOP_REASON=post_exec_identity_unverified; exit 84; }
write_once parent.started 'Post-exec PID/pgrp/session/start/exe hash/context/root credentials/NNP0 verified. This is not socket health or worker qualification.'
write_once parent.journal "$JOURNAL"
start_uptime=$(uptime_seconds)
write_once supervisor.start-uptime-seconds "$start_uptime"
printf 'component_parent_supervisor ready supervisor=%s parent=%s journal=%s\n' "$SUPERVISOR_ID" "$CHILD_ID" "$JOURNAL"
while :; do
    if [ -f "$RUN/STOP" ] && [ ! -L "$RUN/STOP" ]; then STOP_REASON=explicit_STOP; exit 0; fi
    allowed || { STOP_REASON=inhibited; exit 85; }
    exact_identity "$CHILD_ID" || { STOP_REASON=parent_leader_exited_or_changed; exit 86; }
    "$SYS/sh" "$CODE/observe_parent.sh" monitor >/dev/null 2>&1 || { STOP_REASON=parent_runtime_identity_changed; exit 87; }
    now_uptime=$(uptime_seconds)
    [ "$now_uptime" -ge "$start_uptime" ] || { STOP_REASON=uptime_invalid; exit 88; }
    [ "$((now_uptime - start_uptime))" -lt 600 ] || { STOP_REASON=absolute_600s_component_lease; exit 89; }
    "$BB" sleep 1
done
