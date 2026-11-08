#!/system/bin/sh
# Boot-aware v150-r9 phone-only startup. No task submission, retries, ADB, or mounts.
set -eu
umask 077
MODDIR=${0%/*}
BB=/data/adb/magisk/busybox
SYS=/system/bin
# Magisk may invoke this hook in its own session. Admit one private supervisor
# session before any claim, listener or service is created. Manual root startup
# already owns its session and therefore does not re-exec or fork here.
case "$#:${1-}" in 0:|1:--hepta-r9-owned-session) ;; *) exit 78 ;; esac
supervisor_stat=$("$SYS/cat" "/proc/$$/stat")
supervisor_tail=${supervisor_stat##*) }
supervisor_owned=$(printf '%s\n' "$supervisor_tail" | "$BB" awk -v p="$$" '{if ($1=="Z") exit 1; if ($3==p && $4==p) print "yes"; else print "no"}')
if [ "$supervisor_owned" != yes ]; then
    [ "$#" = 0 ] || exit 78
    exec "$BB" setsid "$BB" sh "$MODDIR/service.sh" --hepta-r9-owned-session
fi
STATE=/data/trillionnium/owner-open/state
HISTORY=/data/adb/trillionnium-hepta-phone-local-v150-r10-r1
ROOT=/data/trillionnium/owner-open/root
CLAIM=
PARENT_ID=
STOPPING=0
OWNER_STOP_DEADLINE=
# Preserve original child PID/identity/hash in this real parent, not just files.
OWNED_MODEL_PID=
OWNED_MODEL_ID=
OWNED_MODEL_BINDING=
OWNED_SIDECAR_PID=
OWNED_SIDECAR_ID=
OWNED_SIDECAR_BINDING=
OWNED_PROVIDER_PID=
OWNED_PROVIDER_ID=
OWNED_PROVIDER_BINDING=
EXECUTOR_DATA=/data/trillionnium/owner-open/state/phone-local-v150/executor-r6
EXECUTOR_LOG_ROOT=$EXECUTOR_DATA/module-history-r10-r1
EXECUTOR_LOGDIR=
previous_release_disabled() {
    "$BB" sh "$MODDIR/prior_module_guard.sh"
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
# Unsealed source candidates MUST fail closed. The seal is produced only after review.
[ -f "$MODDIR/SEALED" ] && [ ! -L "$MODDIR/SEALED" ]
[ "$($SYS/cat "$MODDIR/SEALED")" = HEPTA_PHONE_LOCAL_V150_R10_R1_REVIEWED_INPUTS_BOUND ]
[ -f "$MODDIR/module-inputs.sha256" ] && [ ! -L "$MODDIR/module-inputs.sha256" ]
[ -f "$MODDIR/payload-inputs.sha256" ] && [ ! -L "$MODDIR/payload-inputs.sha256" ]
[ -f "$MODDIR/role_guard.sh" ] && [ ! -L "$MODDIR/role_guard.sh" ]
for required in activation_gate.sh prior_module_guard.sh prior-modules.tsv role_identity_probe.sh role-expectations.tsv; do
    [ -f "$MODDIR/$required" ] && [ ! -L "$MODDIR/$required" ]
done
[ "$($SYS/stat -c '%u:%g' "$MODDIR")" = 0:0 ]
[ "$($SYS/stat -c '%a' "$MODDIR")" = 700 ]
cd "$MODDIR"
$SYS/sha256sum -c module-inputs.sha256
$SYS/sha256sum -c payload-inputs.sha256
previous_release_disabled || exit 70
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
write_once model-qualification 'PENDING_NEW_NONCE_FOR_V150_R9; old health is historical only'
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
# Helpers are bounded foreground children, not new resident roles. The shell
# preserves each actual foreground return; only it waits its three original jobs.
owner_stop_clock() {
    # /proc/uptime shares CLOCK_BOOTTIME with the bounded helper. Rounding down
    # makes the new 36-second observation window shorter, never longer.
    owner_uptime=
    owner_idle=
    read -r owner_uptime owner_idle < /proc/uptime || return 4
    owner_seconds=${owner_uptime%%.*}
    case "$owner_seconds" in ''|*[!0-9]*) return 4 ;; esac
    [ "${#owner_seconds}" -le 12 ] || return 4
}
owner_window_remaining() {
    [ -n "$OWNER_STOP_DEADLINE" ] || return 4
    owner_stop_clock || return 4
    [ "$owner_seconds" -lt "$OWNER_STOP_DEADLINE" ] || return 4
}
owner_evidence() {
    owner_tag=$1
    shift
    case "$owner_tag" in
        bind-model|bind-sidecar|bind-provider|probe-model|probe-sidecar|probe-provider|wait-model|wait-sidecar|wait-provider|supervisor-terminal) ;;
        *) return 4 ;;
    esac
    case "$owner_tag" in
        bind-*) ;;
        *) owner_window_remaining || return 4
           set -- "$@" --stop-deadline "$OWNER_STOP_DEADLINE" ;;
    esac
    owner_helper=$MODDIR/resident_owner_terminal.py
    [ -f "$owner_helper" ] && [ ! -L "$owner_helper" ] || return 4
    [ "$("$SYS/stat" -c '%u:%g:%a:%h:%s' "$owner_helper")" = 0:0:600:1:32701 ] || return 4
    [ "$("$SYS/sha256sum" "$owner_helper")" = "958d796590cbd4f1d8440f76fdd95a1b273237c3c78aa1db8696728a697ad55a  $owner_helper" ] || return 4
    if "$BB" env -i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 \
        LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu \
        PYTHONDONTWRITEBYTECODE=1 \
        "$BB" chroot "$ROOT" /usr/bin/python3 -I -B \
        "/proc/1/root$MODDIR/resident_owner_terminal.py" "$@"; then
        owner_rc=0
    else
        owner_rc=$?
    fi
    write_once "owner-$owner_tag.helper-return" "$owner_rc" || return 4
    return "$owner_rc"
}
owner_wait_role() {
    final_role=$1
    case "$final_role" in
        model) final_pid=$OWNED_MODEL_PID; final_id=$OWNED_MODEL_ID; final_binding=$OWNED_MODEL_BINDING ;;
        sidecar) final_pid=$OWNED_SIDECAR_PID; final_id=$OWNED_SIDECAR_ID; final_binding=$OWNED_SIDECAR_BINDING ;;
        provider) final_pid=$OWNED_PROVIDER_PID; final_id=$OWNED_PROVIDER_ID; final_binding=$OWNED_PROVIDER_BINDING ;;
        *) return 4 ;;
    esac
    [ -n "$final_pid" ] || return 0
    if [ -z "$PARENT_ID" ] || [ -z "$final_id" ] || [ -z "$final_binding" ]; then
        write_once "owner-$final_role.wait-unknown" 'original memory binding incomplete; no wait or retry' || :
        return 4
    fi
    # A positive generation-terminal probe makes this original builtin wait
    # nonblocking. Unknown, EACCES and a still-live child do not permit wait.
    if owner_evidence "probe-$final_role" probe --parent-identity "$PARENT_ID" \
        --role "$final_role" --pid "$final_pid" --identity "$final_id" \
        --binding-sha256 "$final_binding"; then
        if ! owner_window_remaining; then
            write_once "owner-$final_role.wait-unknown" 'observer window exhausted after probe; no wait or retry' || :
            return 4
        fi
        if wait "$final_pid"; then
            final_rc=0
        else
            final_rc=$?
        fi
        # Preserve the actual result before diagnostics. 127 is kept ambiguous.
        write_once "owner-$final_role.wait-status" "$final_pid:$final_rc" || return 4
        owner_evidence "wait-$final_role" record-wait --parent-identity "$PARENT_ID" \
            --role "$final_role" --pid "$final_pid" --identity "$final_id" \
            --binding-sha256 "$final_binding" --wait-status "$final_rc"
    else
        write_once "owner-$final_role.wait-unknown" 'positive terminal probe unavailable; no wait or retry' || :
        return 4
    fi
}
owner_terminal() {
    owner_finish_status=$1
    [ -n "$PARENT_ID" ] || return 4
    owner_window_remaining || return 4
    owner_memories="model,$OWNED_MODEL_PID,$OWNED_MODEL_ID,$OWNED_MODEL_BINDING;sidecar,$OWNED_SIDECAR_PID,$OWNED_SIDECAR_ID,$OWNED_SIDECAR_BINDING;provider,$OWNED_PROVIDER_PID,$OWNED_PROVIDER_ID,$OWNED_PROVIDER_BINDING"
    owner_evidence supervisor-terminal terminal --parent-identity "$PARENT_ID" \
        --memories "$owner_memories" --exit-status "$owner_finish_status"
}
stop_owned() {
    [ "$STOPPING" = 0 ] || return
    STOPPING=1
    # This limits only new evidence helpers and newly authorized builtin waits.
    # Original TERM/KILL cleanup below always runs, including clock failure.
    if owner_stop_clock; then
        OWNER_STOP_DEADLINE=$((owner_seconds + 36))
        write_once owner-stop-window "$owner_seconds:$OWNER_STOP_DEADLINE" || :
    fi
    # Stop admission before tools/model. Provider and sidecar own actual effect cancellation.
    for role in provider sidecar model; do terminate_role "$role" || :; done
    for owner_role in provider sidecar model; do owner_wait_role "$owner_role" || :; done
}
finish() {
    result=$?
    # A second stop source must not interrupt the existing bounded role cleanup.
    trap '' INT TERM HUP
    trap - EXIT
    stop_owned
    write_once exit-code "$result" || :
    write_once terminal-scope 'startup supervisor terminal only; no business success or full effect-quiescence claim' || :
    owner_terminal "$result" || :
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
    case "$role" in
        model) OWNED_MODEL_PID=$role_pid ;;
        sidecar) OWNED_SIDECAR_PID=$role_pid ;;
        provider) OWNED_PROVIDER_PID=$role_pid ;;
    esac
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
    case "$role" in
        model) OWNED_MODEL_ID=$captured ;;
        sidecar) OWNED_SIDECAR_ID=$captured ;;
        provider) OWNED_PROVIDER_ID=$captured ;;
    esac
    owner_evidence "bind-$role" bind --parent-identity "$PARENT_ID" \
        --role "$role" --pid "$role_pid" --identity "$captured" || return 1
    owner_binding=$("$SYS/sha256sum" "$CLAIM/owner-$role.bind.json") || return 1
    owner_binding=${owner_binding%% *}
    printf '%s\n' "$owner_binding" | "$BB" grep -Eq '^[0-9a-f]{64}$' || return 1
    case "$role" in
        model) OWNED_MODEL_BINDING=$owner_binding ;;
        sidecar) OWNED_SIDECAR_BINDING=$owner_binding ;;
        provider) OWNED_PROVIDER_BINDING=$owner_binding ;;
    esac
    # Only this exact, already-recorded group can cross the exec barrier.
    write_once "$role.admit" "$captured"
    wait_role_exec_identity "$role" || return 1
    write_once "$role.started" "$($SYS/date -u +%Y-%m-%dT%H:%M:%SZ)"
}
# Per-boot private model receipt/claim namespace; old epochs remain untouched.
MODEL_RUNTIME_ROOT=/data/trillionnium/owner-open/state/phone-local-v150/model-runtime-r10-r1
MODEL_RUN=$MODEL_RUNTIME_ROOT/$boot_id
GNU_MODEL_RUN=/var/lib/trillionnium/owner-open/phone-local-v150/model-runtime-r10-r1/$boot_id
prepare_model_runtime() {
    [ -d "$MODEL_RUNTIME_ROOT" ] && [ ! -L "$MODEL_RUNTIME_ROOT" ]
    [ "$("$SYS/readlink" -f "$MODEL_RUNTIME_ROOT")" = "$MODEL_RUNTIME_ROOT" ]
    [ "$("$SYS/stat" -c '%u:%g:%a' "$MODEL_RUNTIME_ROOT")" = 0:0:700 ]
    "$SYS/mkdir" -m 700 "$MODEL_RUN"
    "$SYS/mkdir" -m 700 "$MODEL_RUN/receipts" "$MODEL_RUN/bindings"
    for path in "$MODEL_RUN" "$MODEL_RUN/receipts" "$MODEL_RUN/bindings"; do
        [ "$("$SYS/stat" -c '%u:%g:%a' "$path")" = 0:0:700 ]
    done
    write_once model-runtime-directory "$MODEL_RUN"
}
bind_model_runtime() {
    identity_live model
    original=$("$SYS/cat" "$CLAIM/model.identity")
    ( set -C; printf '%s\n' "$original" > "$MODEL_RUN/model.identity" )
    "$SYS/cmp" "$CLAIM/model.identity" "$MODEL_RUN/model.identity"
    model_claim_hash=$("$SYS/sha256sum" "$MODEL_RUN/model.identity")
    model_claim_hash=${model_claim_hash%% *}
    write_once model-binding-intent 'read-only bounded readiness and one actual binding; no inference, no model restart'
    "$BB" env -i PATH=/usr/bin:/bin:/usr/libexec/trillionnium \
        PYTHONPATH=/usr/libexec/trillionnium/owner-open PYTHONHOME=/usr PYTHONDONTWRITEBYTECODE=1 \
        LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu \
        LANG=C.UTF-8 LC_ALL=C.UTF-8 NO_COLOR=1 TERM=dumb TMPDIR=/var/lib/trillionnium/owner-open/tmp \
        "$BB" chroot "$ROOT" /usr/bin/python3 -B \
        /var/lib/trillionnium/owner-open/phone-local-v150/provider-r10-r1/wait_and_bind_model.py \
        --config /var/lib/trillionnium/owner-open/phone-local-v150/local-config-r10-r1.json \
        --config-sha256 5ff00467e8432d7119ba72a700ce07cb20f16555d3dc0c90de7cbfc388103f48 \
        --server-sha256 dbca8b3c6d024c414d018146e73df996cae51b18c8cf5d3bdab6b776318a348c \
        --model-claim-sha256 "$model_claim_hash" --runtime-dir "$GNU_MODEL_RUN" \
        >"$CLAIM/model-binding.stdout" 2>"$CLAIM/model-binding.stderr"
    identity_live model
    "$SYS/cmp" "$CLAIM/model.identity" "$MODEL_RUN/model.identity"
    [ -f "$MODEL_RUN/READY-BOUND.json" ] && [ ! -L "$MODEL_RUN/READY-BOUND.json" ]
    write_once model-binding-complete 'actual current boot/process/binary, one idle slot, CPU text and image abort callbacks'
}
# Services may become listeners at different times; no health prompt is auto-issued.
prepare_executor_logs
prepare_model_runtime
start_role model
bind_model_runtime
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
