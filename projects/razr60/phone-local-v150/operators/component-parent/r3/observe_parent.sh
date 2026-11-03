#!/system/bin/sh
# Read-only post-exec identity snapshot; no signal/socket/task.
set -eu
umask 077
[ "$#" = 1 ] || exit 78
MODE=$1
case "$MODE" in startup|monitor) ;; *) exit 78 ;; esac
. /data/local/tmp/hepta-component-parent-r6-r3/common.sh
private_directory "$RUN"
[ -f "$RUN/parent.identity" ] && [ ! -L "$RUN/parent.identity" ]
EXPECTED_ID=$($SYS/cat "$RUN/parent.identity")
PID=${EXPECTED_ID%%:*}
case "$EXPECTED_ID" in "$PID:$PID:$PID:"*) ;; *) exit 78 ;; esac
exact_identity "$EXPECTED_ID"
[ "$($SYS/getenforce)" = Enforcing ]
[ "$($SYS/cat "/proc/$PID/attr/current")" = "$PARENT_CONTEXT" ]
[ "$($SYS/readlink "/proc/$PID/exe")" = "$PARENT_BIN" ]
root_nnp0 "$PID"
if [ "$MODE" = startup ]; then
    digest=$($SYS/sha256sum "/proc/$PID/exe")
    [ "${digest%% *}" = "$PARENT_SHA" ]
fi
exact_identity "$EXPECTED_ID"
[ "$($SYS/cat "/proc/$PID/attr/current")" = "$PARENT_CONTEXT" ]
[ "$($SYS/readlink "/proc/$PID/exe")" = "$PARENT_BIN" ]
printf 'identity=%s context=%s uid=0 euid=0 gid=0 egid=0 nnp=0 exe=%s mode=%s\n' "$EXPECTED_ID" "$PARENT_CONTEXT" "$PARENT_BIN" "$MODE"
