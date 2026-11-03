#!/system/bin/sh
# Own-session child barrier. Only the pinned r6 parent may be exec'd.
set -eu
umask 077
[ "$#" = 1 ] || exit 80
PARENT_ID=$1
. /data/local/tmp/hepta-component-parent-r6-r3/common.sh
private_directory "$RUN"
verify_fixed_inputs
[ "$($SYS/cat /proc/$$/attr/current)" = "$MAGISK_CONTEXT" ]
root_nnp0 "$$"
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
OWN_ID=$(identity "$$")
case "$OWN_ID" in "$$:$$:$$:"*) ;; *) exit 81 ;; esac
exact_identity "$PARENT_ID"
allowed
write_once parent.identity "$OWN_ID"
count=0
while [ "$count" -lt 50 ]; do
    exact_identity "$PARENT_ID"
    allowed
    if [ -f "$RUN/parent.admit" ] && [ ! -L "$RUN/parent.admit" ]; then
        [ "$($SYS/cat "$RUN/parent.admit")" = "$OWN_ID" ] || exit 83
        exact_identity "$PARENT_ID"
        allowed
        verify_fixed_inputs
        exec "$PARENT_BIN" --state-dir "$JOURNAL"
    fi
    "$BB" sleep 0.1
    count=$((count + 1))
done
exit 84
