#!/system/bin/sh
# Frozen argv only; never submits a task or automatically replays work.
set -eu
umask 077
exec '/data/adb/magisk/busybox' 'env' '-i' 'PATH=/system/bin:/vendor/bin' 'TMPDIR=/data/local/tmp' '/data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-sidecar-r6' '--state-dir' '/data/trillionnium/owner-open/state/phone-local-v150/executor-r6'
