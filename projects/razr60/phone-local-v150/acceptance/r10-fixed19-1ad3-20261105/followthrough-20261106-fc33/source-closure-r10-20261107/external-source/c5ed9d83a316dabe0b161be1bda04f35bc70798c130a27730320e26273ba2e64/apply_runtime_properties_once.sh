#!/system/bin/sh
set -eu
umask 077
[ "$#" -eq 2 ]
[ "$1" = '--execute-reviewed-single-runtime-properties-apply' ]
hepta_runtime_properties_binding_sha="$2"
[ "${#hepta_runtime_properties_binding_sha}" -eq 64 ]
case "$hepta_runtime_properties_binding_sha" in *[!0-9a-f]*) exit 64 ;; esac
hepta_runtime_properties_code='/data/trillionnium/owner-open/state/phone-local-v150/policy-runtime-properties-r10-live-code-r1'
hepta_runtime_properties_out='/data/trillionnium/owner-open/state/phone-local-v150/policy-runtime-properties-r10-live-01'
[ "$(/data/adb/magisk/busybox sha256sum "$hepta_runtime_properties_code/guard_live_runtime_properties.py" | /data/adb/magisk/busybox cut -d ' ' -f 1)" = '8bdfa0a0d67e32bedcc53f4217ce15945d5f7d6c43e9624b7fd983b3f38c61b2' ]
[ "$(/data/adb/magisk/busybox sha256sum "$hepta_runtime_properties_code/BINDING.json" | /data/adb/magisk/busybox cut -d ' ' -f 1)" = "$hepta_runtime_properties_binding_sha" ]
/data/adb/magisk/busybox env -i PATH=/usr/bin:/bin:/usr/libexec/trillionnium PYTHONHOME=/usr PYTHONDONTWRITEBYTECODE=1 LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu LANG=C.UTF-8 LC_ALL=C.UTF-8 TMPDIR=/var/lib/trillionnium/owner-open/tmp NO_COLOR=1 TERM=dumb /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B /var/lib/trillionnium/owner-open/phone-local-v150/policy-runtime-properties-r10-live-code-r1/guard_live_runtime_properties.py --binding-sha256 "$hepta_runtime_properties_binding_sha" --preflight-once
set +e
/data/adb/magisk/busybox timeout -s TERM -k 5 45 /data/adb/magisk/magiskpolicy --live --apply "$hepta_runtime_properties_out/runtime-properties.delta.rule" >>"$hepta_runtime_properties_out/policy.stdout" 2>>"$hepta_runtime_properties_out/policy.stderr"
hepta_runtime_properties_apply_rc=$?
set -e
/data/adb/magisk/busybox env -i PATH=/usr/bin:/bin:/usr/libexec/trillionnium PYTHONHOME=/usr PYTHONDONTWRITEBYTECODE=1 LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/android:/usr/lib/aarch64-linux-gnu:/lib/aarch64-linux-gnu LANG=C.UTF-8 LC_ALL=C.UTF-8 TMPDIR=/var/lib/trillionnium/owner-open/tmp NO_COLOR=1 TERM=dumb /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root /usr/bin/python3 -I -B /var/lib/trillionnium/owner-open/phone-local-v150/policy-runtime-properties-r10-live-code-r1/guard_live_runtime_properties.py --binding-sha256 "$hepta_runtime_properties_binding_sha" --postflight-once "$hepta_runtime_properties_apply_rc"
