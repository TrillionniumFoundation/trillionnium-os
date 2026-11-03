# Invoked only by the official Magisk module installer selected by Root.
[ "$BOOTMODE" = true ] || abort "Booted official Magisk installation required"
[ "$(/system/bin/id -u)" = 0 ] || abort "Root installer required"
[ "$(/system/bin/getenforce)" = Enforcing ] || abort "Enforcing required"
[ "$(/system/bin/getprop ro.build.version.sdk)" = 36 ] || abort "Exact API36 target required"
[ "$(/system/bin/getprop ro.build.fingerprint)" = motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys ] || abort "Stock build mismatch"
[ -n "$MAGISKTMP" ] && [ -d "$MAGISKTMP/.magisk/preinit" ] || abort "Verified Magisk pre-init storage required"
# Stage1 original context files must still match; no blind merge over an old attempt.
observed=$(/system/bin/sha256sum /system_ext/etc/selinux/system_ext_property_contexts) || abort "Cannot hash stock baseline"
[ "${observed%% *}" = f0769d5bcce58a8f5498413e98bcabaebc2ade7d46741612243649e3390c3f04 ] || abort "Stock policy baseline mismatch"
observed=$(/system/bin/sha256sum /system_ext/etc/selinux/system_ext_file_contexts) || abort "Cannot hash stock baseline"
[ "${observed%% *}" = 200e6f7fff2d3b04a88c8838ba1cc7c9034a598ad1d7fbce636166c77866bb49 ] || abort "Stock policy baseline mismatch"
observed=$(/system/bin/sha256sum /system_ext/etc/selinux/system_ext_seapp_contexts) || abort "Cannot hash stock baseline"
[ "${observed%% *}" = ec9b89e1d3ecaf60e2e817f25092a8e028f3a99a36d66283e4b60d362895a2b5 ] || abort "Stock policy baseline mismatch"
observed=$(/system/bin/sha256sum /system_ext/etc/selinux/system_ext_mac_permissions.xml) || abort "Cannot hash stock baseline"
[ "${observed%% *}" = ac807420eecf06eda9aa4dcbace592bd4e9b0377d35e22bcc671dcbc925647f8 ] || abort "Stock policy baseline mismatch"
# No live policy load, early-config write, service start, or enable occurs here.
