#!/system/bin/sh
set -eu
MODDIR=${0%/*}
[ "$(/system/bin/getenforce)" = Enforcing ]
[ "$(/system/bin/getprop ro.build.version.sdk)" = 36 ]
[ "$(/system/bin/getprop ro.build.fingerprint)" = motorola/leap_cn/leap:16/W1VL36H.59-53-11/643c83-3ed541:user/release-keys ]
# Runs before magic mounts; only assign already-loaded dedicated types.
/system/bin/chcon u:object_r:trillionnium_owner_open_bootstrap_exec:s0 "$MODDIR/system/system_ext/bin/trillionnium-owner-open-bootstrap"
/system/bin/chcon u:object_r:trillionnium_owner_open_ingress_exec:s0 "$MODDIR/system/system_ext/bin/trillionnium-owner-open-ingress"
/system/bin/chcon u:object_r:trillionnium_owner_open_emergency_stop_exec:s0 "$MODDIR/system/system_ext/bin/trillionnium-owner-open-emergency-stop"
/system/bin/chcon u:object_r:trillionnium_owner_open_payload_file:s0 "$MODDIR/system/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.erofs"
/system/bin/chcon u:object_r:trillionnium_owner_open_payload_file:s0 "$MODDIR/system/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.image-manifest.json"
/system/bin/chcon u:object_r:trillionnium_owner_open_payload_file:s0 "$MODDIR/system/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.erofs.sha256"
/system/bin/chcon u:object_r:trillionnium_owner_open_payload_file:s0 "$MODDIR/system/system_ext/etc/trillionnium/owner-open/profile-codex-host-relay-v1.json"
/system/bin/chcon u:object_r:system_file:s0 "$MODDIR/system/system_ext/app/TrillionniumOwnerOpenShell/TrillionniumOwnerOpenShell.apk"
/system/bin/chcon u:object_r:trillionnium_owner_open_payload_file:s0 "$MODDIR/system/system_ext/etc/trillionnium/owner-open/stock16-backend-init.source.rc"
/system/bin/chcon -R u:object_r:trillionnium_owner_open_payload_file:s0 "$MODDIR/system/system_ext/etc/trillionnium/rootlinux"
/system/bin/chcon -R u:object_r:trillionnium_owner_open_payload_file:s0 "$MODDIR/system/system_ext/etc/trillionnium/owner-open"

# Retain exact stock contexts on four identical early/late config copies.
/system/bin/chcon u:object_r:property_contexts_file:s0 "$MODDIR/system/system_ext/etc/selinux/system_ext_property_contexts"
/system/bin/chcon u:object_r:file_contexts_file:s0 "$MODDIR/system/system_ext/etc/selinux/system_ext_file_contexts"
/system/bin/chcon u:object_r:seapp_contexts_file:s0 "$MODDIR/system/system_ext/etc/selinux/system_ext_seapp_contexts"
/system/bin/chcon u:object_r:mac_perms_file:s0 "$MODDIR/system/system_ext/etc/selinux/system_ext_mac_permissions.xml"
