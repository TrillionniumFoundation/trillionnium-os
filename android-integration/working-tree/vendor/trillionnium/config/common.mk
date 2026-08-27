# Allow vendor/extra to override any property by setting it first
$(call inherit-product-if-exists, vendor/extra/product.mk)

# Allow vendor prebuilt repos to exclude themselves from bp scanning
-include $(sort $(wildcard vendor/*/*/exclude-bp.mk))

PRODUCT_BRAND ?= Trillionnium OS

ifeq ($(PRODUCT_GMS_CLIENTID_BASE),)
PRODUCT_PRODUCT_PROPERTIES += \
    ro.com.google.clientidbase=android-google
else
PRODUCT_PRODUCT_PROPERTIES += \
    ro.com.google.clientidbase=$(PRODUCT_GMS_CLIENTID_BASE)
endif

ifeq ($(PRODUCT_IS_ATV),true)
ifeq ($(PRODUCT_ATV_CLIENTID_BASE),)
PRODUCT_PRODUCT_PROPERTIES += \
    ro.oem.key1=ATV00100020
else
PRODUCT_PRODUCT_PROPERTIES += \
    ro.oem.key1=$(PRODUCT_ATV_CLIENTID_BASE)
endif
endif

ifeq ($(TARGET_BUILD_VARIANT),eng)
# Disable ADB authentication
PRODUCT_SYSTEM_EXT_PROPERTIES += ro.adb.secure=0
else
ifdef WITH_ADB_INSECURE
# Forcebly disable ADB authentication
PRODUCT_SYSTEM_EXT_PROPERTIES += ro.adb.secure=0
else
# Enable ADB authentication
PRODUCT_SYSTEM_EXT_PROPERTIES += ro.adb.secure=1

# Keep adb root disabled for every normal userdebug product by default.  The
# fogos test handset may opt into a deliberately labelled dogfood lane from
# its product makefile; this must never be inferred from TARGET_BUILD_VARIANT
# alone and has no effect on user/release builds.
ifneq ($(TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT),true)
PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG := true
endif
endif

# Disable extra StrictMode features on all non-engineering builds
PRODUCT_PRODUCT_PROPERTIES += persist.sys.strictmode.disable=true
endif

# Backup Tool
PRODUCT_COPY_FILES += \
    vendor/trillionnium/prebuilt/common/bin/backuptool.sh:install/bin/backuptool.sh \
    vendor/trillionnium/prebuilt/common/bin/backuptool.functions:install/bin/backuptool.functions

PRODUCT_PACKAGES += \
    50-trillionnium.sh

PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/addon.d/50-trillionnium.sh

ifneq ($(strip $(AB_OTA_PARTITIONS) $(AB_OTA_POSTINSTALL_CONFIG)),)
PRODUCT_COPY_FILES += \
    vendor/trillionnium/prebuilt/common/bin/backuptool_ab.sh:$(TARGET_COPY_OUT_SYSTEM)/bin/backuptool_ab.sh \
    vendor/trillionnium/prebuilt/common/bin/backuptool_ab.functions:$(TARGET_COPY_OUT_SYSTEM)/bin/backuptool_ab.functions \
    vendor/trillionnium/prebuilt/common/bin/backuptool_postinstall.sh:$(TARGET_COPY_OUT_SYSTEM)/bin/backuptool_postinstall.sh

PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/bin/backuptool_ab.sh \
    system/bin/backuptool_ab.functions \
    system/bin/backuptool_postinstall.sh

ifneq ($(TARGET_BUILD_VARIANT),user)
PRODUCT_PRODUCT_PROPERTIES += \
    ro.ota.allow_downgrade=true
endif
endif

# Trillionnium-specific broadcast actions whitelist
PRODUCT_COPY_FILES += \
    vendor/trillionnium/config/permissions/trillionnium-sysconfig.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/sysconfig/trillionnium-sysconfig.xml

# Trillionnium-specific init rc file
PRODUCT_PACKAGES += \
    init.trillionnium-system_ext.rc

# Enable SIP+VoIP on all targets
PRODUCT_COPY_FILES += \
    frameworks/native/data/etc/android.software.sip.voip.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/android.software.sip.voip.xml

# Credential storage
PRODUCT_PACKAGES += \
    android.software.credentials.prebuilt.xml

# Enable wireless Xbox 360 controller support
PRODUCT_COPY_FILES += \
    frameworks/base/data/keyboards/Vendor_045e_Product_028e.kl:$(TARGET_COPY_OUT_PRODUCT)/usr/keylayout/Vendor_045e_Product_0719.kl

# Component overrides
PRODUCT_PACKAGES += \
    trillionnium-component-overrides.xml

# This is Trillionnium OS!
PRODUCT_COPY_FILES += \
    vendor/trillionnium/config/permissions/org.trillionnium.android.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/permissions/org.trillionnium.android.xml

# Enforce privapp-permissions whitelist
PRODUCT_PRODUCT_PROPERTIES += \
    ro.control_privapp_permissions=enforce

ifneq ($(TARGET_DISABLE_TRILLIONNIUM_SDK), true)
# Trillionnium SDK
include vendor/trillionnium/config/trillionnium_sdk_common.mk
endif

# Do not include art debug targets
PRODUCT_ART_TARGET_INCLUDE_DEBUG_BUILD := false

# Strip the local variable table and the local variable type table to reduce
# the size of the system image. This has no bearing on stack traces, but will
# leave less information available via JDWP.
PRODUCT_MINIMIZE_JAVA_DEBUG_INFO := true

# Enable whole-program R8 Java optimizations for SystemUI and system_server,
# but also allow explicit overriding for testing and development.
SYSTEM_OPTIMIZE_JAVA ?= true
SYSTEMUI_OPTIMIZE_JAVA ?= true

# Disable vendor restrictions
PRODUCT_RESTRICT_VENDOR_FILES := false

ifneq ($(TARGET_DISABLE_EPPE),true)
# Require all requested packages to exist
$(call enforce-product-packages-exist-internal,$(lastword $(_include_stack)),product_manifest.xml rild Calendar android.hidl.memory@1.0-impl.vendor vndk_apex_snapshot_package)
endif

# Bootanimation
TARGET_SCREEN_WIDTH ?= 1080
TARGET_SCREEN_HEIGHT ?= 1920
PRODUCT_PACKAGES += \
    bootanimation.zip \
    bootanimation-dark.zip

# Trillionnium interfaces
PRODUCT_PACKAGES += \
    framework_compatibility_matrix.trillionnium.xml

# Trillionnium packages
ifeq ($(PRODUCT_IS_ATV),)
PRODUCT_PACKAGES += \
    ExactCalculator \
    Jelly
endif

ifeq ($(PRODUCT_IS_AUTOMOTIVE),)
PRODUCT_PACKAGES += \
    TrillionniumParts \
    TrillionniumSetupWizard
endif

PRODUCT_PACKAGES += \
    TrillionniumSettingsProvider \
    Updater

PRODUCT_COPY_FILES += \
    vendor/trillionnium/prebuilt/common/etc/init/init.trillionnium-updater.rc:$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/init/init.trillionnium-updater.rc

# Config
PRODUCT_PACKAGES += \
    SimpleDeviceConfig \
    SimpleSettingsConfig

# Extra tools in Trillionnium
PRODUCT_PACKAGES += \
    bash \
    curl \
    getcap \
    htop \
    nano \
    setcap \
    vim

PRODUCT_PACKAGES += \
    nano_recovery

# Built-in headless Trillionnium root Linux payload. Android ships one measured
# Codex Agent plus the complete essential rootfs. Mobian and retired-provider
# runtime assets are never partition inputs; only bounded OTA retirement state
# handling remains in the active source graph.
PRODUCT_PACKAGES += \
    TrillionniumAiAuthority \
    TrillionniumCapabilityLeaseIssuer \
    TrillionniumAiShell \
    TrillionniumAgentAccessibility \
    org.trillionnium.agent.system_api.xml \
    trillionnium-capability-lease-trust-config \
    trillionnium-root-linux-bootstrap \
    trillionnium-root-linux-run \
    trillionnium_rootfs_tar_staging_filter \
    trillionnium-rootfs-tar-staging-filter-identity \
    trillionniumd \
    trillionnium-agentd-payload \
    trillionnium-agent-egress-guard \
    trillionnium-agent-egress-launcher \
    trillionnium-agent-egress-probe \
    trillionnium-agent-system-api \
    trillionnium-agent-accessibility \
    trillionnium-system-api-replay-sync \
    trillionnium-codex-agent-0.144.1 \
    trillionnium-codex-runtime-0.144.1 \
    trillionnium-codex-agent-manifest \
    trillionnium-agent-operation-journal-v3-promotion-contract \
    trillionnium-agent-operation-epoch-replay-hold-contract \
    trillionnium-root-linux-manifest \
    trillionnium-root-linux-rootfs-essential

# Production variants retain the reviewed v6 evidence. Userdebug has one
# authority only: the staged v9 contract/receipt with v5 artifact sets below.
ifneq ($(TARGET_BUILD_VARIANT),userdebug)
PRODUCT_PACKAGES += \
    trillionnium-rootfs-package-contract \
    trillionnium-rootfs-package-receipt \
    trillionnium-rootfs-common-artifact-set \
    trillionnium-rootfs-fresh-base-receipt \
    trillionnium-rootfs-fresh-base-sbom
endif

# P0-1 is deliberately a userdebug-only vertical slice. Canonical module names
# select their exact sources through the Soong build-variant namespace; only
# the shared verifier core is an additional installed file.
ifeq ($(TARGET_BUILD_VARIANT),userdebug)
PRODUCT_PACKAGES += \
    trillionniumd-p01-core \
    trillionnium-direct-operation-custody-high-water \
    trillionnium-direct-operation-custody-high-water-ready-gate \
    trillionnium-agent-shell \
    trillionnium-shell-exec-broker-userdebug \
    trillionnium-shell-exec-worker-userdebug \
    trillionnium-agentd-materialization-p01-userdebug \
    trillionnium-p01-runtime-config \
    trillionnium-p01-receipt-stage-evidence \
    trillionnium-p01-receipt-stage-custody-evidence \
    trillionnium-shell-exec-artifact-set-v1 \
    trillionnium-p01-final-artifact-set-v5 \
    trillionnium-rootfs-package-contract-v9 \
    trillionnium-rootfs-package-receipt-v9 \
    trillionnium-rootfs-common-artifact-set-v5 \
    trillionnium-rootfs-fresh-base-receipt \
    trillionnium-rootfs-fresh-base-sbom
endif

# Keep only debug tools that still have a bounded product contract.
# WindowsCompat is retired and remains absent from every Android build variant;
# only its small source tombstone and external recovery-archive identity remain.
PRODUCT_PACKAGES_DEBUG += \
    trillionnium-agent-adb \
    init.trillionnium-agent-adb-debug.rc

PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/bin/curl \
    system/bin/getcap \
    system/bin/setcap \
    system/%/libzstd.so

# Filesystems tools
PRODUCT_PACKAGES += \
    fsck.ntfs \
    mkfs.ntfs \
    mount.ntfs

PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/bin/fsck.ntfs \
    system/bin/mkfs.ntfs \
    system/bin/mount.ntfs \
    system/%/libfuse-lite.so \
    system/%/libntfs-3g.so

# FRP
PRODUCT_COPY_FILES += \
    vendor/trillionnium/prebuilt/common/bin/wipe-frp.sh:$(TARGET_COPY_OUT_RECOVERY)/root/system/bin/wipe-frp

# Openssh
PRODUCT_PACKAGES += \
    scp \
    sftp \
    ssh \
    sshd \
    sshd_config \
    ssh-keygen \
    start-ssh

PRODUCT_COPY_FILES += \
    vendor/trillionnium/prebuilt/common/etc/init/init.openssh.rc:$(TARGET_COPY_OUT_PRODUCT)/etc/init/init.openssh.rc

# rsync
PRODUCT_PACKAGES += \
    rsync

# Storage manager
PRODUCT_PRODUCT_PROPERTIES += \
    ro.storage_manager.enabled=true

# These packages are excluded from user builds
PRODUCT_PACKAGES_DEBUG += \
    procmem

ifneq ($(TARGET_BUILD_VARIANT),user)
PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/bin/procmem
endif

# The legacy Lineage privileged-ADB binder helper is intentionally not installed.
# Elevated/root execution will be introduced only through the separately
# measured Trillionnium transport and custody path after the Android shell
# and System API milestones have physical-device evidence.
ifneq ($(TARGET_BUILD_VARIANT),user)
ifeq ($(WITH_SU),true)
PRODUCT_PACKAGES += \
    su

PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/xbin/su
endif
endif

# SystemUI
PRODUCT_DEXPREOPT_SPEED_APPS += \
    CarSystemUI \
    SystemUI

PRODUCT_PRODUCT_PROPERTIES += \
    dalvik.vm.systemuicompilerfilter=speed

ifeq ($(TARGET_BUILD_VARIANT),userdebug)
PRODUCT_PRODUCT_PROPERTIES += \
    debug.sf.enable_transaction_tracing=false
endif

# Audio files
$(call inherit-product, vendor/trillionnium/audio/audio.mk)

# SetupWizard
PRODUCT_PRODUCT_PROPERTIES += \
    setupwizard.theme=glif_v4 \
    setupwizard.feature.day_night_mode_enabled=true

PRODUCT_ENFORCE_RRO_EXCLUDED_OVERLAYS += vendor/trillionnium/overlay/no-rro
PRODUCT_PACKAGE_OVERLAYS += \
    vendor/trillionnium/overlay/common \
    vendor/trillionnium/overlay/no-rro

PRODUCT_PACKAGES += \
    DocumentsUIOverlay \
    NetworkStackOverlay \
    PermissionControllerOverlay

# Translations
CUSTOM_LOCALES += \
    ast_ES \
    gd_GB \
    cy_GB \
    fur_IT \
    nn_NO

PRODUCT_ENFORCE_RRO_EXCLUDED_OVERLAYS += vendor/crowdin/overlay
PRODUCT_PACKAGE_OVERLAYS += vendor/crowdin/overlay

PRODUCT_EXTRA_RECOVERY_KEYS += \
    vendor/trillionnium/build/target/product/security/trillionnium

include vendor/trillionnium/config/version.mk

-include vendor/trillionnium-priv/keys/keys.mk

-include $(WORKSPACE)/build_env/image-auto-bits.mk
-include vendor/trillionnium/config/partner_gms.mk
