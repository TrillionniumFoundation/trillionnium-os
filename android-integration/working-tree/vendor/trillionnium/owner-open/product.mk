# Trillionnium owner-open Android product cut.
# This file is intentionally applied after vendor/trillionnium/config/common.mk.
# It removes every sealed Authority/lease/P01/egress/old-shell/typed-ADB node
# before adding the independently reviewed owner-open source modules.

_TRILLIONNIUM_OWNER_OPEN_FORBIDDEN_PACKAGES := \
    TrillionniumAiAuthority \
    TrillionniumCapabilityLeaseIssuer \
    trillionnium-agent-adb \
    trillionnium-agent-egress-guard \
    trillionnium-agent-egress-launcher \
    trillionnium-agent-egress-probe \
    trillionnium-agent-operation-epoch-replay-hold-contract \
    trillionnium-agent-operation-journal-v3-promotion-contract \
    trillionnium-agentd-materialization-p01-userdebug \
    trillionnium-capability-lease-trust-config \
    trillionnium-direct-operation-custody-high-water \
    trillionnium-direct-operation-custody-high-water-ready-gate \
    trillionnium-p01-final-artifact-set-v5 \
    trillionnium-p01-receipt-stage-custody-evidence \
    trillionnium-p01-receipt-stage-evidence \
    trillionnium-p01-runtime-config \
    trillionnium-shell-exec-artifact-set-v1 \
    trillionnium-shell-exec-broker-userdebug \
    trillionnium-shell-exec-worker-userdebug

_TRILLIONNIUM_OWNER_OPEN_RETIRED_CLIENTS := \
    TrillionniumAiShell

PRODUCT_PACKAGES := $(filter-out $(_TRILLIONNIUM_OWNER_OPEN_FORBIDDEN_PACKAGES),$(PRODUCT_PACKAGES))
PRODUCT_PACKAGES := $(filter-out $(_TRILLIONNIUM_OWNER_OPEN_RETIRED_CLIENTS),$(PRODUCT_PACKAGES))
PRODUCT_PACKAGES_DEBUG := $(filter-out $(_TRILLIONNIUM_OWNER_OPEN_FORBIDDEN_PACKAGES),$(PRODUCT_PACKAGES_DEBUG))
PRODUCT_PACKAGES_DEBUG := $(filter-out $(_TRILLIONNIUM_OWNER_OPEN_RETIRED_CLIENTS),$(PRODUCT_PACKAGES_DEBUG))

PRODUCT_PACKAGES += \
    trillionnium-owner-open-rootfs-image \
    trillionnium-owner-open-rootfs-manifest \
    trillionnium-owner-open-rootfs-digest \
    trillionnium-owner-open-bootstrap \
    trillionnium-owner-open-emergency-stop \
    trillionnium-owner-open-ingress \
    trillionnium-owner-open-init-rc \
    trillionnium-owner-open-profile-config \
    TrillionniumOwnerOpenShell

# The Android 16 adbd in this checkout consults Lineage's ADBRoot Binder
# service before accepting `adb root`.  Keep that service strictly inside the
# explicitly authorised fogos dogfood lane: owner-open user/release products
# and every product without the opt-in remain unable to start it.  The
# matching SELinux fragment is added below only for the same build variants.
ifeq ($(TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT),true)
ifneq ($(filter userdebug eng,$(TARGET_BUILD_VARIANT)),)
PRODUCT_PACKAGES += \
    adb_root
SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += \
    vendor/trillionnium/owner-open/sepolicy/adbroot
endif
endif

PRODUCT_SYSTEM_EXT_PROPERTIES += \
    ro.trillionnium.owner_open.enabled=true

SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += \
    vendor/trillionnium/owner-open/sepolicy/private

_TRILLIONNIUM_OWNER_OPEN_FORBIDDEN_PACKAGES :=
_TRILLIONNIUM_OWNER_OPEN_RETIRED_CLIENTS :=
