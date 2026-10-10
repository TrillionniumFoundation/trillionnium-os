# Explicit API37 dogfood profile. Old typed Authority/Lease/P01 graph remains sealed.
ifeq ($(filter userdebug eng,$(TARGET_BUILD_VARIANT)),)
$(error codex-host-relay-v1 is not qualified for user/release products)
endif
$(call inherit-product, vendor/trillionnium/owner-open/product.mk)
# Product inheritance is deferred. Supply one explicit value here, overriding
# the common optional default during Android property post-processing.
ifeq ($(TRILLINNIUM_LEAP_OWNER_OPEN_RUNTIME_ENABLED),true)
PRODUCT_SYSTEM_EXT_PROPERTIES += ro.trillionnium.owner_open.enabled=true
PRODUCT_PACKAGES += TrillionniumOwnerOpenSystemUIOverlay
else
PRODUCT_SYSTEM_EXT_PROPERTIES += ro.trillionnium.owner_open.enabled=false
endif
PRODUCT_SYSTEM_EXT_PROPERTIES += ro.trillionnium.owner_open.profile=leap-codex-host-relay-v1
