#
# SPDX-FileCopyrightText: The LineageOS Project
# Trillionnium OS local product fork marker.
# SPDX-License-Identifier: Apache-2.0
#

# Inherit from those products. Most specific first.
$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit.mk)
TARGET_SUPPORTS_OMX_SERVICE := false
$(call inherit-product, $(SRC_TARGET_DIR)/product/full_base_telephony.mk)

# Inherit from fogos device
$(call inherit-product, device/motorola/fogos/device.mk)

# Inherit some common Trillionnium stuff.
# Private fogos userdebug dogfood selection; user/release gates remain closed.
ifeq ($(TARGET_BUILD_VARIANT),userdebug)
TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT := true
endif
$(call inherit-product, vendor/trillionnium/config/common_full_phone.mk)

PRODUCT_NAME := trillionnium_fogos
PRODUCT_DEVICE := fogos
PRODUCT_MANUFACTURER := trillionnium
PRODUCT_BRAND := trillionnium
PRODUCT_MODEL := Trillionnium OS

PRODUCT_GMS_CLIENTID_BASE := android-motorola

# Let build/make derive the shipped build description, fingerprint, and
# product name from the Trillionnium product identity and selected release.

# Private exact-candidate Owner-Open integration selection.
$(call inherit-product, vendor/trillionnium/owner-open/product.mk)
