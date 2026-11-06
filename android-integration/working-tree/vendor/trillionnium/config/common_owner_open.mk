# Dedicated owner-open product supplement.
# Android merges inherit-product tags after each product node is evaluated.
# Select the generated shared base before inheritance; filtering a sibling's
# package list inside owner-open/product.mk cannot remove inherited packages.
# common.mk retains the sealed compatibility graph for other products.
$(call inherit-product, vendor/trillionnium/config/common_owner_open_base.mk)
$(call inherit-product, vendor/trillionnium/owner-open/product.mk)
