# Dedicated owner-open product supplement.
# Inherit the sealed common overlay first, then perform the explicit owner-open
# graph cut. A product must opt into this file; common.mk remains migration
# history for non-owner-open targets.
$(call inherit-product, vendor/trillionnium/config/common.mk)
$(call inherit-product, vendor/trillionnium/owner-open/product.mk)
