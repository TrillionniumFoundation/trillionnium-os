# Inherit common mobile Trillionnium stuff
$(call inherit-product, vendor/trillionnium/config/common_owner_open.mk)

# Include AOSP audio files
$(call inherit-product-if-exists, frameworks/base/data/sounds/AudioPackage14.mk)
include vendor/trillionnium/config/aosp_audio.mk

# Include Trillionnium audio files
include vendor/trillionnium/config/trillionnium_audio.mk

# Default notification/alarm sounds
PRODUCT_PRODUCT_PROPERTIES += \
    ro.config.notification_sound=Argon.ogg \
    ro.config.alarm_alert=Hassium.ogg

# Apps
PRODUCT_PACKAGES += \
    AvatarPicker \
    Backgrounds \
    Glimpse \
    LatinIME

ifeq ($(PRODUCT_TYPE), go)
PRODUCT_PACKAGES += \
    Launcher3QuickStepGo

PRODUCT_DEXPREOPT_SPEED_APPS += \
    Launcher3QuickStepGo
else
PRODUCT_PACKAGES += \
    Launcher3QuickStep

PRODUCT_DEXPREOPT_SPEED_APPS += \
    Launcher3QuickStep
endif

PRODUCT_PACKAGES += \
    Launcher3Overlay

# Charger
PRODUCT_PACKAGES += \
    charger_res_images

ifneq ($(WITH_TRILLIONNIUM_CHARGER),false)
PRODUCT_PACKAGES += \
    trillionnium_charger_animation \
    trillionnium_charger_animation_vendor
endif

# Legal
PRODUCT_PRODUCT_PROPERTIES += \
    ro.trillionnium.legal.url=about:blank

# Media
PRODUCT_PRODUCT_PROPERTIES += \
    media.recorder.show_manufacturer_and_model=true

# SystemUI plugins
PRODUCT_PACKAGES += \
    QuickAccessWallet

# TextClassifier
PRODUCT_PACKAGES += \
    libtextclassifier_annotator_en_model \
    libtextclassifier_annotator_universal_model \
    libtextclassifier_actions_suggestions_universal_model \
    libtextclassifier_lang_id_model

PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
    system/etc/textclassifier/actions_suggestions.universal.model \
    system/etc/textclassifier/lang_id.model \
    system/etc/textclassifier/textclassifier.en.model \
    system/etc/textclassifier/textclassifier.universal.model

# Themes
PRODUCT_PACKAGES += \
    TrillionniumBlackTheme \
    ThemePicker \
    ThemesStub
