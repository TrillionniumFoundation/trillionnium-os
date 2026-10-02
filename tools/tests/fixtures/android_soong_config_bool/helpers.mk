# Copyright (C) The Android Open Source Project
# SPDX-License-Identifier: Apache-2.0
# Verbatim config.mk macro definitions; see provenance.json and LICENSE.

define soong_config_define_internal
$(if $(filter $1,$(SOONG_CONFIG_NAMESPACES)),,$(eval SOONG_CONFIG_NAMESPACES:=$(SOONG_CONFIG_NAMESPACES) $(strip $1))) \
$(if $(filter $2,$(SOONG_CONFIG_$(strip $1))),,$(eval SOONG_CONFIG_$(strip $1):=$(SOONG_CONFIG_$(strip $1)) $(strip $2)))
endef

define soong_config_set
$(call soong_config_define_internal,$1,$2) \
$(eval SOONG_CONFIG_$(strip $1)_$(strip $2):=$(strip $3))
endef

define soong_config_set_bool
$(call soong_config_define_internal,$1,$2) \
$(eval SOONG_CONFIG_$(strip $1)_$(strip $2):=$(filter true,$3))
$(eval SOONG_CONFIG_TYPE_$(strip $1)_$(strip $2):=bool)
endef
