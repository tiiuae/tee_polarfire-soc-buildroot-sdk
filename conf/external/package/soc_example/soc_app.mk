################################################################################
#
# SOC_EXAMPLE
#
################################################################################

SOC_EXAMPLE_VERSION = 1.0
SOC_EXAMPLE_SITE = $(BR2_EXTERNAL_SEL4_AMP_PATH)/package/soc_example/src
SOC_EXAMPLE_SITE_METHOD = local

define SOC_EXAMPLE_BUILD_CMDS
    $(MAKE) CC="$(TARGET_CC)" LD="$(TARGET_LD)" -C $(@D)
endef

define SOC_EXAMPLE_INSTALL_TARGET_CMDS
   $(INSTALL) -D -m 0755 $(@D)/sel4-demo $(TARGET_DIR)/usr/bin
endef

$(eval $(generic-package))
