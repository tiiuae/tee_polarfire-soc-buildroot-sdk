################################################################################
#
# SEL4_TOOL
#
################################################################################

SEL4_TOOL_VERSION = 1.0
SEL4_TOOL_SITE = $(BR2_EXTERNAL_SEL4_AMP_PATH)/package/sel4_tool/src
SEL4_TOOL_SITE_METHOD = local

define SEL4_TOOL_BUILD_CMDS
    $(MAKE) CC="$(TARGET_CC)" LD="$(TARGET_LD)" -C $(@D)
endef

define SEL4_TOOL_INSTALL_TARGET_CMDS
   $(INSTALL) -D -m 0755 $(@D)/sel4-tool $(TARGET_DIR)/usr/bin
endef

$(eval $(generic-package))
