################################################################################
#
# SEL4_TOOL
#
################################################################################

SEL4_TOOL_VERSION = platsec_dev
SEL4_TOOL_SITE = ssh://gerrit.ssrc-tre.fi:29418/Platsec/teeos_host
SEL4_TOOL_SITE_METHOD = git
SEL4_TOOL_INSTALL_TARGET = YES

define SEL4_TOOL_BUILD_CMDS
    $(MAKE) CC="$(TARGET_CC)" LD="$(TARGET_LD)" -C $(@D)/sel4_tool
endef

define SEL4_TOOL_INSTALL_TARGET_CMDS
   $(INSTALL) -D -m 0755 $(@D)/sel4_tool/sel4-tool $(TARGET_DIR)/usr/bin
endef

$(eval $(generic-package))
