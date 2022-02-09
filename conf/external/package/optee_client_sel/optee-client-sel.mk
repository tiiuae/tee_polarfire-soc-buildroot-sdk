################################################################################
#
# optee-client-sel4
#
################################################################################

OPTEE_CLIENT_SEL_VERSION = platsec_dev
OPTEE_CLIENT_SEL_SITE = ssh://gerrit.ssrc-tre.fi:29418/Platsec/optee_client
OPTEE_CLIENT_SEL_SITE_METHOD = git
OPTEE_CLIENT_SEL_INSTALL_TARGET = YES


OPTEE_CLIENT_SEL_CONF_OPTS = \
	-DCFG_TEE_FS_PARENT_PATH=$(BR2_PACKAGE_OPTEE_CLIENT_SEL_TEE_FS_PATH) \
	-DCFG_WERROR=OFF

define OPTEE_CLIENT_SEL_INSTALL_INIT_SYSV
	$(INSTALL) -m 0755 -D $(OPTEE_CLIENT_SEL_PKGDIR)/S30optee \
		$(TARGET_DIR)/etc/init.d/S30optee
endef

$(eval $(cmake-package))
