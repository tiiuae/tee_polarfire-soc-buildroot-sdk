################################################################################
#
# SEL4_TOOL
#
################################################################################

SEL4_TOOL_VERSION = platsec_dev
SEL4_TOOL_SITE = ssh://gerrit.ssrc-tre.fi:29418/Platsec/teeos_host
SEL4_TOOL_SITE_METHOD = git
SEL4_TOOL_INSTALL_TARGET = YES
SEL4_TOOL_GIT_SUBMODULES = YES

$(eval $(cmake-package))
