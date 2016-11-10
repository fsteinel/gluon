include $(TOPDIR)/rules.mk

PKG_NAME:=gluon-client-bridge-babel
PKG_VERSION:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(GLUONDIR)/include/package.mk


define Package/gluon-client-bridge-babel
  SECTION:=gluon
  CATEGORY:=Gluon
  TITLE:=Provides a bridge and a wireless interface for clients to connect to
  DEPENDS:=+gluon-core
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

define Build/Compile
	$(call GluonSrcDiet,./luasrc,$(PKG_BUILD_DIR)/luadest/)
endef

define Package/gluon-client-bridge-babel/install
	$(CP) $(PKG_BUILD_DIR)/luadest/* $(1)/
endef

define Package/gluon-client-bridge-babel/postinst
#!/bin/sh
$(call GluonCheckSite,check_site.lua)
endef

$(eval $(call BuildPackage,gluon-client-bridge-babel))
