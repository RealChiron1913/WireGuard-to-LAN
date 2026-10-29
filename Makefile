include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-wgnat6
PKG_VERSION:=1.5.14
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=WireGuard NAT contributors
PKGARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-wgnat6
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=Chinese LuCI manager for scoped WireGuard TCP/UDP NAT
  DEPENDS:=+luci-base +firewall4 +nftables-json +rpcd +lua +libuci-lua +luci-lib-nixio +luci-lib-jsonc +ip-full +wireguard-tools +flock +coreutils-timeout
endef

define Package/luci-app-wgnat6/description
  Transactional WireGuard virtual IPv4 to LAN TCP/UDP mapping with Chinese LuCI,
  firewall4 includes, kernel verification and a confirmation rollback timer.
endef

define Package/luci-app-wgnat6/conffiles
/etc/config/wgnat6
endef

define Build/Compile
endef

define Package/luci-app-wgnat6/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view
	$(CP) ./htdocs/luci-static/resources/view/wgnat6.js $(1)/www/luci-static/resources/view/
	$(CP) ./root/* $(1)/
	chmod 0755 $(1)/usr/sbin/wgnat6 $(1)/usr/libexec/rpcd/wgnat6 $(1)/usr/libexec/wgnat6/watchdog $(1)/etc/init.d/wgnat6
endef

define Package/luci-app-wgnat6/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
/etc/init.d/wgnat6 enable || exit 1
# restart invokes procd delete even on a first install; start is sufficient when
# no worker is running. A live upgrade still restarts the old shell worker.
if /etc/init.d/wgnat6 running >/dev/null 2>&1; then
  /etc/init.d/wgnat6 restart || exit 1
else
  /etc/init.d/wgnat6 start || exit 1
fi
# rc.common can finish service registration even when start_service failed.
# Verify an actual running worker instead of reporting an empty service as ready.
attempt=0
while ! /etc/init.d/wgnat6 running >/dev/null 2>&1; do
  attempt=$$((attempt + 1))
  if [ "$$attempt" -ge 5 ]; then
    echo 'WireGuard NAT worker did not start. Check logread -e wgnat6 before applying a mapping.' >&2
    exit 1
  fi
  sleep 1
done
/etc/init.d/rpcd reload || exit 1
echo 'WireGuard NAT installed. Log in to LuCI: Network -> WireGuard NAT. Configure and initialize from the page. Existing firewall rules have not been changed.'
exit 0
endef

define Package/luci-app-wgnat6/preinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
# opkg supplies 'upgrade OLD_VERSION'; OpenWrt's APK wrapper sets PKG_UPGRADE=1.
# These are authoritative even if the old control/identity file is unavailable.
[ "$$1" = upgrade ] && exit 0
[ "$$PKG_UPGRADE" = 1 ] && exit 0
[ -f /usr/lib/opkg/info/luci-app-wgnat6.control ] && exit 0
[ "$$(cat /usr/share/wgnat6/package-id 2>/dev/null)" = luci-app-wgnat6 ] && exit 0
[ "$$(cat /etc/wgnat6/luci/package-id 2>/dev/null)" = luci-app-wgnat6-state-v1 ] && exit 0

refuse() {
  echo "Refusing to overwrite unowned path: $$1. Existing files are preserved; inspect ownership before installing." >&2
  exit 1
}
# A real directory is not a file collision. Interrupted installs can leave empty
# directories, and unrelated files within them are not touched by this package.
for directory in /usr/lib/wgnat6 /usr/libexec/wgnat6 /usr/share/wgnat6 /etc/wgnat6/luci; do
  [ -L "$$directory" ] && refuse "$$directory"
  if [ -e "$$directory" ] && [ ! -d "$$directory" ]; then refuse "$$directory"; fi
done
for path in /etc/config/wgnat6 /etc/init.d/wgnat6 /usr/sbin/wgnat6 /usr/lib/wgnat6/engine.lua /usr/lib/wgnat6/main.lua /usr/lib/wgnat6/legacy.lua /usr/libexec/rpcd/wgnat6 /usr/libexec/wgnat6/watchdog /usr/share/rpcd/acl.d/luci-app-wgnat6.json /usr/share/luci/menu.d/luci-app-wgnat6.json /www/luci-static/resources/view/wgnat6.js /lib/upgrade/keep.d/wgnat6 /usr/share/wgnat6/package-id /usr/share/wgnat6/version; do
  if [ -e "$$path" ] || [ -L "$$path" ]; then refuse "$$path"; fi
done
# Empty state-directory trees are normal after uninstalling an uninitialized
# application. Actual unregistered state needs review; never follow symlinks.
check_state_tree() {
  for state_path in "$$1"/* "$$1"/.[!.]* "$$1"/..?*; do
    if [ -L "$$state_path" ]; then
      refuse "$$state_path"
    elif [ -d "$$state_path" ]; then
      check_state_tree "$$state_path"
    elif [ -e "$$state_path" ]; then
      refuse "$$state_path"
    fi
  done
}
if [ -d /etc/wgnat6/luci ]; then check_state_tree /etc/wgnat6/luci; fi
exit 0
endef

define Package/luci-app-wgnat6/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
[ "$$1" = upgrade ] || [ "$$PKG_UPGRADE" = 1 ] && exit 0
if [ -f /etc/wgnat6/luci/owned.json ]; then
  echo 'Run wgnat6 detach successfully before removing this package.' >&2
  exit 1
fi
/etc/init.d/wgnat6 stop
/etc/init.d/wgnat6 disable
exit 0
endef

$(eval $(call BuildPackage,luci-app-wgnat6))
