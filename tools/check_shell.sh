#!/bin/sh
# Syntax only: do not invoke the router's service or modify the host firewall.
set -eu
for file in root/usr/sbin/wgnat6 root/usr/libexec/rpcd/wgnat6 root/usr/libexec/wgnat6/watchdog root/etc/init.d/wgnat6; do
    sh -n "$file"
done
printf '%s\n' 'Shell syntax OK'
