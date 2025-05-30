#!/bin/bash
echo "🚀 Lancement DHCP Monitor avec wrapper..."
export DISPLAY=${DISPLAY:-:0}
cd "$(dirname "$0")"
/usr/local/bin/dhcp_monitor
