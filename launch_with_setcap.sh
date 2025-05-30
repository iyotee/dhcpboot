#!/bin/bash
echo "🚀 Lancement DHCP Monitor avec setcap..."
export DISPLAY=${DISPLAY:-:0}
cd "$(dirname "$0")"
python3 monitor.py
