#!/bin/bash
echo "🚀 Lancement DHCP Monitor avec sudo..."
export DISPLAY=${DISPLAY:-:0}
cd "$(dirname "$0")"
sudo -E python3 monitor.py
