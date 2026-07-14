#!/usr/bin/env bash
set -euo pipefail

SERVICE_FILE="/etc/systemd/system/3x-pilang-web.service"

systemctl disable --now 3x-pilang-web.service 2>/dev/null || true
rm -f "$SERVICE_FILE"
systemctl daemon-reload

echo "Removed 3x-pilang-web.service"
echo "Script directory /root/3x-pilang was not deleted."
