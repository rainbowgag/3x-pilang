#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/root/3x-pilang"
SERVICE_FILE="/etc/systemd/system/3x-pilang-web.service"
HOST="${WEB_HOST:-0.0.0.0}"
PORT="${WEB_PORT:-8765}"

if [[ ! -f "$APP_DIR/3xui_batch_nodes.py" ]]; then
  echo "ERROR: $APP_DIR/3xui_batch_nodes.py not found"
  echo "Install first: git clone https://github.com/rainbowgag/3x-pilang.git $APP_DIR"
  exit 1
fi

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=3x-pilang 3x-ui batch node web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/python3 $APP_DIR/3xui_batch_nodes.py --web --web-host $HOST --web-port $PORT
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now 3x-pilang-web.service

echo "Installed and started 3x-pilang-web.service"
echo "URL: http://YOUR_VPS_IP:$PORT"
echo
systemctl --no-pager --full status 3x-pilang-web.service
