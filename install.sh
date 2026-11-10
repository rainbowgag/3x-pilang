#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/root/3x-pilang}"
REPO_URL="https://github.com/rainbowgag/3x-pilang.git"
WEB_HOST="${WEB_HOST:-0.0.0.0}"
WEB_PORT="${WEB_PORT:-8765}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行：sudo bash install.sh" >&2
  exit 1
fi

for cmd in git python3 systemctl; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "缺少必要命令：${cmd}" >&2
    exit 1
  fi
done

if [[ ! -d "${APP_DIR}/.git" ]]; then
  if [[ -e "${APP_DIR}" ]]; then
    echo "目录已存在但不是 git 仓库：${APP_DIR}" >&2
    exit 1
  fi
  echo "克隆仓库到 ${APP_DIR} ..."
  git clone "${REPO_URL}" "${APP_DIR}"
else
  echo "检测到已有安装，更新代码 ..."
  git -C "${APP_DIR}" pull --ff-only
fi

export APP_DIR WEB_HOST WEB_PORT
bash "${APP_DIR}/install_service.sh"

