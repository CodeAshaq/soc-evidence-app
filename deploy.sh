#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
git fetch origin main --quiet
if [ "${1:-}" = "--if-changed" ] && [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ]; then exit 0; fi
git merge --ff-only origin/main
docker compose up -d --build
docker image prune -f >/dev/null
echo "[$(date '+%F %T')] deploy OK: $(git rev-parse --short HEAD)"
