#!/bin/bash
# agentverif.com — deployment setup
# Run as root on a fresh Ubuntu/Debian server.
# Usage: bash setup.sh

set -euo pipefail

REPO_DIR=/root/agentverif
VENV="$REPO_DIR/.venv"

echo "==> Creating Python virtualenv..."
python3 -m venv "$VENV"

echo "==> Installing API dependencies..."
"$VENV/bin/pip" install --upgrade pip --quiet
"$VENV/bin/pip" install fastapi uvicorn[standard] --quiet

echo "==> Installing nginx config..."
cp "$REPO_DIR/nginx/agentverif.conf" /etc/nginx/sites-available/agentverif
ln -sf /etc/nginx/sites-available/agentverif /etc/nginx/sites-enabled/agentverif

echo "==> Testing nginx config..."
nginx -t

echo "==> Reloading nginx..."
systemctl reload nginx

echo "==> Installing systemd service..."
cp "$REPO_DIR/systemd/agentverif-api.service" /etc/systemd/system/agentverif-api.service
systemctl daemon-reload
systemctl enable agentverif-api
systemctl start agentverif-api

echo "==> Waiting for API to start..."
sleep 3
systemctl is-active --quiet agentverif-api && echo "    agentverif-api is running" || echo "    WARNING: agentverif-api failed to start — check: journalctl -u agentverif-api"

echo "==> Provisioning TLS certificates via Certbot..."
certbot --nginx \
  -d agentverif.com \
  -d www.agentverif.com \
  -d verify.agentverif.com \
  -d api.agentverif.com \
  -d sign.agentverif.com \
  --non-interactive \
  --agree-tos \
  --email admin@agentverif.com \
  --redirect

echo ""
echo "✅ Setup complete."
echo "   Web:    https://agentverif.com"
echo "   Verify: https://verify.agentverif.com"
echo "   API:    https://api.agentverif.com/health"
echo ""
echo "   API status: systemctl status agentverif-api"
echo "   API logs:   journalctl -u agentverif-api -f"
