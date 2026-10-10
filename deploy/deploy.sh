#!/usr/bin/env bash
# Deploy the committed HEAD of this repo to the production server.
#
#   deploy/deploy.sh                # deploy to the default host
#   PSI_HOST=1.2.3.4 deploy/deploy.sh
#
# Steps: provision the server (idempotent), upload `git archive HEAD` into a
# fresh release directory, install dependencies, build the client bundle,
# switch the "current" symlink, restart the service, and keep the last 5
# releases for rollback.
set -euo pipefail

HOST="${PSI_HOST:-18.190.63.214}"
SSH_KEY="${PSI_SSH_KEY:-$HOME/.ssh/private-set-intersection.xyz.pem}"
SSH_USER="${PSI_SSH_USER:-ubuntu}"
DOMAIN="${PSI_DOMAIN:-private-set-intersection.xyz}"

cd "$(git rev-parse --show-toplevel)"

if [ -n "$(git status --porcelain)" ]; then
  echo "warning: uncommitted changes are NOT deployed (deploying HEAD $(git rev-parse --short HEAD))" >&2
fi

REV=$(git rev-parse --short HEAD)
RELEASE="$(date -u +%Y%m%d%H%M%S)-$REV"
SSH=(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "$SSH_USER@$HOST")

echo "==> Provisioning $HOST"
"${SSH[@]}" "sudo DOMAIN='$DOMAIN' bash -s" < deploy/provision.sh

echo "==> Uploading $RELEASE"
git archive --format=tar HEAD | "${SSH[@]}" "sudo -u psi mkdir -p /opt/psi/releases/$RELEASE && sudo -u psi tar -x -C /opt/psi/releases/$RELEASE"

echo "==> Installing and building"
"${SSH[@]}" "cd /opt/psi/releases/$RELEASE && sudo -u psi HOME=/opt/psi npm ci --no-audit --no-fund --loglevel=error && sudo -u psi HOME=/opt/psi npm run build --silent"

echo "==> Activating"
"${SSH[@]}" bash -s <<EOF
set -euo pipefail
sudo -u psi ln -sfn /opt/psi/releases/$RELEASE /opt/psi/current
sudo systemctl restart psi
sleep 2
systemctl is-active --quiet psi || { sudo journalctl -u psi -n 30 --no-pager; exit 1; }
curl -fsS http://127.0.0.1:3000/api/config >/dev/null && echo "health check ok"
cd /opt/psi/releases && ls -1t | tail -n +6 | xargs -r sudo rm -rf
EOF

echo "==> Deployed $REV to $HOST (https://$DOMAIN once DNS points at $HOST)"
