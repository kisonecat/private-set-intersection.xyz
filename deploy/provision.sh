#!/usr/bin/env bash
# One-time (idempotent) server setup for Ubuntu 24.04. Run as root on the server;
# deploy/deploy.sh uploads and runs this automatically.
#
# Installs Node.js and Caddy, creates a "psi" service user, writes
# /etc/psi.env (with a generated admin password and join code, if it doesn't
# exist yet), a systemd unit, and a Caddyfile that terminates HTTPS.
set -euo pipefail

DOMAIN="${DOMAIN:-private-set-intersection.xyz}"
NODE_MAJOR=24

export DEBIAN_FRONTEND=noninteractive

if ! command -v node >/dev/null || ! node --version | grep -q "^v${NODE_MAJOR}\."; then
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list
  apt-get update -y
  apt-get install -y nodejs
fi

# Caddy from the Ubuntu archive (the upstream Cloudsmith repo now requires payment).
rm -f /etc/apt/sources.list.d/caddy-stable.list
if ! command -v caddy >/dev/null; then
  apt-get update -y
  apt-get install -y caddy
fi

# Unattended security updates.
apt-get install -y unattended-upgrades >/dev/null

id psi >/dev/null 2>&1 || useradd --system --home /opt/psi --shell /usr/sbin/nologin psi
install -d -o psi -g psi -m 0755 /opt/psi
install -d -o psi -g psi -m 0700 /var/lib/psi

if [ ! -f /etc/psi.env ]; then
  umask 077
  cat > /etc/psi.env <<EOF
PORT=3000
HOST=127.0.0.1
TRUST_PROXY=loopback
DATABASE=/var/lib/psi/psi.sqlite
ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '/+=')
JOIN_CODE=$(openssl rand -hex 4)
LIST_LABELS=Completed applications,All applicants
EOF
  chown root:psi /etc/psi.env
  chmod 0640 /etc/psi.env
fi

cat > /etc/systemd/system/psi.service <<'EOF'
[Unit]
Description=private-set-intersection.xyz
After=network.target

[Service]
User=psi
Group=psi
WorkingDirectory=/opt/psi/current
EnvironmentFile=/etc/psi.env
ExecStart=/usr/bin/node server/index.js
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/psi
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/caddy/Caddyfile <<EOF
${DOMAIN} {
	encode gzip
	reverse_proxy 127.0.0.1:3000
	header {
		Strict-Transport-Security "max-age=31536000"
		X-Content-Type-Options nosniff
		Referrer-Policy no-referrer
		X-Frame-Options DENY
	}
}

www.${DOMAIN} {
	redir https://${DOMAIN}{uri} permanent
}
EOF

systemctl daemon-reload
systemctl enable psi caddy >/dev/null 2>&1
systemctl reload-or-restart caddy
