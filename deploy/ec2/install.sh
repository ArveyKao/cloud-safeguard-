#!/bin/sh
# Installs Cloud Safeguard on an Amazon Linux 2023 / Debian / Ubuntu VM behind Caddy.
# Usage (as root, with the built binary next to this script):
#   CSG_DOMAIN=csg.example.com sh install.sh ./csg
# Open ports 80 and 443 in the security group; keep 8787 closed (it listens on 127.0.0.1 only).
set -eu
BIN="${1:-./csg}"
: "${CSG_DOMAIN:?set CSG_DOMAIN to the domain name of the console}"
HERE="$(cd "$(dirname "$0")" && pwd)"

id csg >/dev/null 2>&1 || useradd --system --home /var/lib/csg --shell /usr/sbin/nologin csg
install -m 0755 "$BIN" /usr/local/bin/csg
install -d -m 0700 -o csg -g csg /var/lib/csg
install -d -m 0750 /etc/csg
printf 'CSG_PUBLIC_URL=https://%s\n' "$CSG_DOMAIN" > /etc/csg/csg.env

if [ ! -e /var/lib/csg/csg.db ]; then
  echo "Initialising /var/lib/csg — the first supervisor's setup code is printed once below:"
  su -s /bin/sh csg -c "/usr/local/bin/csg init --data-dir /var/lib/csg --supervisor ${CSG_SUPERVISOR:-admin}"
fi

install -m 0644 "$HERE/csg.service" /etc/systemd/system/csg.service
systemctl daemon-reload
systemctl enable --now csg

if ! command -v caddy >/dev/null 2>&1; then
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y 'dnf-command(copr)' && dnf copr enable -y @caddy/caddy && dnf install -y caddy
  else
    apt-get update && apt-get install -y caddy
  fi
fi
install -m 0644 "$HERE/Caddyfile" /etc/caddy/Caddyfile
mkdir -p /etc/systemd/system/caddy.service.d
printf '[Service]\nEnvironment=CSG_DOMAIN=%s\n' "$CSG_DOMAIN" > /etc/systemd/system/caddy.service.d/csg.conf
systemctl daemon-reload
systemctl enable --now caddy
systemctl restart caddy
echo "Cloud Safeguard: https://$CSG_DOMAIN  (logs: journalctl -u csg)"
