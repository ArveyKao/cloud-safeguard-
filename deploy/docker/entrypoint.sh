#!/bin/sh
# Starts Cloud Safeguard in a container. On the first start (an empty data
# directory) it runs `csg init`, which prints the first supervisor's one-time
# setup code to the log; later starts only serve. Settings come from the
# environment:
#   CSG_DATA_DIR       data directory (a persistent volume)        default /data
#   CSG_ADDR           listen address                              default 0.0.0.0:8787
#   CSG_PUBLIC_URL     origin people open, e.g. https://csg.example.com (required behind TLS)
#   CSG_TRUSTED_PROXY  proxy addresses/CIDRs whose X-Forwarded-For is trusted
#   CSG_SUPERVISOR     first supervisor's username on init           default admin
#   CSG_MASTER_KEY     32-byte base64 key; when set it is never written to disk
set -eu
DATA="${CSG_DATA_DIR:-/data}"

if [ "$#" -gt 0 ]; then
  # Any other csg command, e.g. `supervisor recover --username admin`.
  exec /usr/local/bin/csg "$@" --data-dir "$DATA"
fi

if [ ! -e "$DATA/csg.db" ]; then
  echo "csg: empty data directory $DATA: initialising (the setup code below is shown once)"
  /usr/local/bin/csg init --data-dir "$DATA" --supervisor "${CSG_SUPERVISOR:-admin}"
fi

set -- serve --data-dir "$DATA" --addr "${CSG_ADDR:-0.0.0.0:8787}"
[ -n "${CSG_PUBLIC_URL:-}" ] && set -- "$@" --public-url "$CSG_PUBLIC_URL"
[ -n "${CSG_TRUSTED_PROXY:-}" ] && set -- "$@" --trusted-proxy "$CSG_TRUSTED_PROXY"
exec /usr/local/bin/csg "$@"
