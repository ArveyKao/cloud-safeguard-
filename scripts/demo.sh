#!/usr/bin/env bash
# Cloud Safeguard end-to-end demo (scenarios S1-S9).
#
# What it does:
#   1. builds build/csg and the demo driver from the current tree
#   2. creates a clean throwaway data directory and bootstraps it with
#      `csg init --demo --json` (a mock cloud account and the first
#      supervisor's setup code)
#   3. starts `csg serve` on the requested loopback port in the background
#   4. runs scenarios S1-S9 (scripts/demo/main.go): people act through the
#      console's HTTP API, the agent through the real csg binary and the
#      mock cloud
#   5. prints PASS/FAIL lines, stops the server via a cleanup trap, and exits
#      non-zero if any scenario failed
#
# Usage: ./scripts/demo.sh [--port 18787] [--data-dir .demo/data]
# Needs go, curl and python3.
#
# The demo runs entirely in mock mode: no real cloud account or credentials are
# used. Setup codes, passwords, tokens and credentials are never echoed.
set -u -o pipefail

for tool in go curl python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "demo: $tool is required" >&2; exit 2; }
done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT" || exit 1

BIN="$ROOT/build/csg"
PORT=18787
DATA_DIR=""
SERVER_PID=""
SERVER_URL=""
TMP=""
INIT_JSON=""
SETUP_CODE=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/demo.sh [--port PORT] [--data-dir DIR]

  --port PORT      loopback port for the control plane (default 18787)
  --data-dir DIR   throwaway data directory (default .demo/data)
  -h, --help       show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --port)
      [ $# -ge 2 ] || { usage; exit 2; }
      PORT="$2"
      shift 2
      ;;
    --data-dir)
      [ $# -ge 2 ] || { usage; exit 2; }
      DATA_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "demo: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

case "$PORT" in
  ''|*[!0-9]*) echo "demo: --port must be a number" >&2; exit 2 ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "demo: --port out of range: $PORT" >&2
  exit 2
fi

DATA_DIR=${DATA_DIR:-"$ROOT/.demo/data"}
case "$DATA_DIR" in
  /*) : ;;
  *) DATA_DIR="$ROOT/$DATA_DIR" ;;
esac
SERVER_URL="http://127.0.0.1:$PORT"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/csg-demo.XXXXXX") || { echo "demo: cannot create temp dir" >&2; exit 1; }

# ---------------------------------------------------------------------------
# cleanup
# ---------------------------------------------------------------------------
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$SERVER_PID" 2>/dev/null || break
      sleep 0.1
    done
    kill -9 "$SERVER_PID" 2>/dev/null || true
  fi
  if [ -n "$SERVER_PID" ]; then
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [ -n "$TMP" ] && [ -d "$TMP" ]; then
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT INT TERM

echo "Cloud Safeguard demo (mock provider; no real cloud credentials)"
echo "  repo:       $ROOT"
echo "  data dir:   $DATA_DIR"
echo "  console:    $SERVER_URL"
echo

echo "== build =="
if ! go build -o "$BIN" ./cmd/csg; then
  echo "demo: go build failed" >&2
  exit 1
fi
if ! go build -o "$TMP/demo-driver" ./scripts/demo; then
  echo "demo: building the demo driver failed" >&2
  exit 1
fi
echo "built $BIN"
echo

# The demo always starts from a clean, throwaway data directory. It deletes
# only a directory that a demo instance lives in: one under this repository's
# .demo/, or one that holds nothing but an instance's own files. Anything
# else is refused, never removed.
if [ -e "$DATA_DIR" ]; then
  REMOVABLE=0
  case "$DATA_DIR" in
    "$ROOT"/.demo/?*)
      case "$DATA_DIR" in *..*) : ;; *) REMOVABLE=1 ;; esac
      ;;
  esac
  if [ "$REMOVABLE" -ne 1 ] && [ -d "$DATA_DIR" ] && [ ! -L "$DATA_DIR" ]; then
    OTHER=$(find "$DATA_DIR" -mindepth 1 -maxdepth 1 \
      ! -name master.key ! -name csg.db ! -name csg.db-wal ! -name csg.db-shm ! -name server.log | head -1)
    if [ -z "$OTHER" ] && [ -f "$DATA_DIR/csg.db" ]; then
      REMOVABLE=1
    fi
  fi
  if [ "$REMOVABLE" -ne 1 ]; then
    echo "demo: $DATA_DIR exists and is not a demo data directory; refusing to delete it." >&2
    echo "demo: use a path under $ROOT/.demo/ or a directory that does not exist yet." >&2
    exit 2
  fi
  echo "removing existing demo data dir: $DATA_DIR"
  rm -rf -- "$DATA_DIR"
fi
mkdir -p "$(dirname "$DATA_DIR")" || { echo "demo: cannot create parent of $DATA_DIR" >&2; exit 1; }

echo "== bootstrap =="
if ! INIT_JSON=$("$BIN" init --demo --data-dir "$DATA_DIR" --json); then
  echo "demo: csg init failed" >&2
  exit 1
fi
# The setup code goes to the driver through the environment, never argv.
SETUP_CODE=$(printf '%s' "$INIT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["supervisor"]["setup_code"])') \
  || { echo "demo: init output has no setup code" >&2; exit 1; }
[ -n "$SETUP_CODE" ] || { echo "demo: init output has no setup code" >&2; exit 1; }
echo "initialized demo data dir (the supervisor's setup code is captured, not printed)"
echo

echo "== start server =="
if curl -sf "$SERVER_URL/healthz" >/dev/null 2>&1; then
  echo "demo: port $PORT already has a healthy service; choose another --port" >&2
  exit 1
fi
"$BIN" serve --data-dir "$DATA_DIR" --addr "127.0.0.1:$PORT" >"$DATA_DIR/server.log" 2>&1 &
SERVER_PID=$!

READY=0
for _ in $(seq 1 200); do
  if curl -sf "$SERVER_URL/healthz" >/dev/null 2>&1; then
    READY=1
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "demo: server exited during startup; log:" >&2
    sed 's/^/  /' "$DATA_DIR/server.log" >&2
    exit 1
  fi
  sleep 0.1
done
if [ "$READY" -ne 1 ]; then
  echo "demo: server did not become healthy within 20s; log:" >&2
  sed 's/^/  /' "$DATA_DIR/server.log" >&2
  exit 1
fi
echo "server healthy at $SERVER_URL (log: $DATA_DIR/server.log)"
echo

echo "== scenarios =="
mkdir -p "$TMP/agent-home"
CSG_DEMO_SETUP_CODE="$SETUP_CODE" "$TMP/demo-driver" \
  --server "$SERVER_URL" --csg "$BIN" --home "$TMP/agent-home" --server-log "$DATA_DIR/server.log"
DRIVER_RC=$?
echo

echo "== cleanup =="
cleanup
trap - EXIT INT TERM
if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "demo: server process $SERVER_PID is still running" >&2
  exit 1
fi
echo "server stopped"

echo
if [ "$DRIVER_RC" -ne 0 ]; then
  echo "demo: some scenarios failed" >&2
  exit 1
fi
echo "all S1-S9 scenarios passed"
exit 0
