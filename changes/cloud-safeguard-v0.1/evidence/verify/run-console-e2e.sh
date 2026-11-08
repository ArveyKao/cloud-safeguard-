#!/usr/bin/env bash
# Runnable wrapper for the console E2E: fresh instance -> serve -> Playwright -> screenshots.
# Tooling: playwright-core installed under /tmp/csg-verify/ui (never added to the repo).
# Evidence: scripts/verify/console-e2e.log, docs/screenshots/*.png
set -uo pipefail
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CLONE=${CLONE:-/tmp/csg-verify/candidate}
BIN=${BIN:-$CLONE/bin/csg}
PORT=${PORT:-18893}
BASE="http://127.0.0.1:$PORT"
WORK=${WORK:-/tmp/csg-verify/ui-run}
SHOTS=${SHOTS:-$REPO/docs/screenshots}
OUT=${OUT:-$REPO/scripts/verify/console-e2e.log}
NODE_PATH=${NODE_PATH:-/tmp/csg-verify/ui/node_modules}
mkdir -p "$SHOTS" "$WORK"

exec > >(tee "$OUT") 2>&1
echo "# Cloud Safeguard console E2E (A13) — captured $(date -u +%FT%TZ)"
echo "# candidate commit: $(git -C "$CLONE" rev-parse HEAD)"
echo "# host: $(uname -m) $(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null), node $(node --version), playwright-core $(node -e "console.log(require('$NODE_PATH/playwright-core/package.json').version)")"
echo "# instance: $BASE, fresh data dir $WORK/data, Playwright Chromium headless 1440x900"

rm -rf "$WORK/data"
"$BIN" init --demo --json --data-dir "$WORK/data" >"$WORK/init.json" 2>&1 || { echo "FATAL: init failed"; cat "$WORK/init.json"; exit 1; }
ADMIN=$(jq -r '.data.admin_token' "$WORK/init.json")
AGENT=$(jq -r '.data.agents[] | select(.name=="claude-code") | .token' "$WORK/init.json")
"$BIN" serve --addr "127.0.0.1:$PORT" --data-dir "$WORK/data" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
cleanup(){ kill -INT "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; }
trap cleanup EXIT
for i in $(seq 1 60); do curl -sf "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.1; done
curl -sf "$BASE/healthz" >/dev/null || { echo "FATAL: server did not start"; tail -5 "$WORK/server.log"; exit 1; }

echo
echo "--- Playwright steps ---"
BASE="$BASE" ADMIN_TOKEN="$ADMIN" AGENT_TOKEN="$AGENT" SHOTS="$SHOTS" NODE_PATH="$NODE_PATH" PW_MODULE="$NODE_PATH/playwright-core" node "$REPO/scripts/verify/console-e2e.mjs"
E2E_EXIT=$?
echo
echo "E2E_EXIT=$E2E_EXIT"
echo
echo "--- server access log (bounded window) ---"
head -3 "$WORK/server.log"
echo "..."
tail -5 "$WORK/server.log"
echo "# E2E finished at $(date -u +%FT%TZ); screenshots:"
ls -la "$SHOTS" | tail -n +2 | awk '{print "  "$9" ("$5" bytes)"}'
exit "$E2E_EXIT"
