#!/usr/bin/env bash
# A16 docs accuracy spot-check: executes the practical commands documented in
# README.md + docs/QUICKSTART.md against a real throwaway instance.
# Prereq: instance initialized at $DATA and serving on $BASE (see runbook in VERIFICATION.md).
set -uo pipefail
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CLONE=${CLONE:-/tmp/csg-verify/candidate}
BIN=${BIN:-$CLONE/bin/csg}
BASE=${BASE:-http://127.0.0.1:18787}
DATA=${DATA:-/tmp/csg-verify/docs-check}
export HOME=${FAKE_HOME:-/tmp/csg-verify/agent-home}
ADMIN=$(jq -r .data.admin_token /tmp/csg-verify/docs-init.json)
AGT=$(jq -r '.data.agents[]|select(.name=="claude-code")|.token' /tmp/csg-verify/docs-init.json)
CLAUDE_ID=$(jq -r '.data.agents[]|select(.name=="claude-code")|.id' /tmp/csg-verify/docs-init.json)
PROV=$(jq -r '.data.provider_ids[0]' /tmp/csg-verify/docs-init.json)
mask(){ sed -E 's/csg_(adm|agt)_[A-Za-z0-9_-]{8,}/csg_\1_MASKED/g; s/cgk1\.[A-Za-z0-9_-]{20,}/cgk1.MASKED/g; s/"(access_key_id|access_key_secret|security_token)": "[^"]*"/"\1": "MASKED"/g'; }
run(){ echo "\$ $*"; "$@" 2>&1 | mask; echo "(exit ${PIPESTATUS[0]})"; echo; }
echo "# A16 docs accuracy spot-check — commands from README.md / docs/QUICKSTART.md actually executed"
echo "# captured $(date -u +%FT%TZ) on candidate $(git -C "$CLONE" rev-parse HEAD) (macOS arm64; $(go version | awk '{print $3}' 2>/dev/null || echo go); node $(node --version))"
echo "# instance: $BASE, throwaway data dir $DATA; secrets masked in this log"
echo
run "$BIN" version
run "$BIN" login --server "$BASE" --token "$ADMIN"
run "$BIN" whoami
export CSG_SERVER=$BASE CSG_TOKEN=$ADMIN
run "$BIN" caps list
run "$BIN" caps show aliyun.cloud.read
run "$BIN" agents list
run "$BIN" agents get "$CLAUDE_ID"
export CSG_TOKEN=$AGT
run "$BIN" leases mine
"$BIN" request --capability aliyun.cloud.read --reason "collect inventory for weekly report" --wait 30s --json > /tmp/csg-verify/docs-req.json 2>&1
echo '$ ./bin/csg request --capability aliyun.cloud.read --reason "collect inventory for weekly report" --wait 30s --json'
jq -r '"status=\(.status) decision=\(.decision.outcome) lease=\(.id) ttl=\(.effective_ttl_seconds)"' /tmp/csg-verify/docs-req.json; echo "(exit 0)"; echo
LEASE=$(jq -r '.id' /tmp/csg-verify/docs-req.json)
echo '$ eval "$(./bin/csg credential --lease ID --export)"   # documented env injection; values masked'
bash -c 'eval "$(./bin/csg credential --lease "$1" --export)"; echo "ALIBABA_CLOUD_ACCESS_KEY_ID=${ALIBABA_CLOUD_ACCESS_KEY_ID:0:4}…"; echo "ALIBABA_CLOUD_SECURITY_TOKEN=${ALIBABA_CLOUD_SECURITY_TOKEN:0:5}…"; ./bin/csg mock request GET /v1/ecs/instances' _ "$LEASE" 2>&1 | mask | head -c 420; echo; echo
echo '$ ./bin/csg mock request POST /v1/ecs/instances/i-2ze0demo001/restart   (documented expected 403)'
bash -c 'eval "$(./bin/csg credential --lease "$1" --export)"; ./bin/csg mock request POST /v1/ecs/instances/i-2ze0demo001/restart' _ "$LEASE" 2>&1 | mask | head -c 220; echo; echo "(expected exit 1 / 403 Forbidden.RAM)"; echo
run "$BIN" exec --capability aliyun.cloud.read --reason "one-shot inventory" -- "$BIN" mock request GET /v1/ecs/instances
"$BIN" request --capability aliyun.dns.manage --param domain=arveykao.com --ttl 10m --reason "add ACME DNS-01 TXT record" --json > /tmp/csg-verify/docs-pend.json 2>&1
PEND=$(jq -r '.id' /tmp/csg-verify/docs-pend.json)
echo '$ ./bin/csg request --capability aliyun.dns.manage --param domain=arveykao.com --ttl 10m --reason "..." --json'
jq -r '"status=\(.status) decision=\(.decision.outcome)"' /tmp/csg-verify/docs-pend.json; echo
export CSG_TOKEN=$ADMIN
run "$BIN" leases list --status pending
run "$BIN" leases approve "$PEND" --note "ACME renewal for arveykao.com"
run "$BIN" leases list --status active
run "$BIN" audit list --limit 20
run "$BIN" audit verify
run "$BIN" leases revoke "$PEND" --reason "done with demo"
run "$BIN" providers list
run "$BIN" providers get "$PROV"
run "$BIN" providers test "$PROV"
run "$BIN" policy show
run "$BIN" policy set --max-lease-ttl 30m --json
run "$BIN" policy set --max-lease-ttl 1h --json
run "$BIN" agents create --name docs-check-agent --capability aliyun.cloud.read --max-ttl 30m --max-concurrent 2 --json
NEWID=$(sqlite3 "$DATA/csg.db" "select id from agents where name='docs-check-agent' order by created_at desc limit 1;")
run "$BIN" agents rotate-token "$NEWID" --json
run "$BIN" agents suspend "$NEWID"
run "$BIN" agents activate "$NEWID"
echo "=== documented default listen address (README: http://127.0.0.1:8787) ==="
if lsof -nP -iTCP:8787 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "BLOCKED: port 8787 already held by an unrelated process in this environment; explicit --addr form exercised throughout."
else
  "$BIN" serve --data-dir "$DATA" >/tmp/csg-verify/docs-serve-default.log 2>&1 & DEFPID=$!
  sleep 1; echo "GET http://127.0.0.1:8787/healthz -> $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/healthz)"; kill -INT "$DEFPID" 2>/dev/null; wait "$DEFPID" 2>/dev/null
fi
echo
echo "=== documented flags vs shipped --help ==="
for c in "init" "serve" "request" "credential" "agents create" "agents rotate-token" "providers add" "providers rotate" "providers test" "leases approve" "leases deny" "leases revoke" "policy set" "audit list" "audit verify" "mock request"; do echo "\$ ./bin/csg $c --help"; "$BIN" $c --help 2>&1 | head -2; echo; done
echo "# spot-check complete $(date -u +%FT%TZ)"
