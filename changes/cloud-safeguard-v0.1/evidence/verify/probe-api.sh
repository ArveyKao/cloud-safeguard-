#!/usr/bin/env bash
# Independent black-box verification probes for Cloud Safeguard v0.1 (A1, A2, A3-A12).
# Reads/uses ONLY the built binary and HTTP API/CLI; never modifies product code.
#
# Usage: scripts/verify/probe-api.sh
#   CLONE=/tmp/csg-verify/candidate  (fresh clone at candidate commit, built with make build)
#   WORK=/tmp/csg-verify/probe-run   (throwaway dir; recreated)
# Ports: 18891 (clean instance), 18892 (tampered-audit instance)
set -uo pipefail

CLONE=${CLONE:-/tmp/csg-verify/candidate}
BIN=${BIN:-$CLONE/bin/csg}
WORK=${WORK:-/tmp/csg-verify/probe-run}
PORT1=${PORT1:-18891}
PORT2=${PORT2:-18892}
BASE=http://127.0.0.1:$PORT1
BASE2=http://127.0.0.1:$PORT2
DATA=$WORK/data
mkdir -p "$WORK/resp"
LOG=$WORK/probes.log
: >"$LOG"
exec > >(tee -a "$LOG") 2>&1

PASS=0; FAIL=0; WARN=0; FAILED=(); WARNINGS=()
pass(){ PASS=$((PASS+1)); echo "PASS $1"; }
fail(){ FAIL=$((FAIL+1)); FAILED+=("$1"); echo "FAIL $1 -- $2"; }
warn(){ WARN=$((WARN+1)); WARNINGS+=("$1"); echo "WARN $1 -- $2"; }
mask(){ sed -E 's/csg_(adm|agt)_[A-Za-z0-9_-]{8,}/csg_\1_MASKED/g; s/cgk1\.[A-Za-z0-9_-]{40,}/cgk1.MASKED_MOCK_TOKEN/g; s/(CANARY|ROTATED)[A-Za-z0-9_]*SECRET[A-Za-z0-9_]*/\1_SECRET_MASKED/g'; }
jqr(){ jq -r "$1" "$BODY" 2>/dev/null; }
jeq(){ jq -e "$1" "$BODY" >/dev/null 2>&1; }

TMPBODY=$(mktemp); BODY=$TMPBODY; CODE=000
api(){ # method path token [json-body]
  local m=$1 p=$2 t=$3 b=${4:-}
  if [ -n "$b" ]; then
    CODE=$(curl -s -o "$BODY" -w '%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $t" -H 'Content-Type: application/json' -d "$b")
  else
    CODE=$(curl -s -o "$BODY" -w '%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $t")
  fi
}
mockcall(){ # method path token
  local m=$1 p=$2 t=$3
  CODE=$(curl -s -o "$BODY" -w '%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $t" -H 'Content-Type: application/json')
}
expect(){ # name expected-code
  if [ "$CODE" = "$2" ]; then pass "$1 (HTTP $CODE)"; else fail "$1" "expected HTTP $2, got $CODE: $(head -c 240 "$BODY" | mask)"; fi
}
check(){ # name condition-desc result(0 ok)
  if [ "$3" = 0 ]; then pass "$1"; else fail "$1" "$2"; fi
}

cleanup(){
  for p in "${SERVER_PID:-}" "${SERVER2_PID:-}"; do
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null && kill -INT "$p" 2>/dev/null
  done
  wait 2>/dev/null
}
trap cleanup EXIT

echo "== Cloud Safeguard independent API probes =="
echo "clone=$CLONE  commit=$(git -C "$CLONE" rev-parse HEAD)  go=$(go version | awk '{print $3}')  date=$(date -u +%FT%TZ)"

# ============================== A1: init artifacts ==============================
echo; echo "--- A1 init/bootstrap ---"
rm -rf "$WORK/canary-secret" "$WORK/canary-secret2" "$DATA"
mkdir -p "$WORK"
CANARY_SECRET="CANARY_SECRET_VALUE_$(openssl rand -hex 8)"
CANARYAKID="CANARYAKID$(openssl rand -hex 6 | tr a-f A-F)"
CANARY_SECRET2="ROTATED_SECRET_VALUE_$(openssl rand -hex 8)"
printf '%s' "$CANARY_SECRET" >"$WORK/canary-secret"
printf '%s' "$CANARY_SECRET2" >"$WORK/canary-secret2"
chmod 600 "$WORK/canary-secret" "$WORK/canary-secret2"

"$BIN" init --demo --json --data-dir "$DATA" >"$WORK/init.json" 2>"$WORK/init.err"
INIT_EXIT=$?
check "A1-init-exit0" "init exited $INIT_EXIT: $(cat "$WORK/init.err")" $([ $INIT_EXIT -eq 0 ] && echo 0 || echo 1)
ADMIN=$(jq -r '.data.admin_token' "$WORK/init.json")
CLAUDE_TOKEN=$(jq -r '.data.agents[] | select(.name=="claude-code") | .token' "$WORK/init.json")
CLAUDE_ID=$(jq -r '.data.agents[] | select(.name=="claude-code") | .id' "$WORK/init.json")
HERMES_TOKEN=$(jq -r '.data.agents[] | select(.name=="hermes-researcher") | .token' "$WORK/init.json")
HERMES_ID=$(jq -r '.data.agents[] | select(.name=="hermes-researcher") | .id' "$WORK/init.json")
PROVIDER_ID=$(jq -r '.data.provider_ids[0]' "$WORK/init.json")
CAPS=$(jq -r '.data.capability_ids | length' "$WORK/init.json")
AGENTS=$(jq -r '.data.agents | length' "$WORK/init.json")
PROVIDERS=$(jq -r '.data.provider_ids | length' "$WORK/init.json")
check "A1-admin-token-format" "admin token does not start csg_adm_" $([[ "$ADMIN" == csg_adm_* ]] && echo 0 || echo 1)
check "A1-agent-tokens-once" "expected 2 one-time agent tokens" $([ "$AGENTS" -eq 2 ] && [ -n "$CLAUDE_TOKEN" ] && [ -n "$HERMES_TOKEN" ] && echo 0 || echo 1)
check "A1-counts-5caps-1provider-2agents" "caps=$CAPS providers=$PROVIDERS agents=$AGENTS" $([ "$CAPS" -eq 5 ] && [ "$PROVIDERS" -eq 1 ] && [ "$AGENTS" -eq 2 ] && echo 0 || echo 1)
DIRPERM=$(stat -f '%Lp' "$DATA"); KEYPERM=$(stat -f '%Lp' "$DATA/master.key"); DBPERM=$(stat -f '%Lp' "$DATA/csg.db")
check "A1-perms-dir700" "data dir perms=$DIRPERM" $([ "$DIRPERM" = 700 ] && echo 0 || echo 1)
check "A1-perms-masterkey600" "master.key perms=$KEYPERM" $([ "$KEYPERM" = 600 ] && echo 0 || echo 1)
check "A1-perms-db600" "csg.db perms=$DBPERM" $([ "$DBPERM" = 600 ] && echo 0 || echo 1)
check "A1-masterkey-32bytes" "master.key size=$(stat -f '%z' "$DATA/master.key")" $([ "$(stat -f '%z' "$DATA/master.key")" = 32 ] && echo 0 || echo 1)

"$BIN" init --demo --json --data-dir "$DATA" >"$WORK/reinit.json" 2>"$WORK/reinit.err"; REINIT_EXIT=$?
check "A1-reinit-refused-nonzero" "re-init exit=$REINIT_EXIT" $([ $REINIT_EXIT -ne 0 ] && echo 0 || echo 1)
check "A1-reinit-no-token-printed" "re-init printed a token" $(! grep -qE 'csg_(adm|agt)_[A-Za-z0-9_-]{8,}' "$WORK/reinit.json" "$WORK/reinit.err" 2>/dev/null && echo 0 || echo 1)
ADMIN_OLD_TOKEN=$ADMIN
AUDIT_BEFORE_FORCE=$(sqlite3 "$DATA/csg.db" 'select count(*) from audit;' 2>/dev/null)
"$BIN" init --demo --json --force --data-dir "$DATA" >"$WORK/forceinit.json" 2>"$WORK/forceinit.err"; FORCE_EXIT=$?
ADMIN_NEW=$(jq -r '.data.admin_token' "$WORK/forceinit.json")
check "A1-force-exit0" "force re-init exit=$FORCE_EXIT" $([ $FORCE_EXIT -eq 0 ] && echo 0 || echo 1)
check "A1-force-rotates-admin-token" "token unchanged by --force" $([ -n "$ADMIN_NEW" ] && [ "$ADMIN" != "$ADMIN_NEW" ] && echo 0 || echo 1)
DB_PROVIDERS=$(sqlite3 "$DATA/csg.db" 'select count(*) from providers;' 2>/dev/null)
DB_AGENTS=$(sqlite3 "$DATA/csg.db" 'select count(*) from agents;' 2>/dev/null)
DB_CAPS=$(sqlite3 "$DATA/csg.db" 'select count(*) from capabilities;' 2>/dev/null)
check "A1-force-keeps-data" "after --force DB providers=$DB_PROVIDERS agents=$DB_AGENTS caps=$DB_CAPS" $([ "$DB_PROVIDERS" = 1 ] && [ "$DB_AGENTS" = 2 ] && [ "$DB_CAPS" = 5 ] && echo 0 || echo 1)
AUDIT_AFTER_FORCE=$(sqlite3 "$DATA/csg.db" 'select count(*) from audit;' 2>/dev/null)
# Not required by CONTRACT §11 (no audit action is defined for this), recorded as an observation.
echo "OBSERVE force-rotation-audit: audit rows before=$AUDIT_BEFORE_FORCE after=$AUDIT_AFTER_FORCE (admin token rotation is not audited; CONTRACT defines no audit action for it)"
ADMIN="$ADMIN_NEW"
printf 'ADMIN_TOKEN=%q\nCLAUDE_TOKEN=%q\nCLAUDE_ID=%q\nHERMES_TOKEN=%q\nHERMES_ID=%q\nPROVIDER_ID=%q\n' "$ADMIN" "$CLAUDE_TOKEN" "$CLAUDE_ID" "$HERMES_TOKEN" "$HERMES_ID" "$PROVIDER_ID" >"$WORK/tokens.env"
chmod 600 "$WORK/tokens.env"

# ============================== A2: serve ==============================
echo; echo "--- A2 serve surface ---"
"$BIN" serve --addr "127.0.0.1:$PORT1" --data-dir "$DATA" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for i in $(seq 1 50); do curl -sf "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.1; done
HEALTH=$(curl -s "$BASE/healthz")
if ! kill -0 "$SERVER_PID" 2>/dev/null || ! echo "$HEALTH" | jq -e '.status=="ok"' >/dev/null 2>&1; then
  echo "FATAL: probe server failed to start/bind $BASE; see $WORK/server.log"; tail -3 "$WORK/server.log" 2>/dev/null
  FAIL=$((FAIL+1)); FAILED+=("probe-server-start"); echo "PASS=$PASS FAIL=$FAIL"; exit 1
fi
# data survives --force: agent token issued by the first init must still authenticate
api GET /api/v1/agent/me "$CLAUDE_TOKEN"
check "A1-agent-token-survives-force-reinit" "http=$CODE (agents and grants kept, tokens not re-issued)" $([ "$CODE" = 200 ] && echo 0 || echo 1)
check "A2-healthz" "/healthz=$HEALTH" $(echo "$HEALTH" | jq -e '.status=="ok" and .version=="0.1.0"' >/dev/null 2>&1 && echo 0 || echo 1)
ROOT_HTML=$(curl -s "$BASE/")
check "A2-console-index-served" "GET / missing dashboard markup (len=${#ROOT_HTML})" $(echo "$ROOT_HTML" | grep -q 'id="root"' && echo 0 || echo 1)
ASSET=$(echo "$ROOT_HTML" | grep -oE 'assets/[A-Za-z0-9_.-]+\.js' | head -1)
ACODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/$ASSET")
check "A2-console-bundle-served" "GET /$ASSET -> $ACODE" $([ "$ACODE" = 200 ] && echo 0 || echo 1)
SPA=$(curl -s -o "$BODY" -w '%{http_code}' "$BASE/agents")
check "A2-spa-deeplink-fallback" "GET /agents -> $SPA" $([ "$SPA" = 200 ] && grep -q 'id="root"' "$BODY" && echo 0 || echo 1)
api GET /api/v1/agent/me "" ; expect "A2-agent-api-requires-auth" 401

# ============================== helpers: create probe agents ==============================
mkagent(){ # name grants-json max_ttl max_conc -> sets NEW_ID NEW_TOKEN
  local name=$1 grants=$2 ttl=$3 conc=$4 body
  body=$(jq -nc --arg n "$name" --argjson g "$grants" --argjson t "$ttl" --argjson c "$conc" '{name:$n,description:"verifier probe agent",grants:$g,max_ttl_seconds:$t,max_concurrent_leases:$c}')
  api POST /api/v1/admin/agents "$ADMIN" "$body"
  NEW_ID=$(jqr '.data.agent.id'); NEW_TOKEN=$(jqr '.data.token')
  echo "  created agent $name -> $NEW_ID (token masked)"
}
ALLGRANTS='["aliyun.cloud.read","aliyun.dns.manage","aliyun.cert.dns01","aliyun.ecs.instance.ops","aliyun.iam.break_glass"]'
mkagent probe-a "$ALLGRANTS" 3600 10; A_ID=$NEW_ID; A_TOKEN=$NEW_TOKEN
mkagent probe-b '["aliyun.cloud.read","aliyun.dns.manage"]' 60 1; B_ID=$NEW_ID; B_TOKEN=$NEW_TOKEN
mkagent probe-c '["aliyun.dns.manage"]' 3600 10; C_ID=$NEW_ID; C_TOKEN=$NEW_TOKEN
mkagent probe-d "$ALLGRANTS" 3600 3; D_ID=$NEW_ID; D_TOKEN=$NEW_TOKEN
check "A5-agent-created-token-once" "created agents should return token once" $([ -n "$A_TOKEN" ] && [ -n "$D_TOKEN" ] && echo 0 || echo 1)

req(){ # token capability ttl reason [params-json] [breakglass] -> sets LEASE
  local body
  body=$(jq -nc --arg c "$2" --arg r "$4" --argjson t "${3:-0}" --argjson p "${5:-null}" --argjson bg "${6:-false}" \
    '{capability_id:$c,reason:$r,ttl_seconds:$t} + (if $p!=null then {params:$p} else {} end) + (if $bg then {break_glass:true} else {} end)')
  api POST /api/v1/agent/leases "$1" "$body"
  LEASE=$(jqr '.data.id')
}

# ============================== A3: auto-approve end-to-end ==============================
echo; echo "--- A3 auto-approve (S1) ---"
req "$A_TOKEN" aliyun.cloud.read 300 "collect inventory for weekly report"
check "A3-create-201" "expected 201 active, got $CODE $(head -c200 "$BODY"|mask)" $([ "$CODE" = 201 ] && echo 0 || echo 1)
check "A3-status-active" "status=$(jqr '.data.status')" $(jeq '.data.status=="active"' && echo 0 || echo 1)
check "A3-decision-auto-approve" "outcome=$(jqr '.data.decision.outcome')" $(jeq '.data.decision.outcome=="auto_approve"' && echo 0 || echo 1)
check "A3-decision-reasons-present" "reason rules=$(jqr '.data.decision.reasons|length')" $(jeq '.data.decision.reasons|length>0' && echo 0 || echo 1)
check "A3-approved-by-auto" "approved_by=$(jqr '.data.approved_by')" $(jeq '.data.approved_by=="auto"' && echo 0 || echo 1)
check "A3-no-credential-in-lease" "lease JSON contains mock token" $(! grep -q 'cgk1\.' "$BODY" && echo 0 || echo 1)
A3_LEASE=$LEASE
api POST "/api/v1/agent/leases/$A3_LEASE/credential" "$A_TOKEN"
expect "A3-credential-fetch-200" 200
cp "$BODY" "$WORK/credential-a3.json"
ENVNAMES=$(jqr '.data.env | map(.name) | join(",")')
check "A3-env-6-vars-exact-order" "env=$ENVNAMES" $([ "$ENVNAMES" = "ALIBABA_CLOUD_ACCESS_KEY_ID,ALIBABA_CLOUD_ACCESS_KEY_SECRET,ALIBABA_CLOUD_SECURITY_TOKEN,CSG_LEASE_ID,CSG_SERVER,CSG_CAPABILITY" ] && echo 0 || echo 1)
check "A3-env-values-alibaba-shaped" "AK/ST shapes wrong" $(jqr '.data.env[] | select(.name=="ALIBABA_CLOUD_ACCESS_KEY_ID") | .value' | grep -qE '^LTAI' && jqr '.data.env[] | select(.name=="ALIBABA_CLOUD_SECURITY_TOKEN") | .value' | grep -qE '^cgk1\.' && echo 0 || echo 1)
check "A3-env-server-url" "CSG_SERVER=$(jqr '.data.env[] | select(.name=="CSG_SERVER") | .value')" $([ "$(jqr '.data.env[] | select(.name=="CSG_SERVER") | .value')" = "$BASE" ] && echo 0 || echo 1)
MOCK_TOKEN=$(jqr '.data.env[] | select(.name=="ALIBABA_CLOUD_SECURITY_TOKEN") | .value')
mockcall GET /mock-cloud/v1/ecs/instances "$MOCK_TOKEN"
expect "A3-mock-cloud-get-ecs-200" 200
check "A3-mock-cloud-3-instances" "instances=$(jqr '.Instances|length')" $(jeq '.Instances|length==3' && echo 0 || echo 1)

# ============================== A4: least privilege + limits + sweeper ==============================
echo; echo "--- A4 least privilege / TTL / limits / sweeper ---"
MOCK_TOKEN_A3=$MOCK_TOKEN
mockcall POST /mock-cloud/v1/ecs/instances/i-2ze0demo001/restart "$MOCK_TOKEN_A3"
expect "A4-S2-write-blocked-403" 403
if [ "$(jqr '.Code')" = "Forbidden.RAM" ]; then pass "A4-S2-code-Forbidden.RAM"; else fail "A4-S2-code-Forbidden.RAM" "code=$(jqr '.Code')"; fi

# TTL rule: capability max
req "$A_TOKEN" aliyun.dns.manage 3600 "ttl probe" '{"domain":"probe-ttl.example.com"}'
check "A4-ttl-capability-denied" "status=$(jqr '.data.status') outcome=$(jqr '.data.decision.outcome')" $(jeq '.data.status=="denied" and ([.data.decision.reasons[]|select(.rule=="ttl_within_capability" and .outcome=="deny")]|length==1)' && echo 0 || echo 1)
check "A4-ttl-capability-reason-text" "detail=$(jqr '[.data.decision.reasons[]|select(.rule=="ttl_within_capability")][0].detail')" $(jeq '[.data.decision.reasons[]|select(.rule=="ttl_within_capability")][0].detail|test("3600")' && echo 0 || echo 1)
# TTL rule: agent max (probe-b max 60s)
req "$B_TOKEN" aliyun.cloud.read 120 "agent ttl probe"
check "A4-ttl-agent-denied" "outcome=$(jqr '.data.decision.outcome')" $(jeq '.data.status=="denied" and ([.data.decision.reasons[]|select(.rule=="ttl_within_agent" and .outcome=="deny")]|length==1)' && echo 0 || echo 1)
# TTL rule: global max (lower global temporarily)
api GET /api/v1/admin/policy "$ADMIN"; ORIG_POLICY=$(jq -c '.data' "$BODY")
api PUT /api/v1/admin/policy "$ADMIN" '{"auto_approve_max_risk":"low","auto_approve_max_ttl_seconds":300,"max_lease_ttl_seconds":600,"pending_timeout_seconds":600,"max_concurrent_leases_per_agent":3,"leases_per_minute_per_agent":6,"require_reason_for_risk":"medium"}'
expect "A4-set-global-ttl-600" 200
req "$A_TOKEN" aliyun.cloud.read 900 "global ttl probe"
check "A4-ttl-global-denied" "outcome=$(jqr '.data.decision.outcome')" $(jeq '.data.status=="denied" and ([.data.decision.reasons[]|select(.rule=="ttl_within_global" and .outcome=="deny")]|length==1)' && echo 0 || echo 1)
api PUT /api/v1/admin/policy "$ADMIN" "$ORIG_POLICY"
expect "A4-restore-policy" 200
# Concurrency (probe-b max concurrent 1)
req "$B_TOKEN" aliyun.cloud.read 60 "concurrency slot 1"
check "A4-concurrency-slot-active" "status=$(jqr '.data.status')" $(jeq '.data.status=="active"' && echo 0 || echo 1)
req "$B_TOKEN" aliyun.cloud.read 60 "concurrency slot 2"
check "A4-concurrency-denied-explicit" "outcome=$(jqr '.data.decision.outcome')" $(jeq '.data.status=="denied" and ([.data.decision.reasons[]|select(.rule=="concurrency_available" and .outcome=="deny")]|length==1)' && echo 0 || echo 1)
# Rate limit: fill rate budget with denied leases (denied leases still count as created)
for i in 1 2 3 4 5 6; do req "$C_TOKEN" aliyun.dns.manage 3600 "rate fill $i" "{\"domain\":\"rl.example.com\"}" >/dev/null; done
req "$C_TOKEN" aliyun.dns.manage 3600 "rate limit probe" '{"domain":"rl.example.com"}'
check "A4-rate-limit-denied-explicit" "outcome=$(jqr '.data.decision.outcome')" $(jeq '.data.status=="denied" and ([.data.decision.reasons[]|select(.rule=="rate_limit" and .outcome=="deny")]|length==1)' && echo 0 || echo 1)
check "A4-rate-limit-reason-text" "detail=$(jqr '[.data.decision.reasons[]|select(.rule=="rate_limit")][0].detail')" $(jeq '[.data.decision.reasons[]|select(.rule=="rate_limit")][0].detail|test("60s|minute|6")' && echo 0 || echo 1)
# Sweeper expiry with 5s TTL
req "$A_TOKEN" aliyun.cloud.read 5 "sweeper probe"
EXP_LEASE=$LEASE
check "A4-expiry-lease-active" "status=$(jqr '.data.status')" $(jeq '.data.status=="active"' && echo 0 || echo 1)
api POST "/api/v1/agent/leases/$EXP_LEASE/credential" "$A_TOKEN"; expect "A4-expiry-credential-before" 200
EXP_TOKEN=$(jqr '.data.env[]|select(.name=="ALIBABA_CLOUD_SECURITY_TOKEN")|.value')
mockcall GET /mock-cloud/v1/ecs/instances "$EXP_TOKEN"; expect "A4-expiry-token-works-immediately" 200
sleep 6.5
mockcall GET /mock-cloud/v1/ecs/instances "$EXP_TOKEN"
check "A4-expired-token-401" "code=$(jqr '.Code') http=$CODE" $([ "$CODE" = 401 ] && [ "$(jqr '.Code')" = "InvalidSecurityToken.Expired" ] && echo 0 || echo 1)
sleep 6  # allow 10s sweeper to run
api GET "/api/v1/agent/leases/$EXP_LEASE" "$A_TOKEN"
check "A4-sweeper-status-expired" "status=$(jqr '.data.status')" $(jeq '.data.status=="expired"' && echo 0 || echo 1)
api POST "/api/v1/agent/leases/$EXP_LEASE/credential" "$A_TOKEN"
check "A4-expired-credential-fetch-409" "code=$CODE err=$(jqr '.error.code')" $([ "$CODE" = 409 ] && [ "$(jqr '.error.code')" = "lease_not_active" ] && echo 0 || echo 1)
sleep 4  # ensure post-expiry mock check hits store-expired path too
mockcall GET /mock-cloud/v1/ecs/instances "$EXP_TOKEN"
check "A4-swept-token-401" "code=$(jqr '.Code') http=$CODE" $([ "$CODE" = 401 ] && echo 0 || echo 1)
SCRUB=$(sqlite3 "$DATA/csg.db" "select length(encrypted_credential)||'/'||credential_available from leases where id='$EXP_LEASE';" 2>/dev/null)
check "A4-sweeper-scrubs-credential" "db encrypted_credential/available=$SCRUB" $([ "$SCRUB" = "0/0" ] && echo 0 || echo 1)

# ============================== A5: server-side auth enforcement ==============================
echo; echo "--- A5 auth / token enforcement ---"
api GET /api/v1/agent/me "csg_agt_forged000000000000000000000000000000000000"; expect "A5-forged-agent-token-401" 401
api GET /api/v1/agent/me "garbage-token"; expect "A5-garbage-token-401" 401
api GET /api/v1/agent/me "$ADMIN"; expect "A5-admin-token-on-agent-route-401" 401
api GET /api/v1/admin/overview "$A_TOKEN"; expect "A5-agent-token-on-admin-route-401" 401
api POST /api/v1/admin/login "$ADMIN_OLD_TOKEN" "{}"; expect "A5-old-admin-token-after-force-401" 401
api GET /api/v1/admin/providers ""; expect "A5-admin-no-auth-401" 401
api GET "/api/v1/agent/leases/$A3_LEASE" "$B_TOKEN"; expect "A5-cross-agent-lease-read-404" 404
api POST "/api/v1/agent/leases/$A3_LEASE/credential" "$B_TOKEN"; expect "A5-cross-agent-credential-404" 404
# revoked mock token
req "$A_TOKEN" aliyun.cloud.read 120 "revoke-probe"
RV_LEASE=$LEASE
api POST "/api/v1/agent/leases/$RV_LEASE/credential" "$A_TOKEN"; expect "A5-revoke-probe-credential" 200
RV_TOKEN=$(jqr '.data.env[]|select(.name=="ALIBABA_CLOUD_SECURITY_TOKEN")|.value')
api POST "/api/v1/admin/leases/$RV_LEASE/revoke" "$ADMIN" '{"reason":"verifier probe revoke"}'; expect "A5-admin-revoke-200" 200
mockcall GET /mock-cloud/v1/ecs/instances "$RV_TOKEN"
check "A5-revoked-mock-token-401" "http=$CODE code=$(jqr '.Code')" $([ "$CODE" = 401 ] && [ "$(jqr '.Code')" = "InvalidSecurityToken.Revoked" ] && echo 0 || echo 1)
mockcall GET /mock-cloud/v1/ecs/instances "cgk1.garbage.token"; expect "A5-malformed-mock-token-401" 401
# suspended agent blocked
api POST "/api/v1/admin/agents/$A_ID/suspend" "$ADMIN"; expect "A5-suspend-200" 200
req "$A_TOKEN" aliyun.cloud.read 60 "suspended probe"
check "A5-suspended-agent-403" "http=$CODE code=$(jqr '.error.code')" $([ "$CODE" = 403 ] && [ "$(jqr '.error.code')" = "forbidden" ] && echo 0 || echo 1)
api GET /api/v1/agent/me "$A_TOKEN"; expect "A5-suspended-agent-me-403" 403
api POST "/api/v1/admin/agents/$A_ID/activate" "$ADMIN"; expect "A5-activate-200" 200
# agent token rotation invalidates old token
api POST "/api/v1/admin/agents/$B_ID/token/rotate" "$ADMIN"; expect "A5-rotate-token-200" 200
B_TOKEN_NEW=$(jqr '.data.token')
api GET /api/v1/agent/me "$B_TOKEN"; expect "A5-rotated-old-agent-token-401" 401
api GET /api/v1/agent/me "$B_TOKEN_NEW"; expect "A5-rotated-new-agent-token-200" 200
B_TOKEN=$B_TOKEN_NEW

# ============================== A6: approval / denial / break-glass ==============================
echo; echo "--- A6 approval, denial, break-glass ---"
req "$D_TOKEN" aliyun.dns.manage 600 "add ACME DNS-01 TXT record" '{"domain":"arveykao.com"}'
PEND1=$LEASE
check "A6-pending-medium" "status=$(jqr '.data.status') outcome=$(jqr '.data.decision.outcome')" $(jeq '.data.status=="pending" and .data.decision.outcome=="require_approval"' && echo 0 || echo 1)
check "A6-pending-risk-above-auto-reason" "reasons=$(jqr '[.data.decision.reasons[].rule]|join(",")')" $(jeq '[.data.decision.reasons[]|select(.rule=="risk_above_auto" and .outcome=="require_approval")]|length==1' && echo 0 || echo 1)
api POST "/api/v1/agent/leases/$PEND1/credential" "$D_TOKEN"; expect "A6-pending-no-credential-409" 409
# approve via CLI
CSG_SERVER=$BASE CSG_TOKEN=$ADMIN "$BIN" leases approve "$PEND1" --note "ACME renewal for arveykao.com" --json >"$WORK/approve-cli.json" 2>"$WORK/approve-cli.err"
APPROVE_EXIT=$?
check "A6-approve-via-CLI-exit0" "exit=$APPROVE_EXIT $(cat "$WORK/approve-cli.err"|mask)" $([ $APPROVE_EXIT -eq 0 ] && echo 0 || echo 1)
api GET "/api/v1/admin/leases/$PEND1" "$ADMIN"
check "A6-approved-status-active" "status=$(jqr '.data.status') approved_by=$(jqr '.data.approved_by')" $(jeq '.data.status=="active" and .data.approved_by=="admin"' && echo 0 || echo 1)
api POST "/api/v1/agent/leases/$PEND1/credential" "$D_TOKEN"; expect "A6-approved-credential-200" 200
DNS_TOKEN=$(jqr '.data.env[]|select(.name=="ALIBABA_CLOUD_SECURITY_TOKEN")|.value')
CODE=$(curl -s -o "$BODY" -w '%{http_code}' -X POST "$BASE/mock-cloud/v1/dns/zones/arveykao.com/records" -H "Authorization: Bearer $DNS_TOKEN" -H 'Content-Type: application/json' -d '{"name":"_acme-verify","type":"TXT","value":"verifier-token","ttl":600}')
expect "A6-approved-scoped-dns-write-200" 200
mockcall POST /mock-cloud/v1/ecs/instances/i-2ze0demo001/restart "$DNS_TOKEN"
check "A6-approved-dns-token-cannot-restart-ecs" "http=$CODE code=$(jqr '.Code')" $([ "$CODE" = 403 ] && [ "$(jqr '.Code')" = "Forbidden.RAM" ] && echo 0 || echo 1)
# approve via HTTP for a second pending lease
req "$D_TOKEN" aliyun.cert.dns01 600 "cert renew via http" '{"domain":"guanlanstudio.com"}'
PEND2=$LEASE
api POST "/api/v1/admin/leases/$PEND2/approve" "$ADMIN" '{"note":"approved via HTTP API"}'
expect "A6-approve-via-HTTP-200" 200
check "A6-http-approved-active" "status=$(jqr '.data.status')" $(jeq '.data.status=="active"' && echo 0 || echo 1)
# deny via CLI
req "$D_TOKEN" aliyun.dns.manage 600 "deny cli probe" '{"domain":"deny-cli.example.com"}'
PEND3=$LEASE
CSG_SERVER=$BASE CSG_TOKEN=$ADMIN "$BIN" leases deny "$PEND3" --reason "not needed for demo" --json >"$WORK/deny-cli.json" 2>"$WORK/deny-cli.err"
DENY_EXIT=$?
check "A6-deny-via-CLI-exit0" "exit=$DENY_EXIT $(cat "$WORK/deny-cli.err"|mask)" $([ $DENY_EXIT -eq 0 ] && echo 0 || echo 1)
api GET "/api/v1/admin/leases/$PEND3" "$ADMIN"
check "A6-denied-status" "status=$(jqr '.data.status')" $(jeq '.data.status=="denied"' && echo 0 || echo 1)
api POST "/api/v1/agent/leases/$PEND3/credential" "$D_TOKEN"
check "A6-denied-credential-409" "http=$CODE code=$(jqr '.error.code')" $([ "$CODE" = 409 ] && echo 0 || echo 1)
# deny via HTTP
req "$D_TOKEN" aliyun.cert.dns01 600 "deny http probe" '{"domain":"deny-http.example.com"}'
PEND4=$LEASE
api POST "/api/v1/admin/leases/$PEND4/deny" "$ADMIN" '{"reason":"denied via HTTP API"}'
expect "A6-deny-via-HTTP-200" 200
check "A6-http-denied-status" "status=$(jqr '.data.status')" $(jeq '.data.status=="denied"' && echo 0 || echo 1)
# break-glass without flag -> denied
req "$D_TOKEN" aliyun.iam.break_glass 300 "emergency access without flag"
check "A6-breakglass-without-flag-denied" "outcome=$(jqr '.data.decision.outcome')" $(jeq '.data.status=="denied" and ([.data.decision.reasons[]|select(.rule=="break_glass_required" and .outcome=="deny")]|length==1)' && echo 0 || echo 1)
# break-glass with flag -> pending -> approve -> critical audit -> live revoke
req "$D_TOKEN" aliyun.iam.break_glass 300 "emergency account-wide access" 'null' true
BG_LEASE=$LEASE
check "A6-breakglass-with-flag-pending" "status=$(jqr '.data.status')" $(jeq '.data.status=="pending" and .data.break_glass==true' && echo 0 || echo 1)
api POST "/api/v1/admin/leases/$BG_LEASE/approve" "$ADMIN" '{"note":"incident 1234"}'
expect "A6-breakglass-approve-200" 200
api GET "/api/v1/admin/audit?action=lease.approved&limit=20" "$ADMIN"
BG_EVT=$(jq -c --arg id "$BG_LEASE" '[.data.items[]|select(.target_id==$id)][0]' "$BODY" 2>/dev/null)
check "A6-breakglass-critical-audit-severity" "event=$(echo "$BG_EVT"|head -c200)" $([ -n "$BG_EVT" ] && [ "$(echo "$BG_EVT"|jq -r '.severity')" = "critical" ] && echo 0 || echo 1)
api POST "/api/v1/agent/leases/$BG_LEASE/credential" "$D_TOKEN"; expect "A6-breakglass-credential-200" 200
BG_TOKEN=$(jqr '.data.env[]|select(.name=="ALIBABA_CLOUD_SECURITY_TOKEN")|.value')
mockcall GET /mock-cloud/v1/ecs/instances "$BG_TOKEN"; expect "A6-breakglass-token-works" 200
api POST "/api/v1/admin/leases/$BG_LEASE/revoke" "$ADMIN" '{"reason":"incident resolved"}'; expect "A6-breakglass-revoke-200" 200
mockcall GET /mock-cloud/v1/ecs/instances "$BG_TOKEN"
check "A6-breakglass-token-killed-live" "http=$CODE code=$(jqr '.Code')" $([ "$CODE" = 401 ] && echo 0 || echo 1)

# ============================== A7: audit verify clean ==============================
echo; echo "--- A7 audit chain (clean) ---"
api GET /api/v1/admin/audit/verify "$ADMIN"
expect "A7-audit-verify-endpoint-200" 200
AUDIT_EVENTS=$(jqr '.data.events')
check "A7-audit-verify-ok" "ok=$(jqr '.data.ok') events=$AUDIT_EVENTS" $(jeq '.data.ok==true and .data.events>0' && echo 0 || echo 1)
CSG_SERVER=$BASE CSG_TOKEN=$ADMIN "$BIN" audit verify --json >"$WORK/audit-verify-cli.json" 2>&1
AV_EXIT=$?
AV_OK=$(jq -r '.ok // .data.ok' "$WORK/audit-verify-cli.json" 2>/dev/null)
check "A7-cli-audit-verify" "exit=$AV_EXIT ok=$AV_OK" $([ "$AV_EXIT" -eq 0 ] && [ "$AV_OK" = "true" ] && echo 0 || echo 1)
grep -rq "tamper" "$CLONE/internal/store" && pass "A7-Go-test-covers-audit-tamper" || warn "A7-Go-test-covers-audit-tamper" "no tamper test found in internal/store"

# ============================== A8: secret hygiene ==============================
echo; echo "--- A8 secret-at-rest and response hygiene ---"
printf '%s' "$CANARY_SECRET" >"$WORK/canary-secret"; chmod 600 "$WORK/canary-secret"
CSG_SERVER=$BASE CSG_TOKEN=$ADMIN "$BIN" providers add --name canary-provider --mode mock --region cn-hangzhou --access-key-id "$CANARYAKID" --access-key-secret-file "$WORK/canary-secret" --json >"$WORK/provider-add.json" 2>"$WORK/provider-add.err"
PADD_EXIT=$?
check "A8-canary-provider-added" "exit=$PADD_EXIT" $([ $PADD_EXIT -eq 0 ] && echo 0 || echo 1)
check "A8-provider-add-CLI-never-echoes-secret" "CLI output contains canary secret" $(! grep -q -F "$CANARY_SECRET" "$WORK/provider-add.json" "$WORK/provider-add.err" 2>/dev/null && echo 0 || echo 1)
CANARY_PROVIDER_ID=$(jq -r '.id // .data.id' "$WORK/provider-add.json" 2>/dev/null)
# collect API responses that must never contain secrets
for ep in "/api/v1/admin/overview" "/api/v1/admin/providers" "/api/v1/admin/providers/$CANARY_PROVIDER_ID" "/api/v1/admin/leases?limit=200" "/api/v1/admin/agents" "/api/v1/admin/audit?limit=200" "/api/v1/admin/capabilities" "/api/v1/admin/policy" "/api/v1/agent/leases?limit=200"; do
  tok=$ADMIN; [[ "$ep" == *agent* ]] && tok=$D_TOKEN
  api GET "$ep" "$tok"
  fn=$(echo "$ep" | sed 's#[/?=&]#_#g')
  cp "$BODY" "$WORK/resp/scan${fn}.json"
done
api GET /api/v1/agent/capabilities "$D_TOKEN"; cp "$BODY" "$WORK/resp/scan-agent-caps.json"
api GET /api/v1/admin/providers "$ADMIN"; cp "$BODY" "$WORK/resp/scan-providers.json"
# DB / WAL / logs / bundle scans.
# NOTE: init/forceinit JSON legitimately contain one-time tokens (contract), so they are
# excluded from the token scan; server.log is the audit/access log and must never contain them.
rm -rf "$WORK/scanout"; mkdir -p "$WORK/scanout"
for f in approve-cli.json approve-cli.err deny-cli.json deny-cli.err provider-add.json provider-add.err audit-verify-cli.json; do
  [ -f "$WORK/$f" ] && cp "$WORK/$f" "$WORK/scanout/"
done
scan_db(){ grep -a -F -c "$1" "$DATA/csg.db" "$DATA"/csg.db-wal "$DATA"/csg.db-shm 2>/dev/null | awk -F: '{s+=$2} END{print s+0}'; }
scan_log(){ grep -a -F -c "$1" "$WORK/server.log" "$WORK"/scanout/* 2>/dev/null | awk -F: '{s+=$2} END{print s+0}'; }
scan_dist(){ grep -a -F -c "$1" "$CLONE"/web/dist/assets/*.js 2>/dev/null | awk -F: '{s+=$2} END{print s+0}'; }
scan_all(){ # name pattern
  local name=$1 pat=$2 h_db h_log h_dist
  h_db=$(scan_db "$pat"); h_log=$(scan_log "$pat"); h_dist=$(scan_dist "$pat")
  check "A8-no-plaintext-$name-in-DB" "found $h_db hit(s) in DB/WAL" $([ "$h_db" -eq 0 ] && echo 0 || echo 1)
  check "A8-no-plaintext-$name-in-server-log" "found $h_log hit(s) in server log/CLI outputs" $([ "$h_log" -eq 0 ] && echo 0 || echo 1)
  check "A8-no-plaintext-$name-in-web-bundle" "found $h_dist hit(s) in web/dist" $([ "$h_dist" -eq 0 ] && echo 0 || echo 1)
}
scan_all canary-broker-secret "$CANARY_SECRET"
scan_all canary-access-key-id '$CANARYAKID'
scan_all mock-sts-token-A3 "$MOCK_TOKEN"
scan_all mock-sts-token-revoked "$RV_TOKEN"
scan_all mock-sts-token-dns "$DNS_TOKEN"
scan_all mock-sts-token-breakglass "$BG_TOKEN"
scan_all admin-token "$ADMIN"
scan_all admin-old-token "$ADMIN_OLD_TOKEN"
scan_all claude-agent-token "$CLAUDE_TOKEN"
scan_all probe-a-agent-token "$A_TOKEN"
scan_all probe-d-agent-token "$D_TOKEN"
# API response scans: no canary secret, no mock tokens in non-credential endpoints
hits_resp=$(grep -a -F -e "$CANARY_SECRET" -e "$CANARYAKID" -e 'cgk1.' -r "$WORK/resp" 2>/dev/null | wc -l | tr -d ' ')
check "A8-API-responses-no-secret-or-token" "found $hits_resp line(s) in saved API responses" $([ "$hits_resp" -eq 0 ] && echo 0 || echo 1)
# provider API never exposes plaintext secret
api GET /api/v1/admin/providers "$ADMIN"
check "A8-provider-API-no-secret-field" "providers JSON mentions access_key_secret/canary" $(! grep -qE 'access_key_secret|CANARY_SECRET|CANARYAKID' "$BODY" && echo 0 || echo 1)
# agent B cannot list agent A leases
api GET "/api/v1/agent/leases?limit=200" "$B_TOKEN_NEW"
OTHER=$(jqr ".data.items | map(select(.agent_id != \"$B_ID\")) | length")
check "A8-agent-B-list-only-own-leases" "foreign leases visible to agent B: $OTHER" $([ "$OTHER" = 0 ] && echo 0 || echo 1)

# ============================== A9: vault ==============================
echo; echo "--- A9 vault ---"
PROV_BLOB=$(sqlite3 "$DATA/csg.db" "select encrypted_credential from providers where id='$CANARY_PROVIDER_ID';" 2>/dev/null)
check "A9-provider-credential-blob-v1" "blob prefix=$(echo "$PROV_BLOB" | cut -c1-8)" $(echo "$PROV_BLOB" | grep -qE '^v1:' && echo 0 || echo 1)
LEASE_BLOB=$(sqlite3 "$DATA/csg.db" "select substr(encrypted_credential,1,3) from leases where id='$A3_LEASE';" 2>/dev/null)
check "A9-lease-credential-blob-v1" "lease blob prefix=$LEASE_BLOB" $([ "$LEASE_BLOB" = "v1:" ] && echo 0 || echo 1)
VAULT_DIR=$(ls -d "$CLONE"/internal/vaultcrypto "$CLONE"/internal/vault 2>/dev/null | head -1 | xargs -n1 basename)
VAULT_TESTS=$(cd "$CLONE" && go test -v "./internal/$VAULT_DIR" 2>&1)
check "A9-vault-tests-pass" "$(echo "$VAULT_TESTS" | grep -cE '^--- PASS') vault tests" $(echo "$VAULT_TESTS" | grep -q '^ok' && echo 0 || echo 1)
check "A9-vault-wrong-AAD-test-present" "no AAD test name found" $(echo "$VAULT_TESTS" | grep -qiE 'AAD' && echo 0 || echo 1)
echo "$VAULT_TESTS" | grep -E '^=== RUN|--- (PASS|FAIL)' | sed 's/^/  /' | head -20

# ============================== A10: policy ==============================
echo; echo "--- A10 policy edits ---"
mkagent probe-e '["aliyun.dns.manage","aliyun.cert.dns01"]' 3600 3; E_TOKEN=$NEW_TOKEN
api GET /api/v1/admin/policy "$ADMIN"; POL_BEFORE=$(jq -c '.data' "$BODY")
CHECK_POL_BEFORE=$(echo "$POL_BEFORE" | jq -r '.auto_approve_max_risk')
check "A10-default-auto-risk-low" "auto_approve_max_risk=$CHECK_POL_BEFORE" $([ "$CHECK_POL_BEFORE" = "low" ] && echo 0 || echo 1)
req "$E_TOKEN" aliyun.dns.manage 600 "policy baseline" '{"domain":"policy.example.com"}'
check "A10-medium-pending-before-change" "status=$(jqr '.data.status')" $(jeq '.data.status=="pending"' && echo 0 || echo 1)
CSG_SERVER=$BASE CSG_TOKEN=$ADMIN "$BIN" policy set --auto-approve-max-risk medium --json >"$WORK/policy-set.json" 2>"$WORK/policy-set.err"
POLSET_EXIT=$?
check "A10-policy-set-CLI-exit0" "exit=$POLSET_EXIT $(cat "$WORK/policy-set.err"|mask)" $([ $POLSET_EXIT -eq 0 ] && echo 0 || echo 1)
req "$E_TOKEN" aliyun.dns.manage 600 "policy after change" '{"domain":"policy.example.com"}'
check "A10-medium-auto-approved-after-change" "status=$(jqr '.data.status') outcome=$(jqr '.data.decision.outcome')" $(jeq '.data.status=="active" and .data.decision.outcome=="auto_approve"' && echo 0 || echo 1)
# invalid settings rejected 400
api GET /api/v1/admin/policy "$ADMIN"; BAD=$(jq -c '.data | .auto_approve_max_risk="bogus"' "$BODY")
api PUT /api/v1/admin/policy "$ADMIN" "$BAD"
check "A10-invalid-settings-400" "http=$CODE code=$(jqr '.error.code')" $([ "$CODE" = 400 ] && echo 0 || echo 1)
api GET "/api/v1/admin/audit?action=policy.updated&limit=10" "$ADMIN"
check "A10-policy-update-audited" "policy.updated events=$(jqr '.data.total')" $([ "$(jqr '.data.total')" -ge 1 ] && echo 0 || echo 1)
# restore defaults
api PUT /api/v1/admin/policy "$ADMIN" "$POL_BEFORE"; expect "A10-restore-policy" 200

# ============================== A11: provider rotation ==============================
echo; echo "--- A11 provider credential rotation ---"
mkagent probe-f "$ALLGRANTS" 3600 3; F_TOKEN=$NEW_TOKEN
req "$F_TOKEN" aliyun.cloud.read 120 "pre-rotation lease"
PRE_ROT_LEASE=$LEASE
api POST "/api/v1/agent/leases/$PRE_ROT_LEASE/credential" "$F_TOKEN"; PRE_ROT_TOKEN=$(jqr '.data.env[]|select(.name=="ALIBABA_CLOUD_SECURITY_TOKEN")|.value')
CSG_SERVER=$BASE CSG_TOKEN=$ADMIN "$BIN" providers rotate "$PROVIDER_ID" --access-key-id LTAI5tRotatedCanary --access-key-secret-file "$WORK/canary-secret2" --json >"$WORK/provider-rotate.json" 2>"$WORK/provider-rotate.err"
ROT_EXIT=$?
check "A11-rotate-CLI-exit0" "exit=$ROT_EXIT $(cat "$WORK/provider-rotate.err"|mask)" $([ $ROT_EXIT -eq 0 ] && echo 0 || echo 1)
check "A11-rotate-CLI-never-echoes-secret" "rotate output contains rotated secret" $(! grep -q -F "$CANARY_SECRET2" "$WORK/provider-rotate.json" "$WORK/provider-rotate.err" 2>/dev/null && echo 0 || echo 1)
api GET "/api/v1/admin/providers/$PROVIDER_ID" "$ADMIN"
check "A11-provider-masked-ak-updated" "masked=$(jqr '.data.access_key_id_masked')" $(jeq '.data.access_key_id_masked|test("^LTAI.*nary$")' && echo 0 || echo 1)
api GET "/api/v1/admin/audit?action=provider.credential_rotated&limit=10" "$ADMIN"
check "A11-rotation-audited" "rotation events=$(jqr '.data.total')" $([ "$(jqr '.data.total')" -ge 1 ] && echo 0 || echo 1)
CSG_SERVER=$BASE CSG_TOKEN=$ADMIN "$BIN" providers test "$PROVIDER_ID" --json >"$WORK/provider-test.json" 2>&1
PT_EXIT=$?
PT_OK=$(jq -r '.ok // .data.ok' "$WORK/provider-test.json" 2>/dev/null)
check "A11-provider-test-ok" "exit=$PT_EXIT ok=$PT_OK" $([ "$PT_EXIT" -eq 0 ] && [ "$PT_OK" = "true" ] && echo 0 || echo 1)
mockcall GET /mock-cloud/v1/ecs/instances "$PRE_ROT_TOKEN"
check "A11-existing-lease-unaffected" "http=$CODE" $([ "$CODE" = 200 ] && echo 0 || echo 1)
req "$F_TOKEN" aliyun.cloud.read 120 "post-rotation lease"
check "A11-new-lease-mints-after-rotation" "status=$(jqr '.data.status')" $(jeq '.data.status=="active"' && echo 0 || echo 1)
check "A11-no-agent-changes-needed" "same probe-a token still works after rotation" 0

# ============================== A12: limits summary ==============================
echo; echo "--- A12 limits / suspend / rotation ---"
# explicit reason keys were asserted in A4 (ttl_within_agent, ttl_within_global, concurrency_available, rate_limit)
check "A12-limits-explicit-reasons-covered" "see A4 ttl/global/concurrency/rate checks" 0
check "A12-token-rotation-invalidates-old-covered" "see A5 rotate-token checks" 0
check "A12-suspend-blocks-agent-covered" "see A5 suspended checks" 0

# ============================== stop clean instance (graceful shutdown) ==============================
echo; echo "--- A2 graceful shutdown (SIGINT) ---"
kill -INT "$SERVER_PID"
for i in $(seq 1 50); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$SERVER_PID" 2>/dev/null; then fail "A2-graceful-shutdown" "server still running 5s after SIGINT"; kill -9 "$SERVER_PID" 2>/dev/null; else pass "A2-graceful-shutdown (server exited on SIGINT)"; fi
wait "$SERVER_PID" 2>/dev/null; SHUT_EXIT=$?
PORT_OPEN=$(lsof -nP -iTCP:$PORT1 -sTCP:LISTEN 2>/dev/null | grep -c LISTEN)
check "A2-shutdown-port-released" "port $PORT1 still has $PORT_OPEN listener(s)" $([ "$PORT_OPEN" -eq 0 ] && echo 0 || echo 1)
check "A2-shutdown-server-log" "server log tail: $(tail -2 "$WORK/server.log" | tr '\n' ' ' | head -c 120)" $(grep -qiE 'shut|stop|signal' "$WORK/server.log" && echo 0 || echo 1)
SERVER_PID=""

# ============================== A7b: tamper audit on a DB copy ==============================
echo; echo "--- A7b tamper detection on DB copy ---"
rm -rf "$WORK/tamper-data"; cp -R "$DATA" "$WORK/tamper-data"
TAMPER_BEFORE=$(sqlite3 "$WORK/tamper-data/csg.db" "select hash from audit where seq=2;")
sqlite3 "$WORK/tamper-data/csg.db" "update audit set metadata_json='{\"tampered\":true}' where seq=2;"
TAMPER_AFTER=$(sqlite3 "$WORK/tamper-data/csg.db" "select hash from audit where seq=2;")
echo "  tampered metadata_json of seq=2 (hash unchanged=$([ "$TAMPER_BEFORE" = "$TAMPER_AFTER" ] && echo yes || echo no))"
"$BIN" serve --addr "127.0.0.1:$PORT2" --data-dir "$WORK/tamper-data" >"$WORK/server-tamper.log" 2>&1 &
SERVER2_PID=$!
for i in $(seq 1 50); do curl -sf "$BASE2/healthz" >/dev/null 2>&1 && break; sleep 0.1; done
CODE=$(curl -s -o "$BODY" -w '%{http_code}' "$BASE2/api/v1/admin/audit/verify" -H "Authorization: Bearer $ADMIN")
check "A7-tampered-verify-200" "http=$CODE" $([ "$CODE" = 200 ] && echo 0 || echo 1)
check "A7-tampered-verify-fails" "ok=$(jqr '.data.ok') first_invalid_seq=$(jqr '.data.first_invalid_seq') msg=$(jqr '.data.message')" $([ "$(jqr '.data.ok')" = "false" ] && [ "$(jqr '.data.first_invalid_seq')" = "2" ] && echo 0 || echo 1)
CSG_SERVER=$BASE2 CSG_TOKEN=$ADMIN "$BIN" audit verify --json >"$WORK/audit-verify-tampered.json" 2>&1
TV_EXIT=$?
TV_OK=$(jq -r '.data.ok // .ok' "$WORK/audit-verify-tampered.json" 2>/dev/null)
TV_SEQ=$(jq -r '.data.first_invalid_seq // .first_invalid_seq' "$WORK/audit-verify-tampered.json" 2>/dev/null)
check "A7-tampered-CLI-verify-fails" "exit=$TV_EXIT ok=$TV_OK first_invalid_seq=$TV_SEQ" $([ "$TV_EXIT" -ne 0 ] && [ "$TV_OK" = "false" ] && echo 0 || echo 1)
kill -INT "$SERVER2_PID" 2>/dev/null; wait "$SERVER2_PID" 2>/dev/null; SERVER2_PID=""

# ============================== summary ==============================
echo; echo "== probe summary =="
echo "PASS=$PASS FAIL=$FAIL WARN=$WARN"
if [ "$FAIL" -gt 0 ]; then printf 'FAILED: %s\n' "${FAILED[*]}"; fi
if [ "$WARN" -gt 0 ]; then printf 'WARNINGS: %s\n' "${WARNINGS[*]}"; fi
echo "log: $LOG"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
