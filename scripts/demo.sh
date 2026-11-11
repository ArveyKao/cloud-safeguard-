#!/usr/bin/env bash
# Cloud Safeguard end-to-end demo (docs/SPEC.md §6.2, scenarios S1-S9).
#
# What it does:
#   1. builds bin/csg from the current tree
#   2. creates a clean throwaway data directory and bootstraps it with
#      `csg init --demo --json` (mock provider + demo agents)
#   3. starts `csg serve` on the requested loopback port in the background
#   4. runs scenarios S1-S9 through the real CLI and mock cloud
#   5. prints PASS/FAIL lines, stops the server via a cleanup trap, and exits
#      non-zero if any scenario failed
#
# Usage: ./scripts/demo.sh [--port 18787] [--data-dir .demo/data]
#
# The demo runs entirely in mock mode: no real cloud account or credentials are
# used. Mock tokens are short-lived demo artifacts and are never echoed.
set -u -o pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT" || exit 1

BIN="$ROOT/bin/csg"
PORT=18787
DATA_DIR=""
PASS=0
FAIL=0
FAILED_SCENARIOS=""
SERVER_PID=""
SERVER_URL=""
TMP=""
INIT_JSON=""
ADMIN_TOKEN=""
CLAUDE_TOKEN=""
HERMES_TOKEN=""
HERMES_ID=""
S1_LEASE=""
S1_TOKEN=""
DNS_LEASE=""
BG_LEASE=""

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

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
# json_get JSON DOTTED.PATH -> prints the value (objects as compact JSON)
json_get() {
  printf '%s' "$1" | node -e '
    let s = "";
    process.stdin.on("data", (d) => (s += d)).on("end", () => {
      let value;
      try { value = JSON.parse(s); } catch { process.exit(2); }
      for (const key of process.argv[1].split(".")) {
        if (value === null || value === undefined) process.exit(1);
        value = value[key];
      }
      if (value === null || value === undefined) process.exit(1);
      process.stdout.write(typeof value === "object" ? JSON.stringify(value) : String(value));
    });' "$2"
}

# json_env_value ENVELOPE NAME -> prints the credential env var value
json_env_value() {
  printf '%s' "$1" | node -e '
    let s = "";
    process.stdin.on("data", (d) => (s += d)).on("end", () => {
      const env = (JSON.parse(s).env) || [];
      const found = env.find((item) => item.name === process.argv[1]);
      if (!found) process.exit(1);
      process.stdout.write(found.value);
    });' "$2"
}

# json_deny_rules LEASE -> comma-separated deny rule names
json_deny_rules() {
  printf '%s' "$1" | node -e '
    let s = "";
    process.stdin.on("data", (d) => (s += d)).on("end", () => {
      const lease = JSON.parse(s);
      const reasons = (lease.decision && lease.decision.reasons) || [];
      process.stdout.write(reasons.filter((r) => r.outcome === "deny").map((r) => r.rule).join(","));
    });'
}

# json_has_events AUDIT_LIST LEASE_ID ACTION... -> "true"/"false"
json_has_events() {
  local json=$1 lease=$2
  shift 2
  printf '%s' "$json" | node -e '
    let s = "";
    process.stdin.on("data", (d) => (s += d)).on("end", () => {
      const items = (JSON.parse(s).items) || [];
      const lease = process.argv[1];
      const want = process.argv.slice(2);
      const found = new Set();
      for (const event of items) {
        if (event.target_id === lease && want.includes(event.action)) found.add(event.action);
      }
      process.stdout.write(found.size === want.length ? "true" : "false");
    });' "$lease" "$@"
}

# json_has_critical_for_lease AUDIT_LIST LEASE_ID -> "true"/"false"
json_has_critical_for_lease() {
  local json=$1 lease=$2
  printf '%s' "$json" | node -e '
    let s = "";
    process.stdin.on("data", (d) => (s += d)).on("end", () => {
      const items = (JSON.parse(s).items) || [];
      const lease = process.argv[1];
      const hit = items.some((event) => event.target_id === lease && event.severity === "critical");
      process.stdout.write(hit ? "true" : "false");
    });' "$lease"
}

# run_agent TOKEN OUT ERR ARGS... -> runs csg as the agent
run_agent() {
  local token=$1 out=$2 err=$3
  shift 3
  CSG_SERVER="$SERVER_URL" CSG_TOKEN="$token" "$BIN" "$@" >"$out" 2>"$err"
}

# run_admin OUT ERR ARGS... -> runs csg as the admin
run_admin() {
  local out=$1 err=$2
  shift 2
  CSG_SERVER="$SERVER_URL" CSG_TOKEN="$ADMIN_TOKEN" "$BIN" "$@" >"$out" 2>"$err"
}

# run_mock MOCK_TOKEN OUT ERR ARGS... -> calls the mock cloud (no CLI token)
run_mock() {
  local token=$1 out=$2 err=$3
  shift 3
  CSG_SERVER="$SERVER_URL" ALIBABA_CLOUD_SECURITY_TOKEN="$token" "$BIN" mock request "$@" >"$out" 2>"$err"
}

# fail_detail prints the captured stderr (and stdout) of a failed CLI call.
fail_detail() {
  local what=$1 out=$2 err=$3
  echo "$what failed" >&2
  [ -s "$err" ] && sed 's/^/  stderr: /' "$err" >&2
  [ -s "$out" ] && sed 's/^/  stdout: /' "$out" | head -5 >&2
  return 1
}

# ---------------------------------------------------------------------------
# scenarios S1-S9
# ---------------------------------------------------------------------------
scenario_s1() {
  local rc lease status outcome token token_env
  run_agent "$CLAUDE_TOKEN" "$TMP/s1.json" "$TMP/s1.err" \
    request --capability aliyun.cloud.read --reason "demo S1: read cloud inventory" --ttl 10m --json
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S1 request" "$TMP/s1.json" "$TMP/s1.err"

  S1_LEASE=$(json_get "$(cat "$TMP/s1.json")" id) || { echo "S1: no lease id in response" >&2; return 1; }
  status=$(json_get "$(cat "$TMP/s1.json")" status) || return 1
  outcome=$(json_get "$(cat "$TMP/s1.json")" decision.outcome) || return 1
  [ "$status" = "active" ] || { echo "S1: lease status=$status, want active" >&2; return 1; }
  [ "$outcome" = "auto_approve" ] || { echo "S1: decision=$outcome, want auto_approve" >&2; return 1; }

  run_agent "$CLAUDE_TOKEN" "$TMP/s1cred.json" "$TMP/s1cred.err" credential --lease "$S1_LEASE" --json
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S1 credential fetch" "$TMP/s1cred.json" "$TMP/s1cred.err"
  token=$(json_get "$(cat "$TMP/s1cred.json")" credential.security_token) || { echo "S1: credential has no security token" >&2; return 1; }
  token_env=$(json_env_value "$(cat "$TMP/s1cred.json")" ALIBABA_CLOUD_SECURITY_TOKEN) || { echo "S1: envelope missing ALIBABA_CLOUD_SECURITY_TOKEN" >&2; return 1; }
  [ "$token_env" = "$token" ] || { echo "S1: envelope env token does not match credential" >&2; return 1; }

  run_mock "$token" "$TMP/s1ecs.json" "$TMP/s1ecs.err" GET /v1/ecs/instances
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S1 mock ECS list" "$TMP/s1ecs.json" "$TMP/s1ecs.err"
  grep -q '"InstanceId":"i-2ze0demo001"' "$TMP/s1ecs.json" || { echo "S1: ECS list missing fixture instance i-2ze0demo001" >&2; return 1; }

  S1_TOKEN=$token
  echo "auto-approved lease $S1_LEASE; credential env + mock ECS list OK"
}

scenario_s2() {
  local rc
  [ -n "$S1_TOKEN" ] || { echo "S2: S1 did not produce a credential token" >&2; return 1; }
  run_mock "$S1_TOKEN" "$TMP/s2.json" "$TMP/s2.err" POST /v1/ecs/instances/i-2ze0demo001/restart
  rc=$?
  [ $rc -ne 0 ] || { echo "S2: write action was allowed with a read-only credential" >&2; return 1; }
  grep -q 'Forbidden.RAM' "$TMP/s2.json" || {
    echo "S2: expected Forbidden.RAM from mock cloud, got: $(head -c 200 "$TMP/s2.json")" >&2
    return 1
  }
  echo "least privilege holds: ecs:RebootInstance denied (403 Forbidden.RAM)"
}

scenario_s3() {
  local rc status outcome
  run_agent "$CLAUDE_TOKEN" "$TMP/s3.json" "$TMP/s3.err" \
    request --capability aliyun.dns.manage --param domain=arveykao.com --ttl 10m \
    --reason "demo S3: manage DNS for arveykao.com" --json
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S3 request" "$TMP/s3.json" "$TMP/s3.err"

  DNS_LEASE=$(json_get "$(cat "$TMP/s3.json")" id) || { echo "S3: no lease id" >&2; return 1; }
  status=$(json_get "$(cat "$TMP/s3.json")" status) || return 1
  outcome=$(json_get "$(cat "$TMP/s3.json")" decision.outcome) || return 1
  [ "$status" = "pending" ] || { echo "S3: lease status=$status, want pending" >&2; return 1; }
  [ "$outcome" = "require_approval" ] || { echo "S3: decision=$outcome, want require_approval" >&2; return 1; }

  run_agent "$CLAUDE_TOKEN" "$TMP/s3cred.json" "$TMP/s3cred.err" credential --lease "$DNS_LEASE"
  rc=$?
  [ $rc -ne 0 ] || { echo "S3: pending lease unexpectedly issued a credential" >&2; return 1; }
  grep -Eqi 'pending|not active|lease_not_active|credential_unavailable' "$TMP/s3cred.err" || {
    echo "S3: unexpected credential error: $(cat "$TMP/s3cred.err")" >&2
    return 1
  }
  echo "medium-risk DNS lease $DNS_LEASE parked for approval; no credential while pending"
}

scenario_s4() {
  local rc status token record_resp
  run_admin "$TMP/s4approve.json" "$TMP/s4approve.err" \
    leases approve "$DNS_LEASE" --note "demo S4: approved DNS change" --json
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S4 approve" "$TMP/s4approve.json" "$TMP/s4approve.err"
  status=$(json_get "$(cat "$TMP/s4approve.json")" status) || return 1
  [ "$status" = "active" ] || { echo "S4: approved lease status=$status, want active" >&2; return 1; }

  run_agent "$CLAUDE_TOKEN" "$TMP/s4cred.env" "$TMP/s4cred.err" credential --lease "$DNS_LEASE" --export
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S4 credential fetch" "$TMP/s4cred.env" "$TMP/s4cred.err"
  token=$(sed -n "s/^export ALIBABA_CLOUD_SECURITY_TOKEN='\(.*\)'$/\1/p" "$TMP/s4cred.env")
  [ -n "$token" ] || { echo "S4: credential export has no ALIBABA_CLOUD_SECURITY_TOKEN" >&2; return 1; }

  run_mock "$token" "$TMP/s4record.json" "$TMP/s4record.err" POST /v1/dns/zones/arveykao.com/records \
    '{"name":"demo-s4","type":"TXT","value":"cloud-safeguard-demo","ttl":600}'
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S4 DNS record create" "$TMP/s4record.json" "$TMP/s4record.err"
  grep -q '"RR":"demo-s4"' "$TMP/s4record.json" || { echo "S4: created record missing from response" >&2; return 1; }

  run_mock "$token" "$TMP/s4ecs.json" "$TMP/s4ecs.err" POST /v1/ecs/instances/i-2ze0demo001/restart
  rc=$?
  [ $rc -ne 0 ] || { echo "S4: ECS restart was allowed with a DNS-scoped credential" >&2; return 1; }
  grep -q 'Forbidden.RAM' "$TMP/s4ecs.json" || { echo "S4: expected Forbidden.RAM for ECS restart" >&2; return 1; }

  echo "operator approved $DNS_LEASE; DNS record created; ECS restart still denied"
}

scenario_s5() {
  local rc status audit_json
  run_agent "$CLAUDE_TOKEN" "$TMP/s5.json" "$TMP/s5.err" \
    request --capability aliyun.dns.manage --param domain=arveykao.com \
    --reason "demo S5: second DNS change" --json
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S5 request" "$TMP/s5.json" "$TMP/s5.err"
  local lease
  lease=$(json_get "$(cat "$TMP/s5.json")" id) || { echo "S5: no lease id" >&2; return 1; }

  run_admin "$TMP/s5deny.json" "$TMP/s5deny.err" leases deny "$lease" --reason "demo S5: denied by operator" --json
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S5 deny" "$TMP/s5deny.json" "$TMP/s5deny.err"
  status=$(json_get "$(cat "$TMP/s5deny.json")" status) || return 1
  [ "$status" = "denied" ] || { echo "S5: denied lease status=$status, want denied" >&2; return 1; }

  run_agent "$CLAUDE_TOKEN" "$TMP/s5cred.json" "$TMP/s5cred.err" credential --lease "$lease"
  rc=$?
  [ $rc -ne 0 ] || { echo "S5: denied lease unexpectedly issued a credential" >&2; return 1; }

  run_admin "$TMP/s5audit.json" "$TMP/s5audit.err" audit list --limit 100 --json
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S5 audit list" "$TMP/s5audit.json" "$TMP/s5audit.err"
  audit_json=$(cat "$TMP/s5audit.json")
  local has_events
  has_events=$(json_has_events "$audit_json" "$lease" lease.requested lease.denied) || has_events="error"
  [ "$has_events" = "true" ] || { echo "S5: audit is missing lease.requested/lease.denied for $lease" >&2; return 1; }

  echo "operator denied $lease; credential fetch blocked; denial audited"
}

scenario_s6() {
  local rc status rules
  run_agent "$HERMES_TOKEN" "$TMP/s6.json" "$TMP/s6.err" \
    request --capability aliyun.ecs.instance.ops --param instance_id=i-2ze0demo001 \
    --reason "demo S6: out-of-scope request" --json
  rc=$?
  [ $rc -eq 1 ] || { echo "S6: denied request exit code=$rc, want 1" >&2; fail_detail "S6 request" "$TMP/s6.json" "$TMP/s6.err"; }
  status=$(json_get "$(cat "$TMP/s6.json")" status) || return 1
  [ "$status" = "denied" ] || { echo "S6: lease status=$status, want denied" >&2; return 1; }
  rules=$(json_deny_rules "$(cat "$TMP/s6.json")") || return 1
  case ",$rules," in
    *,capability_granted,*) : ;;
    *) echo "S6: deny rules=$rules, want capability_granted" >&2; return 1 ;;
  esac

  local lease
  lease=$(json_get "$(cat "$TMP/s6.json")" id) || { echo "S6: no lease id" >&2; return 1; }
  run_agent "$HERMES_TOKEN" "$TMP/s6cred.json" "$TMP/s6cred.err" credential --lease "$lease"
  rc=$?
  [ $rc -ne 0 ] || { echo "S6: denied lease unexpectedly issued a credential" >&2; return 1; }

  echo "hermes-researcher denied immediately (rule $rules); no credential possible"
}

scenario_s7() {
  local rc status rules audit_json critical bg_token
  # 7a: break-glass request without the explicit break_glass flag is denied.
  run_agent "$CLAUDE_TOKEN" "$TMP/s7a.json" "$TMP/s7a.err" \
    request --capability aliyun.account.admin --reason "demo S7: emergency access" --json
  rc=$?
  [ $rc -eq 1 ] || { echo "S7a: denied request exit code=$rc, want 1" >&2; fail_detail "S7a request" "$TMP/s7a.json" "$TMP/s7a.err"; }
  status=$(json_get "$(cat "$TMP/s7a.json")" status) || return 1
  rules=$(json_deny_rules "$(cat "$TMP/s7a.json")") || return 1
  [ "$status" = "denied" ] || { echo "S7a: status=$status, want denied" >&2; return 1; }
  case ",$rules," in
    *,break_glass_required,*) : ;;
    *) echo "S7a: deny rules=$rules, want break_glass_required" >&2; return 1 ;;
  esac

  # 7b: with --break-glass the lease requires human approval.
  run_agent "$CLAUDE_TOKEN" "$TMP/s7b.json" "$TMP/s7b.err" \
    request --capability aliyun.account.admin --break-glass --reason "demo S7: emergency access" --json
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S7b request" "$TMP/s7b.json" "$TMP/s7b.err"
  BG_LEASE=$(json_get "$(cat "$TMP/s7b.json")" id) || { echo "S7b: no lease id" >&2; return 1; }
  status=$(json_get "$(cat "$TMP/s7b.json")" status) || return 1
  [ "$status" = "pending" ] || { echo "S7b: status=$status, want pending" >&2; return 1; }

  run_admin "$TMP/s7approve.json" "$TMP/s7approve.err" leases approve "$BG_LEASE" --note "demo S7: break-glass drill" --json
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S7 approve" "$TMP/s7approve.json" "$TMP/s7approve.err"
  status=$(json_get "$(cat "$TMP/s7approve.json")" status) || return 1
  [ "$status" = "active" ] || { echo "S7: approved break-glass lease status=$status, want active" >&2; return 1; }

  # Approval of break-glass must be audited at critical severity.
  run_admin "$TMP/s7audit.json" "$TMP/s7audit.err" audit list --limit 100 --json
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S7 audit list" "$TMP/s7audit.json" "$TMP/s7audit.err"
  audit_json=$(cat "$TMP/s7audit.json")
  critical=$(json_has_critical_for_lease "$audit_json" "$BG_LEASE") || critical="error"
  [ "$critical" = "true" ] || { echo "S7: break-glass approval not audited at critical severity" >&2; return 1; }

  run_agent "$CLAUDE_TOKEN" "$TMP/s7cred.env" "$TMP/s7cred.err" credential --lease "$BG_LEASE" --export
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S7 credential fetch" "$TMP/s7cred.env" "$TMP/s7cred.err"
  bg_token=$(sed -n "s/^export ALIBABA_CLOUD_SECURITY_TOKEN='\(.*\)'$/\1/p" "$TMP/s7cred.env")
  [ -n "$bg_token" ] || { echo "S7: no break-glass security token" >&2; return 1; }

  run_mock "$bg_token" "$TMP/s7ecs.json" "$TMP/s7ecs.err" GET /v1/ecs/instances
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S7 mock cloud before revoke" "$TMP/s7ecs.json" "$TMP/s7ecs.err"

  # Revocation must kill the already-issued token immediately (mock cloud
  # re-checks lease state on every call).
  run_admin "$TMP/s7revoke.json" "$TMP/s7revoke.err" leases revoke "$BG_LEASE" --reason "demo S7: drill complete" --json
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S7 revoke" "$TMP/s7revoke.json" "$TMP/s7revoke.err"

  run_mock "$bg_token" "$TMP/s7after.json" "$TMP/s7after.err" GET /v1/ecs/instances
  rc=$?
  [ $rc -ne 0 ] || { echo "S7: revoked break-glass token still worked" >&2; return 1; }
  grep -q 'InvalidSecurityToken.Revoked' "$TMP/s7after.json" || {
    echo "S7: expected InvalidSecurityToken.Revoked, got: $(head -c 200 "$TMP/s7after.json")" >&2
    return 1
  }

  echo "break-glass gated (rule $rules), critical audit, approval works, revoke kills token live"
}

scenario_s8() {
  local rc ok events
  run_admin "$TMP/s8.json" "$TMP/s8.err" audit verify --json
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S8 audit verify" "$TMP/s8.json" "$TMP/s8.err"
  ok=$(json_get "$(cat "$TMP/s8.json")" ok) || return 1
  events=$(json_get "$(cat "$TMP/s8.json")" events) || return 1
  [ "$ok" = "true" ] || { echo "S8: audit chain ok=$ok, want true" >&2; return 1; }
  [ "$events" -gt 0 ] 2>/dev/null || { echo "S8: audit event count=$events, want > 0" >&2; return 1; }
  echo "audit chain verified: $events events, ok=true"
}

# S9 (CONTRACT §16.7): guest write denied by role_permits; administrator with
# an aliyun.account.admin lease is blocked on GET /v1/ram/users; a custom
# capability whose template allows ram:* is rejected with 400.
scenario_s9() {
  local rc status rules lease bg_token http_code body

  # 9a: guest requesting a write capability is denied by role_permits.
  run_agent "$HERMES_TOKEN" "$TMP/s9a.json" "$TMP/s9a.err" \
    request --capability aliyun.dns.manage --param domain=arveykao.com \
    --reason "demo S9: guest write attempt" --json
  rc=$?
  [ $rc -eq 1 ] || { echo "S9a: denied request exit code=$rc, want 1" >&2; fail_detail "S9a request" "$TMP/s9a.json" "$TMP/s9a.err"; }
  status=$(json_get "$(cat "$TMP/s9a.json")" status) || return 1
  [ "$status" = "denied" ] || { echo "S9a: lease status=$status, want denied" >&2; return 1; }
  rules=$(json_deny_rules "$(cat "$TMP/s9a.json")") || return 1
  case ",$rules," in
    *,role_permits,*) : ;;
    *) echo "S9a: deny rules=$rules, want role_permits" >&2; return 1 ;;
  esac

  # 9b: administrator holding aliyun.account.admin still cannot list RAM users.
  run_agent "$CLAUDE_TOKEN" "$TMP/s9b.json" "$TMP/s9b.err" \
    request --capability aliyun.account.admin --break-glass \
    --reason "demo S9: account-admin for IAM denial" --json
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S9b request" "$TMP/s9b.json" "$TMP/s9b.err"
  lease=$(json_get "$(cat "$TMP/s9b.json")" id) || { echo "S9b: no lease id" >&2; return 1; }
  status=$(json_get "$(cat "$TMP/s9b.json")" status) || return 1
  [ "$status" = "pending" ] || { echo "S9b: status=$status, want pending" >&2; return 1; }

  run_admin "$TMP/s9bapprove.json" "$TMP/s9bapprove.err" \
    leases approve "$lease" --note "demo S9: show IAM prohibition" --json
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S9b approve" "$TMP/s9bapprove.json" "$TMP/s9bapprove.err"

  run_agent "$CLAUDE_TOKEN" "$TMP/s9bcred.env" "$TMP/s9bcred.err" credential --lease "$lease" --export
  rc=$?
  [ $rc -eq 0 ] || fail_detail "S9b credential fetch" "$TMP/s9bcred.env" "$TMP/s9bcred.err"
  bg_token=$(sed -n "s/^export ALIBABA_CLOUD_SECURITY_TOKEN='\(.*\)'$/\1/p" "$TMP/s9bcred.env")
  [ -n "$bg_token" ] || { echo "S9b: no account-admin security token" >&2; return 1; }

  run_mock "$bg_token" "$TMP/s9bram.json" "$TMP/s9bram.err" GET /v1/ram/users
  rc=$?
  [ $rc -ne 0 ] || { echo "S9b: account-admin token listed RAM users" >&2; return 1; }
  grep -q 'Forbidden.RAM' "$TMP/s9bram.json" || {
    echo "S9b: expected Forbidden.RAM, got: $(head -c 200 "$TMP/s9bram.json")" >&2
    return 1
  }

  # 9c: creating a custom capability that allows ram:* returns 400.
  http_code=$(curl -sS -o "$TMP/s9c.json" -w '%{http_code}' \
    -X POST "$SERVER_URL/api/v1/admin/capabilities" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"demo-ram","provider_type":"aliyun","risk":"high","access":"admin","policy_template":"{\"Version\":\"1\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"ram:*\"],\"Resource\":[\"*\"]}]}","default_ttl_seconds":300,"max_ttl_seconds":600}') || {
    echo "S9c: curl failed" >&2
    return 1
  }
  [ "$http_code" = "400" ] || {
    echo "S9c: create ram:* capability HTTP $http_code, want 400; body: $(head -c 200 "$TMP/s9c.json")" >&2
    return 1
  }
  body=$(cat "$TMP/s9c.json")
  case "$body" in
    *invalid_request*) : ;;
    *) echo "S9c: body missing invalid_request: $body" >&2; return 1 ;;
  esac
  case "$body" in
    *ram:*) : ;;
    *) echo "S9c: body does not name ram:*: $body" >&2; return 1 ;;
  esac

  echo "guest write denied (role_permits); account-admin blocked on RAM; ram:* create rejected 400"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
# run_scenario NAME FUNCTION runs a scenario in the current shell (so scenarios
# can share captured lease IDs/tokens) while capturing its output in files.
run_scenario() {
  local name=$1 fn=$2 rc
  "$fn" >"$TMP/scenario.out" 2>"$TMP/scenario.err"
  rc=$?
  if [ $rc -eq 0 ]; then
    PASS=$((PASS + 1))
    echo "PASS $name"
    [ -s "$TMP/scenario.out" ] && sed 's/^/       /' "$TMP/scenario.out"
  else
    FAIL=$((FAIL + 1))
    FAILED_SCENARIOS="$FAILED_SCENARIOS $name"
    echo "FAIL $name"
    [ -s "$TMP/scenario.out" ] && sed 's/^/       /' "$TMP/scenario.out"
    [ -s "$TMP/scenario.err" ] && sed 's/^/       /' "$TMP/scenario.err"
  fi
}

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
echo "built $BIN"
echo

# The demo always starts from a clean, throwaway data directory.
if [ -e "$DATA_DIR" ]; then
  if [ "$DATA_DIR" = "/" ] || [ "$DATA_DIR" = "$ROOT" ]; then
    echo "demo: refusing to remove unsafe data dir: $DATA_DIR" >&2
    exit 2
  fi
  echo "removing existing data dir: $DATA_DIR"
  rm -rf "$DATA_DIR"
fi
mkdir -p "$(dirname "$DATA_DIR")" || { echo "demo: cannot create parent of $DATA_DIR" >&2; exit 1; }

echo "== bootstrap =="
if ! INIT_JSON=$("$BIN" init --demo --data-dir "$DATA_DIR" --json); then
  echo "demo: csg init failed" >&2
  exit 1
fi
ADMIN_TOKEN=$(json_get "$INIT_JSON" data.admin_token) || { echo "demo: init output has no admin token" >&2; exit 1; }
CLAUDE_TOKEN=$(printf '%s' "$INIT_JSON" | node -e '
  let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
    const agent = JSON.parse(s).data.agents.find((a) => a.name === "claude-code");
    if (!agent) process.exit(1);
    process.stdout.write(agent.token);
  });') || { echo "demo: init output has no claude-code token" >&2; exit 1; }
HERMES_TOKEN=$(printf '%s' "$INIT_JSON" | node -e '
  let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
    const agent = JSON.parse(s).data.agents.find((a) => a.name === "hermes-researcher");
    if (!agent) process.exit(1);
    process.stdout.write(agent.token);
  });') || { echo "demo: init output has no hermes-researcher token" >&2; exit 1; }
echo "initialized demo data dir (admin + 2 agent tokens captured, not printed)"
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
run_scenario "S1 auto-approve read capability" scenario_s1
run_scenario "S2 least privilege blocks write" scenario_s2
run_scenario "S3 risky lease requires approval" scenario_s3
run_scenario "S4 approval unlocks scoped work" scenario_s4
run_scenario "S5 operator denial is durable + audited" scenario_s5
run_scenario "S6 ungranted capability denied" scenario_s6
run_scenario "S7 break-glass approval + live revoke" scenario_s7
run_scenario "S8 audit chain verify" scenario_s8
run_scenario "S9 roles and IAM prohibition" scenario_s9
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
echo "demo summary: $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
  echo "failed scenarios:$FAILED_SCENARIOS" >&2
  exit 1
fi
echo "all S1-S9 scenarios passed"
exit 0
