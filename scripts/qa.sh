#!/usr/bin/env bash
# Cloud Safeguard full QA run: every automated check in one command.
#
# Steps (each logged to build/qa/<run>/<step>.log):
#   gofmt      every tracked Go file is formatted
#   vet        go vet ./...
#   test       go test ./...
#   race       go test -race ./internal/...
#   web        console typecheck, unit tests and build; web/dist matches the source
#   demo       scripts/demo.sh: scenarios S1-S14 against the real binary and the mock cloud
#   smoke      a fresh csg init + serve: health, removed routes, cross-site refusal,
#              unknown commands, no secret in the server log
#   docker     (with --docker) the image builds, starts and answers /healthz
#
# Usage: ./scripts/qa.sh [--docker] [--only STEP[,STEP]] [--skip STEP[,STEP]]
# Prints one PASS/FAIL line per step and a summary in build/qa/latest/summary.txt.
# Exits 0 only when every step that ran passed. Never prints secrets.
set -u -o pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT" || exit 1

DOCKER=0
ONLY=""
SKIP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --docker) DOCKER=1; shift ;;
    --only) ONLY=",$2,"; shift 2 ;;
    --skip) SKIP=",$2,"; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "qa: unknown option $1" >&2; exit 2 ;;
  esac
done

STEPS=",gofmt,vet,test,race,web,demo,smoke,docker,"
for list in "$ONLY" "$SKIP"; do
  for name in ${list//,/ }; do
    [[ "$STEPS" == *",$name,"* ]] || { echo "qa: unknown step '$name' (steps: ${STEPS//,/ })" >&2; exit 2; }
  done
done

RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$ROOT/build/qa/$RUN_ID"
mkdir -p "$OUT"
ln -sfn "$RUN_ID" "$ROOT/build/qa/latest"
SUMMARY="$OUT/summary.txt"
{
  echo "run $RUN_ID"
  echo "commit $(git rev-parse --short HEAD)$( [ -n "$(git status --porcelain)" ] && echo ' (dirty tree)')"
  echo "branch $(git rev-parse --abbrev-ref HEAD)"
} >"$SUMMARY"

FAILED=0
RAN=0
want() {
  local step=$1
  if [ -n "$ONLY" ] && [[ "$ONLY" != *",$step,"* ]]; then return 1; fi
  if [ -n "$SKIP" ] && [[ "$SKIP" == *",$step,"* ]]; then return 1; fi
  return 0
}
run_step() {
  local step=$1; shift
  want "$step" || return 0
  local start=$SECONDS
  RAN=$((RAN + 1))
  printf '%-8s ... ' "$step"
  if "$@" >"$OUT/$step.log" 2>&1; then
    echo "PASS ($((SECONDS - start))s)"
    echo "PASS $step $((SECONDS - start))s" >>"$SUMMARY"
  else
    echo "FAIL ($((SECONDS - start))s)  log: build/qa/$RUN_ID/$step.log"
    echo "FAIL $step $((SECONDS - start))s build/qa/$RUN_ID/$step.log" >>"$SUMMARY"
    tail -25 "$OUT/$step.log" | sed 's/^/    /'
    FAILED=1
  fi
}

step_gofmt() {
  # Tracked and new (not ignored) Go files; a file gofmt cannot parse fails the
  # step through gofmt's exit status, not only through its output.
  local bad
  bad=$(git ls-files -z --cached --others --exclude-standard -- '*.go' | xargs -0 gofmt -l) || { echo "gofmt failed (a file does not parse?)"; return 1; }
  [ -z "$bad" ] || { echo "not gofmt-ed:"; echo "$bad"; return 1; }
}
step_vet() { go vet ./...; }
step_test() { go test -count=1 ./...; }
step_race() { go test -count=1 -race ./internal/...; }
dist_hash() {
  local out
  out=$(cd web/dist && find . -type f -print0 | sort -z | xargs -0 shasum -a 256) || return 1
  [ -n "$out" ] || return 1
  printf '%s' "$out" | shasum -a 256
}
step_web() {
  local before after
  before=$(dist_hash) || { echo "cannot hash web/dist"; return 1; }
  (cd web && npm ci --no-audit --no-fund && npm test && npm run build) || return 1
  after=$(dist_hash) || { echo "cannot hash web/dist after the build"; return 1; }
  # The build must not change web/dist: what is checked in (or about to be
  # committed) is exactly what the source builds to.
  if [ "$before" != "$after" ]; then
    echo "web/dist did not match the console source: run 'make web' and commit web/dist"
    git status --short -- web/dist
    return 1
  fi
}
step_demo() {
  ./scripts/demo.sh --port "$(free_port)" --data-dir "$OUT/demo-data" || return 1
}

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

SMOKE_PID=""
stop_smoke() { [ -n "$SMOKE_PID" ] && kill "$SMOKE_PID" 2>/dev/null; wait "$SMOKE_PID" 2>/dev/null; SMOKE_PID=""; }
trap 'stop_smoke; stop_docker' EXIT
trap 'exit 130' INT TERM

# expect_status DESC WANT CURL_ARGS... : the request answers with HTTP status WANT.
expect_status() {
  local desc=$1 want=$2; shift 2
  local got
  got=$(curl -s -o /dev/null -w '%{http_code}' "$@")
  if [ "$got" = "$want" ]; then echo "ok   $desc ($got)"; else echo "FAIL $desc: got $got, want $want"; return 1; fi
}

step_smoke() {
  local bin="$ROOT/build/csg" data="$OUT/smoke/data" port url rc=0
  mkdir -p "$OUT/smoke"
  go build -o "$bin" ./cmd/csg || return 1
  "$bin" init --demo --json --data-dir "$data" >"$OUT/smoke/init.json" 2>&1 || { echo "csg init failed"; return 1; }
  port=$(free_port)
  url="http://127.0.0.1:$port"
  "$bin" serve --data-dir "$data" --addr "127.0.0.1:$port" >"$OUT/smoke/server.log" 2>&1 &
  SMOKE_PID=$!
  for _ in $(seq 1 40); do curl -sf "$url/healthz" >/dev/null 2>&1 && break; sleep 0.25; done
  expect_status "healthz" 200 "$url/healthz" || return 1

  # Console is served.
  expect_status "console index" 200 "$url/" || rc=1
  # Removed v0.1 routes answer 404 (CONTRACT §17.8).
  expect_status "removed GET /api/v1/admin/agents" 404 "$url/api/v1/admin/agents" || rc=1
  # Under /api/v1/agent/ the token is checked before routing, so without one every path,
  # removed or not, is 401 and reveals nothing; the 404 with a valid token is in the Go tests.
  expect_status "removed POST /api/v1/agent/leases, no token" 401 -X POST -H 'Content-Type: application/json' -d '{}' "$url/api/v1/agent/leases" || rc=1
  expect_status "removed GET /api/v1/agent/capabilities, no token" 401 "$url/api/v1/agent/capabilities" || rc=1
  # No session, no access.
  expect_status "supervisor API without a session" 401 "$url/api/v1/supervisor/people" || rc=1
  expect_status "me API without a session" 401 "$url/api/v1/me/agents" || rc=1
  # Cross-site and wrong content type are refused before anything else.
  expect_status "cross-site agent sign-in start" 403 -X POST -H 'Origin: https://evil.example' -H 'Content-Type: application/json' -d '{"agent_name":"x"}' "$url/api/v1/agent-signin/start" || rc=1
  expect_status "login without JSON content type" 415 -X POST -d 'username=a' "$url/api/v1/auth/login" || rc=1
  expect_status "login with wrong credentials" 401 -X POST -H 'Content-Type: application/json' -d '{"username":"nobody","password":"wrong-password-123","totp":"000000"}' "$url/api/v1/auth/login" || rc=1
  # Agent API needs a token.
  expect_status "agent API without a token" 401 "$url/api/v1/agent/me" || rc=1

  # Removed commands are unknown; help works.
  local c
  local out code
  for c in providers agents caps policy audit request; do
    out=$("$bin" "$c" 2>&1); code=$?
    if [ $code -eq 2 ] && [[ "$out" == *"unknown command"* ]]; then echo "ok   removed command '$c' is unknown"
    else echo "FAIL removed command '$c': exit $code, not an unknown command"; rc=1; fi
  done
  "$bin" help >/dev/null 2>&1 || { echo "FAIL csg help"; rc=1; }

  # The setup code and the master key never reach the server log.
  local code
  code=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["data"]["supervisor"]["setup_code"])' "$OUT/smoke/init.json" 2>/dev/null)
  if [ ! -s "$OUT/smoke/server.log" ]; then echo "FAIL the server log is missing or empty"; rc=1
  elif [ -z "$code" ]; then echo "FAIL could not read the setup code from csg init --json"; rc=1
  elif grep -qF "$code" "$OUT/smoke/server.log"; then echo "FAIL setup code found in the server log"; rc=1
  else echo "ok   no setup code in the server log"; fi
  if [ ! -s "$data/master.key" ]; then echo "FAIL csg init wrote no master.key"; rc=1
  elif grep -qF "$(head -c 32 "$data/master.key")" "$OUT/smoke/server.log"; then echo "FAIL master key found in the server log"; rc=1
  else echo "ok   no master key in the server log"; fi
  rm -f "$OUT/smoke/init.json"
  stop_smoke
  return $rc
}

DOCKER_NAME=""
stop_docker() { [ -n "$DOCKER_NAME" ] && docker rm -f "$DOCKER_NAME" >/dev/null 2>&1; DOCKER_NAME=""; }
step_docker() {
  docker build -t cloud-safeguard:qa . || return 1
  DOCKER_NAME="csg-qa-$RUN_ID-$$"
  local port; port=$(free_port)
  docker run -d --rm --name "$DOCKER_NAME" -p "127.0.0.1:$port:8787" cloud-safeguard:qa || return 1
  local ok=1
  for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$port/healthz" && { ok=0; break; }; sleep 1; done
  if [ $ok -ne 0 ]; then
    # The first start prints the supervisor's setup code: show the log with
    # that line (and anything that looks like a code or key) removed.
    docker logs "$DOCKER_NAME" 2>&1 | grep -viE 'setup code|secret|token|password|key' | tail -40
  fi
  stop_docker
  return $ok
}

echo "Cloud Safeguard QA run $RUN_ID ($(git rev-parse --short HEAD))"
run_step gofmt step_gofmt
run_step vet step_vet
run_step test step_test
run_step race step_race
run_step web step_web
run_step demo step_demo
run_step smoke step_smoke
if [ $DOCKER -eq 1 ]; then run_step docker step_docker; fi

if [ $RAN -eq 0 ]; then echo "qa: no step ran" | tee -a "$SUMMARY"; exit 2; fi
if [ $FAILED -eq 0 ]; then echo "ALL PASS" | tee -a "$SUMMARY"; else echo "QA FAILED" | tee -a "$SUMMARY"; fi
exit $FAILED
