#!/usr/bin/env bash
set -euo pipefail

export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

ROOT="${AGY_BG_ROOT:-/Users/maygo/Projects/agy-acp-gateway}"
ACTIVE_FILE="${AGY_BG_ACTIVE_FILE:-$ROOT/runtime/active-slot}"
PROXY_ADMIN="${AGY_BG_PROXY_ADMIN:-http://127.0.0.1:18959}"
DRAIN_SEC="${AGY_DRAIN_TIMEOUT_SEC:-120}"

BLUE_DIR="${AGY_BG_BLUE_DIR:-/Users/maygo/Projects/agy-acp-gateway-blue}"
BLUE_API_PORT="${AGY_BG_BLUE_API_PORT:-18950}"
BLUE_DASH_PORT="${AGY_BG_BLUE_DASH_PORT:-18951}"

GREEN_DIR="${AGY_BG_GREEN_DIR:-/Users/maygo/Projects/agy-acp-gateway-green}"
GREEN_API_PORT="${AGY_BG_GREEN_API_PORT:-18960}"
GREEN_DASH_PORT="${AGY_BG_GREEN_DASH_PORT:-18961}"

FRONT_API_PORT="${AGY_BG_API_PORT:-18890}"
FRONT_DASH_PORT="${AGY_BG_DASH_PORT:-18891}"
FRONT_AUTO_PORT="${AGY_BG_AUTO_DASH_PORT:-18892}"

slot_dir() {
  case "$1" in
    blue) printf "%s\n" "$BLUE_DIR" ;;
    green) printf "%s\n" "$GREEN_DIR" ;;
    *) echo "Invalid slot: $1 (expected blue or green)" >&2; return 2 ;;
  esac
}

slot_api_port() {
  case "$1" in
    blue) printf "%s\n" "$BLUE_API_PORT" ;;
    green) printf "%s\n" "$GREEN_API_PORT" ;;
    *) return 2 ;;
  esac
}

slot_dash_port() {
  case "$1" in
    blue) printf "%s\n" "$BLUE_DASH_PORT" ;;
    green) printf "%s\n" "$GREEN_DASH_PORT" ;;
    *) return 2 ;;
  esac
}

opposite_slot() {
  case "$1" in
    blue) printf "green\n" ;;
    green) printf "blue\n" ;;
    *) return 2 ;;
  esac
}

port_listening() {
  lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

current_active_slot() {
  if [[ -f "$ACTIVE_FILE" ]]; then
    local s
    s="$(tr -d "[:space:]" < "$ACTIVE_FILE" 2>/dev/null || true)"
    if [[ "$s" == "blue" || "$s" == "green" ]]; then
      printf "%s\n" "$s"
      return 0
    fi
  fi
  return 1
}

slot_env_run() {
  local slot="$1"
  shift
  local sdir api dash run_dir log_dir
  sdir="$(slot_dir "$slot")"
  api="$(slot_api_port "$slot")"
  dash="$(slot_dash_port "$slot")"
  run_dir="$ROOT/runtime/slots/$slot"
  log_dir="$ROOT/logs/slots/$slot"
  mkdir -p "$run_dir" "$log_dir"
  env \
    AGY_ENV_FILE="$ROOT/.env" \
    AGY_LISTEN_HOST=127.0.0.1 \
    AGY_GW_PORT="$api" \
    AGY_DASH_PORT="$dash" \
    AGY_RUN_DIR="$run_dir" \
    AGY_LOG_DIR="$log_dir" \
    AGY_GATEWAY_BIN="$sdir/bin/agy-acp-gateway" \
    AGY_STATE_DB="$ROOT/runtime/gateway.db" \
    AGY_ACCOUNTS_FILE="$ROOT/runtime/accounts.json" \
    AGY_PURE_API_HOME="$ROOT/runtime/pure-api-home" \
    AGY_TOS_TRIPPED_FILE="$ROOT/runtime/tos-tripped" \
    AGY_WAF_RULES_FILE="$ROOT/runtime/waf_rewrite_rules.json" \
    AGY_GW_LOG="$log_dir/gateway.log" \
    AGY_ACP_BIN="$ROOT/bin/agy-acp-900k" \
    AGY_DRAIN_TIMEOUT_SEC="$DRAIN_SEC" \
    "$sdir/scripts/gw.sh" "$@"
}

check_dash_accounts_api() {
  local dash_port="$1"
  python3 - "$ROOT/.env" "$dash_port" << "PY"
import base64, json, os, sys, urllib.request

env_path, port = sys.argv[1], sys.argv[2]
vals = {}
if os.path.exists(env_path):
    for line in open(env_path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        vals[k.strip()] = v.strip().strip(chr(34)).strip(chr(39))

key = ""
for item in vals.get("AGY_API_KEYS", "").split(","):
    item = item.strip()
    if item and not item.startswith("#"):
        key = item
        break
if not key and vals.get("AGY_API_KEYS_FILE") and os.path.exists(vals["AGY_API_KEYS_FILE"]):
    for line in open(vals["AGY_API_KEYS_FILE"], encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#"):
            key = line
            break

hdrs = {}
if key:
    hdrs["Authorization"] = "Basic " + base64.b64encode(("admin:" + key).encode()).decode()

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
req = urllib.request.Request(f"http://127.0.0.1:{port}/api/accounts", headers=hdrs, method="GET")
with opener.open(req, timeout=10) as resp:
    if resp.status != 200:
        raise RuntimeError(f"GET /api/accounts returned {resp.status}")
    d = json.loads(resp.read().decode("utf-8"))
    if d.get("ok") is not True:
        raise RuntimeError("GET /api/accounts ok!=true")
    accts = d.get("accounts") or []
    print(f"accounts_ok count={len(accts)}")
PY
}

cmd_status() {
  local cur="unset"
  if cur="$(current_active_slot)"; then :; else cur="unset"; fi
  echo "active-slot file: $cur ($ACTIVE_FILE)"
  if curl --noproxy "*" -fsS -m 2 "$PROXY_ADMIN/status" 2>/dev/null; then
    echo
  else
    echo "bg-proxy admin ($PROXY_ADMIN/status): unreachable"
  fi
  for s in blue green; do
    local sdir api dash branch sha h
    sdir="$(slot_dir "$s")"
    api="$(slot_api_port "$s")"
    dash="$(slot_dash_port "$s")"
    if [[ -d "$sdir" ]]; then
      branch="$(git -C "$sdir" symbolic-ref --short HEAD 2>/dev/null || echo detached)"
      sha="$(git -C "$sdir" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    else
      branch="missing"; sha="-"
    fi
    if port_listening "$api"; then
      h="$(curl --noproxy "*" -fsS -m 2 "http://127.0.0.1:$api/healthz" 2>/dev/null || echo err)"
    else
      h="stopped"
    fi
    echo "slot=$s dir=$sdir branch=$branch head=$sha ports=$api/$dash status=$h"
  done
}

cmd_build() {
  local slot="$1" sdir
  sdir="$(slot_dir "$slot")"
  [[ -d "$sdir/go-gateway" ]] || { echo "Missing slot worktree: $sdir" >&2; return 1; }
  mkdir -p "$sdir/bin"
  echo "Building $slot binary in $sdir/go-gateway ..."
  (cd "$sdir/go-gateway" && go build -trimpath -o "$sdir/bin/agy-acp-gateway.new" .)
  mv "$sdir/bin/agy-acp-gateway.new" "$sdir/bin/agy-acp-gateway"
  chmod 755 "$sdir/bin/agy-acp-gateway"
  ls -lh "$sdir/bin/agy-acp-gateway"
}

cmd_verify() {
  local slot="$1" with_tests="${2:-0}" sdir
  sdir="$(slot_dir "$slot")"
  if [[ "$with_tests" == "--with-tests" ]]; then
    (cd "$sdir/go-gateway" && go vet ./... && go test -count=1 ./...)
  fi
  cmd_build "$slot"

  local v_api=18954 v_dash=18955
  if port_listening "$v_api" || port_listening "$v_dash"; then
    echo "Verify ports $v_api/$v_dash already occupied" >&2
    return 1
  fi

  (
    local tmp_dir pid=""
    tmp_dir="$(mktemp -d /tmp/agy-bg-verify-XXXXXX)"
    cleanup_verify() {
      if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 1 30); do
          kill -0 "$pid" 2>/dev/null || break
          sleep 0.1
        done
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
      fi
      rm -rf "$tmp_dir"
    }
    trap cleanup_verify EXIT INT TERM

  env \
    AGY_LISTEN_HOST=127.0.0.1 \
    AGY_GW_PORT="$v_api" \
    AGY_DASH_PORT="$v_dash" \
    AGY_GW_HOME="$sdir" \
    AGY_RUN_DIR="$tmp_dir" \
    AGY_STATE_DB="$tmp_dir/gateway.db" \
    AGY_ACCOUNTS_FILE="$tmp_dir/accounts.json" \
    AGY_PURE_API_HOME="$tmp_dir/pure-api-home" \
    AGY_TOS_TRIPPED_FILE="$tmp_dir/tos-tripped" \
    AGY_GW_LOG="$tmp_dir/gateway.log" \
    AGY_ACP_BIN="$ROOT/bin/agy-acp-900k" \
    AGY_API_KEYS=bg-verify-ephemeral-key \
    AGY_UPSTREAM_PROXY=http://127.0.0.1:7890 \
    AGY_APPDATA_LINK="" \
    "$sdir/bin/agy-acp-gateway" \
    >"$tmp_dir/stdout.log" 2>&1 </dev/null &
  pid="$!"

  local ready=0
  for _ in $(seq 1 50); do
    if curl --noproxy "*" -fsS -m 1 "http://127.0.0.1:$v_api/healthz" >/dev/null 2>&1; then
      ready=1
      break
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      cat "$tmp_dir/stdout.log" >&2 || true
      return 1
    fi
    sleep 0.2
  done
  (( ready == 1 )) || { echo "Verify readiness timeout" >&2; return 1; }

  python3 - "$v_dash" << "PY"
import base64, json, sys, urllib.parse, urllib.request

port = sys.argv[1]
tok = base64.b64encode(b"admin:bg-verify-ephemeral-key").decode()
base = {"Authorization": "Basic " + tok}
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def req(method, path, body=None, extra=None):
    hdrs = dict(base)
    if extra:
        hdrs.update(extra)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=hdrs, method=method)
    with opener.open(r, timeout=15) as resp:
        return resp.status, resp.read().decode("utf-8", errors="replace")

st, html = req("GET", "/")
assert st == 200 and "Google OAuth 登录 (ACP 模式)" in html and "安全监测" in html, "dashboard HTML check failed"
st, raw = req("GET", "/api/accounts")
d = json.loads(raw)
assert st == 200 and d.get("ok") is True

mut = {
    "Origin": f"http://127.0.0.1:{port}",
    "Sec-Fetch-Site": "same-origin",
    "X-Agy-Requested-With": "dashboard",
}
st, raw = req("POST", "/api/accounts", {
    "id": "bg-verify",
    "label": "BG Verify",
    "proxyPreset": "direct",
    "allowedModels": ["gemini-4-neon"],
    "enabled": True,
}, mut)
assert st == 200 and json.loads(raw).get("ok") is True

st, raw = req("POST", "/api/accounts/oauth/start", {"accountId": "bg-verify"}, mut)
d = json.loads(raw)
assert st == 200 and d.get("ok") is True
u = urllib.parse.urlparse(d.get("authUrl", ""))
qs = urllib.parse.parse_qs(u.query)
assert u.scheme == "https" and u.netloc == "accounts.google.com" and u.path == "/o/oauth2/auth"
assert qs.get("redirect_uri", [""])[0] == "https://antigravity.google/oauth-callback"
fid = d.get("flowId", "")
assert len(fid) > 0

st, raw = req("POST", "/api/accounts/oauth/cancel", {"accountId": "bg-verify", "flowId": fid}, mut)
dc = json.loads(raw)
assert st == 200 and dc.get("ok") is True and (dc.get("status") or {}).get("phase") == "cancelled"
print("verify_ok oauth_start_cancel=True")
PY
  )
}

cmd_start() {
  local slot="$1"
  slot_env_run "$slot" start go
}

cmd_stop() {
  local slot="$1"
  slot_env_run "$slot" stop
}

cmd_start_active() {
  local slot
  slot="$(current_active_slot || echo blue)"
  local api
  api="$(slot_api_port "$slot")"
  if port_listening "$api"; then
    echo "Active slot $slot already listening on $api"
    return 0
  fi
  cmd_start "$slot"
}

cmd_switch() {
  local target="$1" drain_bg="${2:-}"
  local sdir api dash other cur=""
  sdir="$(slot_dir "$target")"
  api="$(slot_api_port "$target")"
  dash="$(slot_dash_port "$target")"
  other="$(opposite_slot "$target")"

  [[ -x "$sdir/bin/agy-acp-gateway" ]] || { echo "Missing executable binary in $sdir/bin/agy-acp-gateway" >&2; return 1; }
  if cur="$(current_active_slot)"; then :; else cur=""; fi
  if [[ "$cur" == "$target" ]] && port_listening "$api"; then
    echo "Slot $target is already active and listening on $api; switch to $other or run verify/build on $other first." >&2
    return 1
  fi

  if port_listening "$api"; then
    slot_env_run "$target" restart go
  else
    slot_env_run "$target" start go
  fi

  local ok=0
  for _ in $(seq 1 40); do
    if curl --noproxy "*" -fsS -m 2 "http://127.0.0.1:$api/healthz" >/dev/null 2>&1 && check_dash_accounts_api "$dash" >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep 0.25
  done
  (( ok == 1 )) || { echo "Target slot $target failed health/accounts readiness check" >&2; return 1; }

  local tmp_active
  tmp_active="$(mktemp "${ACTIVE_FILE}.tmp.XXXXXX")"
  printf "%s\n" "$target" > "$tmp_active"
  chmod 644 "$tmp_active"
  mv "$tmp_active" "$ACTIVE_FILE"

  local reload_json
  reload_json="$(curl --noproxy "*" -fsS -m 3 -X POST "$PROXY_ADMIN/reload")"
  python3 - "$reload_json" "$target" << "PY"
import json, sys
d = json.loads(sys.argv[1])
if d.get("ok") is not True or d.get("activeSlot") != sys.argv[2]:
    raise SystemExit(f"Proxy reload did not switch to {sys.argv[2]}: {d}")
s_slot = d.get("activeSlot", "")
s_api = d.get("apiTarget", "")
print(f"proxy_switched activeSlot={s_slot} apiTarget={s_api}")
PY

  curl --noproxy "*" -fsS -m 3 "http://127.0.0.1:$FRONT_API_PORT/healthz" >/dev/null
  local listen_host=""
  if [[ -f "$ROOT/.env" ]]; then
    listen_host="$(awk -F= "/^AGY_LISTEN_HOST=/{print \$2; exit}" "$ROOT/.env" | tr -d "\"'[:space:]")"
  fi
  if [[ -n "$listen_host" && "$listen_host" != "127.0.0.1" && "$listen_host" != "0.0.0.0" && "$listen_host" != "::" ]]; then
    curl --noproxy "*" -fsS -m 3 "http://$listen_host:$FRONT_API_PORT/healthz" >/dev/null
  fi
  if port_listening "$FRONT_AUTO_PORT"; then
    curl --noproxy "*" -fsS -m 5 "http://127.0.0.1:$FRONT_AUTO_PORT/" >/dev/null
  fi

  local other_api
  other_api="$(slot_api_port "$other")"
  if port_listening "$other_api"; then
    if [[ "$drain_bg" == "--drain-bg" ]]; then
      echo "Draining previous slot $other in background (AGY_DRAIN_TIMEOUT_SEC=$DRAIN_SEC)..."
      nohup "$0" stop "$other" >>"$ROOT/logs/bluegreen-drain.log" 2>&1 </dev/null &
    else
      echo "Draining previous slot $other (AGY_DRAIN_TIMEOUT_SEC=$DRAIN_SEC)..."
      slot_env_run "$other" stop
    fi
  fi
  echo "Switch to $target completed."
}

cmd_rollback() {
  local cur target
  cur="$(current_active_slot)" || { echo "Cannot rollback: active-slot file missing or invalid" >&2; return 1; }
  target="$(opposite_slot "$cur")"
  cmd_switch "$target"
}

case "${1:-status}" in
  status) cmd_status ;;
  build) [[ $# -ge 2 ]] || { echo "Usage: $0 build <blue|green>" >&2; exit 2; }; cmd_build "$2" ;;
  verify) [[ $# -ge 2 ]] || { echo "Usage: $0 verify <blue|green> [--with-tests]" >&2; exit 2; }; cmd_verify "$2" "${3:-}" ;;
  start) [[ $# -ge 2 ]] || { echo "Usage: $0 start <blue|green>" >&2; exit 2; }; cmd_start "$2" ;;
  stop) [[ $# -ge 2 ]] || { echo "Usage: $0 stop <blue|green>" >&2; exit 2; }; cmd_stop "$2" ;;
  start-active) cmd_start_active ;;
  switch) [[ $# -ge 2 ]] || { echo "Usage: $0 switch <blue|green> [--drain-bg]" >&2; exit 2; }; cmd_switch "$2" "${3:-}" ;;
  rollback) cmd_rollback ;;
  *)
    echo "Usage: $0 {status|build|verify|start|stop|start-active|switch|rollback} ..." >&2
    exit 2
    ;;
esac
