#!/usr/bin/env bash
set -euo pipefail

export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

ROOT="/Users/maygo/Projects/agy-acp-gateway"
RUNTIME="$ROOT/runtime"
LOG_FILE="$RUNTIME/auto_sync.log"
LOCK_FILE="$RUNTIME/auto_sync.lock"
MAX_LOG_LINES=500

CHECK_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --check-only)
      CHECK_ONLY=1
      ;;
    -h|--help)
      echo "Usage: $(basename "$0") [--check-only]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

mkdir -p "$RUNTIME"

# Idempotent non-blocking lock via python3 fcntl (macOS has no flock(1) by default)
if [[ "${_AGY_AUTO_SYNC_LOCKED:-0}" != "1" ]]; then
  exec python3 -c '
import fcntl, os, sys
lock_path = sys.argv[1]
fd = os.open(lock_path, os.O_CREAT | os.O_WRONLY, 0o600)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError:
    sys.stderr.write("auto_sync_gateway.sh already running; exiting\n")
    sys.exit(0)
os.set_inheritable(fd, True)
os.environ["_AGY_AUTO_SYNC_LOCKED"] = "1"
os.execv(sys.argv[2], sys.argv[2:])
' "$LOCK_FILE" "$0" "$@"
fi

log_line() {
  local ts line
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  line="[$ts] $*"
  printf '%s\n' "$line"
  printf '%s\n' "$line" >> "$LOG_FILE"
}

trim_log() {
  if [[ -f "$LOG_FILE" ]]; then
    local lines
    lines="$(wc -l < "$LOG_FILE" | tr -d ' ')"
    if (( lines > MAX_LOG_LINES )); then
      tail -n "$MAX_LOG_LINES" "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
    fi
  fi
}
trap trim_log EXIT

# Read listen host/port from .env if present (without overriding existing env)
LISTEN_HOST="${AGY_LISTEN_HOST:-}"
GW_PORT="${AGY_GW_PORT:-}"
if [[ -f "$ROOT/.env" ]]; then
  if [[ -z "$LISTEN_HOST" ]]; then
    LISTEN_HOST="$(awk -F= '/^AGY_LISTEN_HOST=/{print $2; exit}' "$ROOT/.env" | tr -d "\"'[:space:]")"
  fi
  if [[ -z "$GW_PORT" ]]; then
    GW_PORT="$(awk -F= '/^AGY_GW_PORT=/{print $2; exit}' "$ROOT/.env" | tr -d "\"'[:space:]")"
  fi
fi
LISTEN_HOST="${LISTEN_HOST:-127.0.0.1}"
GW_PORT="${GW_PORT:-18890}"

cd "$ROOT"
log_line "[START] mode=$([[ $CHECK_ONLY -eq 1 ]] && echo check-only || echo sync) host=$LISTEN_HOST port=$GW_PORT"

# 1. Git fetch & optional rebase on local/prod-patches
fetch_rc=0
git fetch origin --prune >/dev/null 2>&1 || fetch_rc=$?
if (( fetch_rc != 0 )); then
  log_line "[WARN] git fetch origin failed (rc=$fetch_rc)"
fi

DEFAULT_PROJ_FILE="runtime/pure-api-home/config/projects/default-cli-project.json"
BRANCH="$(git symbolic-ref --short HEAD 2>/dev/null || git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
DIRTY_COUNT="$(git status --porcelain --untracked-files=no -- . ":!${DEFAULT_PROJ_FILE}" 2>/dev/null | wc -l | tr -d ' ')"
LOCAL_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
REMOTE_SHA="$(git rev-parse --short origin/main 2>/dev/null || echo unknown)"
MERGE_BASE_OK=1
if ! git merge-base HEAD origin/main >/dev/null 2>&1; then
  MERGE_BASE_OK=0
fi
if (( MERGE_BASE_OK == 1 )); then
  BEHIND="$(git rev-list --count HEAD..origin/main 2>/dev/null || echo 0)"
else
  BEHIND=0
fi
log_line "[GIT] branch=$BRANCH dirty=$DIRTY_COUNT head=$LOCAL_SHA origin/main=$REMOTE_SHA behind=$BEHIND merge_base=$MERGE_BASE_OK"

UPDATED=0
EXIT_RC=0

if [[ -f "$RUNTIME/active-slot" ]]; then
  ACTIVE_SLOT="$(tr -d '[:space:]' < "$RUNTIME/active-slot" 2>/dev/null || echo unknown)"
  if (( CHECK_ONLY == 1 )); then
    log_line "[BG_MODE] active-slot=$ACTIVE_SLOT (check-only)"
  else
    log_line "[BG_MODE] blue-green active-slot=$ACTIVE_SLOT detected; skipping in-place rebase and gw.sh restart (use scripts/bluegreen.sh for releases)"
  fi
elif (( MERGE_BASE_OK == 0 )); then
  log_line "[FORCE_PUSH_UPSTREAM] HEAD ($LOCAL_SHA) and origin/main ($REMOTE_SHA) have no common ancestor (upstream force-push detected); skipping auto-rebase cleanly, running service untouched"
  if (( CHECK_ONLY == 0 )); then
    EXIT_RC=1
  fi
elif (( CHECK_ONLY == 1 )); then
  log_line "[CHECK_ONLY] skipping rebase, go test/build, and gw.sh restart"
elif [[ "$BRANCH" == "local/prod-patches" && "$DIRTY_COUNT" == "0" && "$BEHIND" -gt 0 ]]; then
  log_line "[REBASE] attempting git rebase origin/main ($LOCAL_SHA -> $REMOTE_SHA)"
  git update-index --no-skip-worktree "$DEFAULT_PROJ_FILE" >/dev/null 2>&1 || true
  git checkout -- "$DEFAULT_PROJ_FILE" >/dev/null 2>&1 || true
  rebase_out=""
  rebase_rc=0
  rebase_out="$(git rebase origin/main 2>&1)" || rebase_rc=$?
  if (( rebase_rc != 0 )); then
    git rebase --abort >/dev/null 2>&1 || true
    log_line "[CONFLICT] git rebase origin/main failed (rc=$rebase_rc); aborted cleanly, running service untouched"
    EXIT_RC=1
  else
    NEW_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    if [[ "$NEW_SHA" != "$LOCAL_SHA" ]]; then
      UPDATED=1
      log_line "[REBASE_OK] rebased $LOCAL_SHA -> $NEW_SHA"
    else
      log_line "[REBASE_NOOP] HEAD unchanged at $NEW_SHA"
    fi
  fi
  git update-index --skip-worktree "$DEFAULT_PROJ_FILE" >/dev/null 2>&1 || true
else
  log_line "[SKIP_REBASE] branch=$BRANCH dirty=$DIRTY_COUNT behind=$BEHIND"
fi

# 2. If code updated (and not check-only), run tests -> build -> restart -> healthz
if (( CHECK_ONLY == 0 && UPDATED == 1 )); then
  log_line "[TEST] running go test -count=1 ./... in go-gateway/"
  test_rc=0
  (cd "$ROOT/go-gateway" && go test -count=1 ./...) >/tmp/agy_auto_sync_test.out 2>&1 || test_rc=$?
  if (( test_rc != 0 )); then
    tail -n 20 /tmp/agy_auto_sync_test.out | while IFS= read -r l; do log_line "[TEST_ERR] $l"; done
    log_line "[TEST_FAIL] go test failed (rc=$test_rc); skipping build and gw.sh restart"
    EXIT_RC=1
  else
    log_line "[TEST_OK] all go tests passed; building binary"
    build_rc=0
    (cd "$ROOT/go-gateway" && go build -o ../bin/agy-acp-gateway .) >/tmp/agy_auto_sync_build.out 2>&1 || build_rc=$?
    if (( build_rc != 0 )); then
      tail -n 20 /tmp/agy_auto_sync_build.out | while IFS= read -r l; do log_line "[BUILD_ERR] $l"; done
      log_line "[BUILD_FAIL] go build failed (rc=$build_rc); skipping gw.sh restart"
      EXIT_RC=1
    else
      restart_rc=0
      "$ROOT/scripts/gw.sh" restart >/tmp/agy_auto_sync_restart.out 2>&1 || restart_rc=$?
      if (( restart_rc != 0 )); then
        tail -n 20 /tmp/agy_auto_sync_restart.out | while IFS= read -r l; do log_line "[RESTART_ERR] $l"; done
        log_line "[RESTART_FAIL] gw.sh restart failed (rc=$restart_rc)"
        EXIT_RC=1
      else
        health_out=""
        health_rc=0
        health_out="$(curl --noproxy '*' -fsS -m 5 "http://${LISTEN_HOST}:${GW_PORT}/healthz" 2>&1)" || health_rc=$?
        if (( health_rc != 0 )); then
          log_line "[HEALTHZ_FAIL] /healthz check failed (rc=$health_rc): $health_out"
          EXIT_RC=1
        else
          log_line "[DEPLOY_OK] rebuilt, restarted, healthz=$health_out"
        fi
      fi
    fi
  fi
fi

# 3. Upstream agy version & template compatibility check
AGY_VER="$(agy --version 2>/dev/null | head -n 1 | tr -d '\r' || echo unknown)"
WATCH_OUT=""
WATCH_RC=0
WATCH_OUT="$(python3 "$ROOT/scripts/upstream_watch.py" --official-only 2>&1)" || WATCH_RC=$?
UPSTREAM_VER="$(python3 -c '
import json, sys
try:
    d = json.loads(sys.argv[1])
    print(d.get("latest", "unknown"))
except Exception:
    print("parse_error")
' "$WATCH_OUT" 2>/dev/null || echo "unknown")"

AGY_BIN="$ROOT/bin/agy-acp-900k"
if [[ ! -e "$AGY_BIN" ]]; then
  AGY_BIN="$(command -v agy 2>/dev/null || true)"
fi

TPL_SUMMARY="skipped(no_binary)"
TPL_RC=0
if [[ -n "$AGY_BIN" && -e "$AGY_BIN" ]]; then
  TPL_OUT="$(python3 "$ROOT/scripts/agy_notice_templates.py" "$AGY_BIN" 2>&1)" || TPL_RC=$?
  TPL_SUMMARY="$(printf '%s\n' "$TPL_OUT" | tail -n 1 | tr -d '\r')"
fi

log_line "[COMPAT] local_agy=$AGY_VER upstream_agy=$UPSTREAM_VER watch_rc=$WATCH_RC template_rc=$TPL_RC template_summary=\"$TPL_SUMMARY\""
if (( TPL_RC != 0 )); then
  log_line "[TEMPLATE_WARN] agy_notice_templates.py returned rc=$TPL_RC"
  EXIT_RC=1
fi

log_line "[DONE] exit_rc=$EXIT_RC"
exit "$EXIT_RC"
