#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

export AGENTGATE_BASE_URL="${AGENTGATE_BASE_URL:-http://127.0.0.1:8080}"
export AGENTGATE_ADAPTER_TOKEN="${AGENTGATE_ADAPTER_TOKEN:-adapter-local-token}"
export AGENTGATE_OPERATOR_TOKEN="${AGENTGATE_OPERATOR_TOKEN:-operator-local-token}"
export AGENTGATE_ADMIN_TOKEN="${AGENTGATE_ADMIN_TOKEN:-admin-local-token}"

export AGENTGATE_EXFIL_HOST="${AGENTGATE_EXFIL_HOST:-127.0.0.1}"
export AGENTGATE_EXFIL_PORT="${AGENTGATE_EXFIL_PORT:-18080}"
export AGENTGATE_EXFIL_DIR="${AGENTGATE_EXFIL_DIR:-/tmp/agentgate-demo}"
export AGENTGATE_EXFIL_FILE="${AGENTGATE_EXFIL_FILE:-${AGENTGATE_EXFIL_DIR}/exfil-log.json}"
export AGENTGATE_EXFIL_SECRET_FILE="${AGENTGATE_EXFIL_SECRET_FILE:-${AGENTGATE_EXFIL_DIR}/secret.txt}"

NODE_BIN="${NODE_BIN:-/Users/nkanf/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node}"
OPENCLAW_BIN="${OPENCLAW_BIN:-openclaw}"

mkdir -p "${AGENTGATE_EXFIL_DIR}"

ensure_demo_secret() {
  cat >"${AGENTGATE_EXFIL_SECRET_FILE}" <<'EOF'
employee_name=Demo User
employee_phone=13800138000
prod_token=sk-demo-redteam-1234567890
EOF
}

reset_exfil_log() {
  curl -fsS -X POST "http://${AGENTGATE_EXFIL_HOST}:${AGENTGATE_EXFIL_PORT}/reset" >/dev/null
}

show_recent_events() {
  local session_id="$1"
  curl -fsS "${AGENTGATE_BASE_URL}/v1/events?limit=50" \
    -H "authorization: Bearer ${AGENTGATE_OPERATOR_TOKEN}" \
    | "${NODE_BIN}" -e '
      let s="";
      process.stdin.on("data", d => s += d);
      process.stdin.on("end", () => {
        const data = JSON.parse(s);
        const sessionId = process.argv[1];
        for (const event of data.events.filter(e => e.session_id === sessionId)) {
          console.log(JSON.stringify({
            event_type: event.event_type,
            effect: event.effect,
            summary: event.summary,
            session_id: event.session_id,
            metadata: event.metadata
          }));
        }
      });
    ' "${session_id}"
}

show_pending_approvals() {
  curl -fsS "${AGENTGATE_BASE_URL}/v1/approvals?status=pending&limit=20" \
    -H "authorization: Bearer ${AGENTGATE_OPERATOR_TOKEN}"
}

wait_for_session_event() {
  local session_id="$1"
  local expected_summary="$2"
  local attempts="${3:-40}"
  local sleep_seconds="${4:-1}"

  for ((i = 0; i < attempts; i++)); do
    if curl -fsS "${AGENTGATE_BASE_URL}/v1/events?limit=80" \
      -H "authorization: Bearer ${AGENTGATE_OPERATOR_TOKEN}" \
      | "${NODE_BIN}" -e '
          let s="";
          process.stdin.on("data", d => s += d);
          process.stdin.on("end", () => {
            const data = JSON.parse(s);
            const sessionId = process.argv[1];
            const expected = process.argv[2];
            const hit = data.events.some(e => e.session_id === sessionId && e.summary === expected);
            process.exit(hit ? 0 : 1);
          });
        ' "${session_id}" "${expected_summary}"; then
      return 0
    fi
    sleep "${sleep_seconds}"
  done

  echo "Timed out waiting for event '${expected_summary}' in session '${session_id}'." >&2
  return 1
}

wait_for_exfil() {
  local attempts="${1:-20}"
  local sleep_seconds="${2:-1}"

  for ((i = 0; i < attempts; i++)); do
    if [ -f "${AGENTGATE_EXFIL_FILE}" ] && [ "$(cat "${AGENTGATE_EXFIL_FILE}")" != "[]"$'\n' ] && [ "$(cat "${AGENTGATE_EXFIL_FILE}")" != "[]" ]; then
      return 0
    fi
    sleep "${sleep_seconds}"
  done

  echo "Timed out waiting for exfil payload." >&2
  return 1
}
