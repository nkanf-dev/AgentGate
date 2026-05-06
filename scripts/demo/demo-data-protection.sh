#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/demo-common.sh"

session_id="${1:-demo-data-protection}"
task_id="${2:-demo-data-protection-task}"
wrong_session_id="${3:-demo-data-protection-other}"

echo "[demo:data] session=${session_id}"

input_decision="$(
  curl -fsS -X POST "${AGENTGATE_BASE_URL}/v1/decide" \
    -H "authorization: Bearer ${AGENTGATE_ADAPTER_TOKEN}" \
    -H 'content-type: application/json' \
    -d "{
      \"request_id\": \"req_${session_id}_input\",
      \"request_kind\": \"input\",
      \"actor\": { \"user_id\": \"demo-user\", \"host_id\": \"openclaw\" },
      \"session\": { \"session_id\": \"${session_id}\", \"task_id\": \"${task_id}\" },
      \"action\": { \"operation\": \"model_input\" },
      \"target\": { \"kind\": \"model_context\" },
      \"context\": {
        \"surface\": \"input\",
        \"raw\": { \"text\": \"token=sk-live-abcdef1234567890 and phone=13800138000 should be protected\" }
      },
      \"policy\": {}
    }"
)"

handle_id="$(
  printf '%s' "${input_decision}" \
    | "${NODE_BIN}" -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const j=JSON.parse(s);const o=j.obligations.find(o=>o.type==="rewrite_input");console.log(o.params.secret_handles[0].handle_id);})'
)"

echo "[demo:data] handle_id=${handle_id}"

resource_decision="$(
  curl -fsS -X POST "${AGENTGATE_BASE_URL}/v1/decide" \
    -H "authorization: Bearer ${AGENTGATE_ADAPTER_TOKEN}" \
    -H 'content-type: application/json' \
    -d "{
      \"request_id\": \"req_${session_id}_cross_scope\",
      \"request_kind\": \"resource_access\",
      \"actor\": { \"user_id\": \"demo-user\", \"host_id\": \"generic-resource-provider\" },
      \"session\": { \"session_id\": \"${wrong_session_id}\", \"task_id\": \"${wrong_session_id}\" },
      \"action\": { \"operation\": \"resolve_secret_handle\", \"side_effects\": [\"secret_resolve\"] },
      \"target\": { \"kind\": \"secret_handle\", \"identifier\": \"${handle_id}\" },
      \"context\": { \"surface\": \"resource\", \"raw\": { \"purpose\": \"cross-session-demo\" } },
      \"policy\": {}
    }"
)"

echo "[demo:data] resource decision:"
printf '%s\n' "${resource_decision}"
echo
echo "[demo:data] matching events:"
show_recent_events "${session_id}"
show_recent_events "${wrong_session_id}"
