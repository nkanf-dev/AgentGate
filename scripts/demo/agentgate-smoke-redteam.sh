#!/usr/bin/env bash
set -euo pipefail

base_url="${AGENTGATE_BASE_URL:-http://127.0.0.1:8080}"
adapter_token="${AGENTGATE_ADAPTER_TOKEN:-adapter-local-token}"

input_decision="$(
  curl -fsS -X POST "${base_url}/v1/decide" \
    -H "authorization: Bearer ${adapter_token}" \
    -H 'content-type: application/json' \
    -d '{
      "request_id": "req_scope_input_smoke",
      "request_kind": "input",
      "actor": { "user_id": "smoke-user", "host_id": "openclaw" },
      "session": { "session_id": "sess_scope_ok", "task_id": "task_scope_ok" },
      "action": { "operation": "model_input" },
      "target": { "kind": "model_context" },
      "context": {
        "surface": "input",
        "raw": { "text": "token=sk-live-abcdef1234567890 should be protected" }
      },
      "policy": {}
    }'
)"

handle_id="$(
  printf '%s' "${input_decision}" \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const j=JSON.parse(s);const o=j.obligations.find(o=>o.type==="rewrite_input");console.log(o.params.secret_handles[0].handle_id);})'
)"

mismatch_decision="$(
  curl -fsS -X POST "${base_url}/v1/decide" \
    -H "authorization: Bearer ${adapter_token}" \
    -H 'content-type: application/json' \
    -d "{
      \"request_id\": \"req_scope_mismatch_smoke\",
      \"request_kind\": \"resource_access\",
      \"actor\": { \"user_id\": \"smoke-user\", \"host_id\": \"generic-resource-provider\" },
      \"session\": { \"session_id\": \"sess_scope_wrong\", \"task_id\": \"task_scope_wrong\" },
      \"action\": { \"operation\": \"resolve_secret_handle\", \"side_effects\": [\"secret_resolve\"] },
      \"target\": { \"kind\": \"secret_handle\", \"identifier\": \"${handle_id}\" },
      \"context\": {
        \"surface\": \"resource\",
        \"raw\": { \"purpose\": \"scope-mismatch\" }
      },
      \"policy\": {}
    }"
)"

mismatch_effect="$(
  printf '%s' "${mismatch_decision}" \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const j=JSON.parse(s);console.log(`${j.disposition}:${j.reason_code}:${j.obligations.map(o=>o.type).join(",")}`);})'
)"

printf 'handle_id=%s\n' "${handle_id}"
printf 'mismatch_decision=%s\n' "${mismatch_effect}"
