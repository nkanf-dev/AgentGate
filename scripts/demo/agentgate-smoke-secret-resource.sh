#!/usr/bin/env bash
set -euo pipefail

base_url="${AGENTGATE_BASE_URL:-http://127.0.0.1:8080}"
adapter_token="${AGENTGATE_ADAPTER_TOKEN:-adapter-local-token}"
operator_token="${AGENTGATE_OPERATOR_TOKEN:-operator-local-token}"

resource_registration='{
  "adapter_id": "agentgate-resource-adapter",
  "adapter_kind": "resource_provider",
  "host": { "kind": "generic-resource-provider", "version": "dev" },
  "surfaces": ["resource"],
  "capabilities": {
    "can_block": true,
    "can_rewrite_input": false,
    "can_rewrite_tool_args": false,
    "can_pause_for_approval": false
  }
}'

curl -fsS -X POST "${base_url}/v1/register" \
  -H "authorization: Bearer ${adapter_token}" \
  -H 'content-type: application/json' \
  -d "${resource_registration}" >/dev/null

input_decision="$(
  curl -fsS -X POST "${base_url}/v1/decide" \
    -H "authorization: Bearer ${adapter_token}" \
    -H 'content-type: application/json' \
    -d '{
      "request_id": "req_secret_resource_smoke",
      "request_kind": "input",
      "actor": { "user_id": "smoke-user", "host_id": "openclaw" },
      "session": { "session_id": "sess_secret_resource", "task_id": "task_deploy" },
      "action": { "operation": "model_input" },
      "target": { "kind": "model_context" },
      "context": {
        "surface": "input",
        "raw": { "text": "api_key: sk-test-1234567890abcdef deploy assistant" }
      },
      "policy": {}
    }'
)"

handle_id="$(
  printf '%s' "${input_decision}" | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const j=JSON.parse(s);const o=j.obligations.find(o=>o.type==="rewrite_input");console.log(o.params.secret_handles[0].handle_id);})'
)"

resource_decision="$(
  curl -fsS -X POST "${base_url}/v1/decide" \
    -H "authorization: Bearer ${adapter_token}" \
    -H 'content-type: application/json' \
    -d "{
      \"request_id\": \"req_secret_resource_resolve_smoke\",
      \"request_kind\": \"resource_access\",
      \"actor\": { \"user_id\": \"smoke-user\", \"host_id\": \"generic-resource-provider\" },
      \"session\": { \"session_id\": \"sess_secret_resource\", \"task_id\": \"task_deploy\" },
      \"action\": { \"operation\": \"resolve_secret_handle\", \"side_effects\": [\"secret_resolve\"] },
      \"target\": { \"kind\": \"secret_handle\", \"identifier\": \"${handle_id}\" },
      \"context\": { \"surface\": \"resource\", \"raw\": { \"purpose\": \"smoke\" } },
      \"policy\": {}
    }"
)"

printf 'handle_id=%s\n' "${handle_id}"
printf 'resource_decision=%s\n' "$(
  printf '%s' "${resource_decision}" | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const j=JSON.parse(s);console.log(j.effect+":"+j.reason_code);})'
)"
printf 'events='
curl -fsS "${base_url}/v1/events?limit=20" \
  -H "authorization: Bearer ${operator_token}" \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>console.log(JSON.parse(s).events.length));'
