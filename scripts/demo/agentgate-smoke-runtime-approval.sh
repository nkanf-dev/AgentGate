#!/usr/bin/env bash
set -euo pipefail

base_url="${AGENTGATE_BASE_URL:-http://127.0.0.1:8080}"
adapter_token="${AGENTGATE_ADAPTER_TOKEN:-adapter-local-token}"
operator_token="${AGENTGATE_OPERATOR_TOKEN:-operator-local-token}"
run_id="$(date +%s%N)"
session_id="sess_runtime_smoke_${run_id}"
task_id="task_runtime_${run_id}"
attempt_id="attempt_${run_id}"

runtime_decision_file="$(mktemp)"
cleanup() {
  rm -f "${runtime_decision_file}"
}
trap cleanup EXIT

curl -fsS -X POST "${base_url}/v1/decide" \
  -H "authorization: Bearer ${adapter_token}" \
  -H 'content-type: application/json' \
  -d '{
    "request_id": "req_runtime_approval_smoke",
    "request_kind": "tool_attempt",
    "actor": { "user_id": "smoke-user", "host_id": "openclaw" },
    "session": { "session_id": "'"${session_id}"'", "task_id": "'"${task_id}"'", "attempt_id": "'"${attempt_id}"'" },
    "action": {
      "tool": "bash",
      "operation": "execute",
      "side_effects": ["process_spawn", "network_egress"],
      "open_world": true
    },
    "target": { "kind": "process", "identifier": "/bin/sh" },
    "content": { "summary": "curl https://example.com" },
    "context": {
      "surface": "runtime",
      "raw": { "args": { "command": "curl https://example.com" } }
    },
    "policy": {}
  }' >"${runtime_decision_file}" &
decide_pid=$!

approval_id="$(
  for _ in $(seq 1 40); do
    approval_id="$(
      curl -fsS "${base_url}/v1/approvals?limit=50" \
        -H "authorization: Bearer ${operator_token}" \
        | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const j=JSON.parse(s);const sessionId=process.argv[1];const attemptId=process.argv[2];const match=j.approvals.find(a=>a.session_id===sessionId&&a.attempt_id===attemptId&&a.status==="pending");console.log(match?.approval_id ?? "");})' "${session_id}" "${attempt_id}"
    )"
    if [ -n "${approval_id}" ]; then
      printf '%s' "${approval_id}"
      exit 0
    fi
    sleep 1
  done
  exit 1
)"

resolve_response="$(
  curl -fsS -X POST "${base_url}/v1/approvals/${approval_id}/resolve" \
    -H "authorization: Bearer ${operator_token}" \
    -H 'content-type: application/json' \
    -d '{"decision":"allow_once","operator_id":"local-operator","channel":"manual"}'
)"

final_decision="$(
  wait "${decide_pid}"
  cat "${runtime_decision_file}"
)"

first_effect="$(
  printf '%s' "${final_decision}" \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const j=JSON.parse(s);console.log(`${j.disposition}:${j.reason_code}`);})'
)"

grant_decision="$(
  curl -fsS -X POST "${base_url}/v1/decide" \
    -H "authorization: Bearer ${adapter_token}" \
    -H 'content-type: application/json' \
    -d '{
      "request_id": "req_runtime_approval_retry_smoke",
      "request_kind": "tool_attempt",
      "actor": { "user_id": "smoke-user", "host_id": "openclaw" },
      "session": { "session_id": "'"${session_id}"'", "task_id": "'"${task_id}"'", "attempt_id": "'"${attempt_id}"'" },
      "action": {
        "tool": "bash",
        "operation": "execute",
        "side_effects": ["process_spawn", "network_egress"],
        "open_world": true
      },
      "target": { "kind": "process", "identifier": "/bin/sh" },
      "content": { "summary": "curl https://example.com" },
      "context": {
        "surface": "runtime",
        "raw": { "args": { "command": "curl https://example.com" } }
      },
      "policy": {}
    }'
)"

approval_status="$(
  printf '%s' "${resolve_response}" \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const j=JSON.parse(s);console.log(j.status);})'
)"

retry_effect="$(
  printf '%s' "${grant_decision}" \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const j=JSON.parse(s);console.log(`${j.disposition}:${j.reason_code}`);})'
)"

printf 'runtime_first=%s\n' "${first_effect}"
printf 'approval_id=%s\n' "${approval_id}"
printf 'approval_status=%s\n' "${approval_status}"
printf 'runtime_retry=%s\n' "${retry_effect}"
