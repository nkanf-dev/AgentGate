#!/usr/bin/env bash
set -euo pipefail

base_url="${AGENTGATE_BASE_URL:-http://127.0.0.1:8080}"
adapter_token="${AGENTGATE_ADAPTER_TOKEN:-adapter-local-token}"
operator_token="${AGENTGATE_OPERATOR_TOKEN:-operator-local-token}"

curl -fsS -X POST "${base_url}/v1/register" \
  -H "authorization: Bearer ${adapter_token}" \
  -H 'content-type: application/json' \
  -d '{
    "adapter_id": "openclaw-agentgate",
    "adapter_kind": "host_plugin",
    "host": { "kind": "openclaw", "version": "dev" },
    "surfaces": ["input", "runtime"],
    "capabilities": {
      "can_block": true,
      "can_rewrite_input": true,
      "can_rewrite_tool_args": true,
      "can_pause_for_approval": true
    }
  }'

printf '\n'
curl -fsS -X POST "${base_url}/v1/register" \
  -H "authorization: Bearer ${adapter_token}" \
  -H 'content-type: application/json' \
  -d '{
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

printf '\n'
curl -fsS "${base_url}/v1/coverage" \
  -H "authorization: Bearer ${operator_token}"
printf '\n'
