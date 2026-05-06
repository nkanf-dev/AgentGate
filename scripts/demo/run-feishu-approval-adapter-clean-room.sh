#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${AGENTGATE_DEMO_ROOT:-}" ]]; then
  echo "Source scripts/demo/openclaw-feishu-env.sh.example first." >&2
  exit 1
fi

bash scripts/demo/build-feishu-adapter.sh

exec bun packages/feishu-adapter/dist/cli.js
