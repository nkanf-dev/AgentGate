#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
OPENCLAW_NPM_DIR="${OPENCLAW_NPM_DIR:-$OPENCLAW_HOME/npm}"
OPENCLAW_CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-$OPENCLAW_HOME/openclaw.json}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

need_cmd go
need_cmd bun
need_cmd npm

mkdir -p "$OPENCLAW_NPM_DIR"

echo "[agentgate] installing workspace dependencies"
(cd "$ROOT_DIR" && bun install --frozen-lockfile)

echo "[agentgate] building web console and adapters"
(cd "$ROOT_DIR" && bun run build:web)
(cd "$ROOT_DIR" && bun run build:adapters)

echo "[agentgate] installing OpenClaw plugin into $OPENCLAW_NPM_DIR"
(cd "$OPENCLAW_NPM_DIR" && npm install --no-save "$ROOT_DIR/packages/openclaw-adapter")

cat <<EOF

[agentgate] install complete

1. Start AgentGate:
   cd "$ROOT_DIR"
   go run ./cmd/agentgate

2. Open the control plane:
   http://localhost:8080/

3. Add this plugin block to:
   $OPENCLAW_CONFIG_PATH

{
  "plugins": {
    "allow": ["agentgate-openclaw-adapter"]
  },
  "pluginConfig": {
    "agentgate-openclaw-adapter": {
      "agentGate": {
        "baseUrl": "http://127.0.0.1:8080",
        "adapterToken": "adapter-local-token",
        "integrationId": "openclaw-main"
      }
    }
  }
}

4. Optional Feishu approval runtime:
   cd "$ROOT_DIR"
   AGENTGATE_BASE_URL=http://127.0.0.1:8080 \\
   AGENTGATE_ADAPTER_TOKEN=adapter-local-token \\
   AGENTGATE_OPERATOR_TOKEN=operator-local-token \\
   FEISHU_APP_ID=cli_xxx \\
   FEISHU_APP_SECRET=xxx \\
   FEISHU_RECEIVE_ID=oc_xxx \\
   FEISHU_RECEIVE_ID_TYPE=chat_id \\
   node packages/feishu-adapter/dist/cli.js

EOF
