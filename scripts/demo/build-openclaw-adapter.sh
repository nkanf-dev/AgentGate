#!/usr/bin/env bash
set -euo pipefail

bun run --filter @agentgate/openclaw-adapter build

echo "Built @agentgate/openclaw-adapter."
echo "Plugin entry: packages/openclaw-adapter/dist/plugin.js"
echo "Manifest: packages/openclaw-adapter/openclaw.plugin.json"
