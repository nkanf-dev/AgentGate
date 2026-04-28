#!/usr/bin/env bash
set -euo pipefail

bun run --filter @agentgate/feishu-adapter build

echo "Built @agentgate/feishu-adapter."
echo "CLI entry: packages/feishu-adapter/dist/cli.js"
