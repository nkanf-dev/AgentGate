#!/usr/bin/env bash
set -euo pipefail

bun run --filter @agentgate/resource-adapter build

echo "Built @agentgate/resource-adapter."
