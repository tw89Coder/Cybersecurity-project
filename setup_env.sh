#!/usr/bin/env bash
# ============================================================
# setup_env.sh - Attack-Defense Lab Environment Setup
# Tested on: Ubuntu 22.04 / 24.04 (WSL2 or VM)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Installing system packages..."
sudo apt-get update
sudo apt-get install -y \
    python3 python3-pip python3-venv \
    bpfcc-tools python3-bpfcc \
    linux-headers-"$(uname -r)" \
    net-tools nmap netcat-openbsd tcpdump \
    curl iproute2 iputils-ping dnsutils

# Fallback: if exact kernel headers not found (WSL2), try generic
if ! dpkg -s linux-headers-"$(uname -r)" &>/dev/null; then
    echo "[!] Exact kernel headers not found, installing generic..."
    sudo apt-get install -y linux-headers-generic || true
fi

echo "[*] Installing Python packages..."
pip3 install --break-system-packages flask 2>/dev/null || pip3 install flask

echo "[*] Setting script permissions..."
find "$SCRIPT_DIR" -name '*.sh' -exec chmod +x {} +
find "$SCRIPT_DIR" -name '*.py' -exec chmod +x {} +

echo "[*] Verifying installation..."
python3 -c "from flask import Flask; print('  Flask OK')"
python3 -c "from bcc import BPF; print('  BCC/eBPF OK')" 2>/dev/null \
    || echo "  [!] BCC import failed — need: sudo apt-get install python3-bpfcc"
which nmap    >/dev/null && echo "  nmap OK"
which tcpdump >/dev/null && echo "  tcpdump OK"

echo ""
echo "[+] Setup complete."
echo ""
echo "  Run order:"
echo "  Terminal 1 (Target):  sudo python3 target/target_app.py"
echo "  Terminal 2 (Blue):    sudo python3 blue_team/blue_ebpf_mdr.py --kill"
echo "  Terminal 3 (Red C2):  sudo python3 red_team/red_attacker.py -t TARGET_IP -l ATTACKER_IP"
echo "  Terminal 4 (Red ATK): <paste curl command from Terminal 3>"
