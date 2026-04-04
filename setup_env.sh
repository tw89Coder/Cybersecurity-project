#!/usr/bin/env bash
# ============================================================
# setup_env.sh - Attack-Defense Lab Environment Setup
# Tested on: Ubuntu 22.04 / 24.04 (WSL2 or VM)
#
# Uses Python venv for isolation — won't pollute system packages.
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

echo "[*] ===== Attack-Defense Lab Setup ====="
echo ""

# ── System packages ──────────────────────────────────────────
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

# ── Python venv ──────────────────────────────────────────────
echo ""
echo "[*] Setting up Python virtual environment..."

if [ -d "$VENV_DIR" ]; then
    echo "    .venv already exists, updating..."
else
    python3 -m venv --system-site-packages "$VENV_DIR"
    echo "    Created .venv at $VENV_DIR"
fi

# --system-site-packages allows access to system-installed python3-bpfcc
# which cannot be installed via pip (it's a system package with kernel bindings)

source "$VENV_DIR/bin/activate"
echo "    Activated venv: $(which python3)"

echo "[*] Installing Python packages in venv..."
pip install --upgrade pip
pip install -r "$SCRIPT_DIR/requirements.txt"

# ── Permissions ──────────────────────────────────────────────
echo ""
echo "[*] Setting script permissions..."
find "$SCRIPT_DIR" -name '*.sh' -exec chmod +x {} +
find "$SCRIPT_DIR" -name '*.py' -exec chmod +x {} +

# ── Verification ─────────────────────────────────────────────
echo ""
echo "[*] Verifying installation..."
python3 -c "from flask import Flask; print('  Flask OK')"
python3 -c "from bcc import BPF; print('  BCC/eBPF OK')" 2>/dev/null \
    || echo "  [!] BCC import failed — need: sudo apt-get install python3-bpfcc"
which nmap    >/dev/null && echo "  nmap OK"
which tcpdump >/dev/null && echo "  tcpdump OK"

# ── Done ─────────────────────────────────────────────────────
echo ""
echo "[+] Setup complete."
echo ""
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │  IMPORTANT: Activate venv before running any tool:  │"
echo "  │                                                     │"
echo "  │    source .venv/bin/activate                        │"
echo "  │                                                     │"
echo "  │  Or use the full path:                              │"
echo "  │    .venv/bin/python3 <script.py>                    │"
echo "  │                                                     │"
echo "  │  For eBPF tools (need sudo + venv):                 │"
echo "  │    sudo .venv/bin/python3 blue_team/blue_ebpf_mdr.py│"
echo "  └─────────────────────────────────────────────────────┘"
echo ""
echo "  Quick start: see docs/DEMO_FLOW.md"
