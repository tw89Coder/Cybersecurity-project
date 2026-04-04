#!/usr/bin/env bash
# ============================================================
# setup_env.sh - Attack-Defense Lab Environment Setup
# Tested on: Ubuntu 22.04 / 24.04 (WSL2 or native VM)
#
# Automatically detects WSL2 and adjusts installation:
#   - WSL2:   Red team tools only (no eBPF — kernel headers unavailable)
#   - Native: Full installation (red + blue + eBPF)
#
# Uses Python venv for isolation — won't pollute system packages.
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

# ── Detect WSL2 ──────────────────────────────────────────────
IS_WSL=false
if grep -qi "microsoft\|WSL" /proc/version 2>/dev/null; then
    IS_WSL=true
fi

echo "[*] ===== Attack-Defense Lab Setup ====="
echo ""
if $IS_WSL; then
    echo "  Detected: WSL2 (Red Team mode — eBPF not available)"
else
    echo "  Detected: Native Linux (Full mode — Red + Blue + eBPF)"
fi
echo ""

# ── System packages ──────────────────────────────────────────
echo "[*] Installing system packages..."
sudo apt-get update -qq

# Common packages (both WSL2 and native)
sudo apt-get install -y \
    python3 python3-pip python3-venv \
    net-tools nmap netcat-openbsd tcpdump \
    curl iproute2 iputils-ping dnsutils

# Blue team / eBPF packages (native only)
if $IS_WSL; then
    echo ""
    echo "[*] WSL2 detected — skipping eBPF packages"
    echo "    (linux-headers and bpfcc-tools are not available on WSL2)"
    echo "    Blue team tools (eBPF) should run on the Lab machine instead."
else
    echo "[*] Installing eBPF packages..."
    sudo apt-get install -y \
        bpfcc-tools python3-bpfcc \
        linux-headers-"$(uname -r)" \
        || {
            echo "[!] Exact kernel headers not found, trying generic..."
            sudo apt-get install -y linux-headers-generic bpfcc-tools python3-bpfcc || true
        }
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
pip install --upgrade pip -q
pip install -r "$SCRIPT_DIR/requirements.txt" -q

# ── Permissions ──────────────────────────────────────────────
echo ""
echo "[*] Setting script permissions..."
find "$SCRIPT_DIR" -name '*.sh' -exec chmod +x {} +
find "$SCRIPT_DIR" -name '*.py' -exec chmod +x {} +

# ── Verification ─────────────────────────────────────────────
echo ""
echo "[*] Verifying installation..."
python3 -c "from flask import Flask; print('  Flask OK')"

if $IS_WSL; then
    echo "  BCC/eBPF SKIPPED (WSL2 — run on Lab machine)"
else
    python3 -c "from bcc import BPF; print('  BCC/eBPF OK')" 2>/dev/null \
        || echo "  [!] BCC import failed — run: sudo apt-get install python3-bpfcc"
fi

which nmap    >/dev/null && echo "  nmap OK"    || true
which tcpdump >/dev/null && echo "  tcpdump OK" || true

python3 -c "
import ctypes, ctypes.util
lib = ctypes.util.find_library('crypto')
if lib:
    print(f'  OpenSSL OK ({lib})')
else:
    print('  [!] OpenSSL libcrypto not found')
"

# ── Done ─────────────────────────────────────────────────────
echo ""
echo "[+] Setup complete."
echo ""

if $IS_WSL; then
    echo "  ┌─────────────────────────────────────────────────────┐"
    echo "  │  WSL2 — Red Team Only                               │"
    echo "  │                                                     │"
    echo "  │  Available tools:                                   │"
    echo "  │    .venv/bin/python3 red_team/red_attacker.py       │"
    echo "  │    .venv/bin/python3 red_team/red_reverse_shell.py  │"
    echo "  │    .venv/bin/python3 red_team/exploit.py            │"
    echo "  │    bash red_team/recon.sh <TARGET_IP>               │"
    echo "  │                                                     │"
    echo "  │  Blue team + target → run on Lab machine            │"
    echo "  └─────────────────────────────────────────────────────┘"
else
    echo "  ┌─────────────────────────────────────────────────────┐"
    echo "  │  Native Linux — Full Installation                   │"
    echo "  │                                                     │"
    echo "  │  Activate venv:                                     │"
    echo "  │    source .venv/bin/activate                        │"
    echo "  │                                                     │"
    echo "  │  Or use full path:                                  │"
    echo "  │    .venv/bin/python3 <script.py>                    │"
    echo "  │                                                     │"
    echo "  │  For sudo tools:                                    │"
    echo "  │    sudo .venv/bin/python3 blue_team/blue_ebpf_mdr.py│"
    echo "  └─────────────────────────────────────────────────────┘"
fi

echo ""
echo "  Quick start: see docs/DEMO_FLOW.md"
