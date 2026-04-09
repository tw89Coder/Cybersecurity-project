#!/bin/bash
# ============================================
# Red Team - Phase 1: Black-Box Reconnaissance
# MITRE ATT&CK: T1595 (Active Scanning)
# ============================================

TARGET_IP="${1:-100.103.146.70}"
PORT_RANGE="${2:-2000-10000}"
OUTPUT_DIR="./recon_results"

mkdir -p "$OUTPUT_DIR"

echo "[*] ===== Red Team Recon Starting ====="
echo "[*] Target: $TARGET_IP"
echo "[*] Port Range: $PORT_RANGE"
echo ""

# Phase 1a: Fast port discovery
echo "[*] Phase 1a: TCP SYN Port Scan..."
nmap -sS -p "$PORT_RANGE" --open -T4 "$TARGET_IP" -oN "$OUTPUT_DIR/port_scan.txt" 2>/dev/null || \
nmap -sT -p "$PORT_RANGE" --open -T4 "$TARGET_IP" -oN "$OUTPUT_DIR/port_scan.txt"

echo ""

# NOTE: We intentionally skip nmap -sV (service version detection) here.
# -sV opens full TCP connections, which triggers the honeypot on port 2222
# and causes blue_mdr_network.py to auto-block our IP before we even finish
# scanning. The demo flow expects recon to complete cleanly, then the red
# team manually touches the honeypot with nc in a separate step.

# Phase 1b: Quick summary
echo "[*] ===== Scan Summary ====="
echo "[*] Results saved to $OUTPUT_DIR/"
echo ""
echo "[*] Key ports to look for:"
echo "    - 2222 (Possible SSH / Honeypot)"
echo "    - 9999 (Possible Diagnostic API / Real Target)"
echo "    - 4444 (Bind Shell if already deployed)"
echo ""
echo "[!] WARNING: Connecting to port 2222 will trigger honeypot alert!"
echo "[*] Focus attack on port 9999 (vuln_api)"
