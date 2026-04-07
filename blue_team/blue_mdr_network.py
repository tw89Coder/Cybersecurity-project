#!/usr/bin/env python3
"""
blue_mdr_network.py - Network-Level MDR (Micro Managed Detection & Response)
================================================================================
Defence Layer : Network (iptables)
Complement to : blue_ebpf_mdr.py (kernel-level eBPF)

PRINCIPLE — Two-Layer Defense
------------------------------
This project implements defense-in-depth with two independent layers:

  Layer 1 — Network (this file):
    Honeypot on port 2222 logs attacker IPs to trap.log.
    This MDR daemon watches trap.log, extracts new IPs, and blocks them
    with iptables DROP rules.  This prevents the attacker from reaching
    ANY service on the machine.

  Layer 2 — Kernel (blue_ebpf_mdr.py / v2):
    eBPF hooks on syscalls detect malicious behavior (memfd_create,
    reverse shells) regardless of source IP.  This catches attackers
    who bypass the network layer (e.g., via IP alias).

Together they form: Network blocks known-bad IPs, eBPF blocks bad behavior.

HOW IT WORKS:
-------------
  1. Honeypot (target/honeypot.py) listens on port 2222
  2. Attacker connects → honeypot logs "Attacker IP: x.x.x.x" to trap.log
  3. This MDR daemon detects the new log entry (polling trap.log)
  4. Runs: iptables -I INPUT 1 -s <IP> -j DROP
  5. Attacker is blocked from ALL ports immediately

The iptables rule is inserted at position 1 (highest priority), ensuring
it takes effect before any ACCEPT rules.

Usage:
  sudo python3 blue_mdr_network.py                      # default trap.log
  sudo python3 blue_mdr_network.py --log /path/trap.log
  sudo python3 blue_mdr_network.py --cleanup             # remove all rules on exit
================================================================================
"""
import os
import sys
import re
import subprocess
import time
import json
import argparse
import signal

# ═══════════════════════════════════════════════════════════════
#  IP Extraction & Validation
# ═══════════════════════════════════════════════════════════════

IP_PATTERN = re.compile(r'Attacker IP:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')


def is_valid_ip(ip: str) -> bool:
    """Basic IPv4 validation."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            return False
    return True


# ═══════════════════════════════════════════════════════════════
#  iptables Management
# ═══════════════════════════════════════════════════════════════

def block_ip(ip: str) -> bool:
    """Add iptables DROP rule for the given IP at position 1 (highest priority)."""
    result = subprocess.run(
        ['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'],
        capture_output=True, text=True)
    return result.returncode == 0


def unblock_ip(ip: str) -> bool:
    """Remove iptables DROP rule for the given IP."""
    result = subprocess.run(
        ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
        capture_output=True, text=True)
    return result.returncode == 0


def is_already_blocked(ip: str) -> bool:
    """Check if an iptables rule already exists for this IP."""
    result = subprocess.run(
        ['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
        capture_output=True, text=True)
    return result.returncode == 0


# ═══════════════════════════════════════════════════════════════
#  trap.log Watcher
# ═══════════════════════════════════════════════════════════════

class TrapLogWatcher:
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.offset = 0
        self.blocked_ips = set()
        self.block_count = 0

        # If log already exists, skip to the end (only watch new entries)
        if os.path.exists(log_path):
            self.offset = os.path.getsize(log_path)

    def check_new_entries(self) -> list[str]:
        """Read new lines from trap.log and return newly discovered IPs."""
        if not os.path.exists(self.log_path):
            return []

        current_size = os.path.getsize(self.log_path)
        if current_size <= self.offset:
            if current_size < self.offset:
                # File was truncated, reset
                self.offset = 0
            return []

        new_ips = []
        with open(self.log_path, 'r') as f:
            f.seek(self.offset)
            for line in f:
                match = IP_PATTERN.search(line)
                if match:
                    ip = match.group(1)
                    if is_valid_ip(ip) and ip not in self.blocked_ips:
                        new_ips.append(ip)
            self.offset = f.tell()

        return new_ips

    def process_ip(self, ip: str) -> bool:
        """Block an IP and record it."""
        if is_already_blocked(ip):
            self.blocked_ips.add(ip)
            return False

        if block_ip(ip):
            self.blocked_ips.add(ip)
            self.block_count += 1
            return True
        return False

    def cleanup(self):
        """Remove all iptables rules we added."""
        for ip in list(self.blocked_ips):
            if unblock_ip(ip):
                print(f'  [-] Unblocked {ip}')


# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════

def main():
    # Default trap.log path: project root (matches honeypot.py default)
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _project_root = os.path.dirname(_script_dir)  # blue_team/ → project root
    _default_log = os.path.join(_project_root, 'trap.log')

    ap = argparse.ArgumentParser(
        description='Blue Team Network MDR (Honeypot + iptables)')
    ap.add_argument('--log', default=_default_log,
                    help=f'Path to trap.log (default: {_default_log})')
    ap.add_argument('--interval', type=float, default=1.0,
                    help='Poll interval in seconds (default: 1.0)')
    ap.add_argument('--cleanup', action='store_true',
                    help='Remove all iptables rules on exit')
    ap.add_argument('--soc-log', type=str, default='',
                    help='Write events to JSONL file for SOC dashboard')
    args = ap.parse_args()

    if os.geteuid() != 0:
        print('[!] iptables requires root.  Run with: sudo')
        sys.exit(1)

    watcher = TrapLogWatcher(args.log)

    # Cleanup handler
    if args.cleanup:
        def on_exit(sig, frame):
            print('\n[*] Cleaning up iptables rules...')
            watcher.cleanup()
            print(f'[*] MDR stopped.  Blocks={watcher.block_count}')
            sys.exit(0)
        signal.signal(signal.SIGINT, on_exit)
        signal.signal(signal.SIGTERM, on_exit)

    # Banner
    print('\033[94m')
    print('+' + '=' * 52 + '+')
    print('|   Blue Team  Network MDR  v1.0                   |')
    print('|   Honeypot Trap Monitor + iptables Auto-Block     |')
    print('+' + '=' * 52 + '+')
    print('\033[0m')
    print(f'  Log file : {os.path.abspath(args.log)}')
    print(f'  Interval : {args.interval}s')
    cleanup_str = ('\033[92mYES\033[0m' if args.cleanup
                   else '\033[93mNO (rules persist)\033[0m')
    print(f'  Cleanup  : {cleanup_str}')
    print()
    print('[*] Monitoring trap.log...  (Ctrl+C to stop)\n')

    hdr = f"{'TIME':<10} {'ACTION':<10} {'IP':<18} {'STATUS'}"
    print(hdr)
    print('\u2500' * 60)

    def soc_write(evt):
        if args.soc_log:
            with open(args.soc_log, 'a') as f:
                f.write(json.dumps(evt) + '\n')

    try:
        while True:
            new_ips = watcher.check_new_entries()
            for ip in new_ips:
                ts = time.strftime('%H:%M:%S')
                ts_full = time.strftime('%Y-%m-%d %H:%M:%S')
                if watcher.process_ip(ip):
                    print(f'{ts:<10} '
                          f'\033[91mBLOCK\033[0m      '
                          f'{ip:<18} '
                          f'iptables -I INPUT 1 -s {ip} -j DROP')
                    print(f'\033[91m    \u2570\u2500\u25b6 '
                          f'Attacker {ip} blocked from ALL ports!\033[0m')
                    soc_write({
                        'ts': ts_full, 'source': 'NETWORK_MDR',
                        'event': 'IP_BLOCKED', 'severity': 'HIGH',
                        'ip': ip, 'action': 'BLOCKED',
                        'detail': f'iptables DROP {ip}',
                    })
                else:
                    print(f'{ts:<10} '
                          f'\033[93mSKIP\033[0m       '
                          f'{ip:<18} '
                          f'already blocked')

            time.sleep(args.interval)
    except KeyboardInterrupt:
        if not args.cleanup:
            print(f'\n[*] MDR stopped.  Blocks={watcher.block_count}  '
                  f'(rules still active)')
            print(f'    Blocked IPs: {sorted(watcher.blocked_ips)}')
            print('    To remove: sudo iptables -D INPUT -s <IP> -j DROP')


if __name__ == '__main__':
    main()
