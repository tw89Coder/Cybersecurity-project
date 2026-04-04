#!/usr/bin/env python3
"""
honeypot.py - Fake SSH Honeypot (Cyber Deception)
================================================================================
MITRE ATT&CK : T1595 (Active Scanning — triggers detection)
Defence       : Cyber Deception / Honeypot
Kill Chain    : Disrupts Phase 1 Reconnaissance

PRINCIPLE — Why Honeypots Work
-------------------------------
A honeypot is a decoy service that LOOKS legitimate but exists solely to
detect unauthorized access.  Any interaction with the honeypot is suspicious
by definition — legitimate users have no reason to connect.

This honeypot mimics an OpenSSH server on port 2222:
  1. Sends a realistic SSH version banner (SSH-2.0-OpenSSH_8.9p1)
  2. Waits briefly for the attacker's client to send data
  3. Returns a fake "Permission denied" message
  4. Logs the attacker's IP, timestamp, and any data received to trap.log

The trap.log file is monitored by blue_mdr_network.py, which reads new
attacker IPs and immediately blocks them with iptables.

Attack scenario:
  1. Red team runs nmap → discovers port 2222 (looks like SSH)
  2. Red team connects: nc <TARGET> 2222
  3. Honeypot logs IP → MDR reads trap.log → iptables DROP
  4. Red team's IP is now blocked from ALL ports
  5. Red team must use ip_switch.sh to get a new IP

Usage:
  sudo python3 honeypot.py                    # default port 2222
  sudo python3 honeypot.py --port 2222 --log trap.log
================================================================================
"""
import socket
import threading
import argparse
import time
import os
import sys

# ═══════════════════════════════════════════════════════════════
#  Fake SSH Banner
#
#  SSH protocol (RFC 4253) requires the server to send a version
#  string as the first message: "SSH-protoversion-softwareversion"
#  followed by CR LF.  This banner is indistinguishable from a
#  real OpenSSH server to nmap service detection (-sV).
# ═══════════════════════════════════════════════════════════════

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"

FAKE_RESPONSE = (
    b"\r\n"
    b"Permission denied (publickey,password).\r\n"
    b"Connection closed by remote host.\r\n"
)


def handle_client(conn, addr, log_path, verbose):
    """Handle a single honeypot connection."""
    ip = addr[0]
    port = addr[1]
    ts = time.strftime('%Y-%m-%d %H:%M:%S')

    if verbose:
        print(f'\033[91m[!] TRAP  {ts}  {ip}:{port}\033[0m')

    # Collect any data the attacker sends (SSH client hello, etc.)
    client_data = b''
    try:
        # Send fake SSH banner
        conn.sendall(SSH_BANNER)

        # Wait for client data (SSH clients send their version string)
        conn.settimeout(5.0)
        try:
            client_data = conn.recv(4096)
        except socket.timeout:
            pass

        # Send fake rejection and close
        time.sleep(0.5)
        conn.sendall(FAKE_RESPONSE)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass

    # Log to trap.log — format parsed by blue_mdr_network.py
    client_str = client_data.decode(errors='replace').strip()[:100]
    log_line = f"[{ts}] Attacker IP: {ip} Port: {port} Data: {client_str}\n"

    try:
        with open(log_path, 'a') as f:
            f.write(log_line)
    except OSError as e:
        print(f'[!] Failed to write trap.log: {e}')

    if verbose:
        print(f'    Logged: {ip} → {log_path}')
        if client_str:
            print(f'    Client sent: {client_str[:80]}')


def main():
    ap = argparse.ArgumentParser(description='Fake SSH Honeypot')
    ap.add_argument('--port', type=int, default=2222,
                    help='Listen port (default 2222)')
    ap.add_argument('--host', default='0.0.0.0',
                    help='Bind address (default 0.0.0.0)')
    ap.add_argument('--log', default='trap.log',
                    help='Log file path (default trap.log)')
    ap.add_argument('--quiet', action='store_true',
                    help='Suppress console output')
    args = ap.parse_args()

    verbose = not args.quiet

    # Bind socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((args.host, args.port))
    except PermissionError:
        print(f'[!] Cannot bind port {args.port}. Run with: sudo')
        sys.exit(1)
    except OSError as e:
        print(f'[!] Bind failed: {e}')
        sys.exit(1)
    srv.listen(5)

    print(f"\033[93m{'='*55}")
    print(f"  Honeypot (Fake SSH) | {args.host}:{args.port}")
    print(f"  Banner: {SSH_BANNER.decode().strip()}")
    print(f"  Log:    {os.path.abspath(args.log)}")
    print(f"{'='*55}\033[0m")
    print("[*] Waiting for connections...\n")

    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, args.log, verbose),
                daemon=True)
            t.start()
    except KeyboardInterrupt:
        print('\n[*] Honeypot stopped.')
    finally:
        srv.close()


if __name__ == '__main__':
    main()
