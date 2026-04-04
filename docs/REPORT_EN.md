# Advanced Red-Blue Team Technical Analysis Report

## 1. Executive Summary

This project implements a complete Cyberattack Kill Chain exercise with three core components:

| Component | File | Role |
|-----------|------|------|
| Target | `target_app.py` | Flask web service with SSTI vulnerability |
| Red Team | `red_attacker.py` | Fileless attack (memfd_create) + ICMP covert C2 |
| Blue Team | `blue_ebpf_mdr.py` | eBPF real-time detection & kernel-level kill |

This report focuses on the **underlying principles**, **purpose**, and **impact on the target system** for each attack and defense action.

---

## 2. Environment Architecture

```
┌──────────────────┐         ┌──────────────────┐
│  Attacker (WSL2) │  ICMP   │  Target Machine  │
│                  │◄═══════►│                  │
│  red_attacker.py │         │  target_app.py   │
│  (C2 Server)     │         │  (Flask :9999)   │
│                  │         │                  │
│                  │         │  blue_ebpf_mdr.py│
│                  │         │  (eBPF Monitor)  │
└──────────────────┘         └──────────────────┘
```

- **Attacker**: WSL2 Linux (Ubuntu 22.04/24.04), root privileges
- **Target**: Linux server running vulnerable Flask service
- **Protocol**: ICMP Echo Request (Type 8) — no TCP/UDP used

---

## 3. Kill Chain Phase Analysis

### Phase 1: Reconnaissance

**Action**: Identify the `/diag` endpoint and its `query` input parameter.

**Principle**: Web reconnaissance focuses on mapping the **attack surface** — input points where user-controlled data enters the application. The `/diag` endpoint reflects user input in its response without sanitization, suggesting a potential injection vulnerability.

**Impact**: Confirms the attack vector and injection point for weaponization.

---

### Phase 2: Weaponization

**Action**: Construct SSTI payload + memfd_create fileless loader.

#### 2.1 SSTI (Server-Side Template Injection) Mechanism

Flask uses Jinja2 as its template engine. Jinja2 evaluates Python expressions inside `{{ }}` delimiters.

**Root Cause — Two-Step Composition Flaw**:

```python
# Step 1: Python f-string embeds user input into template SOURCE CODE
template = f"Query: {user_input}"
# If user_input = "{{ 7*7 }}", the resulting string is "Query: {{ 7*7 }}"

# Step 2: Jinja2 evaluates {{ 7*7 }} as an expression → 49
render_template_string(template)
```

**Safe pattern** — pass user data as a Jinja2 *variable*, not template source:
```python
render_template_string("Query: {{ q }}", q=user_input)
# Jinja2 treats q as data, never code
```

**SSTI → RCE Escalation Path**:

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
3. Jinja2's sandbox restricts attribute names starting with `_`, but the traversal chain uses `__class__`, `__init__`, `__globals__` — the sandbox checks apply to the attribute *name*, not the resolution result

**Impact**: Full Remote Code Execution (RCE) with the Flask process privileges.

#### 2.2 Fileless Execution via memfd_create

**Problem**: Traditional malware writes executables to disk (`/tmp/backdoor`), creating file artifacts detectable by filesystem watchers (inotify), on-access AV scanners, and forensic analysis.

**Solution**: Linux `memfd_create(2)` system call (syscall 319 on x86_64).

**Core Mechanism**:

```
memfd_create(name, flags) → fd
```

1. Creates an **anonymous file** in the kernel's **tmpfs layer**
2. Returns a file descriptor (fd) that behaves like a regular file
3. The fd is **NOT linked to any directory entry** — invisible in all mounted filesystems
4. Content resides in **page cache (RAM)**, never written to a block device
5. `/proc/<pid>/fd/<N>` provides a synthetic path for `execve()`

**Attack Chain**:

```
fd = syscall(319, "", 0)          # anonymous fd in RAM
os.write(fd, agent_code)           # write payload to fd (still in RAM)
os.fork()                          # fork: parent returns for Flask response
  ├── parent: exits                # popen() completes, HTTP response sent
  └── child: execve(python3,       # execute agent from memfd
        /proc/<pid>/fd/<N>)        # kernel resolves path → reads memfd → RCE
```

**Why `/proc/<pid>/fd/N` works with execve**:
- procfs is a virtual filesystem; each fd entry is a symlink to the kernel's `struct file` object
- `execve()` resolves the symlink, reaches the anonymous inode, and reads the memfd content
- `fork()` duplicates the fd table — the child's fd copy remains valid even after the parent exits

**Why fork() is necessary**:
- The SSTI `popen()` subprocess must exit promptly for Flask to return the HTTP response
- `fork()` creates a child that runs independently; when the parent exits, the child becomes an orphan, re-parented to PID 1
- The child's memfd fd is a duplicate (fork copies fd table), so the memfd remains valid

**Impact**: Zero file artifacts on disk. Evades all file-based AV/EDR detection.

#### 2.3 Double Base64 Encoding

The payload uses double base64 encoding to eliminate **all** escaping issues:

```
[Agent Python source]
    → base64 encode → agent_b64
        → embed in Loader Python script
            → base64 encode → loader_b64
                → embed in SSTI string: echo loader_b64 | base64 -d | python3
                    → URL encode → curl -d "query=..."
```

**Why double, not single**: The SSTI string uses single quotes to wrap the shell command. If the loader script contains quotes or special characters, it breaks the SSTI syntax. Base64 output only contains `A-Za-z0-9+/=`, which are safe in both shell and Jinja2 contexts.

---

### Phase 3: Delivery

**Action**: Send SSTI payload via HTTP POST to `/diag`.

```bash
curl -s -X POST http://TARGET:9999/diag -d "query=SSTI_PAYLOAD"
```

**Principle**: The URL-encoded `query=` parameter in the POST body is decoded by Flask's `request.form.get('query')`, restoring the complete `{{ }}` expression. The f-string then embeds this into the template source, and Jinja2 evaluates it.

**Impact**: Triggers SSTI → RCE → memfd_create → fork+execve → memory-resident agent.

---

### Phase 4: Exploitation & Installation

**Action**: Establish XOR-encrypted ICMP covert C2 channel.

#### 4.1 ICMP Covert Channel Principles

ICMP (Internet Control Message Protocol, RFC 792) is a Layer 3 protocol for network diagnostics.

**Why ICMP is suitable for covert channels**:
1. Firewalls typically **allow ICMP by default** (blocking breaks ping/traceroute)
2. ICMP Echo Request/Reply carry an **arbitrary-length data payload** — the protocol imposes no constraints on content
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
┌────────────��────────────────────────────────────────┐
│ IP Header (20B) │ ICMP Header (8B) │ Payload        │
│                 │ type=8 code=0    │ ┌─────────────┐│
│                 │ checksum         │ │ MAGIC  (1B) ││
│                 │ ID=0x1337        │ │ MSG_TYPE(1B)││
│                 │ SEQ              │ │ XOR data    ││
│                 │                  │ └─────────────┘│
└──────────────────────────────────────���──────────────┘

MSG_TYPE:
  0x01 = Heartbeat (Agent → C2)
  0x02 = Command   (C2 → Agent)
  0x03 = Result    (Agent → C2, chunked with [idx:u16][total:u16] header)
```

Both sides send ICMP type 8 (echo request) and ignore type 0 (echo reply), since kernel auto-replies carry the original payload, not C2 commands.

#### 4.2 XOR Encryption Principles

```
ciphertext[i] = plaintext[i] ⊕ key[i % len(key)]
```

**Properties**:
- **Symmetric**: same operation encrypts and decrypts (A ⊕ K ⊕ K = A)
- **Zero dependencies**: no cryptographic library required
- **Fast**: single CPU instruction per byte

**Cryptographic Limitations** (important for academic analysis):
- **Known-plaintext attack**: if the attacker knows any plaintext byte, they recover the corresponding key byte
- **Key reuse**: identical key + identical plaintext = identical ciphertext (no IV/nonce)
- **NOT cryptographically secure**: real operations require AES-GCM or ChaCha20-Poly1305
- Sufficient for demonstrating the *concept* of encrypted C2 in this lab

#### 4.3 ICMP Checksum (RFC 1071)

```
1. Treat the packet as a sequence of 16-bit big-endian integers
2. Sum all integers using ones' complement addition (carry wraps around)
3. Take the ones' complement (bitwise NOT) of the final sum
```

The receiver performs the same calculation over the entire packet including the checksum field; a result of `0xFFFF` indicates validity.

---

### Phase 5: Command & Control

**Action**: Agent sends periodic heartbeats, receives and executes C2 commands.

**Agent Execution Loop**:
1. Initial heartbeat: transmit hostname, UID, kernel version
2. Repeat heartbeat every 30 seconds
3. Receive MSG_COMMAND → `subprocess.run(cmd, shell=True)` execution
4. Split output into 480-byte chunks → encrypt and transmit each
5. On `__exit__` → close socket and terminate

**Timing Jitter**:
```python
time.sleep(random.uniform(1.0, 2.5))  # random delay each loop iteration
time.sleep(0.05)                       # 50ms inter-chunk delay
```
Random delays make traffic pattern analysis (e.g., periodic beacon detection) more difficult for the blue team.

**Impact**: Full remote shell access, with communication hidden inside ICMP traffic.

---

### Phase 6: Actions on Objectives

**Action**: Execute arbitrary commands via the C2 shell.

Example reconnaissance commands:
```
whoami          → confirm execution identity
id              → UID/GID information
uname -a        → OS and kernel version
cat /etc/passwd → user enumeration
env             → environment variables (may contain secrets)
```

---

## 4. Blue Team Defense Analysis

### 4.1 eBPF Architecture

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
- Sees ALL syscalls before they execute (tracepoints on sys_enter_*)
- Can read process metadata (PID, UID, comm) from kernel task_struct
- Can actively respond: `bpf_send_signal()` kills processes from kernel space
- Cannot be evaded by userspace anti-debugging or rootkit techniques

### 4.2 Tracepoint vs Kprobe

| Property | Tracepoint | Kprobe |
|----------|-----------|--------|
| Type | Static (compiled into kernel) | Dynamic (runtime injection) |
| Stability | Stable ABI across versions | Function signatures may change |
| Trigger timing | Syscall entry/exit | Any kernel function |
| Use case | Syscall monitoring | Deep kernel debugging |

We choose **Tracepoints** because:
1. `sys_enter_*` fires BEFORE the syscall executes → preemptive kill possible
2. Stable across kernel 5.x–6.x
3. BCC provides clean `TRACEPOINT_PROBE()` macros

### 4.3 bpf_send_signal(SIGKILL) Mechanism

Available since Linux 5.3. This BPF helper sends a signal to the CURRENT task (the process that triggered the tracepoint).

**Why more effective than userspace kill()**:

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

**Key difference**: With `bpf_send_signal`, the process is killed BEFORE the `memfd_create` syscall handler runs. The attack chain is broken at the very first step.

### 4.4 Triple-Hook Detection Strategy

| Hook | Syscall | Detection Logic | Severity |
|------|---------|----------------|----------|
| Hook 1 | `memfd_create(319)` | Any invocation → record PID + alert | HIGH |
| Hook 2 | `execve` | Path matches `/proc/*/fd/*` → fileless exec confirmed | CRITICAL |
| Hook 3 | `socket` | AF_INET + SOCK_RAW + ICMP + PID correlates with memfd | CRITICAL |

**Correlation Detection (Multi-Indicator)**:
- memfd_create alone → HIGH (could be legitimate: Chrome IPC, systemd)
- Raw ICMP socket alone → ALERT (could be ping)
- memfd_create **+** raw ICMP socket → **CRITICAL + CORRELATED** (fileless C2 confirmed)

**Cold-Start Detection**: `/proc/*/exe` scanner checks for already-running memfd processes at startup, covering the gap before eBPF hooks are active.

### 4.5 eBPF Data Structures

**BPF_PERF_OUTPUT (Perf Ring Buffer)**:
- Lock-free circular buffer shared between kernel and userspace via mmap
- Kernel writes events; Python reads events
- Zero-copy communication

**BPF_HASH (Hash Map)**:
- Shared hash table between kernel and userspace
- `memfd_pids`: tracks PIDs that called memfd_create
- `whitelist`: userspace writes safe PIDs, kernel reads during hook execution

---

## 5. MITRE ATT&CK Mapping

### Red Team Techniques

| ID | Technique | Implementation |
|----|-----------|---------------|
| T1190 | Exploit Public-Facing Application | SSTI injection into Flask /diag |
| T1059.006 | Command & Scripting: Python | memfd_create loader + agent |
| T1620 | Reflective Code Loading | memfd_create → execve from /proc/fd |
| T1027 | Obfuscated Files or Information | Double Base64 + XOR encryption |
| T1140 | Deobfuscate/Decode | base64 -d pipeline in shell |
| T1095 | Non-Application Layer Protocol | ICMP echo request C2 channel |
| T1071.001 | Application Layer Protocol | Custom protocol inside ICMP payload |
| T1036 | Masquerading | ICMP traffic disguised as normal pings |

### Blue Team Detection

| ID | Detection Surface | Implementation |
|----|-------------------|---------------|
| T1620 | Reflective Code Loading | Hook memfd_create tracepoint |
| T1059 | Command Execution | Hook execve from /proc/*/fd/* |
| T1095 | Non-App Layer Protocol | Hook socket(RAW, ICMP) |
| T1070 | Indicator Removal | /proc/*/exe scan for memfd processes |

---

## 6. Security Considerations & Limitations

### 6.1 XOR Encryption Weakness
- No IV/nonce → susceptible to frequency analysis
- Known-plaintext attack: heartbeat format (hostname, etc.) is partially predictable, allowing key recovery
- Production recommendation: AES-256-GCM or ChaCha20-Poly1305

### 6.2 ICMP Channel Bandwidth
- ~480 bytes payload per ICMP packet
- With jitter delays, effective throughput is extremely low
- Not suitable for large data exfiltration; appropriate for command/control

### 6.3 eBPF Detection Bypass Possibilities
- Attacker could use `shm_open()` instead of `memfd_create` (requires additional hook)
- Attacker could use `fexecve()` instead of execve with /proc path
- Advanced: `ptrace` injection into existing processes (no execve needed)
- Mitigation: add more hook points, or combine with seccomp-BPF

### 6.4 Lab vs Production Environment
- This lab assumes Flask runs as root (providing CAP_NET_RAW)
- In production, web services typically run as low-privilege users
- ICMP raw socket requires additional privilege escalation steps
- eBPF detection should be part of a layered defense, not a standalone solution

---

## 7. Conclusion

This project demonstrates a complete Kill Chain attack-defense cycle:

1. **Attack Surface**: SSTI vulnerability arises from unsafe composition of f-string interpolation and Jinja2 template rendering
2. **Weaponization**: `memfd_create` enables 100% fileless execution, evading traditional file-based detection
3. **C2 Channel**: ICMP covert channel exploits protocol characteristics to bypass firewalls and IDS
4. **Defense**: eBPF provides zero-latency kernel-space detection and response

**Core Insight**: Modern attacks need not leave any artifacts on disk. Defenders must monitor syscall behavior at the kernel level rather than relying solely on file scanning. eBPF provides this capability without impacting system performance.
