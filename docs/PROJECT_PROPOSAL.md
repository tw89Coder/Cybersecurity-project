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
5. [Conclusion](#5-conclusion)
6. [References](#6-references)

---

## 1. Introduction

### 1.1 Project Motivation

Most network security courses teach attacks and defenses separately -- students learn about vulnerability categories, study defense checklists, and maybe run a few Wireshark captures. But real-world security is adversarial and iterative: attackers adapt when they get blocked, defenders upgrade when they get bypassed, and this back-and-forth never really stops. That gap between textbook knowledge and practical experience is what this project tries to address.

The specific attack surface we focus on is covert C2 channels, particularly ICMP tunneling. ICMP is a good case study because most firewalls let it through (blocking it breaks ping and traceroute), and its data payload field is essentially unmonitored in most environments [2]. Real APT groups already exploit this -- MITRE ATT&CK documents ICMP-based C2 in tools like PingPull, Regin, and Cobalt Strike [4]. On the defense side, we use eBPF to do kernel-level behavioral detection, which is interesting because it can catch malicious activity regardless of how well the attacker encrypts their traffic.

### 1.2 Project Objectives

The goal is to build a controlled red-blue team exercise where both sides escalate over multiple rounds. Specifically, we want to:

1. Implement a realistic attack chain covering reconnaissance through C2, mapped to the MITRE ATT&CK framework and the Cyber Kill Chain model.
2. Build a defense-in-depth setup with two layers -- network-level deception (honeypot + firewall blocking) and kernel-level behavioral detection (eBPF syscall monitoring with real-time process termination).
3. Structure the exercise as a 7-round engagement where the red team develops evasion techniques and the blue team upgrades detection in response, so students can see how this adversarial cycle actually plays out.
4. Tie everything together with a SOC dashboard that gives the blue team a unified view of what is happening across all defensive components.

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

Every step is documented with exact commands and expected outputs in `docs/DEMO_FLOW.md` so any team member can reproduce the full exercise.

---

## 2. Background and Analytical Frameworks

### 2.1 The Cyber Kill Chain

The Lockheed Martin Cyber Kill Chain [3] breaks down a cyberattack into seven sequential phases: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command and Control (C2), and Actions on Objectives.

We implement six of the seven phases (excluding Actions on Objectives for safety reasons):

```
Phase 1        Phase 2           Phase 3        Phase 4          Phase 5       Phase 6
Recon    →   Weaponize     →   Deliver    →   Exploit      →   Install   →   C2
nmap         memfd_create       SSTI POST      fork+execve      in-memory     ICMP/TCP
             + AES-256-CTR      via curl       from /proc/fd    agent         covert channel
```

### 2.2 MITRE ATT&CK Framework

MITRE ATT&CK is a knowledge base of adversary behavior based on real-world observations [4]. We map all our implemented techniques to ATT&CK identifiers:

| Tactic | Technique ID | Technique Name | Implementation |
|--------|-------------|----------------|----------------|
| Reconnaissance | T1595 | Active Scanning | nmap port and service scanning |
| Initial Access | T1190 | Exploit Public-Facing Application | SSTI injection via Flask/Jinja2 |
| Execution | T1059.006 | Command and Scripting Interpreter: Python | memfd loader, reverse shell, C2 agent |
| Defense Evasion | T1620 | Reflective Code Loading | memfd_create + execve from /proc/pid/fd |
| Defense Evasion | T1027 | Obfuscated Files or Information | Base64 encoding + AES-256-CTR encryption |
| Command and Control | T1095 | Non-Application Layer Protocol | ICMP covert channel + TCP reverse shell |
| Command and Control | T1571 | Non-Standard Port | C2 and reverse shell on port 4444 |
| Exfiltration | T1048.003 | Exfiltration Over Alternative Protocol | DNS/ICMP data exfiltration |

### 2.3 Extended Berkeley Packet Filter (eBPF)

eBPF allows sandboxed programs to run in Linux kernel space without modifying kernel source code or loading kernel modules [5]. Originally designed for packet filtering, it has since become a general-purpose in-kernel virtual machine used for networking, observability, and security.

What makes eBPF useful for our defense layer:

- **Kernel-space execution**: eBPF programs see all syscalls with zero context-switch overhead, and userspace processes cannot evade them.
- **Safety guarantees**: The eBPF verifier checks every program before loading -- no unbounded loops, no out-of-bounds access, no kernel crashes.
- **Active response**: Since Linux 5.3, `bpf_send_signal()` lets eBPF programs send SIGKILL directly from kernel space, so we can terminate a malicious process without a userspace round-trip [6].
- **Tracepoint hooks**: We attach to syscall entry points (`sys_enter_*`), which fire before the syscall handler runs. This means we can detect and block operations before they complete.

In this project, we hook six tracepoints: `sys_enter_memfd_create`, `sys_enter_execve`, `sys_enter_socket`, `sys_enter_connect`, `sys_enter_dup2`, and `sys_enter_dup3`.

### 2.4 Cyber Deception and Honeypots

Cyber deception uses decoy systems to detect and analyze adversary behavior [7]. A honeypot is a security resource that has no legitimate purpose -- any interaction with it is inherently suspicious.

We deploy a low-interaction honeypot emulating an SSH server on port 2222. When an attacker connects during reconnaissance, the honeypot logs the source IP and triggers automated firewall blocking via iptables. Since no legitimate user has any reason to connect to this service, every connection is unauthorized by definition, which means zero false positives.

### 2.5 AES-256-CTR Encryption via OpenSSL

AES in Counter (CTR) mode is a NIST-standardized symmetric encryption scheme [8]. AES-256-CTR works as a stream cipher: it encrypts successive counter values with AES-256 to produce a keystream, then XORs that keystream with the plaintext.

We use CTR mode for the C2 channel because it does not require padding (ciphertext is the same length as plaintext, which matters for ICMP payloads with size constraints), and with a random IV per message, identical plaintexts produce different ciphertexts. The implementation calls OpenSSL's libcrypto through Python ctypes, so we get real encryption without needing any pip-installed packages.

---

## 3. Problems and Attack Descriptions

### 3.1 Server-Side Template Injection (SSTI)

**Problem**: The target application (`target_app.py`) is a Flask web app that uses Python f-string interpolation to embed user input directly into a Jinja2 template before rendering. This is a textbook Server-Side Template Injection vulnerability (CWE-1336) [9].

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

---

## 5. Conclusion

This project demonstrates that no single defense layer is enough on its own. Network-layer defenses like honeypots and firewalls get bypassed as soon as the attacker changes their IP. Kernel-layer detection (eBPF v1) works until the attacker switches to a different set of syscalls. It is only by stacking multiple independent detection mechanisms that we get something reasonably robust.

The 7-round structure makes this concrete. When eBPF v1 killed the fileless ICMP C2 agent, the red team pivoted to a standard TCP reverse shell that did not trigger any of the monitored hooks. The blue team had to deploy eBPF v2 with additional hooks for `connect()` and `dup2()` to catch the new technique. This kind of back-and-forth is what real security operations look like, and it is hard to appreciate from reading about it in a textbook.

The encryption upgrade from XOR to AES-256-CTR is also instructive. Making the C2 traffic unreadable through payload inspection did nothing to stop eBPF detection, because eBPF watches what the process *does* (which syscalls it makes) rather than what the traffic *contains*. This is a useful lesson for understanding why behavioral detection matters.

On the visibility side, the SOC dashboard turned out to be more useful than expected for understanding the full attack picture. Without it, the blue team would be looking at isolated log files from different components and trying to mentally piece together what happened.

Overall, the project implements 7 ATT&CK techniques and 7 corresponding detection capabilities across two defense layers, giving us hands-on experience with both offensive and defensive operations in a controlled environment.

---

## 6. References

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
