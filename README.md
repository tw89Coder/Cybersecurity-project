# Enterprise Attack-Defense Lab

> Cyberattack Kill Chain 攻防演練專案
> A comprehensive red-blue team exercise based on the Cyberattack Kill Chain framework.

---

## Team / 組員

| Name | Role | Responsibilities |
|------|------|-----------------|
| <!-- add name --> | Red Team | Reconnaissance, exploitation, C2 |
| <!-- add name --> | Blue Team | eBPF detection, incident response |
| <!-- add name --> | Target / Docs | Vulnerable app, reporting |

---

## Project Structure / 專案結構

```
.
├── target/                     # Vulnerable target services
│   └── target_app.py           #   Flask SSTI vulnerable API
│
├── red_team/                   # Red team attack tooling
│   ├── red_attacker.py         #   Fileless ICMP C2 (memfd_create + XOR)
│   ├── red_reverse_shell.py    #   TCP reverse shell (eBPF v1 bypass) ← NEW
│   ├── exploit.py              #   WAF bypass exploit (Base64 + ${IFS})
│   ├── recon.sh                #   nmap reconnaissance
│   ├── post_exploit.sh         #   Post-exploitation enumeration
│   ├── ip_switch.sh            #   IP alias for MDR bypass
│   ├── deploy_agent.sh         #   Exfil agent deployment helper
│   ├── exfil_agent.py          #   DNS/ICMP data exfiltration agent
│   └── exfil_listener.py       #   Exfiltration listener (attacker side)
│
├── blue_team/                  # Blue team defense tooling
│   ├── blue_ebpf_mdr.py       #   eBPF v1: memfd + ICMP detection
│   └── blue_ebpf_mdr_v2.py    #   eBPF v2: + reverse shell detection ← NEW
│
├── docs/                       # Documentation & reports
│   ├── DEMO_FLOW.md            #   Complete 6-round demo script ← NEW
│   ├── RED_TEAM_PLAYBOOK.md    #   Attack playbook (6-phase kill chain)
│   ├── REPORT_ZH.md            #   Technical analysis report (Chinese)
│   ├── REPORT_EN.md            #   Technical analysis report (English)
│   ├── exfiltration-design.md  #   Exfiltration system specification
│   └── exfiltration-plan.md    #   Exfiltration implementation plan
│
├── setup_env.sh                # One-command environment setup
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

---

## Quick Start / 快速開始

### 1. Environment Setup / 環境安裝

```bash
git clone https://github.com/<org>/<repo>.git
cd <repo>
bash setup_env.sh
```

**Requirements**: Ubuntu 22.04/24.04 (WSL2 or VM), root access.

**System packages**: python3, flask, bpfcc-tools, python3-bpfcc, linux-headers, nmap, tcpdump

### 2. Execution Order / 執行順序

Open four terminals. Run commands **from the project root directory**.

> **Complete Demo**: See [docs/DEMO_FLOW.md](docs/DEMO_FLOW.md) for the full 6-round demo script with detailed commands and expected outputs.

**Quick Start (basic 2-scenario test):**

```bash
# Terminal 1 — Target (靶機)
sudo python3 target/target_app.py

# Terminal 2 — Blue Team (藍軍 eBPF v2)
sudo python3 blue_team/blue_ebpf_mdr_v2.py --kill

# Terminal 3 — Red Team C2 (紅軍 C2 Server)
sudo python3 red_team/red_attacker.py -t <TARGET_IP> -l <ATTACKER_IP>

# Terminal 4 — Red Team Attack (紅軍觸發攻擊)
# Paste the curl command printed by Terminal 3
```

### 3. Expected Results / 預期結果

| Scenario | What Happens |
|----------|-------------|
| Blue team **OFF** | Agent deploys in-memory, C2 shell obtained |
| Blue team v1 **ON** (`--kill`) | eBPF detects `memfd_create`, kills process before execution |
| Red team **reverse shell** (v1 bypass) | TCP shell bypasses v1 detection entirely |
| Blue team **v2 ON** (`--kill`) | Detects `connect()` to suspect port + `dup2` fd hijack, kills reverse shell |

---

## Kill Chain Overview / 攻擊鏈概覽

```
Phase 1        Phase 2           Phase 3        Phase 4          Phase 5       Phase 6
Recon    →   Weaponize     →   Deliver    →   Exploit      →   Install   →   C2
nmap         memfd_create       SSTI POST      fork+execve      in-memory     ICMP
recon.sh     + XOR ICMP C2      curl cmd       from /proc/fd    agent         commands
             red_attacker.py    target_app.py                                 heartbeat

Phase 5b (Evasion — bypasses blue v1, caught by v2)
Evasion  →   Deliver    →   Exploit      →   C2
fork()       SSTI POST      connect()        TCP reverse
+ TCP        curl cmd       + dup2(0,1,2)    shell via pty
reverse_shell.py             pty.spawn
```

---

## Technical Highlights / 技術亮點

### Red Team / 紅軍

| Technique | Principle | File |
|-----------|-----------|------|
| **SSTI** | f-string + `render_template_string` → Jinja2 evaluates `{{ }}` as code | `target/target_app.py` |
| **Fileless Execution** | `memfd_create` (syscall 319) creates anonymous RAM-only fd; `execve` via `/proc/pid/fd/N` | `red_team/red_attacker.py` |
| **ICMP Covert C2** | Data hidden in ICMP echo-request payload; XOR encrypted; no TCP/UDP | `red_team/red_attacker.py` |
| **TCP Reverse Shell** | `fork` → `connect` → `dup2(fd,0/1/2)` → `pty.spawn` — bypasses eBPF v1 | `red_team/red_reverse_shell.py` |
| **WAF Bypass** | `${IFS}` space evasion + Base64 encoding + backslash obfuscation | `red_team/exploit.py` |
| **DNS/ICMP Exfil** | Base32-over-DNS and hex-over-ICMP covert exfiltration channels | `red_team/exfil_agent.py` |

### Blue Team / 藍軍

| Technique | Principle | File |
|-----------|-----------|------|
| **eBPF Syscall Hooks (v1)** | Tracepoints on `memfd_create`, `execve`, `socket` | `blue_team/blue_ebpf_mdr.py` |
| **Suspect Port Detection (v2)** | `sys_enter_connect` hook checks destination port against configurable list | `blue_team/blue_ebpf_mdr_v2.py` |
| **Reverse Shell Detection (v2)** | `sys_enter_dup2/dup3` tracks fd 0,1,2 hijacking → confirms shell pattern | `blue_team/blue_ebpf_mdr_v2.py` |
| **Kernel-Space Kill** | `bpf_send_signal(SIGKILL)` terminates process *before* syscall completes | `blue_team/blue_ebpf_mdr*.py` |
| **Correlation Detection** | `memfd_create` PID + raw ICMP socket → confirmed fileless C2 | `blue_team/blue_ebpf_mdr.py` |
| **Cold-Start Scan** | `/proc/*/exe` scan for existing `memfd:` processes at startup | `blue_team/blue_ebpf_mdr*.py` |

---

## MITRE ATT&CK Coverage

### Attack Techniques

| ID | Technique | Implementation |
|----|-----------|---------------|
| T1190 | Exploit Public-Facing App | SSTI injection |
| T1059.006 | Python Execution | memfd loader + agent + reverse shell |
| T1620 | Reflective Code Loading | `memfd_create` → `execve` |
| T1027 | Obfuscation | Double Base64 + XOR |
| T1095 | Non-App Layer Protocol | ICMP covert C2 |
| T1071.001 | Application Layer Protocol | TCP reverse shell |
| T1048.003 | Exfil Over Alternative Protocol | DNS/ICMP exfil |

### Detection Coverage

| ID | Detection Point | Hook | Version |
|----|----------------|------|---------|
| T1620 | Reflective Loading | `sys_enter_memfd_create` | v1 |
| T1059 | Execution from `/proc/fd` | `sys_enter_execve` | v1 |
| T1095 | Raw ICMP Socket | `sys_enter_socket` | v1 |
| T1071.001 | Suspect Port Connect | `sys_enter_connect` | v2 |
| T1059.006 | Reverse Shell fd Hijack | `sys_enter_dup2/dup3` | v2 |

---

## Reports & Docs / 技術報告與文件

- [Demo Flow / 演練腳本](docs/DEMO_FLOW.md) — Complete 6-round attack-defense demo script
- [Red Team Playbook](docs/RED_TEAM_PLAYBOOK.md) — Attack playbook with step-by-step commands
- [Chinese / 中文報告](docs/REPORT_ZH.md) — Kill Chain 各階段原理分析
- [English Report](docs/REPORT_EN.md) — Full technical analysis

---

## Disclaimer / 免責聲明

This project is for **authorized educational and research purposes only**.
All exercises are conducted in isolated lab environments.
Do not use these techniques against systems without explicit authorization.

本專案僅供**授權教育與研究用途**。所有演練在隔離的 Lab 環境中進行。
未經明確授權，禁止對任何系統使用這些技術。
