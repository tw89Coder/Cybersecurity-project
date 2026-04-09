# Enterprise Attack-Defense Lab

> Cyberattack Kill Chain 攻防演練專案
> Red-blue team exercise built around the Cyberattack Kill Chain framework for a network security course.

---

## Team / 組員

| Name | Role | Responsibilities |
|------|------|-----------------|
| 陳品叡 (M143040024) | Red Team | Reconnaissance, exploitation, C2 |
| 呂易鴻 (M143140012) | Blue Team | eBPF detection, incident response |
| 王承煜 (M143140017) | Target / Docs | Vulnerable app, reporting |

---

## Project Structure / 專案結構

```
.
├── target/                     # Vulnerable target services
│   ├── target_app.py           #   Flask SSTI vulnerable API
│   └── honeypot.py             #   Fake SSH honeypot (port 2222) ← NEW
│
├── red_team/                   # Red team attack tooling
│   ├── red_attacker.py         #   Fileless ICMP C2 (memfd_create + AES-256-CTR)
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
│   ├── soc_dashboard.py       #   Real-time SOC web dashboard ← NEW
│   ├── blue_mdr_network.py    #   Network MDR: trap.log + iptables
│   ├── blue_ebpf_mdr.py       #   eBPF v1: memfd + ICMP detection
│   └── blue_ebpf_mdr_v2.py    #   eBPF v2: + reverse shell detection
│
├── docs/                       # Documentation & reports
│   ├── DEMO_FLOW.md            #   Complete 7-round demo script
│   ├── RED_TEAM_PLAYBOOK.md    #   Attack playbook (7-phase kill chain)
│   ├── REPORT_ZH.md            #   Technical analysis report (Chinese)
│   ├── REPORT_EN.md            #   Technical analysis report (English)
│   ├── PROJECT_PROPOSAL.md     #   Project proposal (English)
│   ├── PROJECT_PROPOSAL_ZH.md  #   Project proposal (Chinese)
│   └── design/                 #   Development planning docs (archived)
│       ├── exfiltration-design.md
│       └── exfiltration-plan.md
│
├── setup_env.sh                # One-command environment setup (auto-detects WSL2)
├── cleanup.sh                  # One-command environment reset (kill, iptables, logs)
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

---

## Quick Start / 快速開始

### 1. Environment Setup / 環境安裝

```bash
git clone https://github.com/mickeytony0215-png/Cybersecurity-project.git
cd Cybersecurity-project
bash setup_env.sh
```

We use two machines. `setup_env.sh` auto-detects whether you're on WSL2 or native Linux and installs the right packages.

| Machine | Role | OS | eBPF |
|---------|------|----|------|
| Lab server | Target + Blue Team | Ubuntu 24.04 (native) | Yes |
| Student laptop | Red Team (attacker) | Ubuntu 22.04 (WSL2) | Not needed |

Run `git clone` + `bash setup_env.sh` on both machines.

### 2. Running the Demo / 執行順序

For the full 7-round walkthrough, check [docs/DEMO_FLOW.md](docs/DEMO_FLOW.md).

Here's a quick 2-scenario test:

```bash
# Lab machine — Terminal 1: Target (靶機)
sudo .venv/bin/python3 target/target_app.py

# Lab machine — Terminal 2: Blue Team (藍軍 eBPF v2)
sudo .venv/bin/python3 blue_team/blue_ebpf_mdr_v2.py --kill

# WSL2 — Terminal 3: Red Team C2 (紅軍 C2 Server)
sudo .venv/bin/python3 red_team/red_attacker.py -t <TARGET_IP> -l <ATTACKER_IP>

# WSL2 — Terminal 4: Red Team Attack (紅軍觸發攻擊)
# Paste the curl command printed by Terminal 3
```

### 3. What to Expect / 預期結果

| Scenario | Result |
|----------|--------|
| Blue team **OFF** | Agent deploys in-memory, C2 shell obtained |
| Blue team v1 **ON** (`--kill`) | eBPF detects `memfd_create`, kills process before execution |
| Red team **reverse shell** (v1 bypass) | TCP shell bypasses v1 detection entirely |
| Blue team **v2 ON** (`--kill`) | Detects `connect()` to suspect port + `dup2` fd hijack, kills reverse shell |
| Red team **exfiltration** (defense gap) | DNS/ICMP covert channels extract sensitive files; eBPF v2 does not detect |

---

## Kill Chain Overview / 攻擊鏈概覽

```
Phase 1        Phase 2           Phase 3        Phase 4          Phase 5       Phase 6          Phase 7
Recon    →   Weaponize     →   Deliver    →   Exploit      →   Install   →   C2           →   Exfiltrate
nmap         memfd_create       SSTI POST      fork+execve      in-memory     ICMP/TCP         DNS/ICMP
recon.sh     + AES-256-CTR      curl cmd       from /proc/fd    agent         covert channel   data theft
             red_attacker.py    target_app.py                                                  exfil_agent.py

Phase 5b (Evasion — bypasses blue v1, caught by v2)
Evasion  →   Deliver    →   Exploit      →   C2
fork()       SSTI POST      connect()        TCP reverse
+ TCP        curl cmd       + dup2(0,1,2)    shell via pty
reverse_shell.py             pty.spawn
```

The main chain (phases 1-7) covers the full Kill Chain from reconnaissance to data exfiltration. Phase 5b is the evasion variant -- a TCP reverse shell that sidesteps v1 detection but gets caught by v2's `connect()`/`dup2` hooks. Phase 7 demonstrates a defense gap: DNS/ICMP exfiltration goes undetected by the current eBPF hooks.

---

## How It Works / 技術說明

### Red Team / 紅軍

- **SSTI**: The target Flask app uses `render_template_string` with user input, so Jinja2 evaluates `{{ }}` as code. That's our entry point. (`target/target_app.py`)
- **Fileless execution**: We use `memfd_create` (syscall 319) to create an anonymous fd in RAM, then `execve` through `/proc/pid/fd/N`. Nothing touches disk. (`red_team/red_attacker.py`)
- **ICMP covert C2**: Commands go in ICMP echo-request payloads, encrypted with AES-256-CTR via ctypes+OpenSSL. No TCP/UDP connections to detect. (`red_team/red_attacker.py`)
- **TCP reverse shell**: `fork` -> `connect` -> `dup2(fd,0/1/2)` -> `pty.spawn`. This bypasses eBPF v1 since it doesn't use `memfd_create`. (`red_team/red_reverse_shell.py`)
- **WAF bypass**: `${IFS}` for space evasion, Base64 encoding, backslash obfuscation. (`red_team/exploit.py`)
- **DNS/ICMP exfil**: Base32-over-DNS and hex-over-ICMP for covert data exfiltration. (`red_team/exfil_agent.py`)

### Blue Team / 藍軍

- **eBPF v1**: Hooks `memfd_create`, `execve`, and `socket` tracepoints. Correlates `memfd_create` PID with raw ICMP socket creation to confirm fileless C2. Also does a cold-start `/proc/*/exe` scan for existing `memfd:` processes. (`blue_team/blue_ebpf_mdr.py`)
- **eBPF v2**: Adds `sys_enter_connect` to check destination ports against a configurable suspect list, plus `sys_enter_dup2/dup3` to track fd 0,1,2 hijacking (the classic reverse shell pattern). (`blue_team/blue_ebpf_mdr_v2.py`)
- **Kernel-space kill**: Both versions can call `bpf_send_signal(SIGKILL)` to terminate the process *before* the syscall even completes. (`blue_team/blue_ebpf_mdr*.py`)

---

## MITRE ATT&CK Coverage

### Attack Techniques

| ID | Technique | Implementation |
|----|-----------|---------------|
| T1595 | Active Scanning | nmap SYN port scanning |
| T1190 | Exploit Public-Facing App | SSTI injection |
| T1059.006 | Python Execution | memfd loader + agent + reverse shell |
| T1620 | Reflective Code Loading | `memfd_create` -> `execve` |
| T1027 | Obfuscation | Double Base64 + AES-256-CTR |
| T1095 | Non-App Layer Protocol | ICMP covert C2 + TCP reverse shell |
| T1571 | Non-Standard Port | C2 on port 4444 |
| T1048.003 | Exfil Over Alternative Protocol | DNS/ICMP exfil |
| T1053.003 | Scheduled Task: Cron | Crontab reverse shell persistence |
| T1082 | System Information Discovery | whoami, id, uname (post-exploitation) |
| T1005 | Data from Local System | Exfil agent collects /etc/passwd, SSH keys, history |
| T1070.003 | Clear Command History | history -c |
| T1070.004 | File Deletion | Exfil agent self-deletes after completion |

### Detection Coverage

| ID | Detection Point | Hook | Version |
|----|----------------|------|---------|
| T1620 | Reflective Loading | `sys_enter_memfd_create` | v1 |
| T1059 | Execution from `/proc/fd` | `sys_enter_execve` | v1 |
| T1095 | Raw ICMP Socket | `sys_enter_socket` | v1 |
| T1571 | Non-Standard Port Connect | `sys_enter_connect` | v2 |
| T1059.006 | Reverse Shell fd Hijack | `sys_enter_dup2/dup3` | v2 |

---

## Docs / 相關文件

- [Demo Flow / 演練腳本](docs/DEMO_FLOW.md) -- 7-round attack-defense demo
- [Red Team Playbook](docs/RED_TEAM_PLAYBOOK.md) -- Step-by-step attack commands
- [中文報告](docs/REPORT_ZH.md) -- Kill Chain 各階段原理分析
- [English Report](docs/REPORT_EN.md) -- Full technical analysis

---

## Disclaimer / 免責聲明

This project is for **authorized educational and research purposes only**.
All exercises run in isolated lab environments. Don't use any of this against systems you don't have explicit permission to test.

本專案僅供**授權教育與研究用途**。所有演練在隔離的 Lab 環境中進行。
未經明確授權，禁止對任何系統使用這些技術。
