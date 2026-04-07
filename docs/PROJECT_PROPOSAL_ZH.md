# 企業級攻防實驗室：基於 eBPF 與網路欺敵技術的多層次網路安全演練

**課程：** 網路安全  
**專案類型：** 紅藍隊攻防演練  
**專案連結：** [GitHub — Cybersecurity-project](https://github.com/mickeytony0215-png/Cybersecurity-project)

---

## 目錄

1. [簡介](#1-簡介)
   - 1.1 [專案動機](#11-專案動機)
   - 1.2 [專案目標](#12-專案目標)
   - 1.3 [運作原則](#13-運作原則)
2. [背景知識與分析框架](#2-背景知識與分析框架)
3. [問題描述與攻擊手法](#3-問題描述與攻擊手法)
4. [提出的解決方案](#4-提出的解決方案)
5. [結論](#5-結論)
6. [參考文獻](#6-參考文獻)

---

## 1. 簡介

### 1.1 專案動機

根據 IBM 2024 年的 Data Breach Cost Report，全球資料外洩的平均損失已經來到 488 萬美元，而最常被拿來當作初始攻擊向量的手法還是那些老面孔——竊取憑證跟釣魚攻擊 [1]。另一方面，APT 組織越來越常利用 ICMP tunnel 或 DNS exfiltration 這類隱蔽通道來維持 C2 連線，藉此繞過網路層的安全控制。過去的研究指出，ICMP 協定本身缺乏 port-based multiplexing，data field 很容易被拿來當 covert channel [2]，MITRE ATT&CK 也有記錄像 PingPull、Regin、Cobalt Strike 這些工具利用 ICMP 做 C2 的案例 [4]。

但我們在修課的過程中發現，大部分網路安全的課程還是偏理論——教漏洞分類、列防禦清單，學生很少有機會真正動手做攻擊跟防禦。課堂上學的東西跟實際操作之間有蠻大的落差。這也是我們做這個專案的出發點：我們想建一個可控、可重現的攻防實驗環境，讓大家可以從頭走過一次完整的攻擊生命週期——從 reconnaissance、exploitation 到 exfiltration——同時也實作對應的防禦機制，然後看兩邊怎麼互相升級對抗。

另一個推動我們做這個專案的想法是：攻擊跟防禦不是一次性的事情，而是一個持續的對抗過程。你擋住了一種攻擊，攻擊者就會換招；你升級偵測，他就找新的 evasion 手法。我們把演練設計成多回合制，讓雙方逐步升級，這樣比較能體會到真實世界資安攻防的迭代本質。

### 1.2 專案目標

我們這個專案要做的事情包含以下幾個面向：

- **走完一條完整的 Cyber Kill Chain**——從 reconnaissance、weaponization、delivery、exploitation、installation 到 C2，每個階段都有對應的實作，並且 mapping 到 MITRE ATT&CK framework。
- **做出兩層 defense-in-depth 架構**——網路層用 honeypot 搭配 iptables 自動封鎖，kernel 層用 eBPF 監控 syscall 並即時 kill process。用這個架構來說明為什麼單一防禦不夠。
- **展現攻防升級的過程**——整個演練總共 7 個回合，紅藍隊輪流適應對方。紅隊被擋住就換 evasion 技術，藍隊就針對新的行為升級偵測能力。
- **導入 production-grade 加密**——把 covert channel 的加密從教學用的 XOR cipher 升級到 AES-256-CTR（透過 ctypes 呼叫 OpenSSL），順便證明 behavioral detection 在強加密下一樣有效。
- **提供即時的 SOC dashboard**——把所有防禦元件的事件匯整到一個 web UI 上，讓藍隊有統一的 situational awareness。
- **確保安全性跟可重現性**——所有東西都跑在隔離環境裡，不做 privilege escalation、不做破壞性操作，所有 artifact 都在 memory 裡或是 ephemeral 的。

### 1.3 運作原則

我們在設計和執行整個演練時遵守以下幾個原則：

**受控環境**：所有攻防活動都在隔離的 lab 網路裡進行。Target application 是我們自己寫的有漏洞的服務，不會動到任何 production 系統。紅隊在明確的 scope 底下操作——privilege escalation 和 destructive impact 這類技術我們刻意排除掉，控制 blast radius。

**縱深防禦架構**：藍隊部署兩層防禦：

| 層級 | 機制 | 防護範圍 | 限制 |
|------|------|----------|------|
| 網路層 | 蜜罐 + iptables 自動封鎖 | 封鎖已知惡意 IP | 攻擊者可更換 IP 繞過 |
| 核心層 | eBPF syscall hook + bpf_send_signal | 封鎖惡意行為，不論來源 IP | 需要知道要監控哪些 syscall |

這個架構的重點是：每一層都有自己的限制，只有組合在一起才能提供比較完整的防護。

**多回合對抗演練**：整個演練設計成 7 個回合，用來說明網路安全是一個持續的過程：

| 回合 | 角色 | 行動 | 結果 |
|------|------|------|------|
| 1 | 紅隊 | 偵察（nmap） | 發現目標服務 |
| 1b | 紅隊 → 藍隊 | 觸發蜜罐陷阱 | 紅隊 IP 被封鎖 |
| 1c | 紅隊 | IP alias 繞過 | 重新拿回網路存取 |
| 2 | 紅隊 | SSTI + fileless C2 | 拿到完整的 remote control |
| 3 | 藍隊 | 部署 eBPF v1 | 清掉現有威脅 |
| 4 | 紅隊 | 再次攻擊 | 被 eBPF 攔截 |
| 5 | 紅隊 | TCP reverse shell（evasion） | 繞過 eBPF v1 |
| 6 | 藍隊 | 部署 eBPF v2 | 偵測並終止 reverse shell |

**可重現性跟文件化**：每個攻擊跟防禦步驟都有詳細的指令、預期 output 和技術說明。專案裡附了完整的 demo script（`docs/DEMO_FLOW.md`），任何人都可以自己跑一遍完整的演練。

---

## 2. 背景知識與分析框架

### 2.1 Cyber Kill Chain

Lockheed Martin 的 Cyber Kill Chain 是 Hutchins、Cloppert 和 Amin 在 2011 年提出的框架 [3]，把網路攻擊拆成七個階段來分析：Reconnaissance、Weaponization、Delivery、Exploitation、Installation、C2、Actions on Objectives。

我們的專案實作了其中六個階段（基於安全考量排除 Actions on Objectives），每個階段都對應到具體的工具跟技術：

```
階段 1        階段 2           階段 3        階段 4          階段 5       階段 6
偵察    →   武器化      →   投遞     →   利用       →   安裝    →   命令與控制
nmap         memfd_create       SSTI POST      fork+execve      記憶體駐留     ICMP/TCP
             + AES-256-CTR      透過 curl      從 /proc/fd      agent         隱蔽通道
```

### 2.2 MITRE ATT&CK Framework

MITRE ATT&CK 是一個根據真實攻擊行為整理出來的知識庫 [4]。我們把這次實作的所有技術都 mapping 到對應的 ATT&CK technique ID：

| 戰術 | 技術編號 | 技術名稱 | 我們的實作方式 |
|------|---------|---------|---------|
| Reconnaissance | T1595 | Active Scanning | nmap port scan + service detection |
| Initial Access | T1190 | Exploit Public-Facing Application | Flask/Jinja2 SSTI injection |
| Execution | T1059.006 | Python | memfd loader、reverse shell、C2 agent |
| Defense Evasion | T1620 | Reflective Code Loading | memfd_create + exec from /proc/pid/fd |
| Defense Evasion | T1027 | Obfuscated Files or Information | Base64 encoding + AES-256-CTR encryption |
| C2 | T1095 | Non-Application Layer Protocol | ICMP covert channel + TCP reverse shell |
| C2 | T1571 | Non-Standard Port | C2 和 reverse shell 用 port 4444 |
| Exfiltration | T1048.003 | Exfiltration Over Alternative Protocol | DNS/ICMP data exfiltration |

### 2.3 eBPF（Extended Berkeley Packet Filter）

eBPF 是 Linux kernel 裡面一個很強大的機制，可以讓 sandboxed program 直接在 kernel space 跑，不需要改 kernel source code 或載入 kernel module [5]。它原本是設計來做 packet filtering 的，後來慢慢演變成一個通用的 in-kernel virtual machine，被廣泛用在 networking、observability 和 security 領域。

eBPF 很適合拿來做 security monitoring，主要有幾個原因：

- **在 kernel space 執行**：eBPF program 跑在 kernel 裡面，可以看到所有的 syscall，而且是 zero context switch overhead。從 user space 是沒辦法 evade 的。
- **安全保證**：eBPF verifier 會在 load 之前對每個 program 做 static analysis，確保不會有 unbounded loop、out-of-bounds memory access 或 kernel crash。
- **主動回應能力**：從 Linux 5.3 開始，`bpf_send_signal()` helper 允許 eBPF program 直接從 kernel space 送 signal（包括 SIGKILL）給 current process，不需要繞回 user space 就能即時 kill 掉威脅 [6]。
- **Tracepoint hooking**：eBPF program 可以 attach 到 syscall entry 的 static tracepoint（`sys_enter_*`），在 syscall handler 開始執行前就觸發。這樣可以做到 preemptive detection——惡意操作在完成之前就被擋下來。

我們的專案把 eBPF program attach 到六個 tracepoint：`sys_enter_memfd_create`、`sys_enter_execve`、`sys_enter_socket`、`sys_enter_connect`、`sys_enter_dup2` 和 `sys_enter_dup3`。

### 2.4 網路欺敵與 Honeypot

網路欺敵是一種主動防禦策略，用 decoy system 來偵測、引開和分析攻擊者的行為 [7]。Honeypot 的價值就在於它被探測、被攻擊——任何跟 honeypot 的互動都天生就是可疑的，因為正常使用者根本沒理由去連它。

我們部署了一個 low-interaction honeypot，在 port 2222 上模擬 SSH server。當攻擊者連上來（通常是在 reconnaissance 階段），honeypot 會記錄 source IP 然後透過 iptables 觸發自動封鎖。這個做法的好處是 zero false positive——連到 honeypot 這件事本身就代表是 unauthorized 的行為。

### 2.5 AES-256-CTR 加密（透過 OpenSSL）

AES 的 CTR mode 是 NIST 標準化的對稱加密方案 [8]。AES-256-CTR 的運作方式像 stream cipher：用 AES-256 去加密遞增的 counter value 產生 keystream，再跟 plaintext 做 XOR。幾個重要特性：

- **IND-CPA security**：每個 message 用 random IV，同樣的 plaintext 會產生不同的 ciphertext，擋住 pattern analysis。
- **不需要 padding**：CTR mode 的 ciphertext 長度跟 plaintext 一樣，適合有 size constraint 的網路協定。
- **可以平行化**：counter block 之間互相獨立，可以做 hardware acceleration。

我們用 Python 的 ctypes FFI 去呼叫 OpenSSL libcrypto 裡面的 AES-256-CTR，這樣不用裝任何 pip package 就能達到 production-grade 的加密強度。

---

## 3. 問題描述與攻擊手法

### 3.1 Server-Side Template Injection（SSTI）

**問題**：目標 app（`target_app.py`）是一個 Flask web application，用 Python f-string 把 user input 直接塞進 Jinja2 template 裡面再 render。這就是一個 SSTI 漏洞（CWE-1336）[9]。

**機制**：當使用者送出查詢的時候，app 是這樣 build template 的：

```python
template = f"<pre>Query: {user_input}</pre>"
render_template_string(template)
```

如果 `user_input` 裡面有 Jinja2 expression delimiter（`{{ }}`），template engine 就會把它當 code 執行。攻擊者可以 traverse Python 的 object model 來拿到 `os.popen()`，達成 RCE：

```
{{ config.__class__.__init__.__globals__['os'].popen('COMMAND').read() }}
```

**影響**：以 Flask process 的權限執行任意命令，等於完全的 remote code execution。

### 3.2 透過 memfd_create 的 Fileless Malware

**問題**：傳統的 malware detection 靠的是掃描 disk 上的檔案。但 `memfd_create` syscall（Linux 3.17+，x86_64 上是 syscall 319）可以建立完全在 RAM 裡面的匿名檔案，沒有任何 filesystem entry，所以 file-based detection 完全抓不到 [10]。

**機制**：攻擊的流程是這樣：

1. `memfd_create("", 0)` — 在 kernel tmpfs 裡建立 anonymous file descriptor
2. `write(fd, agent_code)` — 把 C2 agent 寫進去
3. `fork()` — parent process return，讓 web server 繼續回應
4. `execve("/usr/bin/python3", ["/proc/<pid>/fd/<N>"])` — child process 從 anonymous fd 執行 agent

跑起來的 process 完全是從 memory 執行的。Agent 永遠不碰 filesystem，不留下任何 forensic trace 給防毒軟體或鑑識工具。

### 3.3 ICMP Covert C2 Channel

**問題**：傳統的 TCP/UDP C2 channel 會被 firewall 和 IDS/IPS 監控。但 ICMP（RFC 792）通常防火牆都會放行，因為擋掉的話 ping、traceroute 這些基本的網路診斷功能就不能用了 [11]。

**機制**：我們的 C2 channel 把加密過的 command 跟 response 塞進 ICMP echo request（type 8）的 payload field 裡面。Protocol 設計如下：

- **ICMP ID field（0x1337）** 當作 traffic identifier
- **Magic byte（0xDE）** 做快速的 payload 驗證
- **AES-256-CTR 加密**，每個封包都用 random IV
- **分 chunk 傳輸**（每個 chunk 480 bytes）處理大的 command output

C2 server 跟 agent 都是送 ICMP type 8 封包；kernel 自動產生的 reply（type 0）直接忽略。

### 3.4 TCP Reverse Shell（eBPF Evasion）

**問題**：當藍隊部署了 eBPF，監控 `memfd_create`、`/proc/fd` exec 和 raw ICMP socket 之後，攻擊者得想辦法繞過去。標準的 TCP reverse shell 不用上面任何一個被監控的 syscall。

**機制**：evasion 技術是用傳統的 reverse shell 取代 fileless ICMP C2：

1. `fork()` — 把 shell process 丟到背景
2. `socket(AF_INET, SOCK_STREAM, 0)` — 建普通的 TCP socket（不是 SOCK_RAW）
3. `connect(attacker_ip, 4444)` — outbound TCP connection
4. `dup2(sock_fd, 0/1/2)` — 把 stdin、stdout、stderr redirect 到 socket
5. `pty.spawn("/bin/bash")` — spawn interactive shell

這招繞過了 eBPF v1 的全部三個 hook，因為它用的是標準 TCP（不是 raw ICMP）、不呼叫 `memfd_create`、也不從 `/proc/fd` exec。

### 3.5 DNS/ICMP Data Exfiltration

**問題**：拿到存取權限之後，攻擊者通常會想把資料偷出來。傳統的 data transfer 方法（HTTP、FTP、SCP）比較容易被監控，但 DNS 和 ICMP channel 常常被忽略。

**機制**：Exfiltration agent 收集 sensitive file（`/etc/passwd`、SSH key、bash history、app source code）然後透過以下兩種方式送出去：

- **DNS channel**：資料做 Base32 encoding 之後塞進 DNS query 的 subdomain label 裡（`<data>.x.exfil.local`）。攻擊者那邊跑一個假的 DNS server 重組這些 fragment。
- **ICMP channel**：資料做 hex encoding 之後塞進 ICMP echo request 的 padding pattern 裡（透過 `ping -p`）。

兩個 channel 都有 sequence number、checksum 做 integrity check，還有 randomized inter-packet delay 來降低被 pattern-based detection 抓到的機率。

---

## 4. 提出的解決方案

### 4.1 第一層：網路欺敵 — Honeypot 與網路 MDR

**元件 1 — Honeypot（`target/honeypot.py`）**：

Low-interaction SSH honeypot 在 port 2222 上 listen，會顯示看起來很像真的 OpenSSH 8.9p1 banner，足以騙過 nmap `-sV` 這類 service detection tool。任何連線都會記錄到 `trap.log`，包含 timestamp、source IP、port 和 client data。

**元件 2 — 網路 MDR（`blue_team/blue_mdr_network.py`）**：

Monitor daemon 會持續 poll `trap.log` 裡的新 entry。一偵測到攻擊者 IP 就立刻執行：

```
iptables -I INPUT 1 -s <attacker_ip> -j DROP
```

規則插在 INPUT chain 的 position 1（最高優先），確保比任何 existing ACCEPT rule 都先 match 到。這樣攻擊者就連不到機器上的任何 service。

**有效性**：Zero false positive——任何連到 honeypot 的行為，by definition 就是 unauthorized 的。

**限制**：IP-based blocking 可以透過換 source IP（例如 IP alias）繞過。這也是為什麼我們需要第二層（behavioral detection）。

### 4.2 第二層：Kernel 層偵測 — eBPF MDR

**元件 3 — eBPF MDR v1（`blue_team/blue_ebpf_mdr.py`）**：

三個 eBPF tracepoint hook 偵測 fileless malware：

| Hook | Tracepoint | 偵測邏輯 |
|------|--------|---------|
| Hook 1 | `sys_enter_memfd_create` | Server 上出現 memfd_create 呼叫就是可疑的；記錄 PID 做 correlation |
| Hook 2 | `sys_enter_execve` | Pattern match filename 裡的 `/proc/<pid>/fd/` — 代表從 anonymous memory exec |
| Hook 3 | `sys_enter_socket` | 偵測 `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`；跟 memfd PID 做 correlation 確認 high-confidence C2 detection |

開 `--kill` mode 的話，`bpf_send_signal(SIGKILL)` 會在 syscall 完成之前直接從 kernel space kill 掉惡意 process。另外，啟動的時候有個 cold-start scanner 會掃 `/proc/*/exe` 找已經在跑的 `memfd:` process。

**元件 4 — eBPF MDR v2（`blue_team/blue_ebpf_mdr_v2.py`）**：

保留所有 v1 的 hook，再加三個新的來偵測 reverse shell：

| Hook | Tracepoint | 偵測邏輯 |
|------|--------|---------|
| Hook 4 | `sys_enter_connect` | 檢查 destination port 是不是在 suspicious port list 裡（default：4444、4445、5555、1234、1337） |
| Hook 5 | `sys_enter_dup2` | 用 per-PID bitmask 追蹤；fd 0、1、2 全部被 redirect 的話 → 確認是 reverse shell |
| Hook 6 | `sys_enter_dup3` | 跟 Hook 5 一樣，cover Python `os.dup2(fd, fd2, inheritable=False)` 走 dup3 的 code path |

`connect` hook 在連線的時候就能 detect（based on port），`dup2/dup3` hook 則提供 port-independent 的偵測，根據 reverse shell 的 behavioral signature 來判斷。

### 4.3 即時監控 — SOC Dashboard

**元件 5 — SOC Dashboard（`blue_team/soc_dashboard.py`）**：

Flask-based web app（port 8080），把所有防禦元件的事件匯整起來，顯示在一個 real-time dark theme SOC console 上。功能包括：

- **Server-Sent Events（SSE）**：即時串流到瀏覽器
- **多來源 ingestion**：讀 `trap.log`（honeypot 事件）和 `soc_events.jsonl`（eBPF alert、iptables 封鎖）
- **HTTP POST API**（`/api/event`）：讓其他工具可以 programmatically 送事件進來
- **統計卡片**：事件總數、封鎖 IP 數、process kill 數、critical alert 數
- **色彩標記 severity**：CRITICAL（紅）、HIGH（黃）、MEDIUM（藍）、INFO（灰）

藍隊工具透過 `--soc-log` flag 寫 `soc_events.jsonl`，dashboard 就能同時顯示 honeypot 事件、eBPF detection 和網路封鎖。

### 4.4 加密升級 — AES-256-CTR

Covert C2 channel 的加密從 XOR 升級到 AES-256-CTR：

| 特性 | XOR（原始） | AES-256-CTR（升級後） |
|------|------------|---------------------|
| 演算法 | XOR stream cipher | AES-256 Counter Mode |
| Key derivation | 固定 16-byte plaintext key | SHA-256(shared_secret) → 32 bytes |
| IV/Nonce | 無 | 每個封包 random 16-byte IV |
| Known-plaintext resistance | 很容易被破 | Computationally infeasible |
| 實作方式 | 純 Python | ctypes + OpenSSL libcrypto |
| Dependencies | 無 | 系統 libcrypto（Linux 預裝） |

這個升級要展示兩件事：（1）真實世界的 malware 越來越常用強加密；（2）behavioral detection（eBPF）不管加密多強都一樣有效，因為它看的是 syscall pattern，不是 payload content。

### 4.5 縱深防禦總覽

```
┌─────────────────────────────────────────────────────┐
│  第一層 — 網路層（網路欺敵）                          │
│  honeypot.py（port 2222）→ trap.log →               │
│  blue_mdr_network.py → iptables DROP                │
│  偵測：偵察行為，封鎖已知惡意 IP                       │
├─────────────────────────────────────────────────────┤
│  第二層 — Kernel 層（eBPF 行為偵測）                  │
│  v1: memfd_create + execve + raw ICMP socket        │
│  v2: + connect（suspicious port）+ dup2/dup3（shell）│
│  偵測：惡意行為，不論來源 IP                           │
├─────────────────────────────────────────────────────┤
│  監控 — SOC Dashboard（port 8080）                   │
│  Real-time web UI 匯整所有事件                       │
└─────────────────────────────────────────────────────┘
```

---

## 5. 結論

這個專案透過 7 回合的紅藍隊對抗，驗證了幾個我們認為很重要的觀察：

**單一防禦不夠用。** 網路層防禦（honeypot、firewall）換個 IP 就繞過了。Kernel 層防禦（eBPF v1）用不同的 syscall pattern 也能繞。只有多個獨立的偵測機制疊在一起，才能提供比較穩固的防護。

**攻擊者會適應，防禦者就得跟著升級。** 當 eBPF v1 把 fileless ICMP C2 擋掉之後，紅隊改用標準的 TCP reverse shell——一個不觸發任何被監控 syscall 的方法。藍隊的對策是部署 eBPF v2，加上 `connect()` 跟 `dup2()` 的 hook，重新拿回偵測能力。這個來回就是真實世界 security operation 的縮影。

**Behavioral detection 不怕加密。** 把 C2 channel 從 XOR 升級到 AES-256-CTR 之後，payload inspection 變得不可能了，但 eBPF detection 完全不受影響，因為它監控的是 syscall behavior——process 做了什麼——而不是 traffic 裡面裝了什麼。

**SOC 可視化很重要。** Dashboard 提供跨所有防禦元件的統一視野，讓藍隊能理解整個攻擊的全貌，而不是只對個別 alert 做反應。

**Fileless 技術對傳統防禦是個挑戰。** 透過 `memfd_create` 完全在 memory 裡跑的 C2 agent，不留下任何 filesystem trace，傳統的防毒跟鑑識工具都看不到。這也證明了像 eBPF 這種 kernel-level behavioral monitoring 的必要性。

總結來說，我們成功實作了 7 項 MITRE ATT&CK 攻擊技術和 7 項對應的偵測能力，橫跨兩個防禦層，在一個受控、可重現的環境中完成了一次完整的攻防演練。

---

## 6. 參考文獻

[1] IBM Security，「資料外洩成本報告 2024」，IBM Corporation，2024。取自：https://www.ibm.com/reports/data-breach

[2] A. Singh、O. Nordstrom、C. Lu 和 A. L. M. dos Santos，「惡意 ICMP 隧道：漏洞防禦」，*ACISP 2003*，Lecture Notes in Computer Science，vol. 2727，Springer，2003。DOI: 10.1007/3-540-45067-X_20

[3] E. M. Hutchins、M. J. Cloppert 和 R. M. Amin，「以情報驅動的電腦網路防禦——基於對手活動分析與入侵攻擊鏈」，*Leading Issues in Information Warfare & Security Research*，vol. 1，no. 1，pp. 1-14，Lockheed Martin Corporation，2011。

[4] B. Strom、A. Applebaum、D. Miller、K. Nickels、A. Pennington 和 C. Thomas，「MITRE ATT&CK：設計與哲學」，MITRE Corporation，2020。取自：https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf

[5] M. Fleming，「eBPF 深入介紹」，*LWN.net*，2017 年 12 月。取自：https://lwn.net/Articles/740157/

[6] Y. Song，「bpf: 實作 bpf_send_signal 輔助函數」，Linux Kernel Commit，2019。取自：https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8b401f9ed244

[7] L. Spitzner，*蜜罐：追蹤駭客*。Addison-Wesley Professional，2003。ISBN: 0-321-10895-7。

[8] 美國國家標準暨技術研究院，「區塊密碼操作模式建議」，NIST 特刊 800-38A，2001。取自：https://csrc.nist.gov/publications/detail/sp/800-38a/final

[9] J. Kettle，「伺服器端模板注入」，PortSwigger Research，2015。取自：https://portswigger.net/research/server-side-template-injection

[10] M. Kerrisk，「memfd_create(2) — Linux 手冊頁」，*The Linux man-pages project*，2020。取自：https://man7.org/linux/man-pages/man2/memfd_create.2.html

[11] J. Postel，「網際網路控制訊息協定」，RFC 792，Internet Engineering Task Force，1981 年 9 月。取自：https://www.rfc-editor.org/rfc/rfc792

[12] T. Ylonen 和 C. Lonvick，「安全殼層（SSH）傳輸層協定」，RFC 4253，Internet Engineering Task Force，2006 年 1 月。取自：https://www.rfc-editor.org/rfc/rfc4253

[13] BCC 作者群，「BPF 編譯器套件（BCC）— 用於基於 BPF 的 Linux IO 分析、網路、監控等工具」，2015 至今。取自：https://github.com/iovisor/bcc

[14] OpenSSL 專案，「OpenSSL：密碼學與 SSL/TLS 工具套件」，1998 至今。取自：https://www.openssl.org
