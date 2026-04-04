# 進階紅藍對抗技術分析報告

## 1. 摘要

本專案實作一套完整的 Cyberattack Kill Chain 攻防演練，涵蓋三個核心元件：

| 元件 | 檔案 | 角色 |
|------|------|------|
| 靶機 | `target_app.py` | 帶有 SSTI 漏洞的 Flask Web 服務 |
| 紅軍 | `red_attacker.py` | 無檔案攻擊 (memfd_create) + ICMP 隱蔽 C2 |
| 藍軍 | `blue_ebpf_mdr.py` | eBPF 即時偵測與核心層阻斷 |

本報告聚焦於每個攻擊/防禦動作的**底層原理 (underlying principles)**、**目的 (purpose)** 與**對目標系統的影響 (impact)**。

---

## 2. 環境架構

```
┌──────────────────┐         ┌──────────────────┐
│  Attacker (WSL2) │  ICMP   │  Target Machine  │
│                  │◄═══════►│                  │
│  red_attacker.py │         │  target_app.py   │
│  (C2 Server)     │         │  (Flask :9999)   │
│                  │         │                  │
│                  │         │  blue_ebpf_mdr.py│
│                  │         │  (eBPF 偵測)      │
└──────────────────┘         └──────────────────┘
```

- **攻擊機**: WSL2 Linux (Ubuntu 22.04/24.04)，具 root 權限
- **靶機**: Linux 伺服器，運行帶漏洞的 Flask 服務
- **通訊協議**: ICMP Echo Request (Type 8)，完全不使用 TCP/UDP

---

## 3. Kill Chain 各階段分析

### Phase 1: 偵察 (Reconnaissance)

**動作**: 識別目標 Flask 服務的 `/diag` 端點及其輸入參數。

**原理**: Web 應用偵察的核心是理解應用的**輸入面 (attack surface)**。`/diag` 端點接受 POST 參數 `query`，並將其反映在回應中。觀察到回應包含未轉義的使用者輸入，暗示可能存在注入漏洞。

**影響**: 確認攻擊向量，為武器化階段提供精確的注入點。

---

### Phase 2: 武器化 (Weaponization)

**動作**: 構建 SSTI Payload + memfd_create 無檔案載入器。

#### 2.1 SSTI (Server-Side Template Injection) 原理

Flask 使用 Jinja2 作為模板引擎。Jinja2 在 `{{ }}` 分隔符內執行 Python 表達式。

**漏洞成因 — 兩步合成錯誤**:

```python
# Step 1: Python f-string 將使用者輸入嵌入模板原始碼
template = f"Query: {user_input}"
# 若 user_input = "{{ 7*7 }}"，結果字串為 "Query: {{ 7*7 }}"

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

**問題**: 傳統惡意程式寫入磁碟 (`/tmp/backdoor`)，會留下檔案痕跡、觸發 inotify 監控、被 AV 掃描。

**解決方案**: Linux `memfd_create(2)` 系統呼叫 (syscall 319, x86_64)。

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
os.write(fd, agent_code)           # 將惡意程式寫入 fd (仍在 RAM)
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

**動作**: 建立 XOR 加密的 ICMP 隱蔽 C2 通道。

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
│                 │ SEQ              │ │ XOR data    ││
│                 │                  │ └─────────────┘│
└─────────────────────────────────────────────────────┘

MSG_TYPE:
  0x01 = Heartbeat (Agent → C2)
  0x02 = Command   (C2 → Agent)
  0x03 = Result    (Agent → C2, chunked)
```

#### 4.2 XOR 加密原理

```
ciphertext[i] = plaintext[i] ⊕ key[i % len(key)]
```

**特性**:
- **對稱性**: 相同操作加密和解密 (A ⊕ K ⊕ K = A)
- **零依賴**: 不需要密碼學函式庫
- **速度**: 每位元組一個 CPU 指令

**密碼學限制** (重要！):
- **已知明文攻擊**: 如果攻擊者知道任何明文位元組，可以恢復對應的 key 位元組
- **金鑰重用**: 相同 key + 相同明文 = 相同密文 (無 IV/nonce)
- **不具密碼學安全性**: 實際操作應使用 AES-GCM 或 ChaCha20-Poly1305
- 在本 Lab 中足以展示「加密 C2」的概念

#### 4.3 ICMP Checksum (RFC 1071)

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
4. 將輸出分割為 480 byte 的 chunk → 逐一加密傳回
5. 收到 `__exit__` → 關閉 socket 並終止

**Timing Jitter（時序抖動）**:
```python
time.sleep(random.uniform(1.0, 2.5))  # 主迴圈每輪隨機等待 1~2.5 秒
time.sleep(0.05)                       # chunk 之間 50ms 延遲
```
這種隨機延遲使流量模式分析（例如週期性 beacon 偵測）更加困難。

**影響**: 攻擊者獲得完整的遠端 shell 存取，通訊隱藏在 ICMP 流量中。

---

### Phase 6: 目標行動 (Actions on Objectives)

**動作**: 在 C2 shell 中執行任意命令。

可執行的偵察命令示例:
```
whoami          → 確認執行身份
id              → UID/GID 資訊
uname -a        → 作業系統與 kernel 版本
cat /etc/passwd → 使用者列表
env             → 環境變數（可能含密鑰）
```

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

### 4.4 三重偵測策略

| Hook | Syscall | 偵測邏輯 | 嚴重度 |
|------|---------|---------|--------|
| Hook 1 | `memfd_create(319)` | 任何呼叫 → 記錄 PID + 警報 | HIGH |
| Hook 2 | `execve` | 路徑匹配 `/proc/*/fd/*` → 無檔案執行確認 | CRITICAL |
| Hook 3 | `socket` | AF_INET + SOCK_RAW + ICMP + PID 關聯 memfd → C2 確認 | CRITICAL |

**關聯偵測 (Correlation)**:
- 單獨的 memfd_create → HIGH（可能是合法用途如 Chrome IPC）
- 單獨的 raw ICMP socket → ALERT（可能是 ping）
- memfd_create **+** raw ICMP socket → **CRITICAL + CORRELATED**（無檔案 C2 確認）

**冷啟動偵測**: `/proc/*/exe` 掃描器在啟動時檢查已運行的 memfd 程序。

### 4.5 eBPF 資料結構

**BPF_PERF_OUTPUT (Perf Ring Buffer)**:
- kernel 與 userspace 之間的**無鎖環形緩衝區**
- kernel 寫入事件，Python 讀取事件
- 透過 mmap 共享記憶體，零拷貝

**BPF_HASH (Hash Map)**:
- kernel 與 userspace 共享的雜湊表
- `memfd_pids`: 追蹤呼叫過 memfd_create 的 PID
- `whitelist`: userspace 寫入白名單 PID，kernel 讀取

---

## 5. MITRE ATT&CK 完整映射

### 紅軍技術

| ID | 技術名稱 | 本專案實作 |
|----|---------|-----------|
| T1190 | Exploit Public-Facing Application | SSTI 注入 Flask /diag |
| T1059.006 | Command & Scripting: Python | memfd_create loader + agent |
| T1620 | Reflective Code Loading | memfd_create → execve from /proc/fd |
| T1027 | Obfuscated Files or Information | 雙層 Base64 + XOR 加密 |
| T1140 | Deobfuscate/Decode | base64 -d pipeline |
| T1095 | Non-Application Layer Protocol | ICMP echo request C2 channel |
| T1071.001 | Application Layer Protocol | ICMP payload 中嵌入自訂協議 |
| T1036 | Masquerading | ICMP 偽裝為正常 ping 流量 |

### 藍軍偵測

| ID | 偵測面 | 本專案實作 |
|----|--------|-----------|
| T1620 | Reflective Code Loading | Hook memfd_create tracepoint |
| T1059 | Command Execution | Hook execve from /proc/*/fd/* |
| T1095 | Non-App Layer Protocol | Hook socket(RAW, ICMP) |
| T1070 | Indicator Removal | /proc/*/exe 掃描 memfd 程序 |

---

## 6. 安全考量與限制

### 6.1 XOR 加密的弱點
- 無 IV/nonce → 可做頻率分析
- 已知明文攻擊：若抓到 heartbeat 格式（hostname 等可預測內容），可還原 key
- 實際操作建議: AES-256-GCM 或 ChaCha20-Poly1305

### 6.2 ICMP 通道的頻寬限制
- 每個 ICMP 封包 payload 約 480 bytes
- 加上 jitter 延遲，實際吞吐量極低
- 不適合大量資料外洩，適合命令/控制

### 6.3 eBPF 偵測的繞過可能性
- 攻擊者可使用 `shm_open()` 代替 `memfd_create`（需額外 hook）
- 攻擊者可使用 `fexecve()` 代替 execve + /proc 路徑
- 更進階: 使用 `ptrace` 注入已有程序（不需 execve）
- 解決方案: 增加更多 hook 點，或使用 seccomp-BPF 配合

### 6.4 Lab vs 實際環境
- 本 Lab 假設 Flask 以 root 運行（提供 CAP_NET_RAW）
- 實際場景中 Web 服務通常以低權限使用者運行
- ICMP raw socket 需要額外的權限提升步驟

---

## 7. 結論

本專案展示了一個完整的 Kill Chain 攻防循環:

1. **攻擊面**: SSTI 漏洞源於 f-string 與 Jinja2 模板引擎的不安全組合
2. **武器化**: memfd_create 實現 100% 無檔案執行，規避傳統偵測
3. **C2 通道**: ICMP 隱蔽通道利用協議特性躲避防火牆和 IDS
4. **防禦**: eBPF 在 kernel 空間實現零延遲偵測與阻斷

核心洞見: **現代攻擊不需要在磁碟上留下任何痕跡**。防禦方必須從 kernel 層級監控系統呼叫行為，而非僅依賴檔案掃描。eBPF 提供了這種能力，且不影響系統效能。
