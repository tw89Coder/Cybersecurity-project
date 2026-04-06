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

近年來，網路安全威脅態勢發生了顯著變化。根據 IBM X-Force 2024 年威脅情報指數報告，全球資料外洩的平均損失已達 488 萬美元，攻擊者越來越多地利用完全駐留於記憶體中的無檔案惡意程式（fileless malware）技術來規避傳統端點偵測解決方案 [1]。與此同時，進階持續性威脅（APT）組織經常使用隱蔽通訊通道——例如 ICMP 隧道和 DNS 資料外洩——來維持命令與控制（C2）存取，同時繞過網路層級的安全控制措施 [2]。

儘管真實世界的攻擊日益複雜，傳統的網路安全教育往往停留在理論層面，著重於漏洞分類和防禦清單，而非提供學生在攻擊和防禦操作方面的實作經驗。課堂知識與實務能力之間的差距，推動了本專案開發一個可控、可重現的攻防實驗室環境，讓學生能夠體驗網路攻擊的完整生命週期——從偵察、利用到資料外洩——同時實作、測試並迭代改進防禦對策。

本專案進一步的動機源自一個觀察：攻擊與防禦並非靜態的，而是構成一個持續的對抗過程。一個阻擋了某種攻擊向量的防禦機制，可能會被適應其技術的攻擊者所繞過。透過將演練設計為多回合對抗——雙方逐步升級其能力——學生能夠深刻理解真實世界網路安全運作的迭代本質。

### 1.2 專案目標

本專案旨在設計和實作一個全面的紅藍隊攻防演練，達成以下目標：

1. **展示完整的網路攻擊鏈（Cyber Kill Chain）**：實作涵蓋偵察、武器化、投遞、利用、安裝和命令與控制的完整攻擊生命週期，並對應至 MITRE ATT&CK 框架。

2. **實作多層縱深防禦（Defense-in-Depth）**：在網路層（蜜罐欺敵與防火牆 IP 封鎖）和核心層（eBPF 系統呼叫監控與即時程序終止）部署防禦機制，說明單一防禦不足以應對所有威脅的原則。

3. **展現對抗升級**：將演練設計為 7 回合對抗，紅隊和藍隊交替適應——紅隊在被阻擋時發展規避技術，藍隊則針對性地升級偵測能力。

4. **應用業界標準加密**：將隱蔽通道加密從教學用的 XOR 密碼升級為 AES-256-CTR（透過 ctypes 呼叫 OpenSSL），展示行為偵測即使在強加密下仍然有效。

5. **提供即時營運可視化**：實作安全營運中心（SOC）儀表板，聚合所有防禦元件的事件，提供現代安全營運核心所需的統一態勢感知。

6. **維護安全性與可重現性**：確保所有演練在隔離環境中進行，控制爆炸半徑——不進行權限提升、不進行破壞性操作，所有產物均駐留於記憶體或為臨時性的。

### 1.3 運作原則

本專案在設計和執行全程遵循以下運作原則：

**受控環境**：所有攻擊和防禦活動均在隔離的實驗室網路中進行。目標應用程式是專門建構的漏洞服務；不影響任何生產系統。紅隊在明確的範圍約束下運作——權限提升和破壞性影響技術被刻意排除，以維持受控的爆炸半徑。

**縱深防禦架構**：藍隊部署兩層防禦架構：

| 層級 | 機制 | 防護範圍 | 限制 |
|------|------|----------|------|
| 網路層 | 蜜罐 + iptables 自動封鎖 | 封鎖已知惡意 IP | 攻擊者可更換 IP 繞過 |
| 核心層 | eBPF 系統呼叫 hook + bpf_send_signal | 封鎖惡意行為，不論來源 IP | 需要知道要監控哪些系統呼叫 |

此架構展示每一層都有其固有限制，只有它們的組合才能提供穩健的防護。

**迭代式對抗演練**：展示設計為 7 回合對抗，說明網路安全是一個持續過程，而非一次性部署：

| 回合 | 角色 | 行動 | 結果 |
|------|------|------|------|
| 1 | 紅隊 | 偵察（nmap） | 發現目標服務 |
| 1b | 紅隊 → 藍隊 | 觸發蜜罐陷阱 | 紅隊 IP 被封鎖 |
| 1c | 紅隊 | IP 別名繞過 | 重新獲得網路存取 |
| 2 | 紅隊 | SSTI + 無檔案 C2 | 取得完全遠端控制 |
| 3 | 藍隊 | 部署 eBPF v1 | 清除現有威脅 |
| 4 | 紅隊 | 再次攻擊 | 被 eBPF 攔截 |
| 5 | 紅隊 | TCP 反向 Shell（規避） | 繞過 eBPF v1 |
| 6 | 藍隊 | 部署 eBPF v2 | 偵測並終止反向 Shell |

**可重現性與文件化**：每個攻擊和防禦步驟都附有精確的指令、預期輸出和技術說明。專案包含完整的演練腳本（`docs/DEMO_FLOW.md`），使任何團隊成員都能獨立重現完整演練。

---

## 2. 背景知識與分析框架

### 2.1 網路攻擊鏈（Cyber Kill Chain）

洛克希德·馬丁公司的網路攻擊鏈由 Hutchins、Cloppert 和 Amin 於 2011 年提出，提供了一個系統性框架來理解網路攻擊的各階段 [3]。該模型識別七個連續階段：偵察（Reconnaissance）、武器化（Weaponization）、投遞（Delivery）、利用（Exploitation）、安裝（Installation）、命令與控制（C2）以及目標行動（Actions on Objectives）。

本專案實作了七個階段中的六個（基於安全考量排除目標行動），每個階段對應至特定的工具和技術：

```
階段 1        階段 2           階段 3        階段 4          階段 5       階段 6
偵察    →   武器化      →   投遞     →   利用       →   安裝    →   命令與控制
nmap         memfd_create       SSTI POST      fork+execve      記憶體駐留     ICMP/TCP
             + AES-256-CTR      透過 curl      從 /proc/fd      agent         隱蔽通道
```

### 2.2 MITRE ATT&CK 框架

MITRE ATT&CK（對抗戰術、技術與公共知識）框架是一個基於真實觀察的全球公認對手行為知識庫 [4]。本專案將所有實作的技術對應至相應的 ATT&CK 識別碼：

| 戰術 | 技術編號 | 技術名稱 | 實作方式 |
|------|---------|---------|---------|
| 偵察 | T1595 | 主動掃描 | nmap 埠掃描與服務偵測 |
| 初始存取 | T1190 | 利用公開應用程式 | 透過 Flask/Jinja2 的 SSTI 注入 |
| 執行 | T1059.006 | Python 指令碼執行 | memfd 載入器、反向 Shell、C2 代理 |
| 防禦規避 | T1620 | 反射式程式碼載入 | memfd_create + 從 /proc/pid/fd 執行 |
| 防禦規避 | T1027 | 檔案混淆 | Base64 編碼 + AES-256-CTR 加密 |
| 命令與控制 | T1095 | 非應用層協定 | ICMP 隱蔽通道 + TCP 反向 Shell |
| 命令與控制 | T1571 | 非標準埠 | C2 和反向 Shell 使用 port 4444 |
| 資料外洩 | T1048.003 | 透過替代協定外洩 | DNS/ICMP 資料外洩 |

### 2.3 擴展柏克萊封包過濾器（eBPF）

eBPF 是 Linux 核心中的革命性技術，允許沙盒化程式在核心空間中執行，無需修改核心原始碼或載入核心模組 [5]。eBPF 最初設計用於封包過濾，已演化為通用的核心內虛擬機器，應用於網路、可觀察性和安全領域。

使 eBPF 成為安全監控理想選擇的關鍵特性包括：

- **核心空間執行**：eBPF 程式在核心中執行，提供對所有系統呼叫的可視性，且零上下文切換開銷。這使得從使用者空間無法規避。
- **安全保證**：eBPF 驗證器在載入前對每個程式進行靜態分析，確保沒有無界迴圈、越界記憶體存取或核心崩潰。
- **主動回應能力**：自 Linux 5.3 起，`bpf_send_signal()` 輔助函數允許 eBPF 程式直接從核心空間向當前程序發送訊號（包括 SIGKILL），實現無需使用者空間往返的即時威脅終止 [6]。
- **追蹤點 hook**：eBPF 程式可附加至系統呼叫進入點的靜態追蹤點（`sys_enter_*`），在系統呼叫處理程序執行前觸發。這使得搶先偵測成為可能——惡意操作可在完成前被阻止。

本專案將 eBPF 程式附加至六個追蹤點：`sys_enter_memfd_create`、`sys_enter_execve`、`sys_enter_socket`、`sys_enter_connect`、`sys_enter_dup2` 和 `sys_enter_dup3`。

### 2.4 網路欺敵與蜜罐

網路欺敵是一種主動防禦策略，使用誘餌系統來偵測、轉移和分析對手行為 [7]。蜜罐是一種安全資源，其價值在於被探測、攻擊或入侵——任何與蜜罐的互動本質上都是可疑的，因為合法使用者沒有理由存取它。

本專案部署了一個低互動蜜罐，在埠 2222 上模擬 SSH 伺服器。當攻擊者連線時（通常在偵察階段），蜜罐記錄來源 IP 並透過 iptables 觸發自動化防火牆封鎖。這種方法提供零誤報偵測——每個連接到蜜罐的行為，根據定義，都是未經授權的。

### 2.5 AES-256-CTR 加密（透過 OpenSSL）

進階加密標準（AES）的計數器（CTR）模式是由 NIST 標準化的對稱加密方案 [8]。AES-256-CTR 作為串流密碼運作：透過使用 AES-256 加密連續的計數器值來產生偽隨機金鑰流，然後將金鑰流與明文進行 XOR 運算。關鍵特性包括：

- **語義安全性**：每個訊息使用隨機初始化向量（IV），相同的明文會產生不同的密文，防止模式分析。
- **無需填充**：CTR 模式產生與明文等長的密文，適合有大小限制的網路協定。
- **可平行化**：計數器區塊彼此獨立，允許硬體加速加密。

本專案透過 Python 的 ctypes 外部函數介面存取 OpenSSL libcrypto 中的 AES-256-CTR 實作，避免需要任何透過 pip 安裝的加密套件，同時達到業界標準的加密強度。

---

## 3. 問題描述與攻擊手法

### 3.1 伺服器端模板注入（SSTI）

**問題**：目標應用程式（`target_app.py`）是一個 Flask 網路應用程式，使用 Python f-string 插值將使用者輸入直接嵌入 Jinja2 模板中再進行渲染。這構成了伺服器端模板注入漏洞（CWE-1336）[9]。

**機制**：當使用者提交診斷查詢時，應用程式如下建構模板：

```python
template = f"<pre>Query: {user_input}</pre>"
render_template_string(template)
```

如果 `user_input` 包含 Jinja2 表達式分隔符（`{{ }}`），模板引擎會將其作為程式碼執行。攻擊者可以遍歷 Python 的物件模型來達到 `os.popen()` 並實現遠端程式碼執行（RCE）：

```
{{ config.__class__.__init__.__globals__['os'].popen('COMMAND').read() }}
```

**影響**：以 Flask 程序的權限執行完全的遠端程式碼。

### 3.2 透過 memfd_create 的無檔案惡意程式

**問題**：傳統惡意程式偵測依賴掃描磁碟上的檔案。`memfd_create` 系統呼叫（Linux 3.17+，x86_64 上的系統呼叫 319）建立完全存在於 RAM 中、沒有檔案系統條目的匿名檔案，使得無檔案執行能規避基於檔案的偵測 [10]。

**機制**：攻擊鏈如下進行：

1. `memfd_create("", 0)` — 在核心 tmpfs 中建立匿名檔案描述符
2. `write(fd, agent_code)` — 將 C2 代理寫入匿名 fd
3. `fork()` — 父程序返回以讓網路伺服器回應
4. `execve("/usr/bin/python3", ["/proc/<pid>/fd/<N>"])` — 子程序從匿名 fd 執行代理

產生的程序完全從記憶體執行。代理程式永遠不接觸檔案系統，不留下鑑識分析或即時防毒掃描的任何痕跡。

### 3.3 ICMP 隱蔽命令與控制通道

**問題**：傳統的 TCP/UDP C2 通道會被防火牆和 IDS/IPS 系統監控。ICMP（網際網路控制訊息協定，RFC 792）通常被防火牆允許通過，因為封鎖它會破壞基本的網路診斷功能（ping、traceroute）[11]。

**機制**：C2 通道將加密的命令和回應資料嵌入 ICMP echo request（類型 8）封包的 payload 欄位中。協定使用：

- **ICMP ID 欄位（0x1337）** 作為流量識別碼
- **魔術位元組（0xDE）** 用於快速 payload 驗證
- **AES-256-CTR 加密**，每個封包使用隨機 IV 確保 payload 機密性
- **分塊傳輸**（480 位元組的 chunk）用於大型命令輸出

C2 伺服器和代理都發送 ICMP 類型 8 封包；核心自動產生的回覆（類型 0）被忽略。

### 3.4 TCP 反向 Shell（eBPF 規避）

**問題**：當藍隊部署了監控 `memfd_create`、從 `/proc/fd` 執行和原始 ICMP socket 的 eBPF 偵測後，攻擊者必須適應。標準的 TCP 反向 Shell 不使用任何這些被監控的系統呼叫。

**機制**：規避技術用傳統的反向 Shell 取代無檔案 ICMP C2：

1. `fork()` — 將 Shell 程序背景化
2. `socket(AF_INET, SOCK_STREAM, 0)` — 建立普通 TCP socket（非 SOCK_RAW）
3. `connect(attacker_ip, 4444)` — 向外 TCP 連線
4. `dup2(sock_fd, 0/1/2)` — 將 stdin、stdout、stderr 重導向至 socket
5. `pty.spawn("/bin/bash")` — 產生互動式 Shell

這繞過了所有三個 eBPF v1 hook，因為它使用標準 TCP（非原始 ICMP）、不呼叫 `memfd_create`、也不從 `/proc/fd` 執行。

### 3.5 DNS/ICMP 資料外洩

**問題**：在建立存取後，攻擊者可能尋求外洩敏感資料。傳統的資料傳輸方法（HTTP、FTP、SCP）通常被監控。DNS 和 ICMP 通道經常被忽視。

**機制**：外洩代理收集敏感檔案（`/etc/passwd`、SSH 金鑰、bash 歷史記錄、應用程式原始碼）並透過以下方式傳輸：

- **DNS 通道**：資料經 Base32 編碼後嵌入為 DNS 查詢中受控域名的子域名標籤（`<data>.x.exfil.local`）。攻擊者端的假 DNS 伺服器重組這些片段。
- **ICMP 通道**：資料經十六進位編碼後嵌入 ICMP echo request 的填充模式中（透過 `ping -p` 選項）。

兩個通道都使用帶序號的分塊傳輸、完整性驗證的校驗碼，以及隨機化的封包間延遲來規避基於模式的偵測。

---

## 4. 提出的解決方案

### 4.1 第一層：網路欺敵 — 蜜罐與網路 MDR

**元件 1 — 蜜罐（`target/honeypot.py`）**：

低互動 SSH 蜜罐在埠 2222 上監聽，呈現逼真的 OpenSSH 8.9p1 標語，足以欺騙服務偵測工具（如 nmap `-sV`）。任何連線都會被記錄至 `trap.log`，包含時間戳、來源 IP、埠和客戶端資料。

**元件 2 — 網路 MDR（`blue_team/blue_mdr_network.py`）**：

監控常駐程式輪詢 `trap.log` 中的新攻擊者 IP 條目。偵測到後，立即執行：

```
iptables -I INPUT 1 -s <attacker_ip> -j DROP
```

規則插入在 INPUT 鏈的位置 1（最高優先級），確保優先於任何現有的 ACCEPT 規則。這阻止攻擊者存取機器上的任何服務。

**有效性**：零誤報偵測——任何連接到蜜罐的行為根據定義都是未經授權的。

**限制**：基於 IP 的封鎖可透過更改來源 IP（例如透過 IP 別名）來繞過。此限制促使第二層（行為偵測）的需求。

### 4.2 第二層：核心層偵測 — eBPF MDR

**元件 3 — eBPF MDR v1（`blue_team/blue_ebpf_mdr.py`）**：

三個 eBPF 追蹤點 hook 偵測無檔案惡意程式：

| Hook | 追蹤點 | 偵測邏輯 |
|------|--------|---------|
| Hook 1 | `sys_enter_memfd_create` | 伺服器上任何 memfd_create 呼叫都是可疑的；記錄 PID 用於關聯分析 |
| Hook 2 | `sys_enter_execve` | 模式匹配檔名中的 `/proc/<pid>/fd/` — 表示從匿名記憶體執行 |
| Hook 3 | `sys_enter_socket` | 偵測 `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`；與 memfd PID 關聯確認高信心度 C2 偵測 |

啟用 `--kill` 模式時，`bpf_send_signal(SIGKILL)` 在系統呼叫完成前從核心空間終止惡意程序。此外，冷啟動掃描器在啟動時檢查 `/proc/*/exe` 中的現有 `memfd:` 程序。

**元件 4 — eBPF MDR v2（`blue_team/blue_ebpf_mdr_v2.py`）**：

保留所有 v1 hook 並新增三個 hook 來偵測反向 Shell：

| Hook | 追蹤點 | 偵測邏輯 |
|------|--------|---------|
| Hook 4 | `sys_enter_connect` | 檢查目的埠是否在可配置的可疑埠清單中（預設：4444、4445、5555、1234、1337） |
| Hook 5 | `sys_enter_dup2` | 追蹤每個 PID 的位元遮罩；當 fd 0、1、2 全部被重導向時 → 確認反向 Shell |
| Hook 6 | `sys_enter_dup3` | 與 Hook 5 相同，覆蓋 Python `os.dup2(fd, fd2, inheritable=False)` 的程式碼路徑 |

`connect` hook 在連線時提供快速偵測（基於埠），而 `dup2/dup3` hook 提供不依賴埠的偵測，基於反向 Shell 的行為特徵。

### 4.3 即時營運可視化 — SOC 儀表板

**元件 5 — SOC 儀表板（`blue_team/soc_dashboard.py`）**：

基於 Flask 的網路應用程式（埠 8080）聚合所有防禦元件的事件，並在即時暗色主題 SOC 控制台中顯示。功能包括：

- **伺服器推送事件（SSE）**：即時串流至瀏覽器
- **多來源攝取**：讀取 `trap.log`（蜜罐事件）和 `soc_events.jsonl`（eBPF 警報、iptables 封鎖）
- **HTTP POST API**（`/api/event`）：供程式化提交事件
- **統計卡片**：事件總數、封鎖 IP 數、程序終止數、嚴重警報數
- **色彩標記嚴重度**：CRITICAL（紅）、HIGH（黃）、MEDIUM（藍）、INFO（灰）

藍隊工具透過 `--soc-log` 旗標寫入 `soc_events.jsonl`，使儀表板能在蜜罐事件旁同時顯示 eBPF 偵測和網路封鎖。

### 4.4 加密升級 — AES-256-CTR

隱蔽 C2 通道加密從 XOR 升級為 AES-256-CTR：

| 特性 | XOR（原始） | AES-256-CTR（升級後） |
|------|------------|---------------------|
| 演算法 | XOR 串流密碼 | AES-256 計數器模式 |
| 金鑰推導 | 固定 16 位元組明文金鑰 | SHA-256(shared_secret) → 32 位元組 |
| IV/Nonce | 無 | 每個封包隨機 16 位元組 IV |
| 已知明文抵抗性 | 可輕易破解 | 計算上不可行 |
| 實作方式 | 純 Python | ctypes + OpenSSL libcrypto |
| 依賴 | 無 | 系統 libcrypto（Linux 預裝） |

此升級展示兩個重要觀點：（1）真實世界的惡意程式越來越多地使用強加密；（2）行為偵測（eBPF）無論加密強度如何都依然有效，因為它偵測的是惡意的系統呼叫模式，而非 payload 內容。

### 4.5 縱深防禦總覽

```
┌─────────────────────────────────────────────────────┐
│  第一層 — 網路層（網路欺敵）                          │
│  honeypot.py（埠 2222）→ trap.log →                  │
│  blue_mdr_network.py → iptables DROP                │
│  偵測：偵察行為，封鎖已知惡意 IP                       │
├─────────────────────────────────────────────────────┤
│  第二層 — 核心層（eBPF 行為偵測）                     │
│  v1: memfd_create + execve + 原始 ICMP socket        │
│  v2: + connect（可疑埠）+ dup2/dup3（Shell）         │
│  偵測：惡意行為，不論來源 IP                           │
├─────────────────────────────────────────────────────┤
│  可視化 — SOC 儀表板（埠 8080）                      │
│  即時網頁 UI 聚合所有事件                             │
└─────────────────────────────────────────────────────┘
```

---

## 5. 結論

本專案展示了有效的網路安全需要分層、適應性的方法。透過 7 回合的紅藍隊對抗，我們闡述了幾個關鍵洞察：

**沒有單一防禦是足夠的。** 網路層防禦（蜜罐、防火牆）可透過更換 IP 地址繞過。核心層防禦（eBPF v1）可透過使用不同的系統呼叫模式繞過。只有多個獨立偵測機制的組合才能提供穩健的防護。

**攻擊者會適應，因此防禦者必須進化。** 當 eBPF v1 阻擋了無檔案 ICMP C2 後，紅隊轉向使用不涉及任何被監控系統呼叫的標準 TCP 反向 Shell。藍隊則透過部署帶有 `connect()` 和 `dup2()` 額外 hook 的 eBPF v2 來回應，恢復偵測能力。這個循環反映了真實世界的安全營運。

**行為偵測超越加密。** 將 C2 通道從 XOR 升級到 AES-256-CTR 使得 payload 檢查變得不可能，但 eBPF 偵測仍然完全有效，因為它監控的是系統呼叫行為——程序做了什麼——而非流量包含什麼。

**營運可視化至關重要。** SOC 儀表板提供跨所有防禦元件的統一態勢感知，使藍隊能理解完整的攻擊圖像，而非對孤立的警報做出反應。

**無檔案技術挑戰傳統防禦。** 透過 `memfd_create` 完全在記憶體中執行，C2 代理不留下任何檔案系統痕跡供傳統防毒或鑑識工具偵測。這驗證了透過 eBPF 等技術進行核心層行為監控的必要性。

本專案成功實作了 7 項 MITRE ATT&CK 攻擊技術和 7 項對應的偵測能力，橫跨兩個防禦層，在受控、可重現的環境中為學生提供攻擊與防禦網路安全作業的實務經驗。

---

## 6. 參考文獻

[1] IBM Security，「資料外洩成本報告 2024」，IBM Corporation，2024。取自：https://www.ibm.com/reports/data-breach

[2] K. Wilhoit，「剖析 ICMP 協定及其在隧道與外洩中的應用」，*Trend Micro Research*，2013。取自：https://www.trendmicro.com/vinfo/us/threat-encyclopedia/web-attack/137/

[3] E. M. Hutchins、M. J. Cloppert 和 R. M. Amin，「以情報驅動的電腦網路防禦——基於對手活動分析與入侵攻擊鏈」，*第六屆資訊戰爭與安全國際會議論文集*，Lockheed Martin Corporation，2011。

[4] B. Strom、A. Applebaum、D. Miller、K. Nickels、A. Pennington 和 C. Thomas，「MITRE ATT&CK：設計與哲學」，MITRE Corporation，技術報告 MP-19-01075，2020。取自：https://attack.mitre.org

[5] J. Corbet，「eBPF 深入介紹」，*LWN.net*，2017 年 12 月。取自：https://lwn.net/Articles/740157/

[6] Y. Song，「bpf: 實作 bpf_send_signal 輔助函數」，Linux Kernel Commit，2019。取自：https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8b401f9ed244

[7] L. Spitzner，*蜜罐：追蹤駭客*。Addison-Wesley Professional，2003。ISBN: 0-321-10895-7。

[8] 美國國家標準暨技術研究院，「區塊密碼操作模式建議」，NIST 特刊 800-38A，2001。取自：https://csrc.nist.gov/publications/detail/sp/800-38a/final

[9] J. Kettle，「伺服器端模板注入」，PortSwigger Research，2015。取自：https://portswigger.net/research/server-side-template-injection

[10] M. Kerrisk，「memfd_create(2) — Linux 手冊頁」，*The Linux man-pages project*，2020。取自：https://man7.org/linux/man-pages/man2/memfd_create.2.html

[11] J. Postel，「網際網路控制訊息協定」，RFC 792，Internet Engineering Task Force，1981 年 9 月。取自：https://www.rfc-editor.org/rfc/rfc792

[12] T. Ylonen 和 C. Lonvick，「安全殼層（SSH）傳輸層協定」，RFC 4253，Internet Engineering Task Force，2006 年 1 月。取自：https://www.rfc-editor.org/rfc/rfc4253

[13] BCC 作者群，「BPF 編譯器套件（BCC）— 用於基於 BPF 的 Linux IO 分析、網路、監控等工具」，2015 至今。取自：https://github.com/iovisor/bcc

[14] OpenSSL 專案，「OpenSSL：密碼學與 SSL/TLS 工具套件」，1998 至今。取自：https://www.openssl.org
