# Code Review Prompt — 專案實作審查

> 將以下內容交給審查 bot，讓它檢查程式碼品質、架構一致性和文件完整性。

---

## 專案概述

本專案為網路安全課程的紅藍隊攻防演練實驗室。以下是 AI 助手在本專案中完成的所有實作工作。

## 已完成的工作清單

### 1. 紅方攻擊工具

**red_team/red_reverse_shell.py（新建）**
- TCP 反向 Shell，透過 SSTI 注入
- 設計目的：繞過 eBPF v1 的三個 hook（memfd_create / execve / socket）
- 使用 fork → socket(SOCK_STREAM) → connect → dup2 → pty.spawn
- 內建 TCP listener 接收回連 shell
- 不需要 sudo（用 TCP 不用 ICMP raw socket）

**red_team/red_attacker.py（修改 — 加密升級）**
- 將 ICMP C2 加密從 XOR 升級為 AES-256-CTR
- 透過 ctypes 呼叫系統 OpenSSL libcrypto（EVP_aes_256_ctr）
- Key 推導：SHA-256(shared_secret) → 32-byte AES key
- 每封包隨機 16-byte IV，prepend 到密文前
- C2 server 端和嵌入式 agent 端都已更新
- 協議格式：[MAGIC][TYPE][IV(16B)][AES-CTR(data)]

### 2. 藍方防禦工具

**blue_team/blue_ebpf_mdr_v2.py（新建）**
- eBPF v2，保留 v1 的 3 個 hook + 新增 3 個：
  - Hook 4: sys_enter_connect — 偵測外連到可疑 port
  - Hook 5: sys_enter_dup2 — 偵測 fd 0/1/2 全部重導向（reverse shell 模式）
  - Hook 6: sys_enter_dup3 — 覆蓋 Python inheritable=False 路徑
- ctypes Event struct 對齊驗證通過（160 bytes）
- 可配置 --suspect-ports、--whitelist、--soc-log

**blue_team/blue_mdr_network.py（新建）**
- 網路層 MDR：監控 trap.log，自動 iptables DROP 封鎖攻擊者 IP
- 支援 --cleanup（退出時清除規則）、--soc-log（寫入 SOC 事件）

**blue_team/soc_dashboard.py（新建）**
- Flask 即時 SOC 監控儀表板（port 8080）
- Server-Sent Events 即時推送
- 讀取 trap.log + soc_events.jsonl
- 暗色主題 UI：統計卡片 + 事件時間線 + 色彩標記嚴重度
- HTTP POST API（/api/event）

### 3. 靶機服務

**target/honeypot.py（新建）**
- Port 2222 假 SSH 蜜罐
- 模擬 OpenSSH 8.9p1 banner
- 記錄攻擊者 IP/timestamp/client data 到 trap.log
- 多執行緒處理連線

### 4. 環境腳本

**setup_env.sh（重寫）**
- 自動偵測 WSL2 vs 原生 Linux
- WSL2：只裝紅方工具（跳過 eBPF/kernel headers）
- 原生：裝完整環境
- 使用 python3 -m venv --system-site-packages 環境隔離

**cleanup.sh（新建）**
- 一鍵環境重置：殺程序、清 iptables、移除 IP alias、清 log、清 loot、移除 crontab
- 支援 --dry 預覽模式

### 5. 文件

**docs/DEMO_FLOW.md（新建）**
- 完整 7 回合攻防演練腳本
- 雙機架構（WSL2 紅方 / Lab 藍方+靶機）
- 每回合精確指令、預期輸出、講解要點

**docs/PROJECT_PROPOSAL.md（新建）**
- 英文版完整 Project Proposal（6 章節）

**docs/PROJECT_PROPOSAL_ZH.md（新建）**
- 中文版完整 Project Proposal

**docs/RED_TEAM_PLAYBOOK.md（重寫）**
- 從舊版 HackMD 架構更新為現行架構

**docs/REPORT_ZH.md（重寫）**
- 從 3 元件擴充為 15+ 元件的完整中文技術報告

**docs/REPORT_EN.md（重寫）**
- 同上，英文版

**README.md（多次更新）**
- 專案結構、Quick Start、技術亮點、MITRE ATT&CK 表

### 6. MITRE ATT&CK 映射驗證

對 14 個技術 ID 逐一比對官方 MITRE ATT&CK 網站：
- 12 個驗證通過
- 2 個修正：T1036（IP alias 不是 Masquerading）→ 移除、T1071.001（TCP 不是 Web Protocol）→ 改為 T1095 + T1571

---

## 審查重點

請審查 bot 檢查以下項目：

1. **程式碼正確性**：每個 .py 檔案是否能正常 import 和執行？
2. **架構一致性**：所有文件描述是否與實際程式碼一致？
3. **安全性**：是否有引入安全漏洞（command injection、path traversal 等）？
4. **eBPF 正確性**：C struct 與 Python ctypes struct 是否對齊？placeholder 替換是否完整？
5. **AES 加密**：ctypes 函數簽名是否正確？加解密是否 round-trip 成功？
6. **MITRE ATT&CK**：所有技術 ID 是否對應正確？
7. **文件完整性**：README 專案樹是否與實際檔案一致？
