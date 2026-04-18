# PDF Proposal 校對報告

**日期**：2026-04-09
**PDF 檔案**：Cybersecurity_CSE_517_1.pdf（16 頁）
**對照基準**：`docs/PROJECT_PROPOSAL.md`（Git main 分支）

---

## 一、PDF vs Markdown Proposal 校對

### 已修正（PDF 比 Markdown 新）

PDF 已包含先前審查報告（2026-04-08-proposal-exfil-fixes.md）的修改：

| 項目 | Markdown (舊) | PDF (新) | 狀態 |
|------|-------------|---------|------|
| Section 1.2 目標 1 | "reconnaissance through C2" | "reconnaissance through actions on objectives (data exfiltration)" | [OK] 已修 |
| Section 2.2 ATT&CK 表 | 8 項技術 | 13 項技術（補上 T1053.003, T1082, T1005, T1070.003, T1070.004） | [OK] 已修 |
| Section 8 結論 | 缺 exfiltration 盲點段落 | 已加入 data exfiltration blind spot 段落 | [OK] 已修 |
| Section 8 總結句 | "7 ATT&CK techniques" | "13 ATT&CK techniques (spanning 9 tactic categories)" | [OK] 已修 |

### 新發現的問題

| ID | 嚴重度 | 位置 | 問題 |
|----|--------|------|------|
| PDF-001 | **高** | Section 2.1 p.3-4 | 文字寫 "We implement **six** of the seven phases (excluding Actions on Objectives for safety reasons)" 但 Kill Chain 表格明確列出 Phase 7 Exfiltrate，Section 3.5 詳述 DNS/ICMP exfiltration，Round 7 demo 也做了。**應改為 "all seven phases"**（Markdown 版本此處正確） |
| PDF-002 | **高** | Section 9 p.15 | **References 只列到 [6]，缺少 [7]-[14]**。但文中引用了 [7] (Section 2.4 Honeypots)、[8] (Section 2.5 AES)、[9] (Section 3.1 SSTI)、[10] (Section 3.2 memfd_create)、[11] (Section 3.3 ICMP RFC)。讀者會找不到這些引用的出處 |
| PDF-003 | **中** | Section 7 p.14 | Markdown 有 Section 7.4 "Demo Day Risks"（網路不通、eBPF 載入失敗、Port 衝突等備案），PDF 完全刪除了。這段對 demo 準備有實用價值，建議保留 |
| PDF-004 | **低** | Section 8 p.15 | 結論寫 "spanning 9 tactic categories"。數一下：Reconnaissance, Initial Access, Execution, Defense Evasion, C2, Exfiltration, Persistence, Discovery, Collection = 9。**數字正確**，僅提醒確認 |

### PDF-001 詳細說明

PDF Section 2.1 第一段（page 3-4）：

> "Command and Control (C2), and Actions on Objectives. We implement **six of the seven phases (excluding Actions on Objectives for safety reasons)**:"

但隨後的 Kill Chain 表格：

| Phase 7 | Exfiltrate | DNS/ICMP data theft |

以及 Section 3.5、Section 6 Round 7、Section 8 結論都在講 exfiltration。這句話與整份文件的其餘部分矛盾。

**修改建議**：改為 "We implement all seven phases of the Kill Chain:"（與 Markdown `PROJECT_PROPOSAL.md` line 84 一致）

### PDF-002 詳細說明

PDF References section 列出：
```
[1] IBM Security — Data Breach Report 2024
[2] A. Singh et al. — ICMP Tunneling, ACISP 2003
[3] E. M. Hutchins et al. — Cyber Kill Chain, 2011
[4] B. Strom et al. — MITRE ATT&CK, 2020
[5] M. Fleming — eBPF intro, LWN.net 2017
[6] Y. Song — bpf_send_signal, Linux Kernel 2019
```

**缺少但有被引用的**：
```
[7]  L. Spitzner, Honeypots: Tracking Hackers, 2003          → 引用於 Section 2.4
[8]  NIST SP 800-38A, Block Cipher Modes (AES-CTR), 2001     → 引用於 Section 2.5
[9]  J. Kettle, Server-Side Template Injection, 2015          → 引用於 Section 3.1
[10] M. Kerrisk, memfd_create(2) man page, 2020              → 引用於 Section 3.2
[11] J. Postel, RFC 792 (ICMP), 1981                         → 引用於 Section 3.3
```

**有在 Markdown 中但未被引用的（supplementary）**：
```
[12] T. Ylonen, RFC 4253 (SSH Transport Layer), 2006
[13] BCC Authors, BPF Compiler Collection, 2015–
[14] The OpenSSL Project, OpenSSL Toolkit, 1998–
```

---

## 二、文獻審查

### 各文獻引用位置與用途

| # | 文獻 | 引用位置 | 用途 | 審查結果 |
|---|------|---------|------|---------|
| [1] | IBM Data Breach Report 2024 | Section 1.1 動機 | 提供全球資料外洩成本 $4.88M 及常見攻擊向量統計 | [OK] 正確引用，數字與 IBM 2024 報告一致 |
| [2] | Singh et al., ICMP Tunneling, ACISP 2003 | Section 1.1 動機 | 說明 ICMP 缺乏 port-based multiplexing，data field 易被濫用為隱蔽通道 | [OK] 正確引用 |
| [3] | Hutchins et al., Cyber Kill Chain, 2011 | Section 2.1 | 定義 7 階段 Kill Chain 框架作為專案的攻擊結構基礎 | [OK] 正確引用，Lockheed Martin 原始論文 |
| [4] | Strom et al., MITRE ATT&CK, 2020 | Section 1.1 + Section 2.2 | 說明 ICMP C2 案例（PingPull, Regin, Cobalt Strike）；作為技術分類框架 | [OK] 正確引用 |
| [5] | Fleming, eBPF intro, LWN.net 2017 | Section 2.3 | 介紹 eBPF 基礎概念（kernel-space 執行、verifier、tracepoint） | [OK] 正確引用 |
| [6] | Song, bpf_send_signal, 2019 | Section 2.3 | 說明 bpf_send_signal() helper 在 Linux 5.3 加入，允許 eBPF 直接送 SIGKILL | [OK] 正確引用，kernel commit 可驗證 |
| [7] | Spitzner, Honeypots, 2003 | Section 2.4 | 定義網路欺敵與 honeypot 的理論基礎 | [OK] 正確引用，經典教科書 |
| [8] | NIST SP 800-38A, 2001 | Section 2.5 | AES-CTR mode 的標準定義 | [OK] 正確引用，NIST 官方文件 |
| [9] | Kettle, SSTI, PortSwigger 2015 | Section 3.1 | SSTI 漏洞的原始研究與定義 | [OK] 正確引用，PortSwigger Research 原始文章 |
| [10] | Kerrisk, memfd_create(2), 2020 | Section 3.2 | memfd_create syscall 的技術定義（Linux 3.17+, syscall 319） | [OK] 正確引用，Linux man-pages |
| [11] | Postel, RFC 792, 1981 | Section 3.3 | ICMP 協定定義，說明防火牆通常放行 ICMP | [OK] 正確引用，IETF RFC |
| [12] | Ylonen, RFC 4253, 2006 | **未在 PDF 內文引用** | SSH 傳輸層協定（與 honeypot 假 SSH banner 相關） | [WARN] Supplementary，建議在 Section 2.4 提及 SSH banner 時加引用，或從 references 移除 |
| [13] | BCC Authors, 2015– | **未在 PDF 內文引用** | BCC 工具集（eBPF 編譯器） | [WARN] Supplementary，建議在 Section 2.3 或 5.5 提及 BCC 時加引用 |
| [14] | OpenSSL Project, 1998– | **未在 PDF 內文引用** | OpenSSL 加密套件 | [WARN] Supplementary，建議在 Section 2.5 提及 ctypes + OpenSSL 時加引用 |

### 文獻品質評估

| 品質維度 | 評估 |
|---------|------|
| 引用數量 | 14 篇，對課程 proposal 而言足夠 |
| 來源品質 | 優秀——含 NIST 標準、IETF RFC、peer-reviewed 會議論文、知名業界報告 |
| 時效性 | [1] IBM 2024 為最新；[11] RFC 792 (1981) 雖舊但仍是 ICMP 權威定義 |
| 覆蓋面 | 每個技術背景都有對應文獻支撐；攻擊面和防禦面都有覆蓋 |
| 缺失 | 無明顯遺漏。若要更完整，可考慮加入 DNS exfiltration 的專門文獻（如 Nadler et al. 2019 "Detection of Malicious and Low Throughput Data Exfiltration Over the DNS Protocol"），但非必要 |

---

## 三、待修正項目總結

| 優先順序 | ID | 修改內容 |
|---------|-----|--------|
| 1 | PDF-002 | **補上 References [7]-[11]**（被引用但未列出），決定 [12]-[14] 要加引用或移除 |
| 2 | PDF-001 | Section 2.1 "six of the seven phases" → "all seven phases" |
| 3 | PDF-003 | 考慮恢復 Section 7.4 Demo Day Risks |
| 4 | — | Markdown `PROJECT_PROPOSAL.md` 需同步 PDF 的修改（ATT&CK 表 13 項、結論段落等） |
