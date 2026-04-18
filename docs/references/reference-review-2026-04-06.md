# 文獻引用審查報告

**審查日期**：2026-04-06
**審查範圍**：14 篇參考文獻
**審查依據**：`/home/cyw123/cybersecurity/REVIEW_PROMPT_REFERENCES.md`

---

## 總覽表

| # | 文獻 | 存在性 | 作者正確 | 內容正確 | 年份正確 | 幽靈文獻？ | 嚴重度 |
|---|------|--------|---------|---------|---------|-----------|--------|
| 1 | IBM Data Breach 2024 | YES | YES | PARTIAL | YES | 否 | 中 |
| 2 | Wilhoit, ICMP Tunneling | NO | PARTIAL | NO | N/A | **極可能是** | **嚴重** |
| 3 | Hutchins et al., Kill Chain | YES | YES | YES | YES | 否 | 低 |
| 4 | Strom et al., MITRE ATT&CK | YES | YES | YES | YES | 否 | 中 |
| 5 | Corbet, eBPF intro | YES | **NO** | YES | YES | 否 | 中 |
| 6 | Song, bpf_send_signal | YES | YES | PARTIAL | YES | 否 | 低 |
| 7 | Spitzner, Honeypots | YES | YES | YES | YES | 否 | 無 |
| 8 | NIST SP 800-38A | YES | N/A | PARTIAL | YES | 否 | 低 |
| 9 | Kettle, SSTI | YES | YES | YES | YES | 否 | 無 |
| 10 | Kerrisk, memfd_create | YES | YES | PARTIAL | N/A | 否 | 低 |
| 11 | Postel, RFC 792 | YES | YES | YES | YES | 否 | 無 |
| 12 | Ylonen & Lonvick, RFC 4253 | YES | YES | YES | YES | 否 | 無 |
| 13 | BCC (iovisor/bcc) | YES | YES | YES | N/A | 否 | 無 |
| 14 | OpenSSL | YES | YES | YES | N/A | 否 | 無 |

---

## 嚴重問題（必須修正）

### [2] 極可能為幽靈文獻

- **標題** "Dissecting the ICMP Protocol and Its Use in Tunneling and Exfiltration" 不存在於 Trend Micro 網站或任何可查來源
- **URL** `https://www.trendmicro.com/vinfo/us/threat-encyclopedia/web-attack/137/` 實際指向 "Watering Hole 101"，與 ICMP tunneling 無關
- **作者** Kyle Wilhoit 為真實 Trend Micro 研究員，但專長為 ICS/SCADA 蜜罐安全（BlackHat USA/Europe 2013 講者）
- **判定**：典型 AI 幻覺——真實作者 + 真實機構 + 合理 URL，但各元素互不相關
- **處置**：必須替換或移除

### [5] 作者歸屬錯誤

- LWN.net Articles/740157/ 實際作者為 **Matt Fleming**，非 Jonathan Corbet
- 頁面明確標示 "This article was contributed by Matt Fleming"
- Jonathan Corbet 為 LWN.net 主編，非此文作者
- **處置**：將 "J. Corbet" 改為 "M. Fleming"

### [4] 報告編號錯誤

- "MP-19-01075" 並非有效的 MITRE 產品編號
- 正確：MITRE Product Number **MP180360R1**（2020 修訂版）；Distribution Control **PRS-19-01075-28**
- "MP-19-01075" 混淆了 distribution control 編號 (19-01075) 與 MITRE product 前綴 (MP)
- **處置**：更正編號或僅引用 URL

### [1] fileless malware 宣稱無據

- $4.88M 全球平均損失數字正確（IBM 官方新聞稿確認）
- 「fileless malware 技術攻擊趨勢上升」未在此報告中找到。報告討論的攻擊向量為 stolen credentials (16%)、phishing (15%)、BEC、malicious insiders
- **處置**：將 fileless malware 宣稱改用其他來源，或從此引用中移除

---

## 次要問題（建議修正）

### [3] 出版資訊可更精確

- 宣稱 "Proceedings of the 6th International Conference on Information Warfare and Security"
- 更精確："Leading Issues in Information Warfare & Security Research, Vol. 1, Issue 1, pp. 1-14 (2011)"
- 兩者有關聯（期刊收錄 ICIW 2011 論文），不算錯誤但不夠精確

### [6] bpf_send_signal 描述有偏差

- 宣稱：「bpf_send_signal() 允許 eBPF 程式從 kernel 空間發送 SIGKILL」
- 實際：bpf_send_signal() 為**通用信號 helper**，可發送任意有效信號（含 SIGKILL）
- 原始 commit 的範例信號為 SIGALARM，用途為觸發 stack trace collection
- 建議調整措辭：「可發送任意信號（含 SIGKILL）」

### [8] "semantic security" 術語歸屬

- SP 800-38A 為操作規範，未使用 "semantic security" 術語
- CTR mode 確實具備 IND-CPA 安全性（等同 semantic security），但此為密碼學理論分析結果
- 建議補充密碼學教科書引用或改用 "IND-CPA security"

### [10] syscall 319 來源歸屬

- memfd_create 的 syscall number 319 on x86_64 事實正確（Linux kernel syscall_64.tbl 確認）
- 但 man page 本身不列出 syscall 編號，此資訊出自 kernel 原始碼
- 嚴格來說來源歸屬有小瑕疵

---

## 完全正確的文獻（6 篇）

| # | 文獻 | 備註 |
|---|------|------|
| 7 | Spitzner, Honeypots: Tracking Hackers | ISBN、作者、出版年、定義內容全部正確 |
| 9 | Kettle, Server-Side Template Injection | 為 SSTI 研究的原始定義性來源，2015 年 Black Hat USA 同步發表 |
| 11 | RFC 792, ICMP | STD 5, type 8/0 定義正確，Jon Postel 1981 |
| 12 | RFC 4253, SSH Transport Layer | 版本字串格式定義正確，Ylonen & Lonvick 2006 |
| 13 | BCC (iovisor/bcc) | TRACEPOINT_PROBE、BPF_HASH、perf_submit 全部存在於官方 reference guide |
| 14 | OpenSSL | EVP_aes_256_ctr、EVP_EncryptInit_ex、EVP_EncryptUpdate 全部存在於 evp.h |

---

## 統計

- 完全正確：6 篇（43%）
- 小瑕疵：4 篇（29%）——[3] [6] [8] [10]
- 需修正：3 篇（21%）——[1] [4] [5]
- 需替換/移除：1 篇（7%）——[2]

---

## 驗證來源

### [1] IBM Data Breach 2024
- IBM Official Press Release (2024-07-30): https://newsroom.ibm.com/2024-07-30-ibm-report-escalating-data-breach-disruption-pushes-costs-to-new-highs

### [2] Trend Micro ICMP
- Trend Micro web-attack/137 actual content: "Watering Hole 101"
- Kyle Wilhoit at Black Hat USA 2013: ICS/SCADA honeypot research

### [3] Kill Chain
- Lockheed Martin PDF: https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf
- Semantic Scholar: confirmed 3 authors, 2011

### [4] MITRE ATT&CK
- PDF: https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf
- MITRE site: https://www.mitre.org/sites/default/files/2021-11/prs-19-01075-28-mitre-attack-design-and-philosophy.pdf

### [5] LWN eBPF
- https://lwn.net/Articles/740157/ — byline: "contributed by Matt Fleming"

### [6] bpf_send_signal
- Commit: https://github.com/torvalds/linux/commit/8b401f9ed2441ad9e219953927a842d24ed051fc
- LWN 5.3 merge window: https://lwn.net/Articles/793246/

### [7] Honeypots
- Amazon: https://www.amazon.com/Honeypots-Tracking-Hackers-Lance-Spitzner/dp/0321108957
- ACM DL: https://dl.acm.org/doi/10.5555/515237

### [8] NIST SP 800-38A
- NIST CSRC: https://csrc.nist.gov/pubs/sp/800/38/a/final

### [9] SSTI
- PortSwigger: https://portswigger.net/research/server-side-template-injection
- Black Hat USA 2015: https://blackhat.com/us-15/speakers/James-Kettle.html

### [10] memfd_create
- man7.org: https://man7.org/linux/man-pages/man2/memfd_create.2.html
- syscall table: https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl

### [11] RFC 792
- RFC Editor: https://www.rfc-editor.org/rfc/rfc792
- Info: https://www.rfc-editor.org/info/rfc792

### [12] RFC 4253
- IETF Datatracker: https://datatracker.ietf.org/doc/html/rfc4253

### [13] BCC
- GitHub: https://github.com/iovisor/bcc
- Reference guide: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md

### [14] OpenSSL
- Official: https://www.openssl.org
- evp.h: https://github.com/openssl/openssl/blob/master/include/openssl/evp.h
