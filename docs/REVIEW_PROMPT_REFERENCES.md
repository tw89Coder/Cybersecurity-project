# Reference Review Prompt — 文獻引用審查

> 將以下內容交給搜尋 bot，讓它驗證每篇參考文獻的真實性、引用內容的正確性、以及是否存在幽靈文獻。

---

## 審查任務

請對以下 14 篇參考文獻逐一執行：

1. **存在性驗證**：搜尋該文獻是否真實存在（URL 是否可達、書籍 ISBN 是否有效、RFC 編號是否正確）
2. **作者驗證**：列出的作者是否為該文獻的實際作者
3. **內容驗證**：我們在 proposal 中引用的具體內容，是否確實出自該文獻
4. **年份驗證**：標示的出版年份是否正確
5. **幽靈文獻檢查**：是否有任何文獻是 AI 編造的（不存在於任何資料庫）

---

## 文獻清單與引用內容

### [1] IBM Security, "Cost of a Data Breach Report 2024"
- **URL**: https://www.ibm.com/reports/data-breach
- **我們引用的內容**：「全球資料外洩平均損失達 488 萬美元」、「fileless malware 技術攻擊趨勢上升」
- **請驗證**：2024 年報告是否存在？488 萬美元的數字是否正確？報告是否提及 fileless malware？

### [2] K. Wilhoit, "Dissecting the ICMP Protocol and Its Use in Tunneling and Exfiltration"
- **URL**: https://www.trendmicro.com/vinfo/us/threat-encyclopedia/web-attack/137/
- **出版者**：Trend Micro Research, 2013
- **我們引用的內容**：「APT 組織使用 ICMP 隧道和 DNS exfiltration 維持 C2 存取」
- **請驗證**：此文章是否存在？作者 Kyle Wilhoit 是否為 Trend Micro 研究員？內容是否涵蓋 ICMP tunneling？

### [3] Hutchins, Cloppert, Amin, "Intelligence-Driven Computer Network Defense..."
- **出版**：Proceedings of the 6th International Conference on Information Warfare and Security, 2011
- **機構**：Lockheed Martin Corporation
- **我們引用的內容**：Cyber Kill Chain 七階段模型（Reconnaissance → Actions on Objectives）
- **請驗證**：此論文是否存在？是否由 Lockheed Martin 發表？是否定義了 7 階段 Kill Chain？三位作者姓名是否正確？

### [4] Strom et al., "MITRE ATT&CK: Design and Philosophy"
- **URL**: https://attack.mitre.org
- **編號**：Technical Report MP-19-01075, 2020
- **我們引用的內容**：ATT&CK 框架的技術 ID 系統、戰術/技術分類
- **請驗證**：此技術報告是否存在？報告編號 MP-19-01075 是否正確？作者列表是否準確？

### [5] J. Corbet, "A thorough introduction to eBPF"
- **URL**: https://lwn.net/Articles/740157/
- **出版**：LWN.net, December 2017
- **我們引用的內容**：eBPF 的核心特性（kernel-space 執行、verifier 安全保證、tracepoint hooks）
- **請驗證**：此 LWN.net 文章是否存在？作者是否為 Jonathan Corbet？日期是否為 2017 年 12 月？

### [6] Y. Song, "bpf: implement bpf_send_signal helper"
- **URL**: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8b401f9ed244
- **年份**：2019
- **我們引用的內容**：「自 Linux 5.3 起，bpf_send_signal() 允許 eBPF 程式從 kernel 空間發送 SIGKILL」
- **請驗證**：此 kernel commit 是否存在？commit ID 8b401f9ed244 是否正確？作者是否為 Yonghong Song？是否為 Linux 5.3 的一部分？

### [7] L. Spitzner, "Honeypots: Tracking Hackers"
- **ISBN**: 0-321-10895-7
- **出版**：Addison-Wesley Professional, 2003
- **我們引用的內容**：蜜罐的定義——「價值在於被探測、攻擊或入侵的安全資源」
- **請驗證**：此書是否存在？ISBN 是否正確？作者 Lance Spitzner 是否正確？出版年份是否為 2003？

### [8] NIST SP 800-38A, "Recommendation for Block Cipher Modes of Operation"
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-38a/final
- **年份**：2001
- **我們引用的內容**：AES-CTR 模式的特性（語義安全性、無需填充、可平行化）
- **請驗證**：此 NIST 特刊是否存在？編號 800-38A 是否正確？是否涵蓋 CTR 模式？年份 2001 是否正確？

### [9] J. Kettle, "Server-Side Template Injection"
- **URL**: https://portswigger.net/research/server-side-template-injection
- **出版**：PortSwigger Research, 2015
- **我們引用的內容**：SSTI 漏洞的機制（模板引擎將使用者輸入作為程式碼執行）
- **請驗證**：此研究文章是否存在？作者 James Kettle 是否為 PortSwigger 研究員？是否為 2015 年發表？是否為 SSTI 研究的原始/權威來源？

### [10] M. Kerrisk, "memfd_create(2) — Linux manual page"
- **URL**: https://man7.org/linux/man-pages/man2/memfd_create.2.html
- **我們引用的內容**：memfd_create 的特性（syscall 319 on x86_64、匿名 RAM-only fd、無 filesystem entry）
- **請驗證**：此 man page 是否存在？memfd_create 的 syscall 號碼在 x86_64 上是否為 319？作者 Michael Kerrisk 是否為 Linux man-pages 的維護者？

### [11] J. Postel, "Internet Control Message Protocol," RFC 792
- **URL**: https://www.rfc-editor.org/rfc/rfc792
- **年份**：September 1981
- **我們引用的內容**：ICMP echo request payload 欄位結構、type 8（echo request）/ type 0（echo reply）
- **請驗證**：RFC 792 是否為 ICMP 的正式標準？作者 Jon Postel 是否正確？年份 1981 是否正確？是否定義了 type 8 和 type 0？

### [12] Ylonen & Lonvick, "The Secure Shell (SSH) Transport Layer Protocol," RFC 4253
- **URL**: https://www.rfc-editor.org/rfc/rfc4253
- **年份**：January 2006
- **我們引用的內容**：SSH 版本字串格式（"SSH-protoversion-softwareversion"）
- **請驗證**：RFC 4253 是否為 SSH 傳輸層標準？是否定義了版本字串格式？作者和年份是否正確？

### [13] BCC Authors, "BPF Compiler Collection (BCC)"
- **URL**: https://github.com/iovisor/bcc
- **我們引用的內容**：BCC 的 TRACEPOINT_PROBE 巨集、BPF_HASH、perf_submit 等 API
- **請驗證**：此 GitHub repo 是否存在？是否為 eBPF/BCC 的官方 repo？是否包含我們引用的 API？

### [14] OpenSSL Project, "OpenSSL: Cryptography and SSL/TLS Toolkit"
- **URL**: https://www.openssl.org
- **我們引用的內容**：EVP_aes_256_ctr、EVP_EncryptInit_ex、EVP_EncryptUpdate 等 API
- **請驗證**：OpenSSL 官網是否存在？是否提供我們引用的 EVP API？

---

## 輸出格式

請對每篇文獻輸出：

| # | 文獻 | 存在性 | 作者正確 | 內容正確 | 年份正確 | 幽靈文獻？ | 備註 |
|---|------|--------|---------|---------|---------|-----------|------|
| 1 | IBM Data Breach 2024 | ✅/❌ | ✅/❌ | ✅/❌ | ✅/❌ | 是/否 | ... |
| ... | | | | | | | |
