# 全文件同步審查報告

**日期**：2026-04-09
**範圍**：README.md、REPORT_ZH.md、REPORT_EN.md、PROJECT_PROPOSAL.md、PROJECT_PROPOSAL_ZH.md、RED_TEAM_PLAYBOOK.md
**基準**：實際程式碼 + RED_TEAM_PLAYBOOK（已驗證為最新）

---

## 審查摘要

| 檔案 | Kill Chain 階段 | ATT&CK 表 | Exfiltration | 加密標示 | 整體同步度 |
|------|---------------|-----------|-------------|---------|----------|
| RED_TEAM_PLAYBOOK.md | 7 階段 [OK] | 13 項 [OK] | [OK] | AES-256-CTR [OK] | **基準** |
| REPORT_ZH.md | 7 階段 [OK] | 13 項 [OK] | [OK] Phase 5c | AES-256-CTR [OK] | [OK] 同步 |
| REPORT_EN.md | 7 階段 [OK] | 13 項 [OK] | [OK] Phase 5b | AES-256-CTR [OK] | [OK] 同步 |
| PROJECT_PROPOSAL.md | 寫 all 7 [OK] | **8 項** [FAIL] | [OK] | AES-256-CTR [OK] | [WARN] 部分落後 |
| PROJECT_PROPOSAL_ZH.md | 寫到 C2 [FAIL] | **8 項** [FAIL] | [OK] | AES-256-CTR [OK] | [WARN] 部分落後 |
| **README.md** | **只到 Phase 6** [FAIL] | **8 項，缺 5 個** [FAIL] | **完全未提** [FAIL] | **寫 XOR** [FAIL] | [FAIL] 嚴重落後 |
| **PDF (投影片版)** | 寫 six [FAIL] | 13 項 [OK] | [OK] | AES-256-CTR [OK] | [WARN] 一處矛盾 |

---

## 發現事項

### README.md（問題最多）

| ID | 嚴重度 | 行號 | 問題 |
|----|--------|------|------|
| README-001 | **高** | 114-126 | **Kill Chain 圖只到 Phase 6，完全沒有 Phase 7 (Exfiltration)**。應補上 Phase 7: DNS/ICMP data exfiltration |
| README-002 | **高** | 118 | Kill Chain 圖寫 **"+ XOR ICMP C2"**，但加密早已升級為 AES-256-CTR。其他所有文件都正確寫 AES-256-CTR |
| README-003 | **高** | 45 | 寫 `RED_TEAM_PLAYBOOK.md # Attack playbook (6-phase kill chain)`，應改為 **7-phase** |
| README-004 | **高** | 155-164 | ATT&CK Attack Techniques 表只有 8 項，缺少 T1595, T1053.003, T1082, T1005, T1070.003, T1070.004 |
| README-005 | **中** | 103-108 | "What to Expect" 表只列 4 個 scenario（Blue OFF/v1/bypass/v2），沒有 Round 7 exfiltration scenario |
| README-006 | **中** | 128 | 說明文字只講 "main chain (phases 1-6)" 和 "Phase 5b evasion"，沒提 exfiltration |
| README-007 | **低** | 11-14 | Team 表仍是 `<!-- add name -->` 佔位符 |
| README-008 | **低** | 67-68 | git clone URL 用 `<org>/<repo>` 佔位符，未填實際 repo URL |

### PROJECT_PROPOSAL.md（Markdown EN）

| ID | 嚴重度 | 行號 | 問題 |
|----|--------|------|------|
| PROP-EN-001 | **高** | 109-118 | ATT&CK 表只有 8 項，需補到 13 項（PDF 已修，Markdown 未同步） |
| PROP-EN-002 | **高** | 536 | 結論寫 "7 ATT&CK techniques"（PDF 已改為 13，Markdown 未同步） |
| PROP-EN-003 | **高** | 534-535 | 結論缺 exfiltration 盲點段落（PDF 已加，Markdown 未同步） |

### PROJECT_PROPOSAL_ZH.md（Markdown ZH）

| ID | 嚴重度 | 行號 | 問題 |
|----|--------|------|------|
| PROP-ZH-001 | **高** | 40 | 目標 bullet 1 Kill Chain 範圍只到 C2，缺 Actions on Objectives（PDF 已修，Markdown 未同步） |
| PROP-ZH-002 | **高** | 111-120 | ATT&CK 表只有 8 項（同 EN） |
| PROP-ZH-003 | **高** | 540 | 結論寫 "7 項"（同 EN） |
| PROP-ZH-004 | **高** | 538-539 | 結論缺 exfiltration 盲點段落（同 EN） |

### PDF（Cybersecurity_CSE_517_1.pdf）

| ID | 嚴重度 | 頁碼 | 問題 |
|----|--------|------|------|
| PDF-001 | **高** | p.3-4 | Section 2.1 寫 "six of the seven phases (excluding Actions on Objectives)" 但全文其他地方都有 exfiltration |
| PDF-002 | **高** | p.15 | References 只到 [6]，缺 [7]-[14]。其中 [7]-[11] 有在文中被引用 |
| PDF-003 | **中** | — | Section 7.4 Demo Day Risks 被刪除 |
| PDF-004 | **低** | — | [12]-[14] 未在文中標記引用（但專案有使用，建議補引用標記） |

### REPORT_ZH.md / REPORT_EN.md

這兩份報告**已經是最新的**，與實際程式碼同步：
- [OK] Kill Chain 涵蓋 exfiltration（ZH: Phase 5c, EN: Phase 5b）
- [OK] ATT&CK 表有 13 項技術
- [OK] 加密正確標示為 AES-256-CTR
- [OK] 工具清單完整

### RED_TEAM_PLAYBOOK.md

[OK] 已驗證為最新，作為基準。

---

## 修改優先順序

### P0 — README.md（影響所有訪客的第一印象）

1. **Kill Chain 圖補上 Phase 7**：
```
Phase 7
Exfiltrate
DNS/ICMP
data theft
exfil_agent.py
```

2. **修正 XOR → AES-256-CTR**（line 118）：
```
原: recon.sh     + XOR ICMP C2      curl cmd       from /proc/fd    agent         commands
改: recon.sh     + AES-256-CTR      curl cmd       from /proc/fd    agent         commands
              red_attacker.py    SSTI POST                                   ICMP C2
```

3. **修正 "6-phase" → "7-phase"**（line 45）：
```
原: RED_TEAM_PLAYBOOK.md    #   Attack playbook (6-phase kill chain)
改: RED_TEAM_PLAYBOOK.md    #   Attack playbook (7-phase kill chain)
```

4. **ATT&CK 表補 5 項**（line 155-164 後插入）：
```
| T1595 | Active Scanning | nmap recon |
| T1053.003 | Scheduled Task: Cron | Crontab reverse shell persistence |
| T1082 | System Information Discovery | whoami, id, uname (post-exploitation) |
| T1005 | Data from Local System | Exfil agent collects /etc/passwd, SSH keys |
| T1070.003 | Clear Command History | history -c |
| T1070.004 | File Deletion | Exfil agent self-deletes |
```

5. **What to Expect 表補 exfil scenario**：
```
| Red team **exfiltration** (defense gap) | DNS/ICMP data extracted; eBPF v2 does not detect |
```

6. **填入 Team 名字和 repo URL**（或刪除佔位符）

### P1 — Markdown Proposals 同步 PDF 修改

見 `2026-04-08-proposal-exfil-fixes.md` 的完整 diff。

### P2 — PDF 修正

1. Section 2.1 "six" → "all seven"
2. 補上 References [7]-[14]
3. 在 Section 2.4, 2.3, 2.5 補上 [12], [13], [14] 引用標記
