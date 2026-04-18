# Proposal 修改指引：補齊 Exfiltration 相關內容

**日期**：2026-04-08
**來源**：Auditor Bot 審查報告
**目標檔案**：`docs/PROJECT_PROPOSAL_ZH.md`、`docs/PROJECT_PROPOSAL.md`
**參考基準**：`docs/RED_TEAM_PLAYBOOK.md`（已驗證為最新）

> **注意：ZH 和 EN 兩份 Proposal 都要改，以下分別列出。**

---

## 修改 1：Section 1.2 專案目標 — Kill Chain 範圍補上 exfiltration

### ZH（`docs/PROJECT_PROPOSAL_ZH.md` line 40）

**原文：**
```
- **走完一條完整的 Cyber Kill Chain**——從 reconnaissance、weaponization、delivery、exploitation、installation 到 C2，每個階段都有對應的實作，並且 mapping 到 MITRE ATT&CK framework。
```

**改為：**
```
- **走完一條完整的 Cyber Kill Chain**——從 reconnaissance、weaponization、delivery、exploitation、installation、C2 到 actions on objectives（資料竊取），每個階段都有對應的實作，並且 mapping 到 MITRE ATT&CK framework。
```

### EN（`docs/PROJECT_PROPOSAL.md` line 40）

**原文：**
```
1. Implement a realistic attack chain covering reconnaissance through C2, mapped to the MITRE ATT&CK framework and the Cyber Kill Chain model.
```

**改為：**
```
1. Implement a realistic attack chain covering reconnaissance through actions on objectives (data exfiltration), mapped to the MITRE ATT&CK framework and the Cyber Kill Chain model.
```

---

## 修改 2：Section 2.2 ATT&CK 表 — 補上 5 個缺少的技術

### ZH（`docs/PROJECT_PROPOSAL_ZH.md` line 120）

在現有表格最後一行（T1048.003 那行）之後，`|` 結束處，插入以下 5 行：

```
| Persistence | T1053.003 | Scheduled Task/Job: Cron | crontab 植入反向 shell（後滲透階段） |
| Discovery | T1082 | System Information Discovery | whoami、id、uname -a（後滲透情報蒐集） |
| Collection | T1005 | Data from Local System | exfil agent 蒐集 /etc/passwd、SSH key、bash history 等本機檔案 |
| Defense Evasion | T1070.003 | Indicator Removal: Clear Command History | history -c（清除操作痕跡） |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | exfil agent 完成後自動刪除自身 |
```

插入後，完整表格應為 13 行（8 原有 + 5 新增）。

### EN（`docs/PROJECT_PROPOSAL.md` line 118）

同位置，在 T1048.003 行之後插入：

```
| Persistence | T1053.003 | Scheduled Task/Job: Cron | Crontab reverse shell implant (post-exploitation) |
| Discovery | T1082 | System Information Discovery | whoami, id, uname -a (post-exploitation reconnaissance) |
| Collection | T1005 | Data from Local System | Exfil agent collects /etc/passwd, SSH keys, bash history from target |
| Defense Evasion | T1070.003 | Indicator Removal: Clear Command History | history -c (trace cleanup) |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Exfil agent self-deletes after completion |
```

---

## 修改 3：Section 8 結論 — 修正數字 + 補上 exfiltration 盲點論述

### ZH（`docs/PROJECT_PROPOSAL_ZH.md`）

#### 3a. 在 line 538（Fileless 段落）之後、line 540（總結句）之前，插入新段落：

```

**Data exfiltration 是目前防禦的盲點。** 即使兩層防禦同時運作，紅隊仍然透過 DNS subdomain encoding 和 ICMP payload embedding 成功將靶機上的敏感檔案（`/etc/passwd`、SSH key、bash history）外傳到攻擊機。eBPF 監控的是 process-level 的 syscall 行為（memfd_create、reverse shell 的 fd hijack），而 DNS exfiltration 走的是正常的 UDP 53 查詢，不觸發任何被監控的 pattern。這說明 defense-in-depth 是一個持續的過程——部署完不代表結束，防禦者必須不斷擴展偵測面來覆蓋新的攻擊向量。

```

#### 3b. 修改 line 540 的總結句：

**原文：**
```
總結來說，我們成功實作了 7 項 MITRE ATT&CK 攻擊技術和 7 項對應的偵測能力，橫跨兩個防禦層，在一個受控、可重現的環境中完成了一次完整的攻防演練。
```

**改為：**
```
總結來說，我們成功實作了 13 項 MITRE ATT&CK 攻擊技術（涵蓋 10 個戰術類別）和 7 項對應的偵測能力，橫跨兩個防禦層，在一個受控、可重現的環境中完成了一次從偵察到資料竊取的完整攻防演練。
```

### EN（`docs/PROJECT_PROPOSAL.md`）

#### 3a. 在 line 534（Fileless 段落）之後、line 536（Overall 句）之前，插入新段落：

```

Data exfiltration remains a blind spot in the current defense architecture. Even with both defense layers active, the red team successfully extracted sensitive files (`/etc/passwd`, SSH keys, bash history) from the target via DNS subdomain encoding and ICMP payload embedding. The eBPF hooks monitor process-level syscall behavior (memfd_create, reverse shell fd hijacking), but DNS exfiltration uses standard UDP port 53 queries that do not trigger any monitored patterns. This demonstrates that defense-in-depth is an ongoing process -- deployment is not the finish line, and defenders must continuously expand their detection surface to cover new attack vectors.

```

#### 3b. 修改 line 536 的 Overall 句：

**原文：**
```
Overall, the project implements 7 ATT&CK techniques and 7 corresponding detection capabilities across two defense layers, giving us hands-on experience with both offensive and defensive operations in a controlled environment.
```

**改為：**
```
Overall, the project implements 13 ATT&CK techniques (spanning 10 tactic categories) and 7 corresponding detection capabilities across two defense layers, giving us hands-on experience with both offensive and defensive operations in a controlled environment -- including the discovery that data exfiltration through covert channels remains undetected by the current behavioral monitoring approach.
```

---

## 驗收清單

修改完成後，請確認：

- [ ] ZH Proposal Section 1.2 第一個 bullet 包含「actions on objectives（資料竊取）」
- [ ] EN Proposal Section 1.2 objective 1 包含 "actions on objectives (data exfiltration)"
- [ ] ZH ATT&CK 表有 13 行（原 8 + 新 5）
- [ ] EN ATT&CK 表有 13 行（原 8 + 新 5）
- [ ] ZH 結論有 6 段粗體論點（原 5 + 新增 exfiltration 盲點）
- [ ] EN 結論有 6 段（原 5 + 新增 exfiltration blind spot）
- [ ] ZH 總結句寫「13 項...攻擊技術」而非「7 項」
- [ ] EN 總結句寫 "13 ATT&CK techniques" 而非 "7"
- [ ] 兩份文件沒有其他地方提到「7 項技術」的舊數字
