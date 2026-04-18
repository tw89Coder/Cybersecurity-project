# 審查報告：網路安全攻防演練實驗室 — 程式碼品質審查

**日期**：2026-04-06
**範圍**：全專案程式碼（14 個原始碼檔案 + 4 個 Shell 腳本 + README）
**審查依據**：`REVIEW_PROMPT_CODE.md` 七項審查重點

---

## 摘要

專案整體架構清晰、工具分工明確，紅藍隊攻防邏輯完整。eBPF struct 對齊正確，AES-256-CTR 加解密 round-trip 正確，README 專案樹與實際檔案一致。

主要問題集中在 **3 個領域**：
1. `exploit.py` 有 **致命 f-string 語法錯誤**，執行時會 crash（NameError）
2. **3 處 MITRE ATT&CK ID 未同步更新**（README 已修正，但檔案標頭殘留舊值）
3. `honeypot.py` 存在 **日誌注入漏洞**，攻擊者可製造假 IP 觸發 MDR 封鎖友軍

共計 **11 項發現**：1 高、5 中、5 低。

---

## 發現事項

| ID | 類型 | 嚴重度 | 發現 | 位置 |
|----|------|--------|------|------|
| BUG-001 | 程式碼正確性 | **高** | `exploit.py` f-string 引用未定義變數 `IFS`，執行必 crash | `exploit.py:44` |
| ARCH-001 | 架構一致性 | 中 | `exploit.py` 標的為 `vuln_api.py` + WAF，但專案中實際靶機為 `target_app.py`（無 WAF） | `exploit.py:9` |
| ARCH-002 | 架構一致性 | 低 | `exfil_agent.py` 蒐集目標包含 `~/vuln_api.py`（舊檔名） | `exfil_agent.py:79` |
| SEC-001 | 安全性 | 中 | `honeypot.py` 日誌注入 — 客戶端資料含換行時可偽造 `Attacker IP:` 條目，觸發 MDR 封鎖任意 IP | `honeypot.py:95-96` |
| SEC-002 | 安全性 | 低 | `soc_dashboard.py` 的 `/api/event` 端點無認證，任何人可 POST 假事件 | `soc_dashboard.py:169-186` |
| SEC-003 | 安全性 | 低 | AES 加密未呼叫 `EVP_EncryptFinal_ex`（CTR 模式下無影響，但偏離 OpenSSL 最佳實務） | `red_attacker.py:318-327` |
| MITRE-001 | MITRE ATT&CK | 中 | `red_attacker.py` 標頭仍列 T1071.001（Web Protocol），但 ICMP C2 應為 T1095 | `red_attacker.py:5` |
| MITRE-002 | MITRE ATT&CK | 中 | `red_reverse_shell.py` 標頭列 T1071.001，TCP reverse shell 應為 T1095 + T1571 | `red_reverse_shell.py:6` |
| MITRE-003 | MITRE ATT&CK | 中 | `ip_switch.sh` 標頭列 T1036（Masquerading），IP alias 不符此技術定義，應移除 | `ip_switch.sh:5` |
| MITRE-004 | MITRE ATT&CK | 低 | `blue_ebpf_mdr.py` 標頭列偵測 T1070（Indicator Removal），但實際 3 個 hook 均未偵測此技術 | `blue_ebpf_mdr.py:5` |
| CODE-001 | 程式品質 | 低 | `exploit.py` 使用 `sys.argv` 直取參數，其他 10 個工具均使用 `argparse`，風格不一致 | `exploit.py:19-22` |

---

## 詳細分析

### 1. 程式碼正確性

**BUG-001（高）：`exploit.py:44` — f-string NameError**

```python
obfuscated_payload = f"127.0.0.1;echo${{{IFS}}}{b64_payload}|base64${{{IFS}}}-d|b\\a\\s\\h\n"
```

Python f-string 解析 `${{{IFS}}}` 的方式：
- `$` → 字面 `$`
- `{{` → 字面 `{`
- `{IFS}` → **嘗試求值 Python 變數 `IFS`**
- `}}` → 字面 `}`

由於 `IFS` 未在檔案任何位置定義，執行時立即拋出 `NameError: name 'IFS' is not defined`。

**修正方案**：改為 `${{IFS}}`（兩個大括號即可輸出字面 `${IFS}`）：
```python
obfuscated_payload = f"127.0.0.1;echo${{IFS}}{b64_payload}|base64${{IFS}}-d|b\\a\\s\\h\n"
```

**其餘 13 個 Python 檔案**均可正常 import 與執行（已逐一檢查 import 鏈與依賴）。

---

### 2. 架構一致性

**ARCH-001（中）：`exploit.py` 標的不匹配**

`exploit.py` docstring 第 9 行描述 `Target: vuln_api.py on port 9999`，並設計了 WAF bypass 技術（Base64 + `${IFS}` + 反斜線拆字）。但專案中的靶機是 `target/target_app.py`，其 `/diag` 端點是純 SSTI 漏洞，**無 WAF**。

影響：`exploit.py` 發送的混淆 payload 在 `target_app.py` 上仍可運作（SSTI 不在乎 payload 格式），但 WAF bypass 邏輯毫無用武之地。文件與實際行為脫節。

**ARCH-002（低）**：`exfil_agent.py:79` 蒐集 `~/vuln_api.py`，應改為 `~/target_app.py` 或移除。

**README 專案樹 vs 實際檔案**：完全一致 [OK]（18 個檔案逐一驗證）。

---

### 3. 安全性

**SEC-001（中）：`honeypot.py` 日誌注入**

```python
# honeypot.py:95-96
client_str = client_data.decode(errors='replace').strip()[:100]
log_line = f"[{ts}] Attacker IP: {ip} Port: {port} Data: {client_str}\n"
```

`.strip()` 只移除首尾空白，**中間的換行符被保留**。攻擊者可在 SSH 握手資料中嵌入：
```
\nAttacker IP: 10.0.0.1 Port: 22 Data: fake
```

這會在 `trap.log` 產生第二行，`blue_mdr_network.py` 的 `IP_PATTERN` regex 會匹配到 `10.0.0.1`，觸發 `iptables -I INPUT 1 -s 10.0.0.1 -j DROP` — **攻擊者可讓防禦方封鎖任意 IP（含自己的網關）**。

**修正方案**：將 `client_str` 中的換行符替換掉：
```python
client_str = client_data.decode(errors='replace').replace('\n', ' ').replace('\r', ' ').strip()[:100]
```

**SEC-002（低）**：`soc_dashboard.py` 的 `POST /api/event` 無認證。Lab 環境內可接受，若部署於共享網路應加入 token 驗證。

**SEC-003（低）**：AES-256-CTR 加解密未呼叫 `EVP_EncryptFinal_ex()`。CTR 模式下 Final 步驟輸出 0 bytes，故不影響正確性，但偏離 OpenSSL 官方文件建議的 Init→Update→Final 三步流程。

**無高風險安全漏洞**：所有 `subprocess` 呼叫均使用 list form（非 `shell=True`）或僅傳入硬編碼命令字串。`iptables` 的 IP 參數經過 `is_valid_ip()` 驗證。Dashboard 的 JavaScript XSS 防護（DOM-based `esc()`）正確。`target_app.py` 的 SSTI 漏洞為刻意設計。

---

### 4. eBPF 正確性 [OK] 全部通過

**v1 struct 對齊驗證**（`blue_ebpf_mdr.py`）：

| 欄位 | C 類型 | 偏移量 | 大小 | ctypes 對應 | 一致 |
|------|--------|--------|------|-------------|------|
| pid | u32 | 0 | 4 | c_uint32 | [OK] |
| ppid | u32 | 4 | 4 | c_uint32 | [OK] |
| uid | u32 | 8 | 4 | c_uint32 | [OK] |
| event_type | u8 | 12 | 1 | c_uint8 | [OK] |
| killed | u8 | 13 | 1 | c_uint8 | [OK] |
| comm | char[16] | 14 | 16 | c_char*16 | [OK] |
| detail | char[128] | 30 | 128 | c_char*128 | [OK] |
| *尾部填充* | | 158 | 2 | *(自動)* | [OK] |

sizeof = **160 bytes**（4-byte 對齊填充至 160）

**v2 struct 對齊驗證**（`blue_ebpf_mdr_v2.py`）：

| 欄位 | C 類型 | 偏移量 | 大小 | ctypes 對應 | 一致 |
|------|--------|--------|------|-------------|------|
| pid | u32 | 0 | 4 | c_uint32 | [OK] |
| ppid | u32 | 4 | 4 | c_uint32 | [OK] |
| uid | u32 | 8 | 4 | c_uint32 | [OK] |
| event_type | u8 | 12 | 1 | c_uint8 | [OK] |
| killed | u8 | 13 | 1 | c_uint8 | [OK] |
| port | u16 | 14 | 2 | c_uint16 | [OK] |
| comm | char[16] | 16 | 16 | c_char*16 | [OK] |
| detail | char[128] | 32 | 128 | c_char*128 | [OK] |

sizeof = **160 bytes**（無需尾部填充）

**Placeholder 替換完整性**：

| 版本 | Placeholder | BPF 程式碼位置 | Python 替換位置 | 狀態 |
|------|-------------|---------------|----------------|------|
| v1 | `__KILL_MEMFD__` | :223 | :419 | [OK] |
| v1 | `__KILL_EXEC__` | :278 | :420 | [OK] |
| v1 | `__KILL_ICMP_CORR__` | :316 | :421 | [OK] |
| v2 | `__KILL_MEMFD__` | :126 | :419 | [OK] |
| v2 | `__KILL_EXEC__` | :159 | :420 | [OK] |
| v2 | `__KILL_ICMP_CORR__` | :180 | :421 | [OK] |
| v2 | `__KILL_CONNECT__` | :227 | :422 | [OK] |
| v2 | `__KILL_DUP2__` | :265 | :423 | [OK] |
| v2 | `__KILL_DUP3__` | :300 | :424 | [OK] |

所有 placeholder 在 `--kill` 和非 `--kill` 模式下均正確替換。

---

### 5. AES-256-CTR 加密正確性 [OK] 通過（附註一項）

**ctypes 函數簽名驗證**：

| OpenSSL API | 回傳型別 | 參數型別 | ctypes 定義 | 一致 |
|-------------|---------|---------|-------------|------|
| `EVP_CIPHER_CTX_new()` | `EVP_CIPHER_CTX*` | `(void)` | `c_void_p / []` | [OK] |
| `EVP_aes_256_ctr()` | `const EVP_CIPHER*` | `(void)` | `c_void_p / []` | [OK] |
| `EVP_EncryptInit_ex()` | `int` | `(ctx*, cipher*, engine*, key*, iv*)` | `c_int / [c_void_p, c_void_p, c_void_p, c_char_p, c_char_p]` | [OK] |
| `EVP_EncryptUpdate()` | `int` | `(ctx*, out*, outl*, in*, inl)` | `c_int / [c_void_p, c_char_p, POINTER(c_int), c_char_p, c_int]` | [OK] |
| `EVP_CIPHER_CTX_free()` | `void` | `(ctx*)` | `None / [c_void_p]` | [OK] |

**Round-trip 驗證**：

C2 Server 端（`red_attacker.py`）：
- 加密：`aes_encrypt(pt)` → `iv(16B) + AES-CTR(pt, key, iv)`
- 解密：`aes_decrypt(data)` → `AES-CTR(data[16:], key, data[:16])`
- CTR 模式加解密為同一運算 → [OK] round-trip 正確

Agent 端（AGENT_CODE 內嵌）：
- 加密：`enc(d)` → `iv + _ac(d, iv)`
- 解密：`dec(d)` → `_ac(d[16:], d[:16])`
- 同一 `_ac()` 函數、同一 key (`AK = SHA256(SS)`) → [OK] 雙端一致

Key 推導：`SHA-256(b"r3dt34m!@#2024xK")` → 32 bytes → [OK] 符合 AES-256 要求。
每封包隨機 IV：`os.urandom(16)` → [OK] 語義安全。

---

### 6. MITRE ATT&CK 映射

**README 的 ATT&CK 表**：已正確修正（無 T1071.001、無 T1036）[OK]

**個別檔案標頭仍有 3 處殘留錯誤**：

| ID | 檔案 | 目前標註 | 問題 | 正確值 |
|----|------|---------|------|--------|
| MITRE-001 | `red_attacker.py:5` | T1071.001 | ICMP 非 Web Protocol | 移除 T1071.001（T1095 已列出） |
| MITRE-002 | `red_reverse_shell.py:6` | T1071.001 | TCP reverse shell 非 Web Protocol | 改為 T1095 + T1571 |
| MITRE-003 | `ip_switch.sh:5` | T1036 (Masquerading) | IP alias 不符 Masquerading 定義 | 移除或標註「無直接對應」 |
| MITRE-004 | `blue_ebpf_mdr.py:5` | T1070 | 3 個 hook 均不偵測 Indicator Removal | 移除 T1070 |

**其餘映射驗證通過**：

| 檔案 | 標註 | 結果 |
|------|------|------|
| `exploit.py` | T1059.006, T1027, T1190 | [OK] |
| `post_exploit.sh` | T1053.003, T1082, T1070.003 | [OK] |
| `honeypot.py` | T1595 | [OK] |
| `target_app.py` | T1190 | [OK] |
| `blue_ebpf_mdr_v2.py` | (標頭無列出，README 表正確) | [OK] |
| README 攻擊表 | T1190, T1059.006, T1620, T1027, T1095, T1571, T1048.003 | [OK] |
| README 偵測表 | T1620, T1059, T1095, T1571, T1059.006 | [OK] |

---

### 7. 文件完整性 [OK] 全部通過

README 專案樹列出 18 個檔案 + 2 個子目錄，逐一與檔案系統比對：

| README 列出路徑 | 檔案存在 |
|----------------|---------|
| `target/target_app.py` | [OK] |
| `target/honeypot.py` | [OK] |
| `red_team/red_attacker.py` | [OK] |
| `red_team/red_reverse_shell.py` | [OK] |
| `red_team/exploit.py` | [OK] |
| `red_team/recon.sh` | [OK] |
| `red_team/post_exploit.sh` | [OK] |
| `red_team/ip_switch.sh` | [OK] |
| `red_team/deploy_agent.sh` | [OK] |
| `red_team/exfil_agent.py` | [OK] |
| `red_team/exfil_listener.py` | [OK] |
| `blue_team/soc_dashboard.py` | [OK] |
| `blue_team/blue_mdr_network.py` | [OK] |
| `blue_team/blue_ebpf_mdr.py` | [OK] |
| `blue_team/blue_ebpf_mdr_v2.py` | [OK] |
| `docs/DEMO_FLOW.md` | [OK] |
| `docs/RED_TEAM_PLAYBOOK.md` | [OK] |
| `docs/REPORT_ZH.md` | [OK] |
| `docs/REPORT_EN.md` | [OK] |
| `docs/PROJECT_PROPOSAL.md` | [OK] |
| `docs/PROJECT_PROPOSAL_ZH.md` | [OK] |
| `docs/design/exfiltration-design.md` | [OK] |
| `docs/design/exfiltration-plan.md` | [OK] |
| `setup_env.sh` | [OK] |
| `cleanup.sh` | [OK] |
| `requirements.txt` | [OK] |
| `README.md` | [OK] |

無多餘檔案、無遺漏。`.gitignore` 正確排除 `loot/`、`recon_results/`、`*.log`、`.venv/`。

---

## 改善建議（依優先順序）

### 必修（阻斷性問題）

1. **修復 `exploit.py:44` 的 f-string 錯誤**
   - `${{{IFS}}}` → `${{IFS}}`（兩處）
   - 修後應實際執行一次驗證 payload 產出

### 高優先

2. **修復 `honeypot.py` 日誌注入**
   - 在寫入 `trap.log` 前將 `\n`、`\r` 替換為空格
   - 或改用結構化日誌格式（JSON Lines）

3. **同步 MITRE ATT&CK 標頭**
   - `red_attacker.py:5` — 移除 T1071.001
   - `red_reverse_shell.py:6` — T1071.001 → T1095, T1571
   - `ip_switch.sh:5` — 移除 T1036
   - `blue_ebpf_mdr.py:5` — 移除 T1070

### 中優先

4. **釐清 `exploit.py` 與 `target_app.py` 的關係**
   - 若 `exploit.py` 已被 `red_attacker.py` 取代，應在 README 標註 legacy
   - 若仍需保留，docstring 應更新為 `target_app.py`

5. **`exfil_agent.py:79`** — `~/vuln_api.py` → 移除或更新檔名

### 低優先

6. **`exploit.py`** — 改用 `argparse` 以與其他工具一致
7. **AES 加解密** — 加入 `EVP_EncryptFinal_ex` 呼叫（遵循 OpenSSL 最佳實務）
8. **`soc_dashboard.py`** — 在 `/api/event` 加入簡易 token 驗證

---

## 綜合評分

| 維度 | 評分 (1-10) | 說明 |
|------|-------------|------|
| 程式碼正確性 | 7/10 | 13/14 個 .py 檔可執行；`exploit.py` 有致命 bug |
| 架構一致性 | 8/10 | README 與檔案一致；`exploit.py` 標的不匹配 |
| 安全性 | 8/10 | 日誌注入為唯一實質漏洞；其餘安全實務良好 |
| eBPF 正確性 | 10/10 | struct 對齊完美、placeholder 完整 |
| AES 加密 | 9/10 | 簽名正確、round-trip 正確；缺 Final 呼叫（無影響） |
| MITRE ATT&CK | 7/10 | README 正確；4 個檔案標頭殘留舊值 |
| 文件完整性 | 10/10 | 專案樹完全一致 |

**總評：8.4 / 10**

專案品質明顯優於一般課程作業。eBPF v1→v2 的演進設計紮實，AES-256-CTR 的 ctypes 綁定專業。主要問題是 `exploit.py`（可能為早期遺留）和 MITRE ATT&CK 標頭未同步更新。修復上述 3 項必修 / 高優先問題後可達 9+/10。
