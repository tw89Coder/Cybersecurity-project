#!/bin/bash
# ============================================
# Red Team - 環境連通性預檢
# 用途: 在跑 C2 之前確認兩台機器的連通性與環境配置
# ============================================
set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: sudo bash $0 <TARGET_IP> <ATTACKER_IP>"
    echo ""
    echo "  在啟動 C2 之前跑這個腳本，檢查："
    echo "    1. 雙向 ICMP (ping) 連通性"
    echo "    2. UFW / iptables 是否封鎖 ICMP"
    echo "    3. 靶機 Flask 是否在線 (port 9999)"
    echo "    4. 靶機 Python3 路徑"
    echo "    5. memfd_create syscall 可用性"
    exit 1
fi

TARGET_IP="$1"
ATTACKER_IP="$2"
ERRORS=0

echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║   Red Team — 環境連通性預檢                       ║"
echo "╠════════════════════════════════════════════════════╣"
echo "║  Target   : $TARGET_IP"
echo "║  Attacker : $ATTACKER_IP"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# ── 1. ICMP 連通性 ──────────────────────────────────────
echo "[1/6] 測試 ICMP 連通性 (ping)..."
if ping -c 2 -W 2 "$TARGET_IP" > /dev/null 2>&1; then
    echo "  ✅ 攻擊機 → 靶機 ($TARGET_IP) ICMP OK"
else
    echo "  ❌ 攻擊機 → 靶機 ($TARGET_IP) ICMP 不通!"
    echo "     → C2 使用 ICMP 傳輸，這必須通才行"
    echo "     → 檢查靶機的 UFW / iptables / 雲端安全組"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# ── 2. UFW 狀態 ─────────────────────────────────────────
echo "[2/6] 檢查本機 UFW 狀態..."
if command -v ufw > /dev/null 2>&1; then
    UFW_STATUS=$(sudo ufw status 2>/dev/null | head -1 || echo "unknown")
    if echo "$UFW_STATUS" | grep -qi "active"; then
        echo "  ⚠️  UFW 已啟用: $UFW_STATUS"
        echo "     → 確認 ICMP 沒被封鎖:"
        echo "       sudo ufw allow proto icmp from any"
        echo "       或暫時: sudo ufw disable"
        # 檢查是否允許 ICMP
        if sudo ufw status verbose 2>/dev/null | grep -qi "deny.*icmp"; then
            echo "  ❌ UFW 明確封鎖了 ICMP!"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo "  ✅ UFW 未啟用 (不會封鎖 ICMP)"
    fi
else
    echo "  ✅ UFW 未安裝"
fi
echo ""

# ── 3. iptables ICMP 規則 ───────────────────────────────
echo "[3/6] 檢查 iptables ICMP 規則..."
ICMP_DROP=$(sudo iptables -L INPUT -n 2>/dev/null | grep -i "icmp" | grep -i "drop" || true)
if [ -n "$ICMP_DROP" ]; then
    echo "  ❌ iptables 有 ICMP DROP 規則:"
    echo "     $ICMP_DROP"
    echo "     → 移除: sudo iptables -D INPUT -p icmp -j DROP"
    ERRORS=$((ERRORS + 1))
else
    echo "  ✅ iptables 沒有封鎖 ICMP"
fi
IP_DROP=$(sudo iptables -L INPUT -n 2>/dev/null | grep "DROP" | grep "$ATTACKER_IP" || true)
if [ -n "$IP_DROP" ]; then
    echo "  ⚠️  iptables 封鎖了攻擊機 IP ($ATTACKER_IP)!"
    echo "     → 這可能是蜜罐 MDR 上次 demo 留下的"
    echo "     → 清除: sudo bash cleanup.sh"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# ── 4. 靶機 Flask (port 9999) ──────────────────────────
echo "[4/6] 測試靶機 Flask 服務 (port 9999)..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "http://$TARGET_IP:9999/" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo "  ✅ Flask 靶機在線 (HTTP $HTTP_CODE)"
else
    echo "  ❌ Flask 靶機不可達 (HTTP $HTTP_CODE)"
    echo "     → 確認靶機已啟動: sudo .venv/bin/python3 target/target_app.py"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# ── 5. SSTI 漏洞可利用性 ────────────────────────────────
echo "[5/6] 測試 SSTI 漏洞..."
SSTI_RESULT=$(curl -s --connect-timeout 3 -X POST "http://$TARGET_IP:9999/diag" -d "query={{7*7}}" 2>/dev/null || echo "")
if echo "$SSTI_RESULT" | grep -q "49"; then
    echo "  ✅ SSTI 漏洞確認可利用 (7*7=49)"
else
    echo "  ❌ SSTI 測試失敗（靶機可能未啟動或漏洞已修補）"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# ── 6. memfd_create 支援 ───────────────────────────────
echo "[6/6] 檢查本機 memfd_create 支援..."
ARCH=$(uname -m)
KERNEL=$(uname -r)
echo "  架構: $ARCH | Kernel: $KERNEL"
if [ "$ARCH" = "x86_64" ]; then
    echo "  ✅ x86_64 — memfd_create syscall #319 正確"
elif [ "$ARCH" = "aarch64" ]; then
    echo "  ✅ aarch64 — memfd_create syscall #279 正確"
else
    echo "  ⚠️  未知架構 $ARCH — memfd_create syscall 號碼需要確認"
fi
# 驗證 kernel 版本 >= 3.17 (memfd_create 最低需求)
KMAJOR=$(echo "$KERNEL" | cut -d. -f1)
KMINOR=$(echo "$KERNEL" | cut -d. -f2)
if [ "$KMAJOR" -gt 3 ] || ([ "$KMAJOR" -eq 3 ] && [ "$KMINOR" -ge 17 ]); then
    echo "  ✅ Kernel $KERNEL 支援 memfd_create (>= 3.17)"
else
    echo "  ❌ Kernel $KERNEL 太舊，不支援 memfd_create (需 >= 3.17)"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# ── 結果 ────────────────────────────────────────────────
echo "════════════════════════════════════════════════════"
if [ "$ERRORS" -eq 0 ]; then
    echo "  ✅ 全部通過！可以啟動 C2："
    echo ""
    echo "  sudo .venv/bin/python3 red_team/red_attacker.py -t $TARGET_IP -l $ATTACKER_IP"
else
    echo "  ❌ 發現 $ERRORS 個問題，請先修復再啟動 C2"
fi
echo "════════════════════════════════════════════════════"
echo ""
