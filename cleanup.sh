#!/usr/bin/env bash
# ============================================================
# cleanup.sh - Attack-Defense Lab Environment Reset
#
# Cleans up all artifacts from a demo session:
#   - Kill residual processes (honeypot, Flask, eBPF, agents)
#   - Remove iptables rules added by MDR
#   - Remove IP aliases added by ip_switch.sh
#   - Clear log files (trap.log, soc_events.jsonl)
#   - Clear loot directory
#   - Remove red team crontab persistence
#
# Usage:
#   sudo bash cleanup.sh          # full cleanup
#   sudo bash cleanup.sh --dry    # show what would be cleaned (no action)
# ============================================================
set -euo pipefail

DRY=false
if [[ "${1:-}" == "--dry" ]]; then
    DRY=true
    echo "[*] DRY RUN — showing what would be cleaned, no changes made"
    echo ""
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

run() {
    if $DRY; then
        echo "  [dry] $*"
    else
        eval "$@" 2>/dev/null || true
    fi
}

echo "[*] ===== Lab Environment Reset ====="
echo ""

# ── 1. Kill residual processes ───────────────────────────────
echo "[1/6] Killing residual processes..."

# Find and kill our Python tools by script name
for proc in target_app.py honeypot.py blue_ebpf_mdr.py blue_ebpf_mdr_v2.py \
            blue_mdr_network.py soc_dashboard.py red_attacker.py \
            red_reverse_shell.py exfil_listener.py exfil_agent.py; do
    pids=$(pgrep -f "$proc" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        echo "  Found $proc: PID $pids"
        run "kill -9 $pids"
    fi
done

# Kill any memfd agent processes
memfd_pids=$(ls -la /proc/[0-9]*/exe 2>/dev/null | grep 'memfd:' | awk -F/ '{print $3}' || true)
if [[ -n "$memfd_pids" ]]; then
    echo "  Found memfd processes: $memfd_pids"
    for pid in $memfd_pids; do
        run "kill -9 $pid"
    done
fi

echo "  Done."
echo ""

# ── 2. Remove iptables rules ────────────────────────────────
echo "[2/6] Cleaning iptables rules..."

# List current DROP rules in INPUT chain
drop_rules=$(iptables -L INPUT -n --line-numbers 2>/dev/null | grep "DROP" | awk '{print $1, $5}' || true)
if [[ -n "$drop_rules" ]]; then
    echo "  Current DROP rules:"
    echo "$drop_rules" | while read num ip; do
        echo "    #$num  DROP $ip"
    done
    # Remove in reverse order (highest line number first) to avoid index shifting
    iptables -L INPUT -n --line-numbers 2>/dev/null | grep "DROP" | awk '{print $1}' | sort -rn | while read num; do
        run "iptables -D INPUT $num"
    done
else
    echo "  No DROP rules found (clean)."
fi

echo "  Done."
echo ""

# ── 3. Remove IP aliases ────────────────────────────────────
echo "[3/6] Removing IP aliases..."

STATE_FILE="$SCRIPT_DIR/red_team/.alias_ip_state"
if [[ -f "$STATE_FILE" ]]; then
    ALIAS_CIDR=$(sed -n 1p "$STATE_FILE")
    INTERFACE=$(sed -n 2p "$STATE_FILE")
    ALIAS_IP=$(echo "$ALIAS_CIDR" | cut -d/ -f1)
    if ip addr show "$INTERFACE" 2>/dev/null | grep -q "$ALIAS_IP"; then
        echo "  Found alias IP: $ALIAS_IP on $INTERFACE"
        run "ip addr del $ALIAS_CIDR dev $INTERFACE"
    fi
    run "rm -f '$STATE_FILE'"
else
    echo "  No alias IP state found (clean)."
fi

echo "  Done."
echo ""

# ── 4. Clear log files ──────────────────────────────────────
echo "[4/6] Clearing log files..."

for logfile in trap.log soc_events.jsonl; do
    filepath="$SCRIPT_DIR/$logfile"
    if [[ -f "$filepath" ]]; then
        size=$(wc -c < "$filepath")
        echo "  $logfile ($size bytes)"
        run "rm -f '$filepath'"
    fi
done

# Also check common locations
for logfile in /tmp/trap.log /tmp/soc_events.jsonl; do
    if [[ -f "$logfile" ]]; then
        echo "  $logfile"
        run "rm -f '$logfile'"
    fi
done

echo "  Done."
echo ""

# ── 5. Clear loot directory ─────────────────────────────────
echo "[5/6] Clearing loot directory..."

loot_dir="$SCRIPT_DIR/loot"
if [[ -d "$loot_dir" ]]; then
    count=$(find "$loot_dir" -type f | wc -l)
    echo "  Found $count file(s) in loot/"
    run "rm -rf '$loot_dir'"
else
    echo "  No loot directory (clean)."
fi

echo "  Done."
echo ""

# ── 6. Remove crontab persistence ───────────────────────────
echo "[6/6] Checking crontab for red team persistence..."

cron_entries=$(crontab -l 2>/dev/null | grep -c '/dev/tcp\|reverse\|shell\|4444' || true)
if [[ "$cron_entries" -gt 0 ]]; then
    echo "  Found $cron_entries suspicious crontab entries:"
    crontab -l 2>/dev/null | grep '/dev/tcp\|reverse\|shell\|4444' | while read line; do
        echo "    $line"
    done
    if ! $DRY; then
        crontab -l 2>/dev/null | grep -v '/dev/tcp\|reverse\|shell\|4444' | crontab - 2>/dev/null || crontab -r 2>/dev/null || true
    else
        echo "  [dry] Would remove suspicious entries"
    fi
else
    echo "  No suspicious crontab entries (clean)."
fi

echo "  Done."
echo ""

# ── Summary ──────────────────────────────────────────────────
if $DRY; then
    echo "[*] DRY RUN complete. Run without --dry to apply changes."
else
    echo "[+] Cleanup complete. Environment is reset."
    echo ""
    echo "  Ready for next demo session."
    echo "  Start with: docs/DEMO_FLOW.md"
fi
