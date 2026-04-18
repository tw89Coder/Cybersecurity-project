#!/bin/bash
# ============================================
# Red Team - IP Alias 管理
# 用途: 被 MDR 封鎖後切換 IP 繼續攻擊 (適應原生 Ubuntu 動態網卡)
# MITRE ATT&CK: Defense Evasion (IP alias — no specific technique ID)
# ============================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="$SCRIPT_DIR/.alias_ip_state"

get_primary_info() {
    # 找尋主要網卡（略過 lo）
    INTERFACE=$(ip route show default | awk '/default/ {print $5}' | grep -v 'lo' | head -n1)
    if [ -z "$INTERFACE" ]; then
        INTERFACE=$(ip -4 route | awk '{print $5}' | grep -v 'lo' | head -n1)
    fi
    
    PRIMARY_CIDR=$(ip -4 addr show dev "$INTERFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -n1)
    if [ -z "$PRIMARY_CIDR" ]; then
        echo "[!] Cannot detect primary IP or interface."
        exit 1
    fi
    
    PRIMARY_IP=$(echo "$PRIMARY_CIDR" | cut -d/ -f1)
    PRIMARY_MASK=$(echo "$PRIMARY_CIDR" | cut -d/ -f2)
    PRIMARY_MASK=${PRIMARY_MASK:-24}
}

case "$1" in
    add)
        get_primary_info
        echo "[*] Detected default interface: $INTERFACE ($PRIMARY_IP)"
        
        # 動態計算 ALIAS_IP
        PREFIX=$(echo "$PRIMARY_IP" | cut -d. -f1-3)
        LAST=$(echo "$PRIMARY_IP" | cut -d. -f4)
        if [ "$LAST" -lt 100 ]; then
            NEW_LAST=$((LAST + 100))
        else
            NEW_LAST=$((LAST - 50))
        fi
        ALIAS_IP="${PREFIX}.${NEW_LAST}"

        echo "[*] Adding alias IP: $ALIAS_IP on $INTERFACE"
        sudo ip addr add "$ALIAS_IP/$PRIMARY_MASK" dev "$INTERFACE" label "$INTERFACE:0"
        
        # 儲存狀態以便 cleanup 讀取
        echo "$ALIAS_IP/$PRIMARY_MASK" > "$STATE_FILE"
        echo "$INTERFACE" >> "$STATE_FILE"
        
        echo "[+] Done. Current IPs:"
        ip addr show "$INTERFACE" | grep inet
        echo ""
        echo "[*] Demo flow:"
        echo "    1. Use $PRIMARY_IP to hit port 2222 (will be blocked by MDR)"
        echo "    2. Use $ALIAS_IP to hit port 9999:"
        echo "       python3 exploit.py <TARGET_IP> --bind-ip $ALIAS_IP"
        echo "       nc -s $ALIAS_IP -v <TARGET_IP> 4444"
        echo "       curl -s --interface $ALIAS_IP http://<TARGET_IP>:9999/"
        ;;
    remove)
        if [ -f "$STATE_FILE" ]; then
            ALIAS_CIDR=$(sed -n 1p "$STATE_FILE")
            INTERFACE=$(sed -n 2p "$STATE_FILE")
            ALIAS_IP=$(echo "$ALIAS_CIDR" | cut -d/ -f1)
            echo "[*] Removing alias IP: $ALIAS_IP from $INTERFACE"
            sudo ip addr del "$ALIAS_CIDR" dev "$INTERFACE" 2>/dev/null || true
            rm -f "$STATE_FILE"
            
            echo "[+] Done. Current IPs:"
            ip addr show "$INTERFACE" 2>/dev/null | grep inet || true
        else
            echo "[!] No state file found. Is the alias IP active?"
        fi
        ;;
    status)
        if [ -f "$STATE_FILE" ]; then
            ALIAS_CIDR=$(sed -n 1p "$STATE_FILE")
            INTERFACE=$(sed -n 2p "$STATE_FILE")
            ALIAS_IP=$(echo "$ALIAS_CIDR" | cut -d/ -f1)
            echo "[*] Active Alias: $ALIAS_IP on $INTERFACE"
            ip addr show "$INTERFACE" 2>/dev/null | grep "$ALIAS_IP"
        else
            echo "[*] No active alias IP state found."
            get_primary_info
            echo "[*] Current IPs on $INTERFACE:"
            ip addr show "$INTERFACE" 2>/dev/null | grep inet
        fi
        ;;
    *)
        echo "Usage: $0 {add|remove|status}"
        echo ""
        echo "  add    - Add dynamically calculated alias IP for bypassing MDR block"
        echo "  remove - Remove alias IP after demo"
        echo "  status - Show current IPs"
        ;;
esac
