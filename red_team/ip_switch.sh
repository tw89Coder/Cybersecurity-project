#!/bin/bash
# ============================================
# Red Team - IP Alias 管理
# 用途: 被 MDR 封鎖後切換 IP 繼續攻擊
# MITRE ATT&CK: T1036 (Masquerading)
# ============================================

PRIMARY_IP="172.22.137.14"
ALIAS_IP="172.22.137.15"
INTERFACE="eth0"

case "$1" in
    add)
        echo "[*] Adding alias IP: $ALIAS_IP on $INTERFACE"
        sudo ip addr add "$ALIAS_IP/20" dev "$INTERFACE"
        echo "[+] Done. Current IPs:"
        ip addr show "$INTERFACE" | grep inet
        echo ""
        echo "[*] Demo flow:"
        echo "    1. Use $PRIMARY_IP to hit port 2222 (will be blocked by MDR)"
        echo "    2. Use $ALIAS_IP to hit port 9999:"
        echo "       python3 exploit.py <TARGET_IP> --bind-ip $ALIAS_IP"
        echo "       nc -s $ALIAS_IP -v <TARGET_IP> 4444"
        ;;
    remove)
        echo "[*] Removing alias IP: $ALIAS_IP"
        sudo ip addr del "$ALIAS_IP/20" dev "$INTERFACE"
        echo "[+] Done. Current IPs:"
        ip addr show "$INTERFACE" | grep inet
        ;;
    status)
        echo "[*] Current IPs on $INTERFACE:"
        ip addr show "$INTERFACE" | grep inet
        ;;
    *)
        echo "Usage: $0 {add|remove|status}"
        echo ""
        echo "  add    - Add alias IP ($ALIAS_IP) for bypassing MDR block"
        echo "  remove - Remove alias IP after demo"
        echo "  status - Show current IPs"
        ;;
esac
