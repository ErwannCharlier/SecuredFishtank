#!/bin/bash

# Run this script on ws2, ws3 and r1

IPS="10.1.0.1 10.1.0.2 10.1.0.3"

echo "[+] Starting ARP protection"


ip neigh flush all >/dev/null 2>&1 || true

# Delete the previous ARP guard table if it already exists
nft delete table arp arp_guard 2>/dev/null || true

# Create a new nftables table for ARP filtering
nft add table arp arp_guard

# Create an input chain for received ARP packets
nft add chain arp arp_guard input '{ type filter hook input priority 0; policy accept; }'

for IP in $IPS
do
    # If the IP belongs to the current host, skip it
    if ip -4 addr show | grep -q "$IP/"; then
        echo "[+] $IP is local, skipping"
        continue
    fi

    # Force ARP resolution by sending one ping
    ping -c 1 -W 1 "$IP" >/dev/null 2>&1 || true

    # Read the learned MAC address from the ARP cache
    MAC=$(ip neigh show "$IP" | grep lladdr | awk '{print $5}')

    if [ -z "$MAC" ]; then
        echo "[-] Could not find MAC for $IP"
        continue
    fi

    echo "[+] Protecting $IP -> $MAC"

    # Drop ARP packets claiming this IP with a wrong MAC address
    nft add rule arp arp_guard input arp saddr ip "$IP" arp saddr ether != "$MAC" counter drop
done

echo ""
echo "[+] ARP protection enabled"
echo ""
echo "[+] nftables table:"
nft list table arp arp_guard