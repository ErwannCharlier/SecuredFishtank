#!/bin/sh

echo "Cleaning ARP cache"

IFACE=$(ip -o -4 addr show | awk '$4 ~ /^10\.1\.0\./ { print $2; exit }')
MY_IP=$(ip -o -4 addr show dev "$IFACE" | awk '{ print $4; exit }' | cut -d/ -f1)

for ip in 10.1.0.1 10.1.0.2 10.1.0.3; do
    if [ "$ip" != "$MY_IP" ]; then
        ip neigh flush to "$ip" dev "$IFACE" 2>/dev/null
    fi
done

echo "Current ARP cache:"
arp -n
