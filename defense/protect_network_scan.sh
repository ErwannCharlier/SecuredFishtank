#!/bin/sh

echo "Adding network scan protection rules"

nft add chain inet filter scan_protection 2>/dev/null
nft flush chain inet filter scan_protection

nft insert rule inet filter forward iifname "r2-eth0" ip daddr 10.12.0.0/24 jump scan_protection

nft add rule inet filter scan_protection ip protocol icmp icmp type echo-request drop

nft add rule inet filter scan_protection ip daddr 10.12.0.10 tcp dport 80 accept
nft add rule inet filter scan_protection ip daddr 10.12.0.40 tcp dport 21 accept
nft add rule inet filter scan_protection ip daddr 10.12.0.20 udp dport 5353 accept
nft add rule inet filter scan_protection ip daddr 10.12.0.30 udp dport 123 accept

nft add rule inet filter scan_protection drop

echo "Forward chain:"
nft list chain inet filter forward

echo "Scan protection chain:"
nft list chain inet filter scan_protection