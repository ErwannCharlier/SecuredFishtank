#!/bin/bash

echo "[+] Installing anti-spoofing defense on r2"

# If a packet comes from the Internet interface but uses a source IP
# from the workstation LAN => dropped.
nft insert rule inet filter forward iifname "r2-eth0" ip saddr 10.1.0.0/24 counter drop

# If a packet comes from the Internet interface but uses a source IP
# from the DMZ network => dropped.
nft insert rule inet filter forward iifname "r2-eth0" ip saddr 10.12.0.0/24 counter drop

echo "[+] Anti-spoofing rules installed"
nft list chain inet filter forward