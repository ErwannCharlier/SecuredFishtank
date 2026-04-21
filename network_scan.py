#!/usr/bin/env python3

from scapy.all import IP, ICMP, TCP, sr1, send, RandShort, conf
import ipaddress

conf.verb = 0

dmz_network = "10.12.0.0/24"

ports = [21, 22, 53, 80, 123, 443, 5353]


def ping_host(ip):
    packet = IP(dst=str(ip))
    packet.add_payload(ICMP())
    answer = sr1(packet, timeout=0.1)

    return answer is not None


def scan_tcp_port(ip, port):
    syn_packet = IP(dst=str(ip))
    syn_packet.add_payload(TCP(
        sport=RandShort(),
        dport=port,
        flags="S"
    ))

    answer = sr1(syn_packet, timeout=0.1)

    if answer is None:
        return False

    if answer.haslayer(TCP) and answer[TCP].flags == 0x12:
        rst_packet = IP(dst=str(ip))
        rst_packet.add_payload(TCP(
            sport=syn_packet[TCP].sport,
            dport=port,
            flags="R"
        ))

        send(rst_packet, verbose=False)
        return True

    return False

def scan_network(network_name, network):
    print(f"\n[+] Scanning {network_name}: {network}")

    for ip in ipaddress.ip_network(network).hosts():
        print(f"[+] trying: {ip}",end='\r')
        host_is_alive = ping_host(ip)
        open_ports = []

        for port in ports:
            if scan_tcp_port(ip, port):
                open_ports.append(port)

        if host_is_alive or open_ports:
            print(f"\nHost found: {ip}")

            if host_is_alive:
                print("  ICMP reply: yes")

            if open_ports:
                print("  Open TCP ports:")
                for port in open_ports:
                    print(f"    - {port}")


print("Network scan attack")

scan_network("DMZ network", dmz_network)
