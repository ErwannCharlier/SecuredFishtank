#!/usr/bin/env python3

from scapy.all import IP, ICMP, TCP, UDP, DNS, DNSQR, Raw, sr1, send, RandShort, conf
import ipaddress

conf.verb = 0

dmz_network = "10.12.0.0/24"

tcp_ports = [21, 22, 80, 443]
udp_ports = [123, 5353]


def ping_host(ip):
    packet = IP(dst=str(ip))
    packet.add_payload(ICMP())
    answer = sr1(packet, timeout=0.2)

    return answer is not None


def scan_tcp_port(ip, port):
    syn_packet = IP(dst=str(ip))
    syn_packet.add_payload(TCP(
        sport=RandShort(),
        dport=port,
        flags="S"
    ))

    answer = sr1(syn_packet, timeout=0.2)

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


def scan_udp_port(ip, port):
    packet = IP(dst=str(ip)) / UDP(
        sport=RandShort(),
        dport=port
    )

    if port == 5353:
        packet = packet / DNS(
            rd=1,
            qd=DNSQR(qname="example.com")
        )

    if port == 123:
        packet = packet / Raw(
            load=b"\x1b" + 47 * b"\x00"
        )

    answer = sr1(packet, timeout=0.5)

    if answer is None:
        return None

    if answer.haslayer(ICMP):
        icmp = answer[ICMP]
        if icmp.type == 3 and icmp.code == 3:
            return "closed"

    return "open"

def scan_network(network_name, network):
    print(f"\n[+] Scanning {network_name}: {network}")

    for ip in ipaddress.ip_network(network).hosts():
        print(f"[+] trying: {ip}", end='\r')

        host_is_alive = ping_host(ip)
        open_tcp_ports = []
        udp_ports_found = []

        for port in tcp_ports:
            if scan_tcp_port(ip, port):
                open_tcp_ports.append(port)

        for port in udp_ports:
            result = scan_udp_port(ip, port)
            if result == "open":
                udp_ports_found.append((port, result))
        if host_is_alive or open_tcp_ports or udp_ports_found:
            print(f"\nHost found: {ip}")

            if host_is_alive:
                print("  ICMP reply: yes")

            if open_tcp_ports:
                print("  Open TCP ports:")
                for port in open_tcp_ports:
                    print(f"    - {port}")

            if udp_ports_found:
                print("  UDP ports:")
                for port, result in udp_ports_found:
                    print(f"    - {port} ({result})")


print("Network scan attack")

scan_network("DMZ network", dmz_network)