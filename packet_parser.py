from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from datetime import datetime


def parse_packet(packet):

    packet_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": "Unknown",
        "destination_ip": "Unknown",
        "protocol": "Other",
        "length": len(packet),
        "source_port": None,
        "destination_port": None,
        "info": "General packet"
    }

    # IPv4
    if IP in packet:
        ip_layer = packet[IP]

        packet_data["source_ip"] = ip_layer.src
        packet_data["destination_ip"] = ip_layer.dst

        # TCP
        if TCP in packet:
            tcp_layer = packet[TCP]

            packet_data["protocol"] = "TCP"
            packet_data["source_port"] = tcp_layer.sport
            packet_data["destination_port"] = tcp_layer.dport

            packet_data["info"] = (
                f"TCP {tcp_layer.sport} -> {tcp_layer.dport}"
            )

        # UDP
        elif UDP in packet:
            udp_layer = packet[UDP]

            packet_data["protocol"] = "UDP"
            packet_data["source_port"] = udp_layer.sport
            packet_data["destination_port"] = udp_layer.dport

            packet_data["info"] = (
                f"UDP {udp_layer.sport} -> {udp_layer.dport}"
            )

        # ICMP
        elif ICMP in packet:
            packet_data["protocol"] = "ICMP"
            packet_data["info"] = "ICMP packet"

        else:
            packet_data["protocol"] = "IPv4"
            packet_data["info"] = "IPv4 packet"

    # IPv6
    elif IPv6 in packet:
        ipv6_layer = packet[IPv6]

        packet_data["source_ip"] = ipv6_layer.src
        packet_data["destination_ip"] = ipv6_layer.dst
        packet_data["protocol"] = "IPv6"
        packet_data["info"] = "IPv6 packet"

    # ARP
    elif ARP in packet:
        arp_layer = packet[ARP]

        packet_data["source_ip"] = arp_layer.psrc
        packet_data["destination_ip"] = arp_layer.pdst
        packet_data["protocol"] = "ARP"
        packet_data["info"] = "ARP request/reply"

    # Ethernet
    elif Ether in packet:
        ethernet_layer = packet[Ether]

        packet_data["source_ip"] = ethernet_layer.src
        packet_data["destination_ip"] = ethernet_layer.dst
        packet_data["protocol"] = "Ethernet"
        packet_data["info"] = "Ethernet frame"

    return packet_data


