"""Convert Scapy packets into plain dictionaries for storage and display."""
from datetime import datetime
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6


def parse_packet(packet):
    packet_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
        "source_ip": "Unknown",
        "destination_ip": "Unknown",
        "protocol": "Other",
        "length": len(packet),
        "source_port": None,
        "destination_port": None,
        "info": "General packet",
    }

    if IP in packet:
        ip_layer = packet[IP]
        packet_data["source_ip"] = ip_layer.src
        packet_data["destination_ip"] = ip_layer.dst
        transport_layer = packet
        if TCP in packet:
            transport_layer = packet[TCP]
            packet_data["protocol"] = "TCP"
        elif UDP in packet:
            transport_layer = packet[UDP]
            packet_data["protocol"] = "UDP"
        elif ICMP in packet:
            packet_data["protocol"] = "ICMP"
            packet_data["info"] = "ICMP packet"
        else:
            packet_data["protocol"] = "IPv4"

        if TCP in packet or UDP in packet:
            packet_data["source_port"] = transport_layer.sport
            packet_data["destination_port"] = transport_layer.dport
            packet_data["info"] = (
                f"{packet_data['protocol']} "
                f"{transport_layer.sport} -> {transport_layer.dport}"
            )

    elif IPv6 in packet:
        ipv6_layer = packet[IPv6]
        packet_data["source_ip"] = ipv6_layer.src
        packet_data["destination_ip"] = ipv6_layer.dst
        if TCP in packet:
            layer = packet[TCP]
            packet_data.update(
                protocol="TCP", source_port=layer.sport,
                destination_port=layer.dport,
                info=f"TCP {layer.sport} -> {layer.dport}",
            )
        elif UDP in packet:
            layer = packet[UDP]
            packet_data.update(
                protocol="UDP", source_port=layer.sport,
                destination_port=layer.dport,
                info=f"UDP {layer.sport} -> {layer.dport}",
            )
        elif ICMP in packet:
            packet_data.update(protocol="ICMPv6", info="ICMPv6 packet")
        else:
            packet_data.update(protocol="IPv6", info="IPv6 packet")

    elif ARP in packet:
        arp_layer = packet[ARP]
        packet_data.update(
            source_ip=arp_layer.psrc,
            destination_ip=arp_layer.pdst,
            protocol="ARP",
            info="ARP request/reply",
        )

    elif Ether in packet:
        ethernet_layer = packet[Ether]
        packet_data.update(
            source_ip=ethernet_layer.src,
            destination_ip=ethernet_layer.dst,
            protocol="Ethernet",
            info="Ethernet frame",
        )

    return packet_data
