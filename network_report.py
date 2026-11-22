"""Build a network overview from saved packet records."""

import ipaddress
from collections import Counter
from datetime import datetime

PRIVATE_IPV4_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
)

def _private_ipv4(value):
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    if address.version == 4 and any(address in network for network in PRIVATE_IPV4_RANGES):
        return address
    return None


def _network_for(address):
    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def _health_advice(health):
    state = health.get("state", "unavailable")
    description = health.get("description", "No gateway health result is available.")
    if state == "healthy":
        return {
            "level": "ok",
            "title": "Gateway response looks healthy",
            "detail": description,
            "action": "No immediate gateway action is suggested; continue monitoring if users still notice slow connections.",
        }
    if state == "congested":
        return {
            "level": "bad",
            "title": "Possible congestion or path degradation",
            "detail": description,
            "action": "Pause a large download or stream and compare gateway response. Captured senders are possible contributors, not proven causes.",
        }
    if state == "unreachable":
        return {
            "level": "bad",
            "title": "The gateway did not respond",
            "detail": description,
            "action": "Check the router and local connection; some gateways block ping, so compare with another device before concluding the network is down.",
        }
    return {
        "level": "warn",
        "title": "Gateway health is not confirmed",
        "detail": description,
        "action": "Check the gateway connection and run another health check.",
    }


def build_network_report(records, capture_name, health, dropped_packets=None):
    protocols = Counter()
    clients = {}
    total_bytes = 0
    arp_packets = 0
    port_80_packets = 0
    sender_bytes = Counter()
    timestamps = []

    def observe(ip, mac, direction, length, protocol):
        address = _private_ipv4(ip)
        if address is None:
            return
        key = str(address)
        client = clients.setdefault(key, {
            "ip": key,
            "mac": "",
            "sent_packets": 0,
            "received_packets": 0,
            "sent_bytes": 0,
            "received_bytes": 0,
            "protocols": set(),
        })
        if mac and not client["mac"]:
            client["mac"] = str(mac)
        client[f"{direction}_packets"] += 1
        client[f"{direction}_bytes"] += length
        if protocol:
            client["protocols"].add(protocol)
        if direction == "sent":
            sender_bytes[key] += length

    for record in records:
        if not isinstance(record, dict):
            continue
        protocol = str(record.get("protocol") or record.get("pr") or "Other")
        try:
            length = max(0, int(record.get("length") or record.get("len") or 0))
        except (TypeError, ValueError):
            length = 0
        total_bytes += length
        protocols[protocol] += 1
        if protocol.upper() == "ARP":
            arp_packets += 1
        ports = (
            record.get("source_port"),
            record.get("destination_port"),
            record.get("sport"),
            record.get("dport"),
        )
        if any(str(port) == "80" for port in ports if port is not None):
            port_80_packets += 1

        timestamp = str(record.get("timestamp") or record.get("time") or "")
        if timestamp:
            timestamps.append(timestamp)
        source = record.get("source_ip") or record.get("src")
        destination = record.get("destination_ip") or record.get("dst")
        observe(
            source,
            record.get("source_mac") or record.get("src_mac"),
            "sent",
            length,
            protocol,
        )
        observe(
            destination,
            record.get("destination_mac") or record.get("dst_mac"),
            "received",
            length,
            protocol,
        )

    sorted_clients = sorted(
        clients.values(),
        key=lambda item: (
            ipaddress.ip_address(item["ip"]).version,
            int(ipaddress.ip_address(item["ip"])),
        ),
    )
    for client in sorted_clients:
        client["total_bytes"] = client["sent_bytes"] + client["received_bytes"]
        client["protocols"] = sorted(client["protocols"])

    networks = {}
    for client in sorted_clients:
        network = _network_for(ipaddress.ip_address(client["ip"]))
        networks.setdefault(network, []).append(client)
    tree = [
        {"network": network, "clients": entries}
        for network, entries in sorted(networks.items())
    ]

    health = dict(health or {})
    health.setdefault("state", "unavailable")
    health.setdefault("description", "No gateway health result is available.")
    health.setdefault("checked_at", "")
    health.setdefault(
        "context",
        "Live gateway health at report generation; historical health is not stored in packet captures.",
    )

    advice = [_health_advice(health)]
    if not records:
        advice.append({
            "level": "warn",
            "title": "No packets are in this capture",
            "detail": "The saved file contains no packet records.",
            "action": "Check that the intended capture file was opened and that capture was running on the active adapter.",
        })
    else:
        private_source_total = sum(sender_bytes.values())
        if private_source_total:
            top_ip, top_bytes = sender_bytes.most_common(1)[0]
            share = top_bytes / private_source_total * 100
            if share >= 40:
                advice.append({
                    "level": "warn",
                    "title": "One observed LAN sender accounts for a large share",
                    "detail": f"{top_ip} accounts for {share:.0f}% of the captured private-LAN source bytes.",
                    "action": "If that traffic was unexpected, identify the device in the router client list and check for streaming, backups, or large downloads.",
                })
            else:
                advice.append({
                    "level": "ok",
                    "title": "Traffic is spread across observed LAN senders",
                    "detail": f"No single observed sender accounts for 40% of private-LAN source bytes ({private_source_total:,} bytes total).",
                    "action": "Keep monitoring; this describes only traffic visible to the selected adapter.",
                })
        if port_80_packets:
            advice.append({
                "level": "warn",
                "title": "Traffic used port 80",
                "detail": f"{port_80_packets:,} packet(s) used port 80. The port alone does not confirm whether sensitive data was sent.",
                "action": "Check the application and destination, and use HTTPS for sign-ins or sensitive information.",
            })
        if len(records) >= 20 and arp_packets / len(records) >= 0.25:
            advice.append({
                "level": "warn",
                "title": "A large share of observed packets is ARP",
                "detail": f"{arp_packets / len(records) * 100:.0f}% of captured packets are ARP; this can occur during normal discovery.",
                "action": "If the pattern is sustained, check the router for repeated address discovery or duplicate-IP warnings.",
            })
        if clients:
            advice.append({
                "level": "info",
                "title": "Device names are not included in packet records",
                "detail": f"{len(clients):,} private-LAN address(es) were observed; names and ownership cannot be inferred from packet data.",
                "action": "Compare the IP and recorded MAC addresses with your router’s connected-device list.",
            })

    if dropped_packets is None:
        dropped_text = "Not recorded in this saved packet file"
    else:
        dropped_text = f"{int(dropped_packets):,}"
        if int(dropped_packets) > 0:
            advice.append({
                "level": "warn",
                "title": "Some packets were dropped during capture",
                "detail": f"{int(dropped_packets):,} packet(s) could not be queued for display or storage.",
                "action": "Reduce system load or capture for a shorter period; totals and recommendations may be incomplete.",
            })

    return {
        "header": {
            "title": "LAN Traffic Analyzer - Network Report",
            "capture": capture_name or "Current capture",
            "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
            "first_packet": min(timestamps) if timestamps else "—",
            "last_packet": max(timestamps) if timestamps else "—",
            "packet_count": len(records),
            "total_bytes": total_bytes,
            "client_count": len(sorted_clients),
            "dropped_packets": dropped_text,
        },
        "health": health,
        "protocols": [
            {
                "protocol": name,
                "packets": count,
                "percentage": count / len(records) * 100 if records else 0,
            }
            for name, count in protocols.most_common()
        ],
        "advice": advice,
        "clients": sorted_clients,
        "tree": tree,
    }
