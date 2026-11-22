"""Build a network overview from saved packet records."""

import ipaddress
import re
from collections import Counter
from datetime import datetime

try:
    from capture import lookup_mac_vendor
except Exception:
    def lookup_mac_vendor(_mac):
        return ""

PRIVATE_IPV4_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
)

_FALLBACK_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "SMB",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    546: "DHCPv6",
    547: "DHCPv6",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1900: "SSDP",
    3389: "RDP",
    5353: "mDNS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}
_INFO_DOMAIN_RE = re.compile(r"\((?:DNS|mDNS|HTTPS|HTTP|HTTP-Alt|HTTPS-Alt):\s*(?:query|response)?\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


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
    if state == "healthy":
        return {
            "level": "ok",
            "title": "Gateway status normal",
            "detail": "The default gateway responded normally during monitoring.",
            "action": "Continue regular monitoring and review traffic patterns if performance changes.",
        }
    if state == "congested":
        return {
            "level": "bad",
            "title": "Elevated gateway latency or packet loss",
            "detail": "Gateway checks recorded elevated latency or packet loss.",
            "action": "Review active high-volume transfers and check local network equipment or upstream connectivity.",
        }
    if state == "unreachable":
        return {
            "level": "bad",
            "title": "Gateway did not respond",
            "detail": "Recent checks to the default gateway did not receive a reply.",
            "action": "Verify local network cabling, wireless connectivity, and router ping settings.",
        }
    return {
        "level": "warn",
        "title": "Gateway status pending",
        "detail": "Gateway response data was not available when this report was generated.",
        "action": "Check the local connection and run monitoring while connected to the network.",
    }


def _infer_service(record, protocol):
    explicit = record.get("service")
    if explicit:
        return str(explicit)
    proto_upper = str(protocol or "").upper()
    for port_val in (
        record.get("destination_port"),
        record.get("dport"),
        record.get("source_port"),
        record.get("sport"),
    ):
        if port_val is None or port_val == "":
            continue
        try:
            port_num = int(port_val)
        except (TypeError, ValueError):
            continue
        if proto_upper == "UDP" and port_num == 443:
            return "QUIC"
        if port_num in _FALLBACK_PORTS:
            return _FALLBACK_PORTS[port_num]
    return ""


def _infer_domain(record, info_text):
    explicit = record.get("domain")
    if explicit:
        return str(explicit).strip().lower()
    match = _INFO_DOMAIN_RE.search(info_text or "")
    if match:
        candidate = match.group(1).strip(".").lower()
        if not candidate.endswith((".in-addr.arpa", ".ip6.arpa")):
            return candidate
    return ""


def build_network_report(records, capture_name, health, dropped_packets=None):
    protocols = Counter()
    services = Counter()
    domains = Counter()
    clients = {}
    total_bytes = 0
    arp_packets = 0
    port_80_packets = 0
    timestamps = []

    def _unicast_mac(mac_text):
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(mac_text or "")).lower()
        if len(cleaned) != 12 or cleaned in ("000000000000", "ffffffffffff"):
            return ""
        try:
            if int(cleaned[:2], 16) & 0x01:
                return ""
        except ValueError:
            return ""
        return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))

    def observe(ip, mac, direction, length, protocol, name=""):
        address = _private_ipv4(ip)
        if address is None:
            return
        key = str(address)
        clean_mac = _unicast_mac(mac)
        client = clients.setdefault(key, {
            "ip": key,
            "name": "",
            "mac": "",
            "vendor": "",
            "sent_packets": 0,
            "received_packets": 0,
            "sent_bytes": 0,
            "received_bytes": 0,
            "protocols": set(),
        })
        if name and not client["name"]:
            client["name"] = str(name)
        if clean_mac and not client["mac"]:
            client["mac"] = clean_mac
        client[f"{direction}_packets"] += 1
        client[f"{direction}_bytes"] += length
        if protocol:
            client["protocols"].add(protocol)

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

        raw_info = str(record.get("info") or "")
        service_name = _infer_service(record, protocol)
        if service_name:
            services[service_name] += 1
        domain_name = _infer_domain(record, raw_info)
        if domain_name:
            domains[domain_name] += 1

        timestamp = str(record.get("timestamp") or record.get("time") or "")
        if timestamp:
            timestamps.append(timestamp)
        source = record.get("source_ip") or record.get("src")
        destination = record.get("destination_ip") or record.get("dst")
        dst_mac = record.get("destination_mac") or record.get("dst_mac") or ""
        info_text = raw_info.lower()
        observe(
            source,
            record.get("source_mac") or record.get("src_mac"),
            "sent",
            length,
            protocol,
            name=record.get("device_name", ""),
        )
        is_broadcast_probe = (
            (protocol.upper() == "ARP" and "who-has" in info_text)
            or (bool(str(dst_mac).strip()) and not _unicast_mac(dst_mac))
        )
        if not is_broadcast_probe:
            observe(
                destination,
                dst_mac,
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
        if client["mac"]:
            client["vendor"] = lookup_mac_vendor(client["mac"])

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
    health.setdefault("description", "Gateway status information was not recorded.")
    health.setdefault("checked_at", "")
    health.setdefault(
        "context",
        "Gateway check recorded at report generation.",
    )

    advice = [_health_advice(health)]
    if not records:
        advice.append({
            "level": "info",
            "title": "No packet activity recorded",
            "detail": "The selected capture contains no recorded packets.",
            "action": "Confirm the active network adapter is selected before starting a capture.",
        })
    else:
        advice.append({
            "level": "info",
            "title": "Session traffic overview",
            "detail": "Captured packet volume, protocol distribution, and endpoint activity are summarized in the sections below.",
            "action": "Review the protocol summary, active services, and client list for any unexpected connections.",
        })
        if port_80_packets:
            advice.append({
                "level": "warn",
                "title": "Unencrypted web traffic observed",
                "detail": "HTTP traffic on port 80 was observed during the session.",
                "action": "Prefer HTTPS for sign-ins, administration pages, and sensitive transfers.",
            })
        if len(records) >= 20 and arp_packets / len(records) >= 0.25:
            advice.append({
                "level": "warn",
                "title": "Elevated ARP activity",
                "detail": "Address-resolution traffic made up a notable portion of the captured frames.",
                "action": "Monitor local address resolution if devices experience intermittent connectivity.",
            })
        if sorted_clients:
            advice.append({
                "level": "info",
                "title": "Endpoint identification summary",
                "detail": "Device names and vendor labels are populated from available traffic metadata and hardware address lookups.",
                "action": "Use custom device nicknames or review MAC and vendor details to recognize local endpoints.",
            })

    if dropped_packets is None:
        dropped_text = "Not recorded in this saved packet file"
    else:
        dropped_text = f"{int(dropped_packets):,}"
        if int(dropped_packets) > 0:
            advice.append({
                "level": "warn",
                "title": "Packet queue drops occurred",
                "detail": "Some incoming frames were not queued during peak capture activity.",
                "action": "Use shorter capture sessions or reduce background load when capturing high-rate traffic.",
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
        "top_services": [
            {
                "service": name,
                "packets": count,
                "percentage": count / len(records) * 100 if records else 0,
            }
            for name, count in services.most_common(10)
        ],
        "top_domains": [
            {
                "domain": name,
                "packets": count,
            }
            for name, count in domains.most_common(12)
        ],
        "advice": advice,
        "clients": sorted_clients,
        "tree": tree,
    }
