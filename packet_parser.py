"""Convert Scapy packets into plain dictionaries for storage and display."""
from datetime import datetime
import ipaddress
import re

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
try:
    from scapy.layers.inet6 import _ICMPv6
except ImportError:
    _ICMPv6 = None
try:
    from scapy.layers.dns import DNS
except ImportError:
    DNS = None
try:
    from scapy.layers.dhcp import DHCP
except ImportError:
    DHCP = None

WELL_KNOWN_PORTS = {
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

ICMP_TYPES = {
    0: "echo-reply",
    3: "destination-unreachable",
    5: "redirect",
    8: "echo-request",
    11: "time-exceeded",
}

DNS_RCODES = {
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
_HTTP_REQUEST_RE = re.compile(
    rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\r\n\s]{1,120})\s+HTTP/1\.[01]\r\n"
)
_HTTP_HOST_RE = re.compile(rb"(?im)^Host:\s*([^\r\n:]+)")


def _clean_domain(value):
    candidate = str(value or "").strip().rstrip(".").lower()
    if not candidate or len(candidate) > 253:
        return ""
    if candidate.endswith((".in-addr.arpa", ".ip6.arpa")):
        return ""
    try:
        ipaddress.ip_address(candidate)
        return ""
    except ValueError:
        pass
    if "." not in candidate:
        return ""
    if not _HOSTNAME_RE.match(candidate):
        return ""
    return candidate


def _payload_bytes(layer, limit=1500):
    try:
        payload = getattr(layer, "payload", None)
        if payload is None or getattr(payload, "name", "") in ("", "NoPayload"):
            return b""
        return bytes(payload)[:limit]
    except Exception:
        return b""


def _extract_tls_sni(data):
    """Passively extract the unencrypted TLS ClientHello SNI hostname, if present."""
    if len(data) < 48 or data[0] != 0x16 or data[1] != 0x03 or data[2] > 4:
        return ""
    record_len = int.from_bytes(data[3:5], "big")
    limit = min(len(data), 5 + record_len)
    if limit < 48 or data[5] != 0x01:
        return ""

    offset = 9 + 2 + 32  # handshake header(4) + client_version(2) + random(32)
    if offset >= limit:
        return ""
    session_id_len = data[offset]
    offset += 1 + session_id_len
    if offset + 2 > limit:
        return ""
    cipher_suites_len = int.from_bytes(data[offset:offset + 2], "big")
    offset += 2 + cipher_suites_len
    if offset >= limit:
        return ""
    compression_len = data[offset]
    offset += 1 + compression_len
    if offset + 2 > limit:
        return ""
    extensions_len = int.from_bytes(data[offset:offset + 2], "big")
    offset += 2
    extensions_end = min(limit, offset + extensions_len)

    while offset + 4 <= extensions_end:
        ext_type = int.from_bytes(data[offset:offset + 2], "big")
        ext_len = int.from_bytes(data[offset + 2:offset + 4], "big")
        offset += 4
        ext_end = min(extensions_end, offset + ext_len)
        if ext_type == 0x0000 and offset + 2 <= ext_end:
            list_len = int.from_bytes(data[offset:offset + 2], "big")
            pos = offset + 2
            list_end = min(ext_end, pos + list_len)
            while pos + 3 <= list_end:
                name_type = data[pos]
                name_len = int.from_bytes(data[pos + 1:pos + 3], "big")
                pos += 3
                if name_type == 0x00 and pos + name_len <= list_end:
                    raw_name = data[pos:pos + name_len].decode("utf-8", errors="ignore")
                    domain = _clean_domain(raw_name)
                    if domain:
                        return domain
                pos += name_len
        offset += ext_len
    return ""


def _extract_http_info(data):
    """Passively extract HTTP method, path, and Host header from cleartext HTTP."""
    if not data:
        return "", ""
    req_match = _HTTP_REQUEST_RE.match(data)
    if not req_match:
        return "", ""
    method = req_match.group(1).decode("ascii", errors="ignore")
    path = req_match.group(2).decode("ascii", errors="replace")
    if len(path) > 48:
        path = path[:45] + "..."
    host_match = _HTTP_HOST_RE.search(data)
    host = ""
    if host_match:
        host = host_match.group(1).decode("utf-8", errors="ignore").strip()
    domain = _clean_domain(host)
    if host:
        summary = f"{method} {path} · {host[:64]}"
    else:
        summary = f"{method} {path}"
    return summary, domain


def _service_label(protocol, sport, dport):
    for port in (dport, sport):
        if protocol == "UDP" and port == 443:
            return "QUIC"
        if port in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[port]
    return ""


def _dns_details(packet):
    if DNS is None or DNS not in packet:
        return "", ""
    try:
        dns = packet[DNS]
        is_response = bool(getattr(dns, "qr", 0))
        qname = getattr(getattr(dns, "qd", None), "qname", None)
        if isinstance(qname, bytes):
            qname = qname.decode("utf-8", errors="replace")
        qname = str(qname or "").rstrip(".")
        rcode = getattr(dns, "rcode", 0) if is_response else 0
        rcode_label = DNS_RCODES.get(rcode)
        if not qname and not rcode_label:
            return "", ""
        kind = "response" if is_response else "query"
        parts = [kind]
        if qname:
            parts.append(qname)
        if rcode_label:
            parts.append(f"[{rcode_label}]")
        return " ".join(parts), _clean_domain(qname)
    except Exception:
        return "", ""


def _extract_ssdp_device_name(data):
    if not data or not (data.startswith(b"NOTIFY ") or data.startswith(b"HTTP/1.1 200")):
        return ""
    text = data.decode("utf-8", errors="ignore")
    for pattern in (
        r"(?im)^(?:X-Friendly-Name|FriendlyName)\s*:\s*(.+)$",
        r"(?im)^SERVER\s*:\s*(.+)$",
    ):
        match = re.search(pattern, text)
        if match:
            value = re.sub(r"\s+", " ", match.group(1)).strip()
            if value:
                return value[:64]
    return ""


def _extract_netbios_name(data):
    """Decode a half-ASCII NetBIOS Name Service (UDP/137) label if present."""
    if len(data) < 46:
        return ""
    # Skip header (12 bytes); expect length byte 0x20 (32 encoded chars).
    if data[12] != 0x20:
        return ""
    encoded = data[13:45]
    if any(byte < 0x41 or byte > 0x50 for byte in encoded):
        return ""
    decoded = bytes(
        ((encoded[i] - 0x41) << 4) | (encoded[i + 1] - 0x41)
        for i in range(0, 32, 2)
    )
    name = decoded[:15].decode("ascii", errors="ignore").strip(" \x00")
    if not name or name.startswith("*") or "__MSBROWSE__" in name:
        return ""
    if not all(32 <= ord(ch) < 127 for ch in name):
        return ""
    return name


def _extract_device_identity(packet, protocol, sport=None, dport=None, payload=b""):
    if DHCP is not None and DHCP in packet and (sport in (67, 68) or dport in (67, 68)):
        try:
            vendor_class = ""
            for option in getattr(packet[DHCP], "options", ()) or ():
                if not isinstance(option, tuple) or len(option) < 2:
                    continue
                opt_name, raw_val = option[0], option[1]
                if isinstance(raw_val, bytes):
                    raw_val = raw_val.decode("utf-8", errors="replace")
                cleaned = str(raw_val or "").strip().strip("\x00.")
                if opt_name == "hostname" and cleaned and len(cleaned) <= 128:
                    return cleaned, "DHCP"
                if opt_name == "vendor_class_id" and cleaned and len(cleaned) <= 64 and not vendor_class:
                    vendor_class = cleaned
            if vendor_class:
                return vendor_class, "DHCP"
        except Exception:
            pass

    if (
        DNS is not None
        and DNS in packet
        and (sport == 5353 or dport == 5353)
        and getattr(packet[DNS], "qr", 0) == 1
    ):
        try:
            rr = getattr(packet[DNS], "an", None)
            hops = 0
            while rr is not None and hops < 8:
                hops += 1
                rrtype = getattr(rr, "type", None)
                rrname = getattr(rr, "rrname", None)
                if rrtype in (1, 28) and rrname:
                    if isinstance(rrname, bytes):
                        rrname = rrname.decode("utf-8", errors="replace")
                    candidate = str(rrname).strip().rstrip(".")
                    if (
                        candidate
                        and candidate.lower().endswith(".local")
                        and not candidate.startswith("_")
                        and "in-addr.arpa" not in candidate.lower()
                    ):
                        return candidate, "mDNS"
                rr = getattr(rr, "payload", None)
                if rr is None or getattr(rr, "name", "") in ("", "NoPayload"):
                    break
        except Exception:
            pass

    if protocol == "UDP" and (sport == 1900 or dport == 1900):
        ssdp_name = _extract_ssdp_device_name(payload)
        if ssdp_name:
            return ssdp_name, "SSDP"

    if protocol == "UDP" and (sport == 137 or dport == 137):
        nb_name = _extract_netbios_name(payload)
        if nb_name:
            return nb_name, "NetBIOS"

    return "", ""


def _transport_info(protocol, layer, packet, payload=b""):
    sport = getattr(layer, "sport", None)
    dport = getattr(layer, "dport", None)
    base = f"{protocol} {sport} -> {dport}"
    service = _service_label(protocol, sport, dport)
    domain = ""

    if sport in (53, 5353) or dport in (53, 5353):
        dns_note, dns_domain = _dns_details(packet)
        if dns_domain:
            domain = dns_domain
        if service and dns_note:
            return f"{base} ({service}: {dns_note})", service, domain
    elif protocol == "TCP" and payload:
        sni = _extract_tls_sni(payload)
        if sni:
            service = service or "HTTPS"
            domain = sni
            return f"{base} ({service}: {sni})", service, domain
        if sport in (80, 8080, 8000) or dport in (80, 8080, 8000):
            http_note, http_domain = _extract_http_info(payload)
            if http_domain:
                domain = http_domain
            if http_note:
                return f"{base} ({service or 'HTTP'}: {http_note})", service or "HTTP", domain

    if service:
        return f"{base} ({service})", service, domain
    return base, "", domain


def parse_packet(packet):
    packet_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
        "source_ip": "Unknown",
        "destination_ip": "Unknown",
        "protocol": "Other",
        "length": len(packet),
        "source_port": None,
        "destination_port": None,
        "source_mac": packet[Ether].src if Ether in packet else "",
        "destination_mac": packet[Ether].dst if Ether in packet else "",
        "info": "General packet",
    }

    if IP in packet:
        ip_layer = packet[IP]
        packet_data["source_ip"] = ip_layer.src
        packet_data["destination_ip"] = ip_layer.dst
        transport_layer = None
        if TCP in packet:
            transport_layer = packet[TCP]
            packet_data["protocol"] = "TCP"
        elif UDP in packet:
            transport_layer = packet[UDP]
            packet_data["protocol"] = "UDP"
        elif ICMP in packet:
            packet_data["protocol"] = "ICMP"
            icmp_type = getattr(packet[ICMP], "type", None)
            label = ICMP_TYPES.get(icmp_type)
            packet_data["info"] = (
                f"ICMP {label}" if label
                else f"ICMP type {icmp_type}" if icmp_type is not None
                else "ICMP packet"
            )
        else:
            packet_data["protocol"] = "IPv4"

        if transport_layer is not None:
            payload = _payload_bytes(transport_layer)
            info_text, service, domain = _transport_info(
                packet_data["protocol"], transport_layer, packet, payload
            )
            packet_data["source_port"] = transport_layer.sport
            packet_data["destination_port"] = transport_layer.dport
            packet_data["info"] = info_text
            if service:
                packet_data["service"] = service
            if domain:
                packet_data["domain"] = domain
            device_name, id_source = _extract_device_identity(
                packet,
                packet_data["protocol"],
                transport_layer.sport,
                transport_layer.dport,
                payload,
            )
            if device_name:
                packet_data["device_name"] = device_name
                if id_source:
                    packet_data["id_source"] = id_source

    elif IPv6 in packet:
        ipv6_layer = packet[IPv6]
        packet_data["source_ip"] = ipv6_layer.src
        packet_data["destination_ip"] = ipv6_layer.dst
        if TCP in packet:
            layer = packet[TCP]
            payload = _payload_bytes(layer)
            info_text, service, domain = _transport_info("TCP", layer, packet, payload)
            packet_data.update(
                protocol="TCP",
                source_port=layer.sport,
                destination_port=layer.dport,
                info=info_text,
            )
            if service:
                packet_data["service"] = service
            if domain:
                packet_data["domain"] = domain
        elif UDP in packet:
            layer = packet[UDP]
            payload = _payload_bytes(layer)
            info_text, service, domain = _transport_info("UDP", layer, packet, payload)
            packet_data.update(
                protocol="UDP",
                source_port=layer.sport,
                destination_port=layer.dport,
                info=info_text,
            )
            if service:
                packet_data["service"] = service
            if domain:
                packet_data["domain"] = domain
            device_name, id_source = _extract_device_identity(
                packet, "UDP", layer.sport, layer.dport, payload
            )
            if device_name:
                packet_data["device_name"] = device_name
                if id_source:
                    packet_data["id_source"] = id_source
        elif (_ICMPv6 is not None and _ICMPv6 in packet) or getattr(ipv6_layer, "nh", None) == 58:
            packet_data.update(protocol="ICMPv6", info="ICMPv6 packet")
        else:
            packet_data.update(protocol="IPv6", info="IPv6 packet")

    elif ARP in packet:
        arp_layer = packet[ARP]
        op = getattr(arp_layer, "op", None)
        if op == 1:
            arp_info = f"ARP who-has {arp_layer.pdst} tell {arp_layer.psrc}"
        elif op == 2:
            hwsrc = getattr(arp_layer, "hwsrc", "")
            arp_info = f"ARP {arp_layer.psrc} is-at {hwsrc}" if hwsrc else f"ARP reply {arp_layer.psrc}"
        else:
            arp_info = "ARP request/reply"
        packet_data.update(
            source_ip=arp_layer.psrc,
            destination_ip=arp_layer.pdst,
            protocol="ARP",
            info=arp_info,
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
