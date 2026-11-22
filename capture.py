"""Network interface discovery and asynchronous packet capture helpers."""
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import platform
import re
import socket
import subprocess
from threading import Lock
import time

from scapy.all import AsyncSniffer, conf, get_if_addr, get_if_hwaddr, get_if_list
from packet_parser import parse_packet

PRIVATE_IPV4_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
)

HOSTNAME_CACHE_TTL_SECONDS = 300
MAX_HOSTNAME_CACHE = 1024
_identity_lock = Lock()
_hostname_cache = {}

# Curated IEEE OUI prefixes for common LAN adapters, routers, phones, and IoT hardware.
MAC_OUI_VENDORS = {
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:95": "Apple",
    "00:17:F2": "Apple", "00:1B:63": "Apple", "00:1E:C2": "Apple",
    "00:25:00": "Apple", "00:26:BB": "Apple", "04:0C:CE": "Apple",
    "14:10:9F": "Apple", "28:CF:E9": "Apple", "3C:07:54": "Apple",
    "40:6C:8F": "Apple", "58:55:CA": "Apple", "68:5B:35": "Apple",
    "70:56:81": "Apple", "78:31:C1": "Apple", "88:66:5A": "Apple",
    "98:01:A7": "Apple", "A4:83:E7": "Apple", "AC:BC:32": "Apple",
    "BC:52:B7": "Apple", "D0:81:7A": "Apple", "F0:18:98": "Apple",
    "00:02:B3": "Intel", "00:0E:35": "Intel", "00:15:00": "Intel",
    "00:1B:21": "Intel", "00:1E:64": "Intel", "00:21:6A": "Intel",
    "00:24:D7": "Intel", "18:56:80": "Intel", "34:13:E8": "Intel",
    "48:51:B7": "Intel", "60:6C:66": "Intel", "7C:7A:91": "Intel",
    "80:86:F2": "Intel", "94:65:9C": "Intel", "A4:4C:C8": "Intel",
    "B4:6B:FC": "Intel", "DC:53:60": "Intel", "E4:B3:18": "Intel",
    "00:E0:4C": "Realtek", "52:54:00": "QEMU/KVM", "00:0C:29": "VMware",
    "00:50:56": "VMware", "00:05:69": "VMware", "08:00:27": "VirtualBox",
    "00:15:5D": "Microsoft Hyper-V", "00:03:FF": "Microsoft", "00:1D:D8": "Microsoft",
    "28:18:78": "Microsoft", "60:45:BD": "Microsoft", "7C:1E:52": "Microsoft",
    "00:14:22": "Dell", "00:1A:A0": "Dell", "14:FE:B5": "Dell",
    "18:03:73": "Dell", "24:B6:FD": "Dell", "F8:B1:56": "Dell",
    "00:1A:4B": "HP", "00:21:5A": "HP", "10:1F:74": "HP",
    "3C:D9:2B": "HP", "6C:3B:E5": "HP", "94:57:A5": "HP",
    "00:16:36": "Lenovo", "00:21:CC": "Lenovo", "28:D2:44": "Lenovo",
    "54:EE:75": "Lenovo", "70:5A:0F": "HP", "8C:16:45": "Lenovo",
    "00:0D:4B": "Roku", "B0:A7:37": "Roku", "D8:31:34": "Roku",
    "00:0E:58": "Sonos", "5C:AA:FD": "Sonos", "78:28:CA": "Sonos",
    "94:9F:3E": "Sonos", "B8:E9:37": "Sonos",
    "00:17:88": "Philips Hue", "EC:B5:FA": "Philips Hue",
    "00:1A:11": "Google", "3C:5A:B4": "Google", "54:60:09": "Google",
    "6C:AD:F8": "Google", "94:EB:2C": "Google", "F4:F5:D8": "Google",
    "00:FC:8B": "Amazon", "44:65:0D": "Amazon", "68:37:E9": "Amazon",
    "74:C2:46": "Amazon", "84:D6:D0": "Amazon", "F0:27:2D": "Amazon",
    "00:12:FB": "Samsung", "00:15:99": "Samsung", "00:21:19": "Samsung",
    "18:3A:2D": "Samsung", "34:23:BA": "Samsung", "50:32:75": "Samsung",
    "78:47:1D": "Samsung", "8C:77:12": "Samsung", "BC:14:EF": "Samsung",
    "E4:92:FB": "Samsung", "F4:7B:5E": "Samsung",
    "00:1E:B2": "LG", "10:68:3F": "LG", "34:4D:F7": "LG",
    "64:99:5D": "LG", "A8:16:B2": "LG", "CC:2D:8C": "LG",
    "00:0C:43": "MediaTek", "00:13:EF": "Kingmax", "00:24:E4": "Withings",
    "00:1D:0F": "TP-Link", "14:CC:20": "TP-Link", "18:A6:F7": "TP-Link",
    "50:C7:BF": "TP-Link", "60:E3:27": "TP-Link", "74:DA:88": "TP-Link",
    "98:DA:C4": "TP-Link", "B0:4E:26": "TP-Link", "C0:25:E9": "TP-Link",
    "D8:07:B6": "TP-Link", "E8:DE:27": "TP-Link", "F4:F2:6D": "TP-Link",
    "00:1D:7E": "Cisco-Linksys", "00:25:9C": "Cisco-Linksys", "14:91:82": "Belkin/Linksys",
    "C0:56:27": "Belkin/Linksys", "EC:1A:59": "Belkin",
    "00:1B:2F": "Netgear", "00:24:B2": "Netgear", "00:26:F2": "Netgear",
    "20:4E:7F": "Netgear", "44:94:FC": "Netgear", "A0:21:B7": "Netgear",
    "C4:3D:C7": "Netgear", "E0:46:9A": "Netgear",
    "00:0C:6E": "ASUS", "00:1E:8C": "ASUS", "04:92:26": "ASUS",
    "1C:87:2C": "ASUS", "2C:56:DC": "ASUS", "38:D5:47": "ASUS",
    "50:46:5D": "ASUS", "60:45:CB": "ASUS", "AC:9E:17": "ASUS",
    "B0:6E:BF": "ASUS", "F8:32:E4": "ASUS",
    "00:15:6D": "Ubiquiti", "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti",
    "18:E8:29": "Ubiquiti", "24:A4:3C": "Ubiquiti", "44:D9:E7": "Ubiquiti",
    "68:72:51": "Ubiquiti", "74:83:C2": "Ubiquiti", "78:8A:20": "Ubiquiti",
    "80:2A:A8": "Ubiquiti", "B4:FB:E4": "Ubiquiti", "DC:9F:DB": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    "00:00:0C": "Cisco", "00:1A:A1": "Cisco", "00:40:96": "Cisco",
    "00:11:32": "Synology", "00:08:9B": "QNAP", "24:5E:BE": "QNAP",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "2C:CF:67": "Raspberry Pi", "D8:3A:DD": "Raspberry Pi",
    "18:FE:34": "Espressif", "24:0A:C4": "Espressif", "30:AE:A4": "Espressif",
    "3C:71:BF": "Espressif", "5C:CF:7F": "Espressif", "84:CC:A8": "Espressif",
    "A4:CF:12": "Espressif", "CC:50:E3": "Espressif", "EC:FA:BC": "Espressif",
    "00:1E:8F": "Canon", "00:80:77": "Brother", "30:05:5C": "Brother",
    "00:26:AB": "Epson", "64:EB:8C": "Epson",
    "00:04:1F": "Sony", "00:13:15": "Sony", "28:0D:FC": "Sony",
    "70:9E:29": "Sony", "FC:0F:E6": "Sony",
    "00:19:1D": "Nintendo", "00:1F:32": "Nintendo", "34:AF:2C": "Nintendo",
    "58:BD:A3": "Nintendo", "7C:BB:8A": "Nintendo", "98:B6:E9": "Nintendo",
    "00:9E:C8": "Xiaomi", "28:6C:07": "Xiaomi", "34:CE:00": "Xiaomi",
    "64:09:80": "Xiaomi", "7C:1D:D9": "Xiaomi", "F8:A4:5F": "Xiaomi",
    "00:1E:10": "Huawei", "00:46:4B": "Huawei", "28:31:52": "Huawei",
    "48:46:FB": "Huawei", "70:72:3C": "Huawei", "88:28:B3": "Huawei",
}


def lookup_mac_vendor(mac_address):
    """Return a known manufacturer or private-MAC indicator for a MAC address."""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(mac_address or "")).upper()
    if len(cleaned) < 6:
        return ""
    if cleaned.startswith("FFFFFF"):
        return ""
    try:
        first_octet = int(cleaned[:2], 16)
    except ValueError:
        return ""
    if first_octet & 0x01:
        return ""
    prefix = f"{cleaned[0:2]}:{cleaned[2:4]}:{cleaned[4:6]}"
    vendor = MAC_OUI_VENDORS.get(prefix, "")
    if vendor:
        return vendor
    if first_octet & 0x02:
        return "Private / randomized MAC"
    return ""


def get_local_hostname():
    """Return this computer's local hostname."""
    try:
        return socket.gethostname() or ""
    except OSError:
        return ""


def _is_private_ipv4(value):
    try:
        address = ipaddress.IPv4Address(str(value or ""))
    except (ipaddress.AddressValueError, ValueError):
        return False
    return any(address in net for net in PRIVATE_IPV4_NETWORKS)


def resolve_hostname(ip_address):
    """Resolve and cache a local private IPv4 hostname using reverse DNS."""
    ip_text = str(ip_address or "").strip()
    if not _is_private_ipv4(ip_text):
        return ""
    now = time.monotonic()
    with _identity_lock:
        cached = _hostname_cache.get(ip_text)
        if cached and cached[1] > now:
            return cached[0]

    hostname = ""
    try:
        resolved, _, _ = socket.gethostbyaddr(ip_text)
        resolved = str(resolved or "").strip().rstrip(".")
        if resolved and resolved != ip_text:
            hostname = resolved
    except (OSError, ValueError):
        hostname = ""

    with _identity_lock:
        if len(_hostname_cache) >= MAX_HOSTNAME_CACHE:
            _hostname_cache.pop(next(iter(_hostname_cache)))
        _hostname_cache[ip_text] = (hostname, now + HOSTNAME_CACHE_TTL_SECONDS)
    return hostname


def identify_devices(entries):
    """Resolve hostnames and MAC vendors for a batch of private IPv4 devices."""
    normalized = []
    seen = set()
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        ip_text = str(entry.get("ip") or "").strip()
        mac_text = str(entry.get("mac") or "").strip()
        if not ip_text or ip_text in seen or not _is_private_ipv4(ip_text):
            continue
        seen.add(ip_text)
        normalized.append((ip_text, mac_text))
        if len(normalized) >= 64:
            break

    if not normalized:
        return {}

    names = {}
    with ThreadPoolExecutor(max_workers=min(16, len(normalized))) as executor:
        futures = {executor.submit(resolve_hostname, ip_text): ip_text for ip_text, _ in normalized}
        for future, ip_text in futures.items():
            try:
                names[ip_text] = future.result()
            except Exception:
                names[ip_text] = ""

    return {
        ip_text: {
            "name": names.get(ip_text, ""),
            "vendor": lookup_mac_vendor(mac_text),
        }
        for ip_text, mac_text in normalized
    }


def get_default_gateway():
    """Return the IPv4 gateway selected by Scapy's default route, if available."""
    route = conf.route.route("0.0.0.0")
    if route and len(route) >= 3:
        gateway = str(route[2] or "")
        if gateway and gateway != "0.0.0.0":
            return gateway
    return None


def ping_gateway(gateway):
    """Return the gateway response time in milliseconds, or None on packet loss."""
    if platform.system() == "Windows":
        command = ["ping", "-n", "1", "-w", "1000", gateway]
    else:
        command = ["ping", "-c", "1", "-W", "1", gateway]

    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=2,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None

    if result.returncode != 0:
        return None

    output = result.stdout or ""
    if re.search(r"unreachable|timed out|100%\s*loss", output, re.IGNORECASE):
        return None

    match = re.search(r"\btime\s*[=<]\s*(\d+(?:\.\d+)?)\s*ms", output, re.IGNORECASE)
    if match:
        return float(match.group(1))

    # Some localized ping outputs omit the English "time=" token, but keep TTL=.
    if re.search(r"\bTTL\s*=", output, re.IGNORECASE):
        return (time.perf_counter() - started) * 1000
    return None


def _route_interface_name(route_interface, available=None):
    if route_interface is None:
        return None
    candidates = [
        getattr(route_interface, "name", None),
        getattr(route_interface, "network_name", None),
        str(route_interface),
    ]
    if available is None:
        available = set(get_if_list())
    for candidate in candidates:
        if candidate and candidate in available:
            return candidate
    for candidate in candidates:
        if candidate:
            for name in available:
                if name.lower() == str(candidate).lower():
                    return name
    return None


def detect_active_interface():
    """Return the interface Scapy uses for the IPv4 default route."""
    try:
        route = conf.route.route("0.0.0.0")
        if route and route[0]:
            return _route_interface_name(route[0])
    except Exception as error:
        print("Default-route detection error:", error)
    return None


def get_interface_details():
    active_name = detect_active_interface()
    details = []
    for name in get_if_list():
        try:
            ip_address = get_if_addr(name)
        except Exception:
            ip_address = ""
        try:
            mac_address = get_if_hwaddr(name)
        except Exception:
            mac_address = ""

        lowered = name.lower()
        is_loopback = (
            lowered in {"lo", "lo0"}
            or "loopback" in lowered
            or ip_address.startswith("127.")
        )
        details.append({
            "name": name,
            "ip": ip_address if ip_address != "0.0.0.0" else "",
            "mac": mac_address,
            "is_default_route": name == active_name,
            "is_loopback": is_loopback,
        })

    details.sort(key=lambda item: (
        not item["is_default_route"],
        item["is_loopback"],
        not bool(item["ip"]),
        item["name"].lower(),
    ))
    return details


def get_interfaces():
    return [item["name"] for item in get_interface_details()]


def start_capture(interface, packet_callback):
    """Start capture; callback must remain lightweight and thread-safe."""
    if interface not in get_if_list():
        raise ValueError(
            f"Interface '{interface}' is no longer available. Refresh the list."
        )

    def process_packet(packet):
        try:
            packet_callback(parse_packet(packet))
        except Exception as error:
            # Do not let one malformed packet terminate the capture thread.
            print("Packet processing error:", error)

    sniffer = AsyncSniffer(
        iface=interface,
        prn=process_packet,
        store=False,
    )
    sniffer.start()
    return sniffer


def stop_capture(sniffer):
    """Stop and join the Scapy capture thread. Call from a worker thread."""
    if sniffer is None:
        return
    try:
        if sniffer.running:
            sniffer.stop(join=True)
    except AttributeError:
        # Compatibility with Scapy versions/backends without a running property.
        sniffer.stop(join=True)
