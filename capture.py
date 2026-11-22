"""Network interface discovery and asynchronous packet capture helpers."""
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import platform
import re
import subprocess
import time

from scapy.all import AsyncSniffer, conf, get_if_addr, get_if_hwaddr, get_if_list
from scapy.error import Scapy_Exception
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from packet_parser import parse_packet

MAX_DISCOVERY_ADDRESSES = 256
DISCOVERY_WORKERS = 32
DISCOVERY_TIMEOUT_MS = 800
ARP_DISCOVERY_TIMEOUT_SECONDS = 1.5
PRIVATE_IPV4_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
)


def get_default_gateway():
    """Return the IPv4 gateway selected by Scapy's default route, if available."""
    route = conf.route.route("0.0.0.0")
    if route and len(route) >= 3:
        gateway = str(route[2] or "")
        if gateway and gateway != "0.0.0.0":
            return gateway
    return None


def get_interface_ipv4_network(interface):
    """Find the selected interface's routed local IPv4 subnet."""
    try:
        interfaces = get_if_list()
    except Scapy_Exception as exc:
        raise ValueError(f"Could not enumerate network interfaces: {exc}") from exc
    if interface not in interfaces:
        raise ValueError(f"Interface '{interface}' is no longer available.")
    try:
        interface_ip = ipaddress.IPv4Address(get_if_addr(interface))
    except (ipaddress.AddressValueError, OSError, Scapy_Exception) as exc:
        raise ValueError("The selected interface does not have a usable IPv4 address.") from exc

    networks = []
    try:
        routes = conf.route.routes
    except Scapy_Exception as exc:
        raise ValueError(f"Could not inspect local IPv4 routes: {exc}") from exc
    for route in routes:
        if len(route) < 5:
            continue
        network_number, netmask_number, _, route_interface, route_address = route[:5]
        if str(route_interface) != interface or str(route_address) != str(interface_ip):
            continue
        try:
            network = ipaddress.IPv4Network(
                f"{ipaddress.IPv4Address(int(network_number))}/"
                f"{ipaddress.IPv4Address(int(netmask_number))}",
                strict=False,
            )
        except (TypeError, ValueError):
            continue
        if network.prefixlen < 32 and interface_ip in network:
            networks.append(network)

    if not networks:
        raise ValueError("Could not determine the selected interface's local IPv4 subnet.")
    network = max(networks, key=lambda item: item.prefixlen)
    if not any(network.subnet_of(private) for private in PRIVATE_IPV4_NETWORKS):
        raise ValueError("Device discovery is limited to a private IPv4 subnet.")
    if network.prefixlen >= 31:
        raise ValueError("The selected IPv4 subnet has no usable host range to scan.")
    if network.num_addresses > MAX_DISCOVERY_ADDRESSES:
        raise ValueError(
            f"The selected subnet has {network.num_addresses} addresses; "
            f"discovery is limited to {MAX_DISCOVERY_ADDRESSES} per scan."
        )
    return network, interface_ip


def _ping_ipv4_address(address):
    if platform.system() == "Windows":
        command = ["ping", "-n", "1", "-w", str(DISCOVERY_TIMEOUT_MS), str(address)]
    else:
        command = ["ping", "-c", "1", "-W", "1", str(address)]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=DISCOVERY_TIMEOUT_MS / 1000 + 1,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


def _discover_ipv4_hosts_arp(interface, network, interface_ip):
    """Discover responding devices on the local Layer-2 subnet and learn MACs."""
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network.with_prefixlen)
    answered, _ = srp(
        request,
        iface=interface,
        timeout=ARP_DISCOVERY_TIMEOUT_SECONDS,
        retry=0,
        verbose=False,
    )
    hosts = {}
    for _, response in answered:
        arp_response = response.getlayer(ARP)
        if arp_response is None:
            continue
        try:
            address = ipaddress.IPv4Address(arp_response.psrc)
        except (ipaddress.AddressValueError, TypeError):
            continue
        if address == interface_ip or address not in network:
            continue
        mac_address = str(arp_response.hwsrc or "").strip().lower()
        hosts[str(address)] = {"ip": str(address), "mac": mac_address, "arp": True}
    return hosts


def discover_ipv4_hosts(interface):
    """Discover private-subnet hosts with ARP, then enrich results with ICMP ping."""
    network, interface_ip = get_interface_ipv4_network(interface)
    discovered = {}
    warning = ""

    # ARP is local-LAN discovery: it can identify devices that do not answer ping.
    try:
        discovered = _discover_ipv4_hosts_arp(interface, network, interface_ip)
    except Exception as exc:
        # Keep the original ping scan usable if raw ARP access is unavailable.
        warning = f"ARP discovery was unavailable; ping fallback ran instead ({exc})."

    targets = [address for address in network.hosts() if address != interface_ip]
    with ThreadPoolExecutor(max_workers=min(DISCOVERY_WORKERS, len(targets))) as executor:
        responses = executor.map(_ping_ipv4_address, targets)
        for address, responded in zip(targets, responses):
            if not responded:
                continue
            key = str(address)
            host = discovered.setdefault(key, {"ip": key, "mac": ""})
            host["ping"] = True

    hosts = []
    for address, host in sorted(
        discovered.items(), key=lambda item: ipaddress.IPv4Address(item[0])
    ):
        methods = []
        if host.get("arp"):
            methods.append("ARP scan")
        if host.get("ping"):
            methods.append("Ping scan")
        hosts.append({
            "ip": address,
            "mac": host.get("mac", ""),
            "methods": methods,
        })

    return {
        "network": network.with_prefixlen,
        "hosts": hosts,
        "warning": warning,
    }


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

    match = re.search(r"\btime\s*[=<]\s*(\d+(?:\.\d+)?)\s*ms", result.stdout, re.IGNORECASE)
    if match:
        return float(match.group(1))

    # Some localized ping outputs omit the English "time=" token.
    return (time.perf_counter() - started) * 1000


def _route_interface_name(route_interface):
    if route_interface is None:
        return None
    candidates = [
        getattr(route_interface, "name", None),
        getattr(route_interface, "network_name", None),
        str(route_interface),
    ]
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
