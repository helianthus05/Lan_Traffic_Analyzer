"""Network interface discovery and asynchronous packet capture helpers."""
from scapy.all import AsyncSniffer, conf, get_if_addr, get_if_hwaddr, get_if_list
from packet_parser import parse_packet


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
