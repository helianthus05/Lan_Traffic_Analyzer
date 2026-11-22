import os
from datetime import datetime
from pathlib import Path
from threading import RLock

import msgpack

SESSION_DIRECTORY = Path(__file__).resolve().parent / "session_packets"
FILE_NAME = str(Path(__file__).resolve().parent / "packets.msgpack")
next_id = 1
_db_lock = RLock()


def start_session():
    """Create a new per-run packet log and make it the active database file."""
    global FILE_NAME, next_id

    with _db_lock:
        SESSION_DIRECTORY.mkdir(parents=True, exist_ok=True)
        session_name = datetime.now().strftime("packets_%Y%m%d_%H%M%S_%f.msgpack")
        FILE_NAME = str(SESSION_DIRECTORY / session_name)
        Path(FILE_NAME).touch()
        next_id = 1
        return FILE_NAME


def _iter_records(source_path):
    if not os.path.exists(source_path):
        return
    with open(source_path, "rb") as file:
        unpacker = msgpack.Unpacker(
            file,
            raw=False,
            strict_map_key=False
        )
        for record in unpacker:
            if isinstance(record, dict):
                yield record


def read_records(file_path=None):
    """Read all saved packet records."""
    with _db_lock:
        source_path = FILE_NAME if file_path is None else file_path
        if os.path.abspath(source_path) == os.path.abspath(FILE_NAME):
            return list(_iter_records(source_path))
    return list(_iter_records(source_path))


def read_records_page(file_path=None, offset=0, limit=200):
    """Stream saved packet records and return only the requested slice plus total count."""
    offset = max(0, int(offset))
    limit = max(1, int(limit))
    end = offset + limit

    def _collect(source_path):
        page = []
        total = 0
        for record in _iter_records(source_path):
            if offset <= total < end:
                page.append(record)
            total += 1
        return page, total

    with _db_lock:
        source_path = FILE_NAME if file_path is None else file_path
        if os.path.abspath(source_path) == os.path.abspath(FILE_NAME):
            return _collect(source_path)
    return _collect(source_path)


def get_session_summary(file_path=None):
    """Stream saved packet records to compute packet count and total bytes."""
    def _summarize(source_path):
        total = 0
        total_bytes = 0
        for record in _iter_records(source_path):
            total += 1
            try:
                total_bytes += max(0, int(record.get("length", 0) or 0))
            except (TypeError, ValueError):
                pass
        return total, total_bytes

    with _db_lock:
        source_path = FILE_NAME if file_path is None else file_path
        if os.path.abspath(source_path) == os.path.abspath(FILE_NAME):
            return _summarize(source_path)
    return _summarize(source_path)


def init_db():
    """Initialize packet record IDs."""
    global next_id
    with _db_lock:
        max_id = 0
        for record in _iter_records(FILE_NAME):
            try:
                max_id = max(max_id, int(record.get("id", 0) or 0))
            except (TypeError, ValueError):
                pass
        next_id = max_id + 1


def clear_session():
    """Start a fresh packet file while preserving the previous capture file."""
    return start_session()


def save_packets(packets):
    """Save a batch of packet records using MessagePack."""
    global next_id

    if not packets:
        return

    with _db_lock:
        records_to_write = []
        for packet in packets:
            explicit_id = packet.get("id")
            if explicit_id is not None:
                record_id = int(explicit_id)
                if record_id >= next_id:
                    next_id = record_id + 1
            else:
                record_id = next_id
                next_id += 1
            record = {
                "id": record_id,
                "timestamp": packet.get("timestamp", ""),
                "source_ip": packet.get("source_ip", ""),
                "destination_ip": packet.get("destination_ip", ""),
                "protocol": packet.get("protocol", ""),
                "length": packet.get("length", 0),
                "info": packet.get("info", ""),
                "source_port": packet.get("source_port"),
                "destination_port": packet.get("destination_port"),
                "source_mac": packet.get("source_mac", ""),
                "destination_mac": packet.get("destination_mac", ""),
            }
            if packet.get("device_name"):
                record["device_name"] = str(packet["device_name"])
            if packet.get("id_source"):
                record["id_source"] = str(packet["id_source"])
            if packet.get("domain"):
                record["domain"] = str(packet["domain"])
            if packet.get("service"):
                record["service"] = str(packet["service"])
            records_to_write.append(record)

        with open(FILE_NAME, "ab") as file:
            for record in records_to_write:
                msgpack.pack(
                    record,
                    file,
                    use_bin_type=True
                )


def get_filtered_packets(
    protocol="",
    source_ip="",
    destination_ip="",
    port="",
    keyword="",
    min_size="",
    max_size="",
    start_time="",
    end_time="",
    search=""
):
    """Filter saved packet records."""
    selected_port = str(int(port)) if port else ""
    min_len = int(min_size) if min_size else None
    max_len = int(max_size) if max_size else None
    search_lower = search.strip().lower()
    protocol_lower = protocol.lower() if protocol and protocol != "All" else ""
    source_lower = source_ip.lower()
    dest_lower = destination_ip.lower()
    keyword_lower = keyword.lower()

    records = read_records()
    results = []

    for record in reversed(records):
        if search_lower:
            searchable_values = (
                record.get("source_ip", ""),
                record.get("destination_ip", ""),
                record.get("protocol", ""),
                record.get("info", ""),
                record.get("source_port", ""),
                record.get("destination_port", ""),
            )
            if not any(search_lower in str(value).lower() for value in searchable_values):
                continue

        if protocol_lower:
            if str(record.get("protocol", "")).lower() != protocol_lower:
                continue

        if source_lower:
            if source_lower not in str(record.get("source_ip", "")).lower():
                continue

        if dest_lower:
            if dest_lower not in str(record.get("destination_ip", "")).lower():
                continue

        if selected_port:
            packet_ports = {
                str(record.get("source_port") or ""),
                str(record.get("destination_port") or ""),
            }
            if selected_port not in packet_ports:
                continue

        if keyword_lower:
            if keyword_lower not in str(record.get("info", "")).lower():
                continue

        if min_len is not None or max_len is not None:
            try:
                pkt_len = int(record.get("length", 0) or 0)
            except (TypeError, ValueError):
                continue
            if min_len is not None and pkt_len < min_len:
                continue
            if max_len is not None and pkt_len > max_len:
                continue

        if start_time:
            if record.get("timestamp", "") < start_time:
                continue

        if end_time:
            if record.get("timestamp", "") > end_time:
                continue

        results.append(record)

    return [
        (
            item.get("id"),
            item.get("timestamp"),
            item.get("source_ip"),
            item.get("destination_ip"),
            item.get("protocol"),
            item.get("length"),
            item.get("source_port"),
            item.get("destination_port"),
            item.get("info")
        )
        for item in results
    ]


def get_all_packets():
    """Retrieve all saved packet records."""
    return get_filtered_packets()


def get_export_packets():
    return get_all_packets()