import os
from datetime import datetime
from pathlib import Path

import msgpack

SESSION_DIRECTORY = Path(__file__).resolve().parent / "session_packets"
FILE_NAME = str(Path(__file__).resolve().parent / "packets.msgpack")
next_id = 1


def start_session():
    """Create a new per-run packet log and make it the active database file."""
    global FILE_NAME, next_id

    SESSION_DIRECTORY.mkdir(parents=True, exist_ok=True)
    session_name = datetime.now().strftime("packets_%Y%m%d_%H%M%S_%f.msgpack")
    FILE_NAME = str(SESSION_DIRECTORY / session_name)
    Path(FILE_NAME).touch()
    next_id = 1
    return FILE_NAME


def read_records(file_path=None):
    """Read all saved packet records."""
    source_path = FILE_NAME if file_path is None else file_path
    if not os.path.exists(source_path):
        return []

    records = []
    with open(source_path, "rb") as file:
        unpacker = msgpack.Unpacker(
            file,
            raw=False,
            strict_map_key=False
        )
        for record in unpacker:
            if isinstance(record, dict):
                records.append(record)
    return records


def init_db():
    """Initialize packet record IDs."""
    global next_id
    records = read_records()
    if records:
        next_id = max(
            int(record.get("id", 0))
            for record in records
        ) + 1
    else:
        next_id = 1


def clear_session():
    """Start a fresh packet file while preserving the previous capture file."""
    return start_session()


def save_packets(packets):
    """Save a batch of packet records using MessagePack."""
    global next_id

    if not packets:
        return

    records_to_write = []
    for packet in packets:
        record = {
            "id": next_id,
            "timestamp": packet.get("timestamp", ""),
            "source_ip": packet.get("source_ip", ""),
            "destination_ip": packet.get("destination_ip", ""),
            "protocol": packet.get("protocol", ""),
            "length": packet.get("length", 0),
            "info": packet.get("info", ""),
            "source_port": packet.get("source_port"),
            "destination_port": packet.get("destination_port")
        }
        records_to_write.append(record)
        next_id += 1

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
    records = read_records()
    results = []
    search = search.strip().lower()

    for record in records:
        if search:
            searchable_values = (
                record.get("source_ip", ""),
                record.get("destination_ip", ""),
                record.get("protocol", ""),
                record.get("info", ""),
                record.get("source_port", ""),
                record.get("destination_port", ""),
            )
            if not any(search in str(value).lower() for value in searchable_values):
                continue

        if protocol and protocol != "All":
            if str(record.get("protocol", "")).lower() != protocol.lower():
                continue

        if source_ip:
            if source_ip.lower() not in str(
                record.get("source_ip", "")
            ).lower():
                continue

        if destination_ip:
            if destination_ip.lower() not in str(
                record.get("destination_ip", "")
            ).lower():
                continue

        if port:
            try:
                selected_port = int(port)
            except ValueError:
                continue

            packet_ports = {
                str(record.get("source_port") or ""),
                str(record.get("destination_port") or ""),
            }
            if str(selected_port) not in packet_ports:
                continue

        if keyword:
            if keyword.lower() not in str(
                record.get("info", "")
            ).lower():
                continue

        if min_size:
            try:
                if int(record.get("length", 0)) < int(min_size):
                    continue
            except ValueError:
                continue

        if max_size:
            try:
                if int(record.get("length", 0)) > int(max_size):
                    continue
            except ValueError:
                continue

        if start_time:
            if record.get("timestamp", "") < start_time:
                continue

        if end_time:
            if record.get("timestamp", "") > end_time:
                continue

        results.append(record)

    results.sort(
        key=lambda item: item.get("id", 0),
        reverse=True
    )

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