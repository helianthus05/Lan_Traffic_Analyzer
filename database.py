"""SQLite storage helpers for captured network packets."""
import sqlite3
from contextlib import contextmanager
from datetime import datetime

DB_PATH = "packets.db"


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


@contextmanager
def _connection():
    """Commit/rollback as a context manager and always close the connection."""
    conn = _connect()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db():
    with _connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                length INTEGER,
                source_port INTEGER,
                destination_port INTEGER,
                info TEXT
            )
        """)
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(packets)").fetchall()
        }
        if "source_port" not in columns:
            conn.execute("ALTER TABLE packets ADD COLUMN source_port INTEGER")
        if "destination_port" not in columns:
            conn.execute("ALTER TABLE packets ADD COLUMN destination_port INTEGER")


def save_packets(packet_dicts):
    """Insert a batch in one transaction instead of reconnecting per packet."""
    rows = []
    for packet in packet_dicts:
        rows.append((
            packet.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            packet.get("source_ip", "N/A"),
            packet.get("destination_ip", "N/A"),
            packet.get("protocol", "N/A"),
            int(packet.get("length", 0) or 0),
            packet.get("source_port"),
            packet.get("destination_port"),
            packet.get("info", ""),
        ))
    if not rows:
        return 0

    with _connection() as conn:
        conn.executemany("""
            INSERT INTO packets (
                timestamp, source_ip, destination_ip, protocol, length,
                source_port, destination_port, info
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
    return len(rows)


def save_packet(packet_dict):
    """Backward-compatible single-packet helper."""
    return save_packets([packet_dict])


def get_filtered_packets(
    protocol="", source_ip="", destination_ip="", port="", keyword="",
    min_size="", max_size="", start_time="", end_time=""
):
    query = """
        SELECT id, timestamp, source_ip, destination_ip, protocol, length, info
        FROM packets WHERE 1=1
    """
    params = []
    if protocol and protocol != "All":
        query += " AND protocol = ?"
        params.append(protocol)
    if source_ip:
        query += " AND source_ip LIKE ?"
        params.append(f"%{source_ip}%")
    if destination_ip:
        query += " AND destination_ip LIKE ?"
        params.append(f"%{destination_ip}%")
    if port:
        query += " AND (source_port = ? OR destination_port = ?)"
        params.extend([int(port), int(port)])
    if keyword:
        query += " AND info LIKE ?"
        params.append(f"%{keyword}%")
    if min_size != "":
        query += " AND length >= ?"
        params.append(int(min_size))
    if max_size != "":
        query += " AND length <= ?"
        params.append(int(max_size))
    if start_time:
        query += " AND timestamp >= ?"
        params.append(start_time)
    if end_time:
        query += " AND timestamp <= ?"
        params.append(end_time)
    query += " ORDER BY id DESC"

    with _connection() as conn:
        return conn.execute(query, params).fetchall()


def get_all_packets():
    return get_filtered_packets()


if __name__ == "__main__":
    init_db()
    print("Database initialized!")
