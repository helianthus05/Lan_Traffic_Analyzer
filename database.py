import sqlite3
from datetime import datetime


def init_db():
    conn = sqlite3.connect("packets.db")
    cursor = conn.cursor()

    cursor.execute("""
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

    # Add port columns if an older database already exists
    cursor.execute("PRAGMA table_info(packets)")
    columns = [row[1] for row in cursor.fetchall()]

    if "source_port" not in columns:
        cursor.execute(
            "ALTER TABLE packets ADD COLUMN source_port INTEGER"
        )

    if "destination_port" not in columns:
        cursor.execute(
            "ALTER TABLE packets ADD COLUMN destination_port INTEGER"
        )

    conn.commit()
    conn.close()


def save_packet(packet_dict):
    conn = sqlite3.connect("packets.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO packets (
            timestamp, source_ip, destination_ip,
            protocol, length, source_port,
            destination_port, info
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        packet_dict.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        packet_dict.get("source_ip", "N/A"),
        packet_dict.get("destination_ip", "N/A"),
        packet_dict.get("protocol", "N/A"),
        packet_dict.get("length", 0),
        packet_dict.get("source_port"),
        packet_dict.get("destination_port"),
        packet_dict.get("info", "")
    ))

    conn.commit()
    conn.close()


def get_filtered_packets(
    protocol="",
    source_ip="",
    destination_ip="",
    port="",
    keyword="",
    min_size="",
    max_size="",
    start_time="",
    end_time=""
):

    conn = sqlite3.connect("packets.db")
    cursor = conn.cursor()

    query = """
        SELECT id, timestamp, source_ip, destination_ip,
               protocol, length, info
        FROM packets
        WHERE 1=1
    """

    params = []

    # Filter by protocol
    if protocol and protocol != "All":
        query += " AND protocol = ?"
        params.append(protocol)

    # Filter by source IP
    if source_ip:
        query += " AND source_ip LIKE ?"
        params.append(f"%{source_ip}%")

    # Filter by destination IP
    if destination_ip:
        query += " AND destination_ip LIKE ?"
        params.append(f"%{destination_ip}%")

    # Filter by source OR destination port
    if port:
        query += """
            AND (source_port = ? OR destination_port = ?)
        """
        params.extend([port, port])

    # Search packet information
    if keyword:
        query += " AND info LIKE ?"
        params.append(f"%{keyword}%")

    # Minimum packet size
    if min_size:
        query += " AND length >= ?"
        params.append(min_size)

    # Maximum packet size
    if max_size:
        query += " AND length <= ?"
        params.append(max_size)

    # Start time
    if start_time:
        query += " AND timestamp >= ?"
        params.append(start_time)

    # End time
    if end_time:
        query += " AND timestamp <= ?"
        params.append(end_time)

    query += " ORDER BY id DESC"

    cursor.execute(query, params)
    rows = cursor.fetchall()

    conn.close()

    return rows


def get_all_packets():
    return get_filtered_packets()


if __name__ == "__main__":
    init_db()
    print("Database initialized!")