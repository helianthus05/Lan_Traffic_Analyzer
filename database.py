import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect("packets.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            length INTEGER,
            info TEXT
        )
    ''')
    conn.commit()
    conn.close()


def save_packet(packet_dict):
    conn = sqlite3.connect("packets.db")
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO packets (timestamp, source_ip, destination_ip, protocol, length, info)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        packet_dict.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        packet_dict.get("source_ip", "N/A"),
        packet_dict.get("destination_ip", "N/A"),
        packet_dict.get("protocol", "N/A"),
        packet_dict.get("length", 0),
        packet_dict.get("info", "")
    ))
    conn.commit()
    conn.close()


def get_all_packets():
    conn = sqlite3.connect("packets.db")
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, source_ip, destination_ip, protocol, length, info FROM packets ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


if __name__ == "__main__":
    init_db()

    sample = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": "192.168.1.6",
        "destination_ip": "142.250.190.46",
        "protocol": "TCP",
        "length": 64,
        "info": "Test Packet"
    }

    save_packet(sample)
    print("Saved!")

    print("All packets:", get_all_packets())
