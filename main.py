"""
Main application entry point for LAN Traffic Analyzer.

Connects:
- capture.py: obtains interfaces and captures packets
- packet_parser.py: converts captured packets into dictionaries
- database.py: stores packet records in SQLite
- gui.py: displays packets and lets the user select a network interface
"""

from datetime import datetime
import tkinter as tk

import capture
import database
from gui import PacketApp


class TrafficAnalyzer:
    def __init__(self):
        self.sniffer = None
        self.packet_number = 0

        self.app = PacketApp(
            on_start=self.start_capture,
            on_stop=self.stop_capture,
            on_refresh=self.refresh_interfaces
        )

        # Prepare the SQLite database before packet capture begins.
        database.init_db()

        # Load the available interfaces into the GUI selector.
        self.refresh_interfaces()

        # Stop the sniffer cleanly when the window is closed.
        self.app.protocol("WM_DELETE_WINDOW", self.close)

    def refresh_interfaces(self):
        """Get the interfaces detected by Scapy and update the selector."""
        try:
            interfaces = capture.get_interface_details()
            self.app.set_interfaces(interfaces)

            if interfaces:
                recommended = next(
                    (item for item in interfaces if item["is_default_route"]),
                    None,
                )
                if recommended:
                    self.app.set_status(
                        "Recommended interface: "
                        f"{recommended['name']} ({recommended['ip'] or 'no IPv4 address'})"
                    )
                else:
                    self.app.set_status(
                        f"{len(interfaces)} interface(s) found; no default-route adapter detected"
                    )
            else:
                self.app.set_status("No network interfaces found")

        except Exception as error:
            self.app.set_interfaces([])
            self.app.set_status(f"Could not load interfaces: {error}")
            print("Interface discovery error:", error)

    def start_capture(self, interface):
        """Start capturing packets on the interface selected by the user."""
        if self.sniffer is not None:
            self.app.set_status("A capture is already running")
            return

        if not interface:
            self.app.set_status("Please select a network interface")
            return

        try:
            self.sniffer = capture.start_capture(
                interface,
                self.handle_packet
            )
            self.app.set_capture_state(True)
            self.app.set_status(f"Capturing on {interface}")

        except Exception as error:
            self.sniffer = None
            self.app.set_capture_state(False)
            self.app.set_status(f"Capture error: {error}")
            print("Capture start error:", error)

    def handle_packet(self, packet_data):
        """
        Receive parsed packet data from capture.py.

        This callback runs on Scapy's capture thread. Save the packet
        there, then schedule the Tkinter update on the GUI thread.
        """
        self.packet_number += 1

        timestamp = packet_data.get("timestamp") or datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        source = packet_data.get("source", "Unknown")
        destination = packet_data.get("destination", "Unknown")
        protocol = packet_data.get("protocol", "Other")
        length = packet_data.get("length", 0)
        info = packet_data.get("info", "")

        # database.py expects source_ip/destination_ip, while
        # packet_parser.py supplies source/destination.
        database_record = {
            "timestamp": timestamp,
            "source_ip": source,
            "destination_ip": destination,
            "protocol": protocol,
            "length": length,
            "info": info
        }

        try:
            database.save_packet(database_record)
        except Exception as error:
            print("Database save error:", error)

        # gui.py expects no/time/src/dst rather than the parser's keys.
        display_record = {
            "no": self.packet_number,
            "time": timestamp.split(" ")[-1],
            "src": source,
            "dst": destination,
            "protocol": protocol,
            "length": length,
            "info": info
        }

        try:
            self.app.after(0, self.app.add_packet, display_record)
        except tk.TclError:
            # The window may have been closed while a packet arrived.
            pass

    def stop_capture(self):
        """Stop the current packet capture, if one is running."""
        if self.sniffer is None:
            self.app.set_capture_state(False)
            return

        try:
            capture.stop_capture(self.sniffer)
        except Exception as error:
            print("Capture stop error:", error)
        finally:
            self.sniffer = None
            self.app.set_capture_state(False)
            self.app.set_status("Stopped")

    def close(self):
        """Stop packet capture before closing the application."""
        self.stop_capture()
        self.app.destroy()

    def run(self):
        self.app.mainloop()


if __name__ == "__main__":
    TrafficAnalyzer().run()
