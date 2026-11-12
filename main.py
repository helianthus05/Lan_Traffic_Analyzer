"""Main application entry point for the LAN Traffic Analyzer."""
from datetime import datetime
from queue import Queue, Full, Empty
from threading import Thread
import tkinter as tk

import capture
import database
from gui import PacketApp


QUEUE_MAX_SIZE = 20000
BATCH_SIZE = 250
POLL_INTERVAL_MS = 50


class TrafficAnalyzer:
    def __init__(self):
        self.sniffer = None
        self.packet_queue = Queue(maxsize=QUEUE_MAX_SIZE)
        self.packet_number = 0
        self.dropped_packets = 0
        self.closing = False
        self.stop_in_progress = False
        self.final_summary_pending = False

        self.app = PacketApp(
            on_start=self.start_capture,
            on_stop=self.stop_capture,
            on_refresh=self.refresh_interfaces,
        )
        database.init_db()
        self.refresh_interfaces()
        self.app.protocol("WM_DELETE_WINDOW", self.close)
        self.app.after(POLL_INTERVAL_MS, self._process_packet_queue)

    def refresh_interfaces(self):
        try:
            interfaces = capture.get_interface_details()
            self.app.set_interfaces(interfaces)
            if interfaces:
                recommended = next(
                    (item for item in interfaces if item["is_default_route"]), None
                )
                if recommended:
                    self.app.set_status(
                        f"Recommended interface: {recommended['name']} "
                        f"({recommended['ip'] or 'no IPv4 address'})"
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
        if self.sniffer is not None or self.stop_in_progress:
            self.app.set_status("A capture is already running or stopping")
            return
        if not interface:
            self.app.set_status("Please select a network interface")
            return

        try:
            self.sniffer = capture.start_capture(interface, self.handle_packet)
            self.app.set_capture_state(True)
            self.app.set_status(f"Capturing on {interface}")
        except Exception as error:
            self.sniffer = None
            self.app.set_capture_state(False)
            self.app.set_status(f"Capture error: {error}")
            print("Capture start error:", error)

    def handle_packet(self, packet_data):
        """Scapy-thread callback: enqueue only; never touch Tkinter or SQLite here."""
        try:
            self.packet_queue.put_nowait(packet_data)
        except Full:
            # Drop the newest packet rather than blocking Scapy's capture thread.
            self.dropped_packets += 1

    def _process_packet_queue(self):
        if self.closing:
            return

        batch = []
        for _ in range(BATCH_SIZE):
            try:
                batch.append(self.packet_queue.get_nowait())
            except Empty:
                break

        if batch:
            try:
                database.save_packets(batch)
            except Exception as error:
                print("Database batch save error:", error)

            display_batch = []
            for packet_data in batch:
                self.packet_number += 1
                timestamp = packet_data.get("timestamp") or datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                source = packet_data.get("source_ip", "Unknown")
                destination = packet_data.get("destination_ip", "Unknown")
                display_batch.append({
                    "no": self.packet_number,
                    "time": timestamp.split(" ")[-1],
                    "src": source,
                    "dst": destination,
                    "protocol": packet_data.get("protocol", "Other"),
                    "length": packet_data.get("length", 0),
                    "info": packet_data.get("info", ""),
                })
            self.app.add_packets(display_batch)

        if self.dropped_packets and self.sniffer is not None:
            self.app.set_status(
                f"Capturing | queue full: {self.dropped_packets:,} packet(s) dropped"
            )

        # A final summary must wait until every packet already queued is processed.
        if self.final_summary_pending and self.packet_queue.empty():
            self.final_summary_pending = False
            self.app.show_summary()

        self.app.after(POLL_INTERVAL_MS, self._process_packet_queue)

    def stop_capture(self):
        """Stop Scapy in a worker so the Tkinter event loop remains responsive."""
        if self.sniffer is None:
            self.app.set_capture_state(False)
            self.app.set_status("Stopped")
            self.app.show_summary()
            return
        if self.stop_in_progress:
            return

        self.stop_in_progress = True
        sniffer_to_stop = self.sniffer
        self.app.set_status("Stopping capture...")
        self.app.stop_button.configure(state="disabled")

        def worker():
            error = None
            try:
                capture.stop_capture(sniffer_to_stop)
            except Exception as exc:
                error = exc
            try:
                self.app.after(0, self._finish_stop, error)
            except tk.TclError:
                pass

        Thread(target=worker, name="CaptureStop", daemon=True).start()

    def _finish_stop(self, error=None):
        self.sniffer = None
        self.stop_in_progress = False
        self.app.set_capture_state(False)
        if error:
            self.app.set_status(f"Stopped with warning: {error}")
            print("Capture stop error:", error)
        else:
            self.app.set_status("Stopped")
        # Let the regular batch processor drain the remaining queue before
        # drawing the final summary.
        self.final_summary_pending = True
        self._process_packet_queue()

        if self.closing:
            self.app.destroy()

    def close(self):
        if self.closing:
            return
        self.closing = True
        if self.sniffer is None:
            self.app.destroy()
            return

        sniffer_to_stop = self.sniffer

        def worker():
            try:
                capture.stop_capture(sniffer_to_stop)
            except Exception as error:
                print("Capture stop error during shutdown:", error)
            try:
                self.app.after(0, self.app.destroy)
            except tk.TclError:
                pass

        Thread(target=worker, name="CaptureShutdown", daemon=True).start()

    def run(self):
        self.app.mainloop()


if __name__ == "__main__":
    TrafficAnalyzer().run()
