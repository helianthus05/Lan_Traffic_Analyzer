"""Main application entry point for the LAN Traffic Analyzer."""
from collections import deque
from datetime import datetime
import os
from pathlib import Path
import statistics
from tkinter import filedialog, messagebox, simpledialog
from queue import Queue, Full, Empty
from threading import Thread
import tkinter as tk

import capture
import database
import export
from auth import FirebaseAuthClient
from auth_gui import AuthWindow
from auth_session import AuthSessionStore
from gui import PacketApp


QUEUE_MAX_SIZE = 20000
BATCH_SIZE = 250
POLL_INTERVAL_MS = 50
SERVICE_ACCOUNT_FILENAME = (
    "packet-sniffer-auth-firebase-adminsdk-fbsvc-fce9c28df6.json"
)


class TrafficAnalyzer:
    def __init__(self, session_store=None):
        self.sniffer = None
        self.packet_queue = Queue(maxsize=QUEUE_MAX_SIZE)
        self.packet_number = 0
        self.dropped_packets = 0
        self.closing = False
        self.stop_in_progress = False
        self.final_summary_pending = False
        self.session_store = session_store
        self.logout_requested = False

        self.app = PacketApp(
            on_start=self.start_capture,
            on_stop=self.stop_capture,
            on_refresh=self.refresh_interfaces,
            on_export=self.export_packets,
            on_packets=self.open_packet_file,
            on_filter=self.filter_packets,
            on_clear=self.clear_packets,
            on_logout=self.logout,
        )
        self.session_file = database.start_session()
        database.init_db()
        self.refresh_interfaces()
        self.app.protocol("WM_DELETE_WINDOW", self.close)
        self.app.after(POLL_INTERVAL_MS, self._process_packet_queue)
        self._gateway_samples = deque(maxlen=5)
        self._health_gateway = None
        self.app.after(100, self._check_gateway_health)

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
            self.dropped_packets = 0
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
                    "timestamp": timestamp,
                    "src": source,
                    "dst": destination,
                    "source_ip": source,
                    "destination_ip": destination,
                    "protocol": packet_data.get("protocol", "Other"),
                    "length": packet_data.get("length", 0),
                    "source_port": packet_data.get("source_port"),
                    "destination_port": packet_data.get("destination_port"),
                    "info": packet_data.get("info", ""),
                    "src_mac": packet_data.get("source_mac", ""),
                    "dst_mac": packet_data.get("destination_mac", ""),
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

    def filter_packets(self, filters):
        """Load matching packet rows from the active session file."""
        try:
            packets = database.get_filtered_packets(**filters)
            self.app.set_filtered_packets(packets, filters)
        except Exception as error:
            messagebox.showerror(
                "Filter failed",
                f"Could not filter packet data:\n{error}",
                parent=self.app,
            )

    def clear_packets(self):
        """Rotate to a new session file and reset the live capture display."""
        try:
            self.session_file = database.clear_session()
        except Exception as error:
            messagebox.showerror(
                "Clear failed",
                f"Could not start a fresh packet file:\n{error}",
                parent=self.app,
            )
            return

        while True:
            try:
                self.packet_queue.get_nowait()
            except Empty:
                break

        self.packet_number = 0
        self.dropped_packets = 0
        self.final_summary_pending = False
        self.app.clear_packets()
        self.app.set_status("Cleared current capture; previous session file was preserved.")

    def export_packets(
        self, file_format, mode="filtered", filters=None, selected_packets=None
    ):
        """Export filtered or selected packet rows as password-protected CSV/PDF."""
        extensions = {
            "csv": (".csv", "CSV files", "*.csv"),
            "pdf": (".pdf", "PDF files", "*.pdf"),
        }
        if file_format not in extensions:
            return

        extension, file_label, pattern = extensions[file_format]
        destination = filedialog.asksaveasfilename(
            parent=self.app,
            title=f"Export packets as {file_format.upper()}",
            defaultextension=extension,
            filetypes=[(file_label, pattern), ("All files", "*.*")],
            initialfile=f"network_traffic_{datetime.now():%Y%m%d_%H%M%S}{extension}",
        )
        if not destination:
            return

        password = simpledialog.askstring(
            "Export Password",
            f"Enter a password to protect the {file_format.upper()} file:",
            parent=self.app,
            show="*",
        )
        if password is None:
            return
        if len(password) < 8:
            messagebox.showwarning(
                "Password Too Short",
                "Please use a password with at least 8 characters.",
                parent=self.app,
            )
            return

        confirm = simpledialog.askstring(
            "Confirm Password",
            "Re-enter the password:",
            parent=self.app,
            show="*",
        )
        if confirm is None:
            return
        if password != confirm:
            messagebox.showerror(
                "Password Mismatch",
                "The passwords do not match. The file was not created.",
                parent=self.app,
            )
            return

        try:
            if mode == "selected":
                packets = selected_packets or []
            elif mode == "filtered":
                packets = database.get_filtered_packets(**(filters or {}))
            else:
                raise ValueError(f"Unsupported packet export mode: {mode}")

            if not packets:
                messagebox.showinfo(
                    "Nothing to export", "No packets match the selected export scope.",
                    parent=self.app
                )
                return

            if file_format == "csv":
                export.export_csv(destination, password, packets)
            else:
                export.export_pdf(destination, password, packets)

            self.app.set_status(
                f"Exported {len(packets):,} packet(s) to {Path(destination).name}"
            )
            messagebox.showinfo(
                "Export complete",
                f"Successfully exported {len(packets):,} packet(s).\n\n{destination}"
                + ("\n\nThe CSV contents are encrypted. Decrypt the file before opening it in Excel."
                   if file_format == "csv" else ""),
                parent=self.app,
            )
        except Exception as error:
            messagebox.showerror(
                "Export failed", f"Could not export packet data:\n{error}",
                parent=self.app,
            )

    def _check_gateway_health(self):
        """Check the default gateway asynchronously without blocking the GUI."""
        if self.closing:
            return

        try:
            gateway = capture.get_default_gateway()
        except Exception as error:
            self.app.set_network_health(
                "unavailable",
                f"Could not determine the default gateway: {error}",
            )
            self.app.after(5000, self._check_gateway_health)
            return

        if gateway != self._health_gateway:
            self._health_gateway = gateway
            self._gateway_samples.clear()

        if not gateway:
            self.app.set_network_health(
                "unavailable",
                "No IPv4 default gateway is available to test.",
            )
            self.app.after(5000, self._check_gateway_health)
            return

        self.app.set_network_health(
            "checking",
            f"Testing default gateway {gateway} (one response check every 5 seconds).",
        )

        def worker():
            try:
                latency_ms = capture.ping_gateway(gateway)
                error = None
            except OSError as exc:
                latency_ms = None
                error = exc
            try:
                self.app.after(
                    0, self._finish_gateway_health_check,
                    gateway, latency_ms, error,
                )
            except tk.TclError:
                pass

        Thread(target=worker, name="GatewayHealthCheck", daemon=True).start()

    def _finish_gateway_health_check(self, gateway, latency_ms, error):
        if self.closing:
            return
        if gateway != self._health_gateway:
            self.app.after(0, self._check_gateway_health)
            return

        if error:
            self.app.set_network_health(
                "unavailable",
                f"Could not run the gateway response check: {error}",
            )
        else:
            self._gateway_samples.append(latency_ms)
            self._update_gateway_health(gateway)
        self.app.after(5000, self._check_gateway_health)

    def _update_gateway_health(self, gateway):
        samples = list(self._gateway_samples)
        successful = [sample for sample in samples if sample is not None]
        lost = len(samples) - len(successful)

        if not successful:
            if len(samples) < 3:
                self.app.set_network_health(
                    "checking",
                    f"No response from {gateway} yet; collecting more checks.",
                )
            else:
                self.app.set_network_health(
                    "unreachable",
                    f"No ping replies from {gateway} in {len(samples)} consecutive "
                    "checks. It may be unreachable or filter ping requests.",
                )
            return

        median_ms = statistics.median(successful)
        loss_percent = lost / len(samples) * 100
        details = (
            f"Gateway {gateway}: median response {median_ms:.1f} ms; "
            f"{loss_percent:.0f}% loss over {len(samples)} check(s)."
        )
        if loss_percent >= 20 or median_ms >= 150:
            self.app.set_network_health(
                "congested",
                f"Possible congestion or path degradation. {details}",
            )
        else:
            self.app.set_network_health(
                "healthy",
                f"No obvious congestion to the default gateway. {details}",
            )

    def open_packet_file(self):
        """Open a saved MessagePack capture in the in-app packet viewer."""
        try:
            database.SESSION_DIRECTORY.mkdir(parents=True, exist_ok=True)
            file_path = filedialog.askopenfilename(
                parent=self.app,
                title="Open packet capture",
                initialdir=str(database.SESSION_DIRECTORY),
                filetypes=[
                    ("MessagePack packet files", "*.msgpack"),
                ],
            )
            if not file_path:
                return
            records = database.read_records(file_path)
            self.app.show_packet_file(file_path, records)
        except Exception as error:
            messagebox.showerror(
                "Could not open packet file",
                f"Could not read the selected MessagePack file:\n{error}",
                parent=self.app,
            )

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

    def logout(self):
        confirmed = messagebox.askyesno(
            "Log out",
            "Are you sure you want to log out? Any active capture will stop, "
            "and you will need to sign in again.",
            parent=self.app,
        )
        if not confirmed:
            return

        try:
            if self.session_store is not None:
                self.session_store.clear()
        except OSError as error:
            messagebox.showerror(
                "Could not log out",
                f"The saved login could not be cleared:\n{error}",
                parent=self.app,
            )
            return

        self.logout_requested = True
        self.close()

    def run(self):
        self.app.mainloop()
        return self.logout_requested


if __name__ == "__main__":
    app_directory = Path(__file__).resolve().parent
    default_service_account = app_directory.parent / SERVICE_ACCOUNT_FILENAME
    web_api_key = os.environ.get("FIREBASE_WEB_API_KEY", "").strip()
    service_account_path = os.environ.get(
        "FIREBASE_SERVICE_ACCOUNT_PATH",
        str(default_service_account),
    )

    if not web_api_key:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Firebase configuration required",
            "Set FIREBASE_WEB_API_KEY in your Windows environment before starting the app.",
            parent=root,
        )
        root.destroy()
        raise SystemExit(1)

    try:
        auth_client = FirebaseAuthClient(web_api_key, service_account_path)
        session_store = AuthSessionStore()
    except (OSError, ValueError, RuntimeError) as error:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Firebase configuration error",
            str(error),
            parent=root,
        )
        root.destroy()
        raise SystemExit(1) from error

    authenticated_user = None
    notice = ""
    try:
        saved_refresh_token = session_store.load()
    except (OSError, RuntimeError) as error:
        notice = f"Saved login could not be read. Please sign in again. ({error})"
        session_store.clear()
        saved_refresh_token = None

    if saved_refresh_token:
        restored = auth_client.restore_session(saved_refresh_token)
        if restored.get("ok"):
            authenticated_user = restored
            try:
                session_store.save(restored.get("refresh_token", ""))
            except (OSError, RuntimeError, ValueError) as error:
                notice = f"Could not refresh the protected saved login: {error}"
                authenticated_user = None
        else:
            notice = restored.get("error", "Saved login expired; please sign in again.")

    if authenticated_user is None:
        auth_window = AuthWindow(auth_client, session_store, notice)
        auth_window.mainloop()
        authenticated_user = auth_window.result

    while authenticated_user:
        analyzer = TrafficAnalyzer(session_store)
        if not analyzer.run():
            break
        auth_window = AuthWindow(
            auth_client,
            session_store,
            "You have been logged out. Sign in again to continue.",
        )
        auth_window.mainloop()
        authenticated_user = auth_window.result
