import tkinter as tk
from tkinter import ttk

# SAMPLE PACKETS ONLY :)
SAMPLE_PACKETS = [
    {"no": 1, "time": "12:00:01", "src": "192.168.1.5",  "dst": "8.8.8.8",      "protocol": "UDP", "length": 74,  "info": "DNS query"},
    {"no": 2, "time": "12:00:02", "src": "8.8.8.8",      "dst": "192.168.1.5",  "protocol": "UDP", "length": 90,  "info": "DNS response"},
    {"no": 3, "time": "12:00:03", "src": "192.168.1.5",  "dst": "142.250.1.1",  "protocol": "TCP", "length": 66,  "info": "SYN"},
]

# COLUMN NAMES FOR THE PACKET TABLE
COLUMNS = ("no", "time", "src", "dst", "protocol", "length", "info")


class PacketApp(tk.Tk):
    """Main window for the LAN Traffic Analyzer."""

    def __init__(self, on_start=None, on_stop=None, on_refresh=None):
        super().__init__()
        self.title("NETWORK TRAFFIC ANALYZER")
        self.geometry("1000x550")
        self.on_start = on_start
        self.on_stop = on_stop
        self.on_refresh = on_refresh

        self._build_controls()
        self._build_table()
        self._build_status()

    def _build_controls(self):
        """Create the interface selector and Start, Stop, and Clear buttons."""
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8, pady=6)

        ttk.Label(bar, text="Network Interface:").pack(side="left", padx=(0, 6))

        self.interface_var = tk.StringVar()
        # Display labels may include helpful metadata; capture always receives
        # the exact Scapy interface name stored in this mapping.
        self._interface_name_by_label = {}
        self.interface_combo = ttk.Combobox(
            bar,
            textvariable=self.interface_var,
            state="readonly",
            width=55
        )
        self.interface_combo.pack(side="left", padx=(0, 8))

        ttk.Button(
            bar,
            text="Refresh",
            command=self._refresh_interfaces
        ).pack(side="left", padx=(0, 8))

        self.start_button = ttk.Button(bar, text="Start", command=self._start)
        self.start_button.pack(side="left")

        self.stop_button = ttk.Button(
            bar,
            text="Stop",
            command=self._stop,
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=4)

        ttk.Button(
            bar,
            text="Clear",
            command=self.clear_packets
        ).pack(side="left")

    def _refresh_interfaces(self):
        """Ask the main application to refresh the available interface list."""
        if self.on_refresh:
            self.on_refresh()

    def set_interfaces(self, interfaces):
        """Populate the selector and automatically prefer the default route."""
        current_selection = self.interface_var.get()
        entries = list(interfaces or [])
        self._interface_name_by_label = {}
        labels = []
        recommended_label = None

        for entry in entries:
            # Accept plain strings too, so the GUI remains usable standalone.
            if isinstance(entry, dict):
                name = entry.get("name", "")
                ip_address = entry.get("ip", "")
                is_default = entry.get("is_default_route", False)
                is_loopback = entry.get("is_loopback", False)
            else:
                name = str(entry)
                ip_address = ""
                is_default = False
                is_loopback = False

            if not name:
                continue

            label = name
            if ip_address:
                label += f"  [{ip_address}]"
            if is_loopback:
                label += "  (loopback)"
            if is_default:
                label += "  ★ DEFAULT ROUTE"
                recommended_label = label

            labels.append(label)
            self._interface_name_by_label[label] = name

        self.interface_combo["values"] = labels

        if current_selection in labels:
            self.interface_var.set(current_selection)
        elif recommended_label:
            self.interface_var.set(recommended_label)
        elif labels:
            self.interface_var.set(labels[0])
        else:
            self.interface_var.set("")

    def get_selected_interface(self):
        """Return the exact interface name, not its decorated display label."""
        selected_label = self.interface_var.get().strip()
        return self._interface_name_by_label.get(selected_label, selected_label)

    def set_capture_state(self, capturing):
        """Lock the interface selection while capturing and update buttons."""
        self.interface_combo.configure(state="disabled" if capturing else "readonly")
        self.start_button.configure(state="disabled" if capturing else "normal")
        self.stop_button.configure(state="normal" if capturing else "disabled")

    def _build_table(self):
        """Create the packet table and its vertical scrollbar."""
        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True, padx=8)

        self.tree = ttk.Treeview(frame, columns=COLUMNS, show="headings")
        for col in COLUMNS:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=110, anchor="w")

        self.tree.column("info", width=280)

        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _build_status(self):
        """Create the status bar at the bottom of the window."""
        self.status = tk.StringVar(value="Idle")
        ttk.Label(
            self,
            textvariable=self.status,
            relief="sunken",
            anchor="w"
        ).pack(fill="x", side="bottom")

    def add_packet(self, pkt: dict):
        """Add a packet record as a new row in the table."""
        self.tree.insert("", "end", values=[pkt.get(c, "") for c in COLUMNS])
        self.tree.yview_moveto(1)

    def clear_packets(self):
        """Remove all rows from the packet table."""
        self.tree.delete(*self.tree.get_children())

    def set_status(self, text: str):
        """Update the message shown in the status bar."""
        self.status.set(text)

    def _start(self):
        """Start capture using the interface selected by the user."""
        selected_interface = self.get_selected_interface()

        if not selected_interface:
            self.set_status("Please select a network interface")
            return

        if self.on_start:
            self.on_start(selected_interface)

    def _stop(self):
        """Stop the active packet capture."""
        if self.on_stop:
            self.on_stop()
        else:
            self.set_status("Stopped")


if __name__ == "__main__":
    app = PacketApp()
    app.set_interfaces(["Example Ethernet Adapter", "Example Wi-Fi Adapter"])
    for packet in SAMPLE_PACKETS:
        app.add_packet(packet)
    app.mainloop()
