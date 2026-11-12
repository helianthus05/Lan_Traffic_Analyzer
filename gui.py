import tkinter as tk
from tkinter import ttk
# Counter keeps a running tally per IP address; used by the "most active IPs" stats
from collections import Counter

# SAMPLE PACKETS ONLY :)
SAMPLE_PACKETS = [
    {"no": 1, "time": "12:00:01", "src": "192.168.1.5",  "dst": "8.8.8.8",      "protocol": "UDP", "length": 74,  "info": "DNS query"},
    {"no": 2, "time": "12:00:02", "src": "8.8.8.8",      "dst": "192.168.1.5",  "protocol": "UDP", "length": 90,  "info": "DNS response"},
    {"no": 3, "time": "12:00:03", "src": "192.168.1.5",  "dst": "142.250.1.1",  "protocol": "TCP", "length": 66,  "info": "SYN"},
]

# COLUMN NAMES FOR THE PACKET TABLE
COLUMNS = ("no", "time", "src", "dst", "protocol", "length", "info")

# How many entries the "most active source/destination IPs" lists show
TOP_N = 5
MAX_DISPLAY_ROWS = 2000  # Keep the Treeview bounded during long captures.

# Size of each chart drawing area and of the pie itself (in pixels)
CHART_W = 440
CHART_H = 110
PIE_SIZE = 96


class PacketApp(tk.Tk):
    """Main window for the LAN Traffic Analyzer."""

    def __init__(self, on_start=None, on_stop=None, on_refresh=None):
        super().__init__()
        self.title("NETWORK TRAFFIC ANALYZER")
        self.geometry("1000x550")
        self.on_start = on_start
        self.on_stop = on_stop
        self.on_refresh = on_refresh

        # Register the green/red button styles before the buttons are created
        self._build_button_styles()
        self._build_controls()
        # Build the statistics panel between the controls and the packet table
        self._build_stats()
        # Build the traffic summary panel (filled in only when Stop is clicked)
        self._build_summary()
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
        # Reset the label -> IP mapping used to decide incoming vs outgoing
        self._interface_ip_by_label = {}
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
            # Remember this interface's IP address for the traffic summary
            self._interface_ip_by_label[label] = ip_address

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
        # Keep the button colors in sync when the main app changes the state
        self._set_button_colors(capturing)

    # ------------------------------------------------------------------
    # Start (green) / Stop (red) button colors
    # ------------------------------------------------------------------
    def _build_button_styles(self):
        """Define the green and red button styles used by Start and Stop."""
        style = ttk.Style(self)
        # The 'clam' theme is used because the native Windows/macOS themes
        # ignore custom button background colors
        style.theme_use("clam")

        # Green style for the Start button while a capture is running
        style.configure("Green.TButton", background="#2e9e4f", foreground="white")
        # Keep the same colors when hovered or disabled (disabled while capturing)
        style.map(
            "Green.TButton",
            background=[("disabled", "#2e9e4f"), ("active", "#37b85d")],
            foreground=[("disabled", "white")],
        )

        # Red style for the Stop button once a capture has been stopped
        style.configure("Red.TButton", background="#d64545", foreground="white")
        style.map(
            "Red.TButton",
            background=[("disabled", "#d64545"), ("active", "#e35d5d")],
            foreground=[("disabled", "white")],
        )

        # Remembers whether a capture was ever started, so Stop is not
        # shown red when the app first opens
        self._has_captured = False

    def _set_button_colors(self, capturing):
        """Start turns green while capturing; Stop turns red after stopping."""
        if capturing:
            self._has_captured = True
            self.start_button.configure(style="Green.TButton")
            self.stop_button.configure(style="TButton")
        else:
            # Back to the default look for Start; Stop goes red only if a
            # capture was actually running before
            self.start_button.configure(style="TButton")
            if self._has_captured:
                self.stop_button.configure(style="Red.TButton")
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # statistics panel
    # ------------------------------------------------------------------
    def _build_stats(self):
        """Create the live statistics panel shown above the packet table."""
        # Running totals that every incoming packet updates
        self._src_counter = Counter()   # packets seen per source IP
        self._dst_counter = Counter()   # packets seen per destination IP
        self._total_packets = 0         # number of packets captured
        self._total_bytes = 0           # sum of all packet lengths
        self._protocol_counter = Counter()  # packets seen per protocol (TCP, UDP, ...)
        self._src_bytes = Counter()         # bytes sent per source IP
        self._dst_bytes = Counter()         # bytes received per destination IP

        # Titled box that holds the whole statistics panel
        panel = ttk.LabelFrame(self, text="Statistics")
        panel.pack(fill="x", padx=8, pady=(0, 6))

        # Left column: summary numbers
        summary = ttk.Frame(panel)
        summary.pack(side="left", anchor="n", padx=10, pady=4)

        # StringVars let us change the displayed text just by calling .set()
        self.total_packets_var = tk.StringVar(value="0")
        self.total_data_var = tk.StringVar(value="0 B")
        self.avg_size_var = tk.StringVar(value="0 B")

        # Each row is (label text, variable shown next to it)
        rows = (
            ("Total packets:", self.total_packets_var),
            ("Total data:", self.total_data_var),
            ("Avg packet size:", self.avg_size_var),
        )
        # Lay the rows out in a grid: label on the left, bold value on the right
        for r, (label, var) in enumerate(rows):
            ttk.Label(summary, text=label).grid(row=r, column=0, sticky="w", padx=(0, 8))
            ttk.Label(summary, textvariable=var, font=("TkDefaultFont", 9, "bold")).grid(
                row=r, column=1, sticky="w"
            )

        # Middle and right columns: most active IPs
        # These hold the multi-line "IP  count" text for each list
        self.top_src_var = tk.StringVar(value="-")
        self.top_dst_var = tk.StringVar(value="-")

        # One column for source IPs and one for destination IPs
        for title, var in (
            (f"Top {TOP_N} source IPs", self.top_src_var),
            (f"Top {TOP_N} destination IPs", self.top_dst_var),
        ):
            col = ttk.Frame(panel)
            col.pack(side="left", anchor="n", padx=10, pady=4, expand=True, fill="x")
            # Bold heading, then the list in a fixed-width font so it lines up
            ttk.Label(col, text=title, font=("TkDefaultFont", 9, "bold")).pack(anchor="w")
            ttk.Label(col, textvariable=var, justify="left", font=("Courier", 9)).pack(anchor="w")

    @staticmethod
    def _format_bytes(num_bytes):
        """Return a human-readable size such as '532 B', '12.40 KB' or '3.07 MB'."""
        # Pick the largest unit that keeps the number readable (1 KB = 1024 B)
        if num_bytes < 1024:
            return f"{num_bytes:.0f} B"
        if num_bytes < 1024 ** 2:
            return f"{num_bytes / 1024:.2f} KB"
        if num_bytes < 1024 ** 3:
            return f"{num_bytes / 1024 ** 2:.2f} MB"
        return f"{num_bytes / 1024 ** 3:.2f} GB"

    @staticmethod
    def _format_top(counter):
        """Format the most common entries of a Counter as aligned text lines."""
        # Show a dash when nothing has been counted yet
        if not counter:
            return "-"
        # One line per IP: left-aligned address, right-aligned packet count
        return "\n".join(f"{ip:<16} {count:>6} pkts" for ip, count in counter.most_common(TOP_N))

    def _record_stats(self, pkt: dict, refresh=True):
        """Update running totals; batch callers refresh the panel once per batch."""
        # Read the packet size safely; bad or missing values count as 0
        # so one malformed packet can't crash the GUI
        try:
            length = int(pkt.get("length", 0) or 0)
        except (TypeError, ValueError):
            length = 0

        # Update the overall totals
        self._total_packets += 1
        self._total_bytes += length

        # Update the per-IP counters (ignore packets with no address)
        src = pkt.get("src", "")
        dst = pkt.get("dst", "")
        if src:
            self._src_counter[src] += 1
            self._src_bytes[src] += length
        if dst:
            self._dst_counter[dst] += 1
            self._dst_bytes[dst] += length

        # Count the packet under its protocol (TCP, UDP, ...)
        self._protocol_counter[str(pkt.get("protocol", "")).upper()] += 1

        if refresh:
            self._refresh_stats()

    def _refresh_stats(self):
        """Redraw every value in the statistics panel."""
        # Average = total bytes / packet count (guard against dividing by zero)
        avg = self._total_bytes / self._total_packets if self._total_packets else 0
        self.total_packets_var.set(f"{self._total_packets:,}")
        self.total_data_var.set(self._format_bytes(self._total_bytes))
        self.avg_size_var.set(self._format_bytes(avg))
        self.top_src_var.set(self._format_top(self._src_counter))
        self.top_dst_var.set(self._format_top(self._dst_counter))

    def _reset_stats(self):
        """Zero all statistics (used when the table is cleared)."""
        self._src_counter.clear()
        self._dst_counter.clear()
        self._total_packets = 0
        self._total_bytes = 0
        self._protocol_counter.clear()
        self._src_bytes.clear()
        self._dst_bytes.clear()
        # Go back to the "press Stop" message in the traffic summary
        self._clear_summary()
        # Redraw so the panel shows zeros / dashes straight away
        self._refresh_stats()
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # traffic summary (incoming/outgoing ratio, TCP/UDP distribution)
    # ------------------------------------------------------------------
    def _build_summary(self):
        """Create the traffic summary panel shown below the statistics panel."""
        # Label -> IP mapping, filled in by set_interfaces()
        self._interface_ip_by_label = {}

        # Titled box that holds both pie charts
        panel = ttk.LabelFrame(self, text="Traffic Summary (calculated when capture is stopped)")
        panel.pack(fill="x", padx=8, pady=(0, 6))

        # One chart for incoming/outgoing traffic and one for TCP/UDP
        self.direction_canvas = self._make_chart(panel, "Incoming vs Outgoing")
        self.protocol_canvas = self._make_chart(panel, "TCP / UDP distribution")

        self._clear_summary()

    def _make_chart(self, parent, title):
        """Create a titled drawing area (Canvas) where a pie chart and its legend are drawn."""
        col = ttk.Frame(parent)
        col.pack(side="left", anchor="n", padx=10, pady=4, expand=True, fill="x")
        # Bold heading above the chart
        ttk.Label(col, text=title, font=("TkDefaultFont", 9, "bold")).pack(anchor="w")
        # Match the canvas background to the surrounding frame so it blends in
        background = ttk.Style(self).lookup("TFrame", "background") or self.cget("bg")
        canvas = tk.Canvas(col, width=CHART_W, height=CHART_H, highlightthickness=0, bg=background)
        canvas.pack(anchor="w")
        return canvas

    def _draw_message(self, canvas, text):
        """Replace whatever is drawn on a chart with a single line of text."""
        canvas.delete("all")
        canvas.create_text(4, CHART_H // 2, text=text, anchor="w")

    def _draw_pie(self, canvas, slices, header="", footer=""):
        """Draw a pie chart with a legend; slices are (label, value, color, detail) tuples."""
        canvas.delete("all")
        total = sum(value for _, value, _, _ in slices)
        if total <= 0:
            self._draw_message(canvas, "No packets captured")
            return

        # Bounding square of the pie, with a small margin
        box = (6, 7, 6 + PIE_SIZE, 7 + PIE_SIZE)
        angle = 90  # start at the top of the circle
        for _, value, color, _ in slices:
            if value <= 0:
                continue
            if value == total:
                # A single slice is a full circle (an arc of 360 degrees would not draw)
                canvas.create_oval(*box, fill=color, outline="white")
            else:
                extent = value / total * 360
                canvas.create_arc(*box, start=angle, extent=extent, fill=color,
                                  outline="white", style="pieslice")
                angle += extent

        # Legend to the right of the pie: header, one row per slice, then footer
        x = PIE_SIZE + 22
        y = 8
        font = ("Courier", 9)
        if header:
            canvas.create_text(x, y, text=header, anchor="nw", font=font)
            y += 16
        for label, _, color, detail in slices:
            # Colored square matching the slice, followed by its numbers
            canvas.create_rectangle(x, y + 2, x + 10, y + 12, fill=color, outline=color)
            canvas.create_text(x + 16, y, text=f"{label:<9}{detail}", anchor="nw", font=font)
            y += 16
        if footer:
            canvas.create_text(x, y, text=footer, anchor="nw", font=font)

    def _clear_summary(self):
        """Show the placeholder message until Stop is clicked."""
        self._draw_message(self.direction_canvas, "Click Stop to calculate")
        self._draw_message(self.protocol_canvas, "Click Stop to calculate")

    def _get_local_ip(self):
        """Return this machine's IP: the selected interface's, else the busiest address."""
        # Prefer the IP of the interface the user selected
        ip_address = self._interface_ip_by_label.get(self.interface_var.get().strip(), "")
        if ip_address:
            return ip_address
        # Fallback: the address that appears most often as source or destination
        seen = self._src_counter + self._dst_counter
        return seen.most_common(1)[0][0] if seen else ""

    def _show_summary(self):
        """Calculate the overall traffic ratios and draw the pie charts (called when Stop is clicked)."""
        total = self._total_packets
        if total == 0:
            self._draw_message(self.direction_canvas, "No packets captured")
            self._draw_message(self.protocol_canvas, "No packets captured")
            return

        def pct(part, whole):
            # Percentage text, safe against dividing by zero
            return f"{part / whole * 100:5.1f}%" if whole else "  0.0%"

        # Incoming = packets sent TO this machine; outgoing = packets sent FROM it
        local_ip = self._get_local_ip()
        in_pkts = self._dst_counter[local_ip]
        out_pkts = self._src_counter[local_ip]
        in_bytes = self._dst_bytes[local_ip]
        out_bytes = self._src_bytes[local_ip]
        # Packets that are neither to nor from this machine (broadcast, other hosts)
        other_pkts = max(total - in_pkts - out_pkts, 0)
        whole = in_pkts + out_pkts + other_pkts

        direction_slices = [
            ("Incoming", in_pkts, "#3b82f6",
             f"{in_pkts:,} pkts {pct(in_pkts, whole)} {self._format_bytes(in_bytes)}"),
            ("Outgoing", out_pkts, "#f59e0b",
             f"{out_pkts:,} pkts {pct(out_pkts, whole)} {self._format_bytes(out_bytes)}"),
        ]
        if other_pkts:
            direction_slices.append(
                ("Other", other_pkts, "#9ca3af", f"{other_pkts:,} pkts {pct(other_pkts, whole)}")
            )
        # Overall ratio of incoming to outgoing packets
        ratio = f"{in_pkts / out_pkts:.2f} : 1" if out_pkts else "n/a"
        self._draw_pie(self.direction_canvas, direction_slices,
                       header=f"Local IP: {local_ip}", footer=f"In : Out ratio  {ratio}")

        # Protocol distribution: TCP and UDP, everything else grouped as Other
        tcp = self._protocol_counter["TCP"]
        udp = self._protocol_counter["UDP"]
        other_proto = total - tcp - udp
        protocol_slices = [
            ("TCP", tcp, "#8b5cf6", f"{tcp:,} pkts {pct(tcp, total)}"),
            ("UDP", udp, "#14b8a6", f"{udp:,} pkts {pct(udp, total)}"),
        ]
        if other_proto:
            protocol_slices.append(
                ("Other", other_proto, "#9ca3af", f"{other_proto:,} pkts {pct(other_proto, total)}")
            )
        self._draw_pie(self.protocol_canvas, protocol_slices)
    # ------------------------------------------------------------------

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
        """Backward-compatible single-packet insert."""
        self.add_packets([pkt])

    def add_packets(self, packets):
        """Insert a batch of rows and refresh statistics only once."""
        if not packets:
            return
        for pkt in packets:
            self.tree.insert("", "end", values=[pkt.get(c, "") for c in COLUMNS])
            self._record_stats(pkt, refresh=False)

        # Prevent the visible table from growing without limit.
        children = self.tree.get_children()
        excess = len(children) - MAX_DISPLAY_ROWS
        if excess > 0:
            self.tree.delete(*children[:excess])

        self._refresh_stats()
        self.tree.yview_moveto(1)

    def show_summary(self):
        """Public entry point used after capture has fully stopped."""
        self._show_summary()

    def clear_packets(self):
        """Remove all rows from the packet table."""
        self.tree.delete(*self.tree.get_children())
        # Reset the statistics so they match the now-empty table
        self._reset_stats()

    def set_status(self, text: str):
        """Update the message shown in the status bar."""
        self.status.set(text)

    def _start(self):
        """Start capture using the interface selected by the user."""
        selected_interface = self.get_selected_interface()

        if not selected_interface:
            self.set_status("Please select a network interface")
            return

        # Turn Start green as soon as the capture is requested
        self._set_button_colors(True)
        # Hide the previous summary while a new capture is running
        self._clear_summary()

        if self.on_start:
            self.on_start(selected_interface)

    def _stop(self):
        """Stop the active packet capture."""
        # The controller changes button state after the capture thread has stopped.
        if self.on_stop:
            self.on_stop()
        else:
            self.set_status("Stopped")
        # The controller displays the final summary after the capture thread stops.


if __name__ == "__main__":
    app = PacketApp()
    app.set_interfaces(["Example Ethernet Adapter", "Example Wi-Fi Adapter"])
    for packet in SAMPLE_PACKETS:
        app.add_packet(packet)
    app.mainloop()
