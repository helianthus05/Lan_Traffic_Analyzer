import tkinter as tk
from tkinter import messagebox, ttk
from datetime import datetime
# Counter keeps a running tally per IP address; used by the "most active IPs" stats
from collections import Counter, deque
# ipaddress tells private LAN addresses from internet ones and groups devices by subnet
import ipaddress

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
MAX_DISPLAY_ROWS = 2000  # Bound the visible packet table during long captures.

# Size of each chart drawing area and of the pie itself (in pixels)
CHART_W = 440
CHART_H = 110
PIE_SIZE = 96
LIVE_GRAPH_SECONDS = 60

# Columns of the client list table shown in the Clients window
CLIENT_COLUMNS = ("ip", "mac", "role", "sent", "received", "data", "protocols", "first_seen", "last_seen")


class PacketApp(tk.Tk):
    """Main window for the LAN Traffic Analyzer."""

    def __init__(
        self, on_start=None, on_stop=None, on_refresh=None, on_export=None,
        on_packets=None, on_filter=None, on_clear=None, on_logout=None
    ):
        super().__init__()
        self.title("NETWORK TRAFFIC ANALYZER")
        self.geometry("1150x800")
        self.minsize(900, 650)
        self.on_start = on_start
        self.on_stop = on_stop
        self.on_refresh = on_refresh
        self.on_export = on_export
        self.on_packets = on_packets
        self.on_filter = on_filter
        self.on_clear = on_clear
        self.on_logout = on_logout

        # Register the green/red button styles before the buttons are created
        self._build_button_styles()
        self._build_status()
        self._build_scroll_container()
        self._build_controls()
        self._build_health_banner()
        # Build the statistics panel between the controls and the packet table
        self._build_stats()
        self._build_live_graph()
        # Build the traffic summary panel (filled in only when Stop is clicked)
        self._build_summary()
        # Create the discovered-clients storage and the "Clients" button
        self._build_client_view()
        self._build_filters()
        self._build_table()
        self._live_graph_job = self.after(1000, self._tick_live_graph)

    def _build_scroll_container(self):
        """Put the main dashboard in a vertically scrollable area."""
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)
        self.content_canvas = tk.Canvas(container, highlightthickness=0)
        self.content_scrollbar = ttk.Scrollbar(
            container, orient="vertical", command=self.content_canvas.yview
        )
        self.content_canvas.configure(yscrollcommand=self.content_scrollbar.set)
        self.content_canvas.pack(side="left", fill="both", expand=True)
        self.content_scrollbar.pack(side="right", fill="y")

        self.content_frame = ttk.Frame(self.content_canvas)
        self._content_window = self.content_canvas.create_window(
            (0, 0), window=self.content_frame, anchor="nw"
        )
        self.content_frame.bind("<Configure>", self._update_scroll_region)
        self.content_canvas.bind("<Configure>", self._resize_scroll_content)
        self.bind_all("<MouseWheel>", self._on_mousewheel)
        self.bind_all("<Button-4>", self._on_linux_mousewheel)
        self.bind_all("<Button-5>", self._on_linux_mousewheel)

    def _update_scroll_region(self, event):
        if event.widget is self.content_frame:
            self.content_canvas.configure(
                scrollregion=self.content_canvas.bbox("all")
            )

    def _resize_scroll_content(self, event):
        self.content_canvas.itemconfigure(self._content_window, width=event.width)

    def _on_mousewheel(self, event):
        widget = self.winfo_containing(event.x_root, event.y_root)
        while widget is not None and widget is not self:
            if widget is self.tree and not (event.state & 0x0001):
                return
            if widget is self.content_canvas:
                break
            widget = getattr(widget, "master", None)
        if event.delta:
            units = int(-event.delta / 120)
            if not units:
                units = -1 if event.delta > 0 else 1
            self.content_canvas.yview_scroll(units, "units")
            return "break"

    def _on_linux_mousewheel(self, event):
        widget = self.winfo_containing(event.x_root, event.y_root)
        while widget is not None and widget is not self:
            if widget is self.tree:
                return
            if widget is self.content_canvas:
                break
            widget = getattr(widget, "master", None)
        direction = -1 if event.num == 4 else 1
        self.content_canvas.yview_scroll(direction, "units")
        return "break"

    def _build_controls(self):
        """Create the interface selector and Start, Stop, and Clear buttons."""
        bar = ttk.Frame(self.content_frame)
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
            command=self._clear_packets
        ).pack(side="left")

        self.export_menu = tk.Menu(self, tearoff=False)
        self.export_menu.add_command(
            label="Export filtered as CSV...",
            command=lambda: self._export("csv", "filtered"),
        )
        self.export_menu.add_command(
            label="Export filtered as PDF...",
            command=lambda: self._export("pdf", "filtered"),
        )
        self.export_menu.add_separator()
        self.export_menu.add_command(
            label="Export selected as CSV...",
            command=lambda: self._export("csv", "selected"),
        )
        self.export_menu.add_command(
            label="Export selected as PDF...",
            command=lambda: self._export("pdf", "selected"),
        )
        ttk.Button(
            bar,
            text="Export",
            command=lambda: self.export_menu.tk_popup(
                self.winfo_pointerx(), self.winfo_pointery()
            )
        ).pack(side="left")
        ttk.Button(
            bar,
            text="Packets...",
            command=self._open_packets,
        ).pack(side="left", padx=(6, 0))
        ttk.Button(
            bar,
            text="Log out",
            command=self._logout,
        ).pack(side="right", padx=(6, 0))

    def _logout(self):
        if self.on_logout:
            self.on_logout()
        else:
            self.set_status("Logout is unavailable in standalone preview mode")

    def _open_packets(self):
        """Ask the controller to open a saved MessagePack file."""
        if self.on_packets:
            self.on_packets()
        else:
            self.set_status("Packet file viewer is unavailable in standalone preview mode")

    def _build_health_banner(self):
        """Show default-gateway health and a concise explanation."""
        self.health_banner = tk.Frame(self.content_frame, relief="ridge", borderwidth=1)
        self.health_banner.pack(fill="x", padx=8, pady=(0, 6))
        self.health_title = tk.Label(
            self.health_banner,
            text="NETWORK STATUS CHECKING",
            font=("TkDefaultFont", 10, "bold"),
            anchor="w",
            padx=10,
            pady=6,
        )
        self.health_title.pack(fill="x")
        self.health_description = tk.Label(
            self.health_banner,
            text="Checking the default gateway response.",
            anchor="w",
            padx=10,
            pady=4,
        )
        self.health_description.pack(fill="x")
        self.set_network_health("checking", "Checking the default gateway response.")

    def set_network_health(self, state, description):
        """Update the color-coded default-gateway health indicator."""
        palettes = {
            "checking": ("#e5e7eb", "#374151", "NETWORK STATUS CHECKING"),
            "healthy": ("#dcfce7", "#166534", "NETWORK HEALTHY"),
            "congested": ("#ffedd5", "#9a3412", "POSSIBLE NETWORK CONGESTION"),
            "unreachable": ("#fee2e2", "#991b1b", "GATEWAY NOT RESPONDING"),
            "unavailable": ("#e5e7eb", "#374151", "NETWORK STATUS UNAVAILABLE"),
        }
        background, foreground, title = palettes.get(state, palettes["unavailable"])
        self.health_banner.configure(background=background)
        self.health_title.configure(
            text=title, background=background, foreground=foreground
        )
        self.health_description.configure(
            text=description, background=background, foreground=foreground
        )

    def _export(self, file_format, mode):
        """Delegate filtered or selected packet export to the controller."""
        if self.on_export:
            selected_packets = (
                self._get_selected_export_rows() if mode == "selected" else None
            )
            if mode == "selected" and not selected_packets:
                messagebox.showinfo(
                    "Nothing selected",
                    "Select one or more packet rows before exporting.",
                    parent=self,
                )
                return
            self.on_export(
                file_format,
                mode,
                dict(self._current_filters),
                selected_packets,
            )
        else:
            self.set_status("Export is unavailable in standalone preview mode")

    def _clear_packets(self):
        """Ask the controller to clear the active session, or clear preview rows."""
        if self.on_clear:
            self.on_clear()
        else:
            self.clear_packets()

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
        was_capturing = getattr(self, "_capture_active", False)
        self._capture_active = capturing
        if capturing and not was_capturing:
            self._reset_live_graph()
        if capturing != was_capturing:
            self._draw_live_graph()
            self._draw_bandwidth_graph()
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
        panel = ttk.LabelFrame(self.content_frame, text="Capture-wide Statistics")
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

    def _build_live_graph(self):
        """Create live packet-rate and bandwidth graphs."""
        self._live_history = deque([0] * LIVE_GRAPH_SECONDS, maxlen=LIVE_GRAPH_SECONDS)
        self._bandwidth_history = deque([0] * LIVE_GRAPH_SECONDS, maxlen=LIVE_GRAPH_SECONDS)
        self._live_interval_packets = 0
        self._live_interval_bytes = 0
        self._capture_active = False
        panel = ttk.LabelFrame(self.content_frame, text="Live Traffic (last 60 seconds)")
        panel.pack(fill="x", padx=8, pady=(0, 6))
        graphs = (
            ("Packets per second", "live_graph"),
            ("Bandwidth", "bandwidth_graph"),
        )
        for title, attribute in graphs:
            graph_frame = ttk.Frame(panel)
            graph_frame.pack(side="left", fill="x", expand=True, padx=6, pady=4)
            ttk.Label(graph_frame, text=title, font=("TkDefaultFont", 9, "bold")).pack(
                anchor="w"
            )
            canvas = tk.Canvas(
                graph_frame,
                height=120,
                background="#ffffff",
                highlightthickness=1,
                highlightbackground="#d1d5db",
            )
            canvas.pack(fill="x", expand=True)
            canvas.bind("<Configure>", self._on_live_graph_resize)
            setattr(self, attribute, canvas)
        self._draw_live_graph()
        self._draw_bandwidth_graph()

    def _on_live_graph_resize(self, event):
        if event.widget in (self.live_graph, self.bandwidth_graph):
            self._draw_live_graph()
            self._draw_bandwidth_graph()

    def _draw_live_graph(self):
        self._draw_traffic_graph(
            self.live_graph,
            self._live_history,
            lambda value: f"{value:,} pkt/s",
        )

    def _draw_bandwidth_graph(self):
        self._draw_traffic_graph(
            self.bandwidth_graph,
            self._bandwidth_history,
            lambda value: f"{self._format_bytes(value)}/s",
        )

    def _draw_traffic_graph(self, canvas, history, format_rate):
        canvas.delete("all")
        width = max(canvas.winfo_width(), 300)
        height = max(canvas.winfo_height(), 100)
        left, right, top, bottom = 42, width - 12, 14, height - 24
        values = list(history)
        peak = max(values, default=0)
        scale = max(peak, 1)

        canvas.create_text(
            left, 4, anchor="nw", text=f"Peak: {format_rate(peak)}", fill="#374151"
        )
        canvas.create_line(left, top, left, bottom, fill="#9ca3af")
        canvas.create_line(left, bottom, right, bottom, fill="#9ca3af")
        for fraction in (0.25, 0.5, 0.75, 1.0):
            y = bottom - (bottom - top) * fraction
            canvas.create_line(left, y, right, y, fill="#e5e7eb")
        points = []
        span = max(right - left, 1)
        for index, value in enumerate(values):
            x = left + span * index / max(len(values) - 1, 1)
            y = bottom - (bottom - top) * value / scale
            points.extend((x, y))
        if len(points) >= 4:
            canvas.create_line(*points, fill="#2563eb", width=2, smooth=True)
        elif points:
            canvas.create_oval(
                points[0] - 3, points[1] - 3,
                points[0] + 3, points[1] + 3,
                fill="#2563eb", outline="#2563eb",
            )
        if not self._capture_active:
            canvas.create_text(
                (left + right) / 2,
                (top + bottom) / 2,
                text="Capture stopped — graph paused",
                fill="#6b7280",
            )

    def _reset_live_graph(self):
        self._live_history.clear()
        self._live_history.extend([0] * LIVE_GRAPH_SECONDS)
        self._bandwidth_history.clear()
        self._bandwidth_history.extend([0] * LIVE_GRAPH_SECONDS)
        self._live_interval_packets = 0
        self._live_interval_bytes = 0
        self._draw_live_graph()
        self._draw_bandwidth_graph()

    def _tick_live_graph(self):
        """Advance the live graph once per second only while capture is active."""
        if self._capture_active:
            self._live_history.append(self._live_interval_packets)
            self._bandwidth_history.append(self._live_interval_bytes)
            self._live_interval_packets = 0
            self._live_interval_bytes = 0
            self._draw_live_graph()
            self._draw_bandwidth_graph()
        self._live_graph_job = self.after(1000, self._tick_live_graph)

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
        """Update running totals with one packet and refresh the panel."""
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

        # Batch callers redraw once after processing the complete batch.
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
        panel = ttk.LabelFrame(
            self.content_frame,
            text="Traffic Summary (calculated when capture is stopped)",
        )
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

    # ------------------------------------------------------------------
    # client list and network tree
    # ------------------------------------------------------------------
    def _build_client_view(self):
        """Create the storage for discovered clients and the button that opens the Clients window."""
        # ip address -> information collected about that device
        self._clients = {}
        self._client_window = None        # the Clients window, or None while it is closed
        self._client_refresh_job = None   # pending after() id, so refreshes are throttled

        # Put the button in the same bar as Start, Stop and Clear
        bar = self.start_button.master
        self.clients_button = ttk.Button(bar, text="Clients (0)", command=self._open_client_view)
        self.clients_button.pack(side="left", padx=(8, 0))

    @staticmethod
    def _is_lan_address(address):
        """Return True for a private LAN address; False for internet, loopback, multicast or broadcast."""
        try:
            ip = ipaddress.ip_address(str(address))
        except ValueError:
            return False
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified:
            return False
        if ip == ipaddress.ip_address("255.255.255.255"):
            return False
        return ip.is_private

    @staticmethod
    def _network_of(address):
        """Return the subnet a device belongs to (/24 for IPv4, /64 for IPv6)."""
        ip = ipaddress.ip_address(address)
        prefix = 24 if ip.version == 4 else 64
        return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)

    @staticmethod
    def _find_gateway(addresses):
        """Guess the router: the address ending in .1, else .254, else none."""
        for suffix in (".1", ".254"):
            for address in addresses:
                if address.endswith(suffix):
                    return address
        return ""

    def _record_client(self, pkt: dict):
        """Add or update the LAN devices that sent or received a packet."""
        # Read the packet size safely, like the statistics do
        try:
            length = int(pkt.get("length", 0) or 0)
        except (TypeError, ValueError):
            length = 0
        when = str(pkt.get("time", ""))
        protocol = str(pkt.get("protocol", "")).upper()

        # Handle the sender and the receiver of the packet in the same way
        for side in ("src", "dst"):
            address = str(pkt.get(side, ""))
            if not self._is_lan_address(address):
                continue

            # Create the record the first time this device is seen
            client = self._clients.setdefault(address, {
                "mac": "", "sent": 0, "recv": 0, "bytes_sent": 0, "bytes_recv": 0,
                "protocols": set(), "first": when, "last": when,
            })

            # The MAC address is shown only if the capture module provides it
            # as "src_mac" / "dst_mac" in the packet
            mac = pkt.get(f"{side}_mac", "")
            if mac:
                client["mac"] = str(mac)

            # Count the packet and its size for the correct direction
            if side == "src":
                client["sent"] += 1
                client["bytes_sent"] += length
            else:
                client["recv"] += 1
                client["bytes_recv"] += length

            if protocol:
                client["protocols"].add(protocol)
            client["last"] = when

        self._schedule_client_refresh()

    def _reset_clients(self):
        """Forget every discovered client and redraw the views."""
        self._clients.clear()
        self._refresh_client_view()

    def _schedule_client_refresh(self):
        """Redraw the client views at most once per second instead of once per packet."""
        if self._client_refresh_job is None:
            self._client_refresh_job = self.after(1000, self._run_client_refresh)

    def _run_client_refresh(self):
        """Run the throttled redraw."""
        self._client_refresh_job = None
        self._refresh_client_view()

    def _client_roles(self):
        """Return {address: role} marking this device, the likely gateway and the other clients."""
        roles = {address: "Client" for address in self._clients}

        # Mark one likely gateway per subnet
        by_network = {}
        for address in self._clients:
            by_network.setdefault(self._network_of(address), []).append(address)
        for addresses in by_network.values():
            gateway = self._find_gateway(addresses)
            if gateway:
                roles[gateway] = "Gateway (likely)"

        # This device wins over the other labels
        local_ip = self._get_local_ip()
        if local_ip in roles:
            roles[local_ip] = "This device"
        return roles

    def _open_client_view(self):
        """Open the Clients window (or bring it to the front if it is already open)."""
        if self._client_window is not None:
            self._client_window.lift()
            return

        win = tk.Toplevel(self)
        win.title("Network Clients")
        win.geometry("950x420")
        win.protocol("WM_DELETE_WINDOW", self._close_client_view)
        self._client_window = win

        # Header: how many clients were discovered, and how they are found
        self.client_count_var = tk.StringVar()
        ttk.Label(win, textvariable=self.client_count_var,
                  font=("TkDefaultFont", 11, "bold")).pack(anchor="w", padx=8, pady=(8, 0))
        ttk.Label(win, text="Devices are discovered passively from captured traffic "
                            "(private LAN addresses only).").pack(anchor="w", padx=8)

        notebook = ttk.Notebook(win)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        # Tab 1: table with one row per discovered client
        list_tab = ttk.Frame(notebook)
        notebook.add(list_tab, text="Client List")
        self.client_tree = ttk.Treeview(list_tab, columns=CLIENT_COLUMNS, show="headings")
        widths = {"ip": 120, "mac": 130, "role": 120, "sent": 70, "received": 80,
                  "data": 90, "protocols": 110, "first_seen": 80, "last_seen": 80}
        for col in CLIENT_COLUMNS:
            self.client_tree.heading(col, text=col.replace("_", " ").upper())
            self.client_tree.column(col, width=widths[col], anchor="w")
        list_scroll = ttk.Scrollbar(list_tab, orient="vertical", command=self.client_tree.yview)
        self.client_tree.configure(yscrollcommand=list_scroll.set)
        self.client_tree.pack(side="left", fill="both", expand=True)
        list_scroll.pack(side="right", fill="y")

        # Tab 2: tree of the network (subnet -> gateway -> devices)
        tree_tab = ttk.Frame(notebook)
        notebook.add(tree_tab, text="Network Tree")
        self.topology_tree = ttk.Treeview(tree_tab, columns=("role", "mac", "traffic"),
                                          show="tree headings")
        self.topology_tree.heading("#0", text="NETWORK / DEVICE")
        self.topology_tree.column("#0", width=300, anchor="w")
        for col, text, width in (("role", "ROLE", 140), ("mac", "MAC", 140), ("traffic", "TRAFFIC", 220)):
            self.topology_tree.heading(col, text=text)
            self.topology_tree.column(col, width=width, anchor="w")
        tree_scroll = ttk.Scrollbar(tree_tab, orient="vertical", command=self.topology_tree.yview)
        self.topology_tree.configure(yscrollcommand=tree_scroll.set)
        self.topology_tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")

        self._refresh_client_view()

    def _close_client_view(self):
        """Close the Clients window; discovery keeps running in the background."""
        if self._client_window is not None:
            self._client_window.destroy()
            self._client_window = None

    def _refresh_client_view(self):
        """Update the button count and, if the window is open, the client list and network tree."""
        count = len(self._clients)
        self.clients_button.configure(text=f"Clients ({count})")
        if self._client_window is None:
            return

        self.client_count_var.set(f"Clients discovered: {count}")
        roles = self._client_roles()

        # Client list: update rows in place so scrolling and selection are kept
        for address, client in self._clients.items():
            values = (
                address,
                client["mac"] or "-",
                roles[address],
                f"{client['sent']:,}",
                f"{client['recv']:,}",
                self._format_bytes(client["bytes_sent"] + client["bytes_recv"]),
                ", ".join(sorted(client["protocols"])) or "-",
                client["first"],
                client["last"],
            )
            if self.client_tree.exists(address):
                self.client_tree.item(address, values=values)
            else:
                self.client_tree.insert("", "end", iid=address, values=values)
        # Remove rows of clients that no longer exist (after Clear)
        for iid in self.client_tree.get_children():
            if iid not in self._clients:
                self.client_tree.delete(iid)

        # Network tree: rebuilt each time, keeping the selected device selected
        selected = self.topology_tree.selection()
        topology_items = self.topology_tree.get_children()
        if topology_items:
            self.topology_tree.delete(*topology_items)

        by_network = {}
        for address in self._clients:
            by_network.setdefault(self._network_of(address), []).append(address)

        for network in sorted(by_network, key=lambda n: (n.version, n)):
            addresses = sorted(by_network[network], key=ipaddress.ip_address)
            network_id = f"net:{network}"
            self.topology_tree.insert("", "end", iid=network_id, text=f"Network {network}",
                                      values=("", "", f"{len(addresses)} device(s)"), open=True)

            def device_values(address):
                # Role, MAC and traffic summary shown next to a device in the tree
                client = self._clients[address]
                traffic = (f"{client['sent'] + client['recv']:,} pkts, "
                           f"{self._format_bytes(client['bytes_sent'] + client['bytes_recv'])}")
                return (roles[address], client["mac"] or "-", traffic)

            # Devices hang under the gateway when one was found, else under the network
            gateway = self._find_gateway(addresses)
            parent = network_id
            if gateway:
                self.topology_tree.insert(network_id, "end", iid=gateway, text=gateway,
                                          values=device_values(gateway), open=True)
                parent = gateway
            for address in addresses:
                if address != gateway:
                    self.topology_tree.insert(parent, "end", iid=address, text=address,
                                              values=device_values(address))

        # Restore the selection if the selected device still exists
        self.topology_tree.selection_set([i for i in selected if self.topology_tree.exists(i)])
    # ------------------------------------------------------------------

    def _build_filters(self):
        """Create packet search and filtering controls above the table."""
        panel = ttk.LabelFrame(self.content_frame, text="Search and Filters")
        panel.pack(fill="x", padx=8, pady=(0, 6))

        self.search_var = tk.StringVar()
        self.protocol_filter_var = tk.StringVar(value="All")
        self.source_filter_var = tk.StringVar()
        self.destination_filter_var = tk.StringVar()
        self.port_filter_var = tk.StringVar()
        self.min_size_filter_var = tk.StringVar()
        self.max_size_filter_var = tk.StringVar()
        self.start_time_filter_var = tk.StringVar()
        self.end_time_filter_var = tk.StringVar()
        self._current_filters = {}

        fields = (
            (0, 0, "Search", self.search_var, 20),
            (0, 2, "Protocol", self.protocol_filter_var, 12),
            (0, 4, "Source IP", self.source_filter_var, 16),
            (0, 6, "Destination IP", self.destination_filter_var, 16),
            (0, 8, "Port", self.port_filter_var, 8),
            (1, 0, "Min bytes", self.min_size_filter_var, 8),
            (1, 2, "Max bytes", self.max_size_filter_var, 8),
            (1, 4, "Start time", self.start_time_filter_var, 18),
            (1, 6, "End time", self.end_time_filter_var, 18),
        )
        for row, column, label, variable, width in fields:
            ttk.Label(panel, text=label).grid(
                row=row, column=column, sticky="w", padx=(6, 3), pady=3
            )
            if variable is self.protocol_filter_var:
                field = ttk.Combobox(
                    panel,
                    textvariable=variable,
                    values=("All", "TCP", "UDP", "ICMP", "ARP", "Other"),
                    width=width,
                )
            else:
                field = ttk.Entry(panel, textvariable=variable, width=width)
            field.grid(row=row, column=column + 1, sticky="ew", padx=(0, 6), pady=3)
            field.bind("<Return>", self._handle_filter_return)

        ttk.Button(panel, text="Apply", command=self.apply_filters).grid(
            row=1, column=8, padx=4, pady=3
        )
        ttk.Button(panel, text="Reset", command=self.reset_filters).grid(
            row=1, column=9, padx=(0, 6), pady=3
        )
        for column in (1, 3, 5, 7):
            panel.columnconfigure(column, weight=1)

    def _handle_filter_return(self, event):
        if event.widget:
            self.apply_filters()
        return "break"

    def _read_filters(self):
        filters = {
            "search": self.search_var.get().strip(),
            "protocol": self.protocol_filter_var.get().strip(),
            "source_ip": self.source_filter_var.get().strip(),
            "destination_ip": self.destination_filter_var.get().strip(),
            "port": self.port_filter_var.get().strip(),
            "min_size": self.min_size_filter_var.get().strip(),
            "max_size": self.max_size_filter_var.get().strip(),
            "start_time": self.start_time_filter_var.get().strip(),
            "end_time": self.end_time_filter_var.get().strip(),
        }

        for key in ("port", "min_size", "max_size"):
            if filters[key]:
                try:
                    value = int(filters[key])
                except ValueError as error:
                    raise ValueError(f"{key.replace('_', ' ').title()} must be a whole number.") from error
                if value < 0:
                    raise ValueError(f"{key.replace('_', ' ').title()} cannot be negative.")

        for key in ("start_time", "end_time"):
            value = filters[key]
            if not value:
                continue
            try:
                parsed = datetime.fromisoformat(value)
            except ValueError as error:
                raise ValueError(
                    f"{key.replace('_', ' ').title()} must use YYYY-MM-DD HH:MM:SS format."
                ) from error
            if len(value) == 10:
                filters[key] = (
                    f"{value} 23:59:59" if key == "end_time"
                    else f"{value} 00:00:00"
                )
            else:
                filters[key] = parsed.strftime("%Y-%m-%d %H:%M:%S")

        if (
            filters["min_size"] and filters["max_size"]
            and int(filters["min_size"]) > int(filters["max_size"])
        ):
            raise ValueError("Minimum bytes cannot be greater than maximum bytes.")
        if (
            filters["start_time"] and filters["end_time"]
            and filters["start_time"] > filters["end_time"]
        ):
            raise ValueError("Start time cannot be later than end time.")
        return filters

    def apply_filters(self):
        try:
            filters = self._read_filters()
        except ValueError as error:
            messagebox.showerror("Invalid filter", str(error), parent=self)
            return

        self._current_filters = filters
        if self.on_filter:
            self.on_filter(filters)
            return

        rows = [self._packet_export_tuple(self._details_by_iid[iid])
                for iid in self.tree.get_children()
                if self._matches_current_filters(self._details_by_iid[iid])]
        self.set_filtered_packets(rows, filters)

    def reset_filters(self):
        self.search_var.set("")
        self.protocol_filter_var.set("All")
        self.source_filter_var.set("")
        self.destination_filter_var.set("")
        self.port_filter_var.set("")
        self.min_size_filter_var.set("")
        self.max_size_filter_var.set("")
        self.start_time_filter_var.set("")
        self.end_time_filter_var.set("")
        self.apply_filters()

    def set_filtered_packets(self, packets, filters):
        """Replace visible table rows with the active session's filter results."""
        self._current_filters = dict(filters)
        existing_items = self.tree.get_children()
        if existing_items:
            self.tree.delete(*existing_items)
        self._details_by_iid.clear()
        for row in reversed(packets[:MAX_DISPLAY_ROWS]):
            record = {
                "id": row[0],
                "no": row[0],
                "timestamp": row[1],
                "time": str(row[1]).split(" ")[-1],
                "source_ip": row[2],
                "src": row[2],
                "destination_ip": row[3],
                "dst": row[3],
                "protocol": row[4],
                "length": row[5],
                "source_port": row[6],
                "destination_port": row[7],
                "info": row[8],
            }
            self._insert_packet(record)
        if self.tree.get_children():
            self.tree.yview_moveto(1)
        self.set_status(
            f"Showing {len(packets):,} matching packet(s)"
            + (f" (display limited to {MAX_DISPLAY_ROWS:,})"
               if len(packets) > MAX_DISPLAY_ROWS else "")
        )

    def _matches_current_filters(self, packet):
        filters = self._current_filters
        searchable = " ".join(str(packet.get(key, "")) for key in (
            "src", "source_ip", "dst", "destination_ip", "protocol", "info",
            "source_port", "destination_port",
        )).lower()
        if filters.get("search") and filters["search"].lower() not in searchable:
            return False
        if filters.get("protocol") not in (None, "", "All"):
            if str(packet.get("protocol", "")).lower() != filters["protocol"].lower():
                return False
        for key, packet_key in (
            ("source_ip", "source_ip"),
            ("destination_ip", "destination_ip"),
        ):
            value = filters.get(key, "").lower()
            packet_value = str(packet.get(packet_key) or packet.get(
                "src" if key == "source_ip" else "dst", ""
            )).lower()
            if value and value not in packet_value:
                return False
        if filters.get("port"):
            selected_port = str(int(filters["port"]))
            packet_ports = {
                str(packet.get("source_port") or ""),
                str(packet.get("destination_port") or ""),
            }
            if selected_port not in packet_ports:
                return False
        try:
            length = int(packet.get("length", 0) or 0)
        except (TypeError, ValueError):
            length = 0
        if filters.get("min_size") and length < int(filters["min_size"]):
            return False
        if filters.get("max_size") and length > int(filters["max_size"]):
            return False
        timestamp = str(packet.get("timestamp") or packet.get("time") or "")
        if filters.get("start_time") and timestamp < filters["start_time"]:
            return False
        if filters.get("end_time") and timestamp > filters["end_time"]:
            return False
        return True

    def _build_table(self):
        """Create the packet table and its vertical scrollbar."""
        frame = ttk.Frame(self.content_frame)
        frame.pack(fill="both", expand=True, padx=8)

        self.tree = ttk.Treeview(frame, columns=COLUMNS, show="headings", height=25)
        self._details_by_iid = {}
        for col in COLUMNS:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=110, anchor="w")

        self.tree.column("info", width=280)

        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.bind("<Double-1>", self._show_selected_packet_details)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _insert_packet(self, packet):
        item_id = self.tree.insert(
            "", "end", values=[packet.get(column, "") for column in COLUMNS]
        )
        self._details_by_iid[item_id] = dict(packet)

    @staticmethod
    def _packet_export_tuple(packet):
        return (
            packet.get("id", packet.get("no")),
            packet.get("timestamp", packet.get("time", "")),
            packet.get("source_ip", packet.get("src", "")),
            packet.get("destination_ip", packet.get("dst", "")),
            packet.get("protocol", ""),
            packet.get("length", 0),
            packet.get("source_port"),
            packet.get("destination_port"),
            packet.get("info", ""),
        )

    def _get_selected_export_rows(self):
        return [
            self._packet_export_tuple(self._details_by_iid[item_id])
            for item_id in self.tree.selection()
            if item_id in self._details_by_iid
        ]

    def _show_selected_packet_details(self, event):
        if event.widget is not self.tree:
            return
        selection = self.tree.selection()
        if selection:
            packet = self._details_by_iid.get(selection[0])
            if packet:
                self._show_packet_details(packet)

    def _show_packet_details(self, packet, parent=None):
        """Show the selected packet's captured fields in a detail window."""
        if not packet:
            return
        parent = self if parent is None else parent
        window = tk.Toplevel(parent)
        window.title("Packet details")
        window.geometry("700x480")
        window.minsize(500, 320)

        values = (
            ("Packet number", packet.get("id", packet.get("no", ""))),
            ("Timestamp", packet.get("timestamp", packet.get("time", ""))),
            ("Source IP", packet.get("source_ip", packet.get("src", ""))),
            ("Source MAC", packet.get("source_mac", packet.get("src_mac", ""))),
            ("Source port", packet.get("source_port", "")),
            ("Destination IP", packet.get("destination_ip", packet.get("dst", ""))),
            ("Destination MAC", packet.get("destination_mac", packet.get("dst_mac", ""))),
            ("Destination port", packet.get("destination_port", "")),
            ("Protocol", packet.get("protocol", "")),
            ("Length", packet.get("length", "")),
        )
        frame = ttk.Frame(window, padding=10)
        frame.pack(fill="both", expand=True)
        for row, (label, value) in enumerate(values):
            ttk.Label(frame, text=f"{label}:").grid(
                row=row, column=0, sticky="nw", padx=(0, 12), pady=2
            )
            ttk.Label(
                frame,
                text=str(value) if value not in (None, "") else "-",
                wraplength=520,
                justify="left",
            ).grid(row=row, column=1, sticky="nw", pady=2)

        info_row = len(values)
        ttk.Label(frame, text="Info:").grid(
            row=info_row, column=0, sticky="nw", padx=(0, 12), pady=2
        )
        info = tk.Text(frame, height=5, wrap="word")
        info.insert("1.0", str(packet.get("info", "")))
        info.configure(state="disabled")
        info.grid(row=info_row, column=1, sticky="nsew", pady=2)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(info_row, weight=1)

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
        """Add one packet and update statistics and discovered LAN clients."""
        self.add_packets([pkt])

    def add_packets(self, packets):
        """Insert a batch efficiently while updating statistics and client discovery."""
        if not packets:
            return
        for pkt in packets:
            if self._capture_active:
                self._live_interval_packets += 1
                try:
                    self._live_interval_bytes += int(pkt.get("length", 0) or 0)
                except (TypeError, ValueError):
                    pass
            if self._matches_current_filters(pkt):
                self._insert_packet(pkt)
            self._record_stats(pkt, refresh=False)
            self._record_client(pkt)

        self._refresh_stats()
        children = self.tree.get_children()
        excess = len(children) - MAX_DISPLAY_ROWS
        if excess > 0:
            removed = children[:excess]
            for item_id in removed:
                self._details_by_iid.pop(item_id, None)
            self.tree.delete(*removed)
        if self.tree.get_children():
            self.tree.yview_moveto(1)

    def show_summary(self):
        """Public entry point used by the controller after capture has fully stopped."""
        self._show_summary()

    def clear_packets(self):
        """Reset the packet table, filters, statistics, clients, and live graphs."""
        existing_items = self.tree.get_children()
        if existing_items:
            self.tree.delete(*existing_items)
        self._details_by_iid.clear()
        self._current_filters = {}
        self.search_var.set("")
        self.protocol_filter_var.set("All")
        self.source_filter_var.set("")
        self.destination_filter_var.set("")
        self.port_filter_var.set("")
        self.min_size_filter_var.set("")
        self.max_size_filter_var.set("")
        self.start_time_filter_var.set("")
        self.end_time_filter_var.set("")
        self._reset_live_graph()
        # Reset the statistics so they match the now-empty table
        self._reset_stats()
        # Forget all discovered clients as well
        self._reset_clients()

    def set_status(self, text: str):
        """Update the message shown in the status bar."""
        self.status.set(text)

    def show_packet_file(self, file_path, records):
        """Display a saved MessagePack packet capture in a separate window."""
        window = tk.Toplevel(self)
        window.title(f"Packet file - {file_path}")
        window.geometry("1100x600")
        window.minsize(750, 350)

        columns = (
            "id", "timestamp", "source_ip", "destination_ip", "protocol",
            "length", "source_port", "destination_port", "info",
        )
        frame = ttk.Frame(window)
        frame.pack(fill="both", expand=True, padx=8, pady=8)
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        for column in columns:
            tree.heading(column, text=column.replace("_", " ").upper())
            tree.column(column, width=110, anchor="w")
        tree.column("info", width=300)

        vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        details_by_iid = {}
        for record in records:
            item_id = tree.insert(
                "", "end", values=[record.get(column, "") for column in columns]
            )
            details_by_iid[item_id] = dict(record)
        tree.bind(
            "<Double-1>",
            lambda event: self._show_packet_details(
                details_by_iid.get(event.widget.focus()), window
            ),
        )
        ttk.Label(
            window,
            text=f"{len(records):,} packet(s) | {file_path}",
            anchor="w",
        ).pack(fill="x", padx=8, pady=(0, 8))

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
        # Turn Stop red (and Start back to normal) as soon as Stop is clicked
        self._set_button_colors(False)
        if self.on_stop:
            self.on_stop()
        else:
            self.set_status("Stopped")
        # The controller displays the summary after the capture thread and queue finish.


if __name__ == "__main__":
    app = PacketApp()
    app.set_interfaces(["Example Ethernet Adapter", "Example Wi-Fi Adapter"])
    for packet in SAMPLE_PACKETS:
        app.add_packet(packet)
    app.mainloop()
