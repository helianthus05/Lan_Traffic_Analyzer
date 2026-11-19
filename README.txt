LAN Traffic Analyzer - integrated build

Files:
  main.py          Application controller and entry point
  gui.py           Updated GUI with LAN client discovery and export controls
  database.py      MessagePack packet storage (based on database_new.py)
  capture.py       Scapy interface discovery and packet capture
  packet_parser.py Packet parsing, including Ethernet MAC addresses

Run:
  pip install scapy msgpack reportlab pypdf cryptography requests firebase-admin
  python main.py

Authentication setup (personal testing only):
- Set FIREBASE_WEB_API_KEY in your Windows environment to the Firebase Web API
  key for this project. The app does not store it in source code.
- The default local service-account path is the matching JSON file in the
  workspace's parent folder. Set FIREBASE_SERVICE_ACCOUNT_PATH to override it.
- Registration reserves a unique username, creates a Firebase Auth account,
  and sends Firebase's email-verification link. Sign-in requires a verified
  email and a username/email plus password. Verification is account-wide and
  happens once; there is no per-device email code or trusted-device flow.
- "Keep me signed in until Windows restarts" stores the Firebase refresh token
  encrypted with Windows DPAPI under the current Windows user profile. The
  token is refreshed when the app starts and is discarded after a reboot.
- The main window's Log out button asks for confirmation, stops any active
  capture, clears the saved login, and returns to the sign-in screen.
- The service-account JSON grants administrator access. Never package, commit,
  or share it; use a server-side backend before distributing this application.

Notes:
- Each run stores packets in its own file under the session_packets folder.
- Use Packets... to open a saved MessagePack capture in the in-app viewer. The
  file dialog opens in session_packets by default.
- The live packets-per-second and byte-throughput graphs freeze when capture
  stops. The color-coded network-health banner periodically checks response
  time and packet loss to the default gateway. High latency or loss is shown as
  possible congestion or path degradation, not a definitive diagnosis; gateways
  that block ping may appear not to respond.
- Search and filters can narrow the packet table by text, protocol, addresses,
  ports, size, and time. Double-click a packet to inspect its details. Export
  filtered results or selected rows as encrypted CSV/PDF.
- The main dashboard scrolls vertically; the packet table has its own scrollbar.
- Clear starts a fresh packet file and resets the table, counters, statistics,
  and graphs; the previous packet file remains available in session_packets.
- CSV exports are encrypted with a password using PBKDF2 and Fernet.
- PDF exports are AES-256 encrypted with a password using reportlab and pypdf.
- Packet capture may require administrator/root privileges and a supported capture
  backend (such as Npcap on Windows).
- Client discovery is passive and limited to private LAN IP addresses visible
  in captured traffic. MAC addresses are populated when Ethernet headers expose them.
