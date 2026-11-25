LAN TRAFFIC ANALYZER — WEB & DESKTOP VERSION

WHAT THIS IS
This local web dashboard includes the traffic-analyzer features from the
Tkinter application. The Python server performs packet capture and authentication;
the browser only displays data and sends local requests to that server.

FEATURES
- Firebase sign-in, registration, Gmail verification, resend-verification, and
  logout.
- Interface selection and refresh, live Scapy capture, stop, and clear.
- Capture totals, averages, current pkt/s & bandwidth rate, top talkers,
  60-second charts, and incoming/outgoing and protocol summaries.
- Passive network alerts banner flagging IP-to-MAC conflicts (possible ARP
  spoofing), port scans / host sweeps, cleartext Telnet/FTP or HTTP spikes,
  and repeated failed DNS / query bursts, with one-click traffic inspection.
- A live plain-language traffic explanation with packet totals, recent rates,
  leading IPv4 sender, common protocol, and any relevant port-80 or ARP notes.
- Passive IPv4 neighboring-client tracking learned directly from captured
  traffic (with reverse DNS, passive DHCP/mDNS/SSDP/NetBIOS device names,
  MAC/OUI vendor lookup, custom local nicknames, Neighbors-only filtering,
  role, traffic totals, protocols, and first/last-seen details), plus an
  IPv4-only subnet tree. IPv6 packets are still captured and remain available
  in packet records and exports.
- Passive TLS ClientHello SNI and HTTP Host inspection, Top Domains & Services
  breakdowns, and a dedicated DNS activity tab (with an Errors-only toggle).
- Search and filters for protocol (including ICMPv6), addresses, ports, packet
  size, and time, with paging over filtered results. Click any device, domain,
  service, or top talker to filter its traffic, pause/resume the live packet
  view while reading, switch to Conversations (Flows) or DNS activity, or
  double-click a packet to inspect its fields.
- Password-encrypted exports (minimum 8-character password): Export PDF Packets,
  Export CSV Packets, and Export PDF Report, plus an in-dashboard
  "Decrypt CSV…" dialog and CLI helper (`py export.py <in.csv> <out.csv>`).
- Open, rename, delete, or compare saved MessagePack captures in
  session_packets/, or choose a .msgpack file from elsewhere on the computer.
  Saved captures include a network report with a client list, subnet tree,
  protocol summary, gateway health, data-based advice, and two-session
  comparison (traffic deltas, new/missing devices, and protocol shifts).
  Health is the live gateway check at report generation because historical
  health is not stored in packet files. New captures retain observed MAC
  addresses; older captures may not contain them.
- Default-gateway response, latency, and packet-loss status, plus exact gateway
  role identification in the client list when the default gateway is resolved.
- Compact navy-header dashboard with Light / Dark theme toggle, plus No
  activity, healthy, and congestion states. A congestion warning lists top
  observed private-LAN senders by bytes captured in the preceding minute,
  including MAC addresses when available. This identifies possible
  contributors, not proven causes.
- A "What to do next" panel with capture setup help, gateway health, recent
  private-LAN sender share, port-80 observations, unidentified LAN peers, ARP
  patterns, and capture-drop guidance. Advice is based only on packets visible
  to the selected adapter and is not a full security assessment.
- Password show/hide controls and live registration-password requirement checks.
- Dedicated About, team, quick tutorial, and FAQ page (`about.html`) linked
  from both the sign-in screen and dashboard header, with navigation back to
  the main dashboard.

WINDOWS QUICK START
Use Python 3.10 or later.
1. Open PowerShell in this folder.
2. Create and activate a virtual environment (recommended):
     py -m venv .venv
     .venv\Scripts\activate
3. Install dependencies:
     py -m pip install -r requirements.txt
4. Install Npcap from https://npcap.com/ (required by Scapy on Windows).
   During installation, enable WinPcap API-compatible mode if offered.
5. Configure Firebase Authentication and Firestore in your Windows System (or User)
   Environment Variables:
     - Set FIREBASE_WEB_API_KEY to the Firebase Web API key.
     - Set FIREBASE_SERVICE_ACCOUNT_PATH to the full path of your Firebase
       service-account JSON file (or set GOOGLE_APPLICATION_CREDENTIALS to that
       path, or FIREBASE_SERVICE_ACCOUNT_JSON to the JSON contents).
     - Never put the service-account JSON in this folder, commit it, or
       distribute it. It grants administrator access.
6. Run the terminal as Administrator if packet capture permissions require it.
7. Start LAN Traffic Analyzer:
   - Desktop window mode (loads the UI directly via pywebview with no HTTP server or open localhost port):
     py desktop_app.py
   - Or browser mode:
     py web_server.py
     and open http://127.0.0.1:5000 in your browser.

SECURITY AND DATA
- The server binds to 127.0.0.1, rejects non-local Host/Origin/Sec-Fetch-Site
  requests, and adds nosniff/X-Frame-Options/Referrer-Policy/no-store headers.
  Do not expose it to your LAN or the internet; it is a personal local app, not
  a multi-user deployment.
- The browser receives only a random, signed session identifier. Firebase
  refresh tokens remain on the Python server in memory for the current server
  session.
- Each run creates a MessagePack packet file in session_packets/. Clear starts
  a new file without deleting previous captures.
- Files opened from elsewhere are uploaded only to this local server's temporary
  directory and removed when opening another file, logging out, or shutting
  down. Uploads are limited to 256 MB.
- CSV files are encrypted with PBKDF2 and Fernet (with spreadsheet formula-prefix
  neutralization). PDF files use AES-256 password encryption and cap the packet
  table at 5,000 rows (full packet records remain available in encrypted CSV).
  Use the "Decrypt CSV…" button or `py export.py` to decrypt CSV files before
  opening them in a spreadsheet program.
- Capture may require administrator/root privileges and a supported capture
  backend. Captured traffic is limited to packets visible on the selected
  adapter; switched networks generally do not expose all other devices'
  unicast traffic. Neighboring devices appear passively from observed traffic.
- Congestion is inferred from gateway checks (at least 150 ms median latency
  or 20% packet loss across recent checks). Source attribution is based only on
  packets visible to the selected adapter and is not causal proof.

TROUBLESHOOTING
- Sign-in setup error: check your FIREBASE_WEB_API_KEY and
  FIREBASE_SERVICE_ACCOUNT_PATH (or FIREBASE_SERVICE_ACCOUNT_JSON /
  GOOGLE_APPLICATION_CREDENTIALS) system environment variables.
- No adapters: check Scapy/Npcap installation and run the terminal as
  Administrator.
- Start fails: choose an active adapter and check the error shown by the page
  and the Python terminal.
- Blank page: keep the server terminal running and refresh the browser.

CUSTOMIZING FIREBASE VERIFICATION PAGE & EMAIL BRANDING
1. In Firebase Console -> Project Settings -> General, set the "Public-facing name"
   to "LAN Traffic Analyzer" so verification emails no longer say "packet-sniffer-auth".
2. Deploy `firebase_hosting/auth-action.html` using Firebase Hosting:
     cd firebase_hosting
     firebase login
     firebase use packet-sniffer-auth
     firebase deploy --only hosting
3. In Firebase Console -> Authentication -> Templates -> Email address verification,
   click Edit -> Customize action URL and set it to:
     https://packet-sniffer-auth.web.app/auth-action.html

