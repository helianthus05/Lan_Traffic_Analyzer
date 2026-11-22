LAN WATCH — WEB VERSION

WHAT THIS IS
This local web dashboard includes the traffic-analyzer features from the
Tkinter application. The Python server performs packet capture and authentication;
the browser only displays data and sends local requests to that server.

FEATURES
- Firebase sign-in, registration, Gmail verification, resend-verification, and
  logout.
- Optional "keep me signed in until Windows restarts" using Windows DPAPI.
- Interface selection and refresh, live Scapy capture, stop, and clear.
- Capture totals, averages, top talkers, 60-second packet-rate and bandwidth
  charts, and incoming/outgoing and protocol summaries.
- A live plain-language traffic explanation with packet totals, recent rates,
  leading IPv4 sender, common protocol, and any relevant port-80 or ARP notes.
- IPv4 client list with IP/MAC, role, traffic, protocol, and first/last-seen
  details, plus an IPv4-only subnet tree. IPv6 packets are still captured and
  remain available in packet records and exports.
- Optional-at-capture-start IPv4 device discovery using a local ARP sweep
  plus one ping per host on the selected private subnet, limited to at most
  256 addresses. ARP can identify devices that block ICMP ping and supplies
  their MAC addresses when they answer ARP.
- Search and filters for protocol, addresses, ports, packet size, and time.
  Double-click a packet to inspect its fields.
- Password-encrypted CSV/PDF export for filtered results, selected packets,
  or a complete network report.
- Open and page through saved MessagePack captures in session_packets/ or
  choose a .msgpack file from elsewhere on the computer. Saved captures include
  a network report with a client list, subnet tree, protocol summary, gateway
  health, and data-based advice. Health is the live gateway check at report
  generation because historical health is not stored in packet files. New
  captures retain observed MAC addresses; older captures may not contain them.
- Default-gateway response, latency, and packet-loss status.
- Compact navy-header/light dashboard styling, with No activity, healthy, and
  congestion states. A congestion warning lists top observed private-LAN
  senders by bytes captured in the preceding minute, including MAC addresses
  when available. This identifies possible contributors, not proven causes.
- A "What to do next" panel with capture setup help, gateway health, recent
  private-LAN sender share, port-80 observations, unidentified LAN peers, ARP
  patterns, and capture-drop guidance. Advice is based only on packets visible
  to the selected adapter and is not a full security assessment.
- Password show/hide controls and live registration-password requirement checks.
- About, team, quick tutorial, and FAQ sections at the bottom of the dashboard,
  covering capture/export steps, visibility, discovery, permissions, privacy,
  and downloads.

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
5. Configure Firebase Authentication and Firestore as used by the Tkinter
   version:
     - Set FIREBASE_WEB_API_KEY to the Firebase Web API key.
     - Place the Firebase service-account JSON in the workspace parent folder,
       or set FIREBASE_SERVICE_ACCOUNT_PATH to its full path.
     - Never put the service-account JSON in this web folder, commit it, or
       distribute it. It grants administrator access.
6. Run the terminal as Administrator if packet capture permissions require it.
7. Start the server:
     py web_server.py
8. Open http://127.0.0.1:5000 in your browser.

SECURITY AND DATA
- The server binds to 127.0.0.1 and rejects non-local Host/Origin requests.
  Do not expose it to your LAN or the internet; it is a personal local app, not
  a multi-user deployment.
- The browser receives only a random, signed session identifier. Firebase
  refresh tokens remain on the Python server. If "keep signed in" is selected,
  the refresh token is protected with Windows DPAPI and invalidated after a
  Windows restart.
- Each run creates a MessagePack packet file in session_packets/. Clear starts
  a new file without deleting previous captures.
- Files opened from elsewhere are uploaded only to this local server's temporary
  directory and removed at logout or server shutdown. Uploads are limited to
  256 MB.
- CSV files are encrypted with PBKDF2 and Fernet. PDF files use AES-256
  password encryption. Encrypted CSV data must be decrypted before opening it
  in a spreadsheet program.
- Capture may require administrator/root privileges and a supported capture
  backend. Captured traffic is limited to packets visible on the selected
  adapter; switched networks generally do not expose all other devices'
  unicast traffic.
- Active discovery is limited to the selected private IPv4 subnet (maximum
  256 addresses). ARP works only on the local Layer-2 network and does not
  cross routers or VLAN boundaries. ARP discovery may require Administrator
  or root privileges; if unavailable, the existing ping fallback still runs.
- Congestion is inferred from gateway checks (at least 150 ms median latency
  or 20% packet loss across recent checks). Source attribution is based only on
  packets visible to the selected adapter and is not causal proof.

TROUBLESHOOTING
- Sign-in setup error: check FIREBASE_WEB_API_KEY and the service-account path.
- No adapters: check Scapy/Npcap installation and run the terminal as
  Administrator.
- Start fails: choose an active adapter and check the error shown by the page
  and the Python terminal.
- Blank page: keep the server terminal running and refresh the browser.
