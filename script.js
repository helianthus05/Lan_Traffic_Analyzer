const $ = selector => document.querySelector(selector);
const MAX_PACKETS = 3000;
const PAGE_SIZE = 200;
let S;
let pollTimer = null;
let renderTimer = null;
let healthTimer = null;
let discoveryTimer = null;
let selectedIp = "";
let filteredPackets = null;
let filteredTotal = 0;
let currentFilters = {};
let selectedPackets = new Map();
let stopComplete = null;
let savedOffset = 0;
let savedTotal = 0;
let viewerToken = "";
let savedReportSource = null;
let gatewayHealthState = "checking";
let gatewayHealthDescription = "Checking the default gateway response.";
let captureStartTotal = 0;
let captureStartedAt = 0;
let congestionAlertActive = false;
let droppedPacketCount = 0;

const blank = () => ({
  run: false, packets: [], total: 0, bytes: 0, src: {}, dst: {}, srcBytes: {}, dstBytes: {}, protocols: {},
  clients: {}, historyPackets: Array(60).fill(0), historyBytes: Array(60).fill(0),
  intervalPackets: 0, intervalBytes: 0, http: false, arp: 0
});
S = blank();

function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value.toFixed(0)} B`;
  if (value < 1048576) return `${(value / 1024).toFixed(2)} KB`;
  if (value < 1073741824) return `${(value / 1048576).toFixed(2)} MB`;
  return `${(value / 1073741824).toFixed(2)} GB`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[char]));
}

function isIPv4Address(ip) {
  const octets = String(ip || "").split(".").map(Number);
  return octets.length === 4 &&
    octets.every(value => Number.isInteger(value) && value >= 0 && value <= 255);
}

function isLan(ip) {
  const value = String(ip || "").toLowerCase();
  if (isIPv4Address(value)) {
    const octets = value.split(".").map(Number);
    return octets[0] === 10 ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168) ||
      (octets[0] === 169 && octets[1] === 254);
  }
  return value.startsWith("fc") || value.startsWith("fd") || value.startsWith("fe80:");
}

function client(ip, mac, found = "Traffic") {
  if (!isLan(ip)) return null;
  let record = S.clients[ip];
  if (!record) {
    record = S.clients[ip] = {
      mac: mac || "", network: "", sent: 0, received: 0, sentBytes: 0, receivedBytes: 0,
      protocols: new Set(), found: new Set(), first: "", last: ""
    };
  }
  if (mac && !record.mac) record.mac = mac;
  record.found.add(found);
  return record;
}

function addPacket(packet) {
  const src = packet.src || "Unknown";
  const dst = packet.dst || "Unknown";
  const protocol = packet.pr || "Other";
  const length = Number(packet.len) || 0;
  const stamp = packet.timestamp || packet.time || "";
  const timestamp = stamp.split(" ").slice(-1)[0];
  S.total++;
  S.bytes += length;
  S.intervalPackets++;
  S.intervalBytes += length;
  S.src[src] = (S.src[src] || 0) + 1;
  S.dst[dst] = (S.dst[dst] || 0) + 1;
  S.srcBytes[src] = (S.srcBytes[src] || 0) + length;
  S.dstBytes[dst] = (S.dstBytes[dst] || 0) + length;
  S.protocols[protocol] = (S.protocols[protocol] || 0) + 1;
  if (protocol === "ARP") S.arp++;
  if (Number(packet.sport) === 80 || Number(packet.dport) === 80) S.http = true;

  const sender = client(src, packet.src_mac);
  if (sender) {
    sender.sent++;
    sender.sentBytes += length;
    sender.protocols.add(protocol);
    if (!sender.first) sender.first = timestamp;
    sender.last = timestamp;
  }
  const receiver = client(dst, packet.dst_mac);
  if (receiver) {
    receiver.received++;
    receiver.receivedBytes += length;
    receiver.protocols.add(protocol);
    if (!receiver.first) receiver.first = timestamp;
    receiver.last = timestamp;
  }
  S.packets.push({
    ...packet, no: packet.no || S.total, timestamp: stamp,
    time: timestamp, src, dst, pr: protocol, len: length
  });
  if (S.packets.length > MAX_PACKETS) S.packets.shift();
}

function topList(counter, selector) {
  const entries = Object.entries(counter)
    .filter(([address]) => isIPv4Address(address))
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  const peak = entries[0]?.[1] || 1;
  $(selector).innerHTML = entries.length
    ? entries.map(([address, count]) => `<div class="row"><code>${escapeHtml(address)}</code><div class="meter"><i style="width:${count / peak * 100}%"></i></div><span>${count.toLocaleString()}</span></div>`).join("")
    : '<span class="sub">Nothing yet</span>';
}

function graph(selector, values, format) {
  const canvas = $(selector);
  if (!canvas) return;
  const width = canvas.width = Math.max(1, canvas.clientWidth * 2);
  const height = canvas.height = 180;
  const context = canvas.getContext("2d");
  const peak = Math.max(1, ...values);
  const color = getComputedStyle(document.documentElement).getPropertyValue("--teal").trim();
  context.clearRect(0, 0, width, height);
  context.strokeStyle = color;
  context.lineWidth = 3;
  context.beginPath();
  values.forEach((value, index) => {
    const x = index / 59 * width;
    const y = height - 6 - value / peak * (height - 16);
    if (index) context.lineTo(x, y);
    else context.moveTo(x, y);
  });
  context.stroke();
  context.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--mute").trim();
  context.font = "22px sans-serif";
  context.fillText(`peak ${format(peak)}`, 6, 20);
}

function setHealth(state, description) {
  const element = $("#health");
  const titles = {
    checking: "NETWORK STATUS CHECKING",
    no_activity: "NO ACTIVITY",
    healthy: "NETWORK HEALTHY",
    congested: "POSSIBLE NETWORK CONGESTION",
    unreachable: "GATEWAY NOT RESPONDING",
    unavailable: "NETWORK STATUS UNAVAILABLE"
  };
  const stateClass = {
    no_activity: "no-activity",
    healthy: "ok",
    congested: "bad",
    unreachable: "bad"
  }[state] || "";
  element.className = `health ${stateClass}`;
  element.innerHTML = `<b>${escapeHtml(titles[state] || "Network status")}</b><span>${escapeHtml(description)}</span>`;
}

function updateDisplayedHealth() {
  if (S.run && S.total === captureStartTotal && gatewayHealthState !== "congested") {
    setHealth("no_activity", "Capture is running, but no packets have been received yet.");
    return;
  }
  if (S.run && S.total > captureStartTotal && gatewayHealthState === "healthy") {
    setHealth("healthy", `${gatewayHealthDescription} Capture is receiving packets.`);
    return;
  }
  setHealth(gatewayHealthState, gatewayHealthDescription);
}

function showCongestionWarning(description) {
  // Do not attribute congestion to individual LAN devices: packet capture on
  // this adapter cannot establish which device caused gateway latency/loss.
  $("#congestionDescription").textContent = description;
  const dialog = $("#congestionDialog");
  if (!dialog.open) dialog.showModal();
}

function advice() {
  const result = [];
  if (S.run && S.total === captureStartTotal &&
      gatewayHealthState !== "congested" && gatewayHealthState !== "unreachable") {
    return [["", "No packets observed yet", "Capture is running, but no packets have arrived from the selected adapter.", "Confirm the correct Wi-Fi/Ethernet adapter is selected and that packet capture permissions are available."]];
  }
  if (!S.total && gatewayHealthState !== "congested" && gatewayHealthState !== "unreachable") {
    return [["", "Waiting for a capture", "There is no traffic data to assess yet.", "Select the active network adapter and start capture."]];
  }
  if (gatewayHealthState === "congested") {
    result.push([
      "bad",
      "The network may be congested",
      "The gateway is responding slowly or losing packets. The capture cannot identify which device, if any, is responsible.",
      "Check gateway response from another device and inspect router-level diagnostics. LAN Watch does not assign congestion to individual devices."
    ]);
  } else if (gatewayHealthState === "unreachable") {
    result.push([
      "bad",
      "The gateway is not responding",
      "Ping checks did not receive a reply. Some gateways block ping, so this alone does not confirm an outage.",
      "Check the router and Wi-Fi/Ethernet connection, then compare with another device."
    ]);
  } else if (gatewayHealthState === "healthy") {
    result.push([
      "ok",
      "Gateway response looks healthy",
      gatewayHealthDescription,
      "No immediate gateway action is suggested. Continue monitoring if users still notice slow connections."
    ]);
  }



  if (S.http) {
    result.push([
      "warn",
      "Traffic used port 80",
      "Port 80 is commonly used for unencrypted HTTP, but the port alone cannot confirm what data was sent.",
      "Check the application and destination. Use HTTPS for sign-ins and sensitive information."
    ]);
  }

  const unknown = Object.entries(S.clients).filter(([ip, record]) =>
    isIPv4Address(ip) && !record.name && ip !== selectedIp && localRole(ip) !== "Gateway (likely)"
  );
  if (unknown.length) {
    const devices = unknown.slice(0, 3).map(([ip, record]) =>
      `${ip} (${record.mac || "MAC not observed"})`
    ).join(", ");
    result.push([
      "warn",
      `${unknown.length} LAN device(s) need identification`,
      `Observed peers: ${devices}${unknown.length > 3 ? `, and ${unknown.length - 3} more` : ""}.`,
      "Compare the IP and MAC addresses with your router’s connected-device list; this dashboard cannot determine device ownership."
    ]);
  }

  if (S.total >= 20 && S.arp / S.total >= 0.25) {
    result.push([
      "warn",
      "A large share of observed packets is ARP",
      `${((S.arp / S.total) * 100).toFixed(0)}% of captured packets are ARP. This can happen during normal discovery, but a sustained burst may be worth checking.`,
      "If the pattern continues, review the client list and router for repeated address discovery or duplicate IP warnings."
    ]);
  }

  if (droppedPacketCount > 0) {
    result.push([
      "warn",
      "Some captured packets were dropped",
      `${droppedPacketCount.toLocaleString()} packet(s) could not be queued for display/storage.`,
      "Reduce other system load or capture for a shorter period; totals and advice may be incomplete."
    ]);
  }

  if (!result.length) {
    result.push([
      "ok",
      "No immediate action suggested",
      `Captured ${S.total.toLocaleString()} packet(s), ${formatBytes(S.bytes)} total, across ${Object.keys(S.src).length} source address(es).`,
      "Review unfamiliar devices and destinations. This dashboard is a traffic monitor, not a complete security audit."
    ]);
  }
  return result;
}

function renderAdvice() {
  $("#adv").innerHTML = advice().map(item =>
    `<div class="adv ${item[0]}"><b>${escapeHtml(item[1])}</b><p>${escapeHtml(item[2])}</p><p><em>Do this:</em> ${escapeHtml(item[3])}</p></div>`
  ).join("");
}

function renderPies() {
  const total = S.total || 1;
  const incoming = S.dst[selectedIp] || 0;
  const outgoing = S.src[selectedIp] || 0;
  const other = Math.max(0, S.total - incoming - outgoing);
  const tcp = S.protocols.TCP || 0;
  const udp = S.protocols.UDP || 0;
  const otherProtocols = Math.max(0, S.total - tcp - udp);
  const makePie = (values, labels, colors, title) => {
    let position = 0;
    const gradient = values.map((value, index) => {
      const start = position;
      position += value / total * 100;
      return `${colors[index]} ${start}% ${position}%`;
    }).join(", ");
    const legend = values.map((value, index) =>
      `<div><i style="background:${colors[index]}"></i>${labels[index]}: ${value.toLocaleString()} (${(value / total * 100).toFixed(1)}%)</div>`
    ).join("");
    return `<div class="pie"><div class="donut" style="background:conic-gradient(${gradient})" role="img" aria-label="${title}"></div><div class="leg"><b>${title}</b>${legend}</div></div>`;
  };
  $("#pies").innerHTML = makePie(
    [incoming, outgoing, other], ["Incoming", "Outgoing", "Other"],
    ["var(--in)", "var(--out)", "var(--gray)"], "Direction"
  ) + makePie(
    [tcp, udp, otherProtocols], ["TCP", "UDP", "Other"],
    ["var(--tcp)", "var(--udp)", "var(--gray)"], "Protocol"
  ) + '<p class="sub" style="width:100%">Direction is based on the selected adapter’s IPv4 address where available; the charts summarize the current in-memory capture.</p>';
}

function localRole(ip) {
  if (ip === selectedIp) return "This device";
  if (ip.endsWith(".1") || ip.endsWith(".254")) return "Gateway (likely)";
  return "Client";
}

function networkOf(ip) {
  if (ip.includes(".")) return ip.split(".").slice(0, 3).join(".") + ".0/24";
  return ip.split(":").slice(0, 4).join(":") + "::/64";
}

function renderClients() {
  const entries = Object.entries(S.clients)
    .filter(([ip]) => isIPv4Address(ip))
    .sort((a, b) => a[0].localeCompare(b[0]));
  $("#cn").textContent = entries.length.toLocaleString();
  $("#cb").innerHTML = entries.map(([ip, record]) => {
    const data = record.sentBytes + record.receivedBytes;
    return `<tr><td class="m">${escapeHtml(ip)}</td><td>${escapeHtml(record.name || "Unknown device")}</td><td class="m">${escapeHtml(record.mac || "—")}</td><td>${localRole(ip)}</td><td>${record.sent.toLocaleString()}</td><td>${record.received.toLocaleString()}</td><td>${formatBytes(data)}</td><td>${escapeHtml([...record.protocols].sort().join(", ") || "—")}</td><td>${escapeHtml([...record.found].join(" + "))}</td><td>${escapeHtml(record.first || "—")}</td><td>${escapeHtml(record.last || "—")}</td></tr>`;
  }).join("") || '<tr><td colspan="11">No devices observed yet. Start capture to discover devices passively.</td></tr>';

  const networks = new Map();
  entries.forEach(([ip, record]) => {
    const network = record.network || networkOf(ip);
    if (!networks.has(network)) networks.set(network, []);
    networks.get(network).push([ip, record]);
  });
  $("#v2").innerHTML = entries.length
    ? `<ul>${[...networks].sort(([a], [b]) => a.localeCompare(b)).map(([network, devices]) =>
      `<li><b>Network ${escapeHtml(network)}</b><ul>${devices.map(([ip, record]) =>
        `<li>${escapeHtml(ip)} · ${localRole(ip)} · ${escapeHtml(record.mac || "—")} <small>${formatBytes(record.sentBytes + record.receivedBytes)}</small></li>`
      ).join("")}</ul></li>`
    ).join("")}</ul>`
    : '<span class="sub">No devices observed.</span>';
}

function addDiscoveredHosts(hosts, network) {
  const foundAt = new Date().toLocaleTimeString();
  hosts.forEach(host => {
    const methods = Array.isArray(host.methods) && host.methods.length
      ? host.methods : ["Ping scan"];
    const record = client(host.ip, host.mac, methods[0]);
    if (!record) return;
    if (network) record.network = network;
    methods.forEach(method => record.found.add(method));
    if (!record.first) record.first = foundAt;
    record.last = foundAt;
  });
  renderClients();
}

async function pollDiscovery() {
  if (discoveryTimer) clearTimeout(discoveryTimer);
  try {
    const result = await api("/api/discovery");
    addDiscoveredHosts(result.hosts || [], result.network);
    if (result.running) {
      $("#scanmsg").textContent = `Discovering devices with ARP and ping on ${result.network || "the selected subnet"}…`;
      discoveryTimer = setTimeout(pollDiscovery, 900);
    } else if (result.error) {
      $("#scanmsg").textContent = `IPv4 device discovery failed: ${result.error}`;
    } else if (result.complete) {
      const hosts = result.hosts || [];
      const count = hosts.length;
      const arpCount = hosts.filter(host => (host.methods || []).includes("ARP scan")).length;
      const summary = count
        ? `${count} device(s) discovered on ${result.network} (${arpCount} with MAC addresses via ARP).`
        : `No devices responded to ARP or ping on ${result.network}.`;
      $("#scanmsg").textContent = result.warning ? `${summary} ${result.warning}` : summary;
    }
  } catch (error) {
    $("#scanmsg").textContent = `IPv4 discovery status unavailable: ${error.message}`;
  }
}

function renderLiveSummary() {
  const output = $("#liveSummaryText");
  if (!S.total) {
    output.textContent = S.run
      ? "Capture is running, but no packets have arrived yet. Check that the selected adapter is active."
      : "Start a capture to see a plain-language explanation of the traffic.";
    return;
  }
  if (S.run && S.total === captureStartTotal) {
    output.textContent =
      `Capture is running, but no new packets have arrived since you started it. ` +
      `This view still contains ${S.total.toLocaleString()} earlier packet(s).`;
    return;
  }

  const seconds = captureStartedAt
    ? Math.max(1, Math.min(60, (Date.now() - captureStartedAt) / 1000))
    : 60;
  const recentPackets = [...S.historyPackets, S.intervalPackets]
    .slice(-60)
    .reduce((sum, value) => sum + value, 0);
  const recentBytes = [...S.historyBytes, S.intervalBytes]
    .slice(-60)
    .reduce((sum, value) => sum + value, 0);
  const ipv4Senders = Object.entries(S.src)
    .filter(([ip]) => isIPv4Address(ip))
    .sort((a, b) => b[1] - a[1]);
  const ipv4PacketTotal = ipv4Senders.reduce((sum, [, count]) => sum + count, 0);
  const topSender = ipv4Senders[0];
  const topProtocol = Object.entries(S.protocols).sort((a, b) => b[1] - a[1])[0];
  const ipv4ClientCount = Object.keys(S.clients).filter(isIPv4Address).length;
  const sentences = [
    `${S.total.toLocaleString()} packet(s) have been recorded in this view, carrying ${formatBytes(S.bytes)} in total; that averages ${formatBytes(S.bytes / S.total)} per packet.`
  ];

  if (S.run) {
    const newPackets = Math.max(0, S.total - captureStartTotal);
    sentences.push(
      `${newPackets.toLocaleString()} new packet(s) have arrived since Start. ` +
      `Over the last ${Math.round(seconds)} seconds, traffic averaged ` +
      `${(recentPackets / seconds).toFixed(1)} packets/s and ${formatBytes(recentBytes / seconds)}/s.`
    );
  } else {
    sentences.push(
      `The last ${Math.round(seconds)} seconds averaged ${(recentPackets / seconds).toFixed(1)} packets/s ` +
      `and ${formatBytes(recentBytes / seconds)}/s.`
    );
  }

  if (topSender && ipv4PacketTotal) {
    sentences.push(
      `The busiest IPv4 sender was ${topSender[0]} (${topSender[1].toLocaleString()} packets, ` +
      `${(topSender[1] / ipv4PacketTotal * 100).toFixed(0)}% of observed IPv4-sourced packets).`
    );
  } else {
    sentences.push("No IPv4 sender was identified in the captured packets.");
  }
  sentences.push(
    topProtocol
      ? `${topProtocol[0]} was the most common protocol (${topProtocol[1].toLocaleString()} of ${S.total.toLocaleString()} packets); ${ipv4ClientCount} IPv4 device(s) were identified.`
      : `No protocol breakdown is available; ${ipv4ClientCount} IPv4 device(s) were identified.`
  );
  if (S.http) sentences.push("Port 80 was observed; it can indicate unencrypted HTTP, but the port alone does not reveal what data was sent.");
  if (S.arp && S.arp / S.total >= 0.25) sentences.push("ARP address-discovery traffic makes up a noticeable share of this capture.");
  sentences.push("IPv6 packets remain captured and included in totals, but device lists show IPv4 only.");
  output.textContent = sentences.join(" ");
}

function packetKey(packet) {
  return packet.id !== undefined && packet.id !== null ? `id:${packet.id}` : `no:${packet.no}`;
}

function packetRow(packet) {
  const key = packetKey(packet);
  const selected = selectedPackets.has(key);
  return `<tr data-packet-key="${escapeHtml(key)}"><td><input type="checkbox" class="packet-select" data-key="${escapeHtml(key)}" aria-label="Select packet ${escapeHtml(packet.id ?? packet.no)}" ${selected ? "checked" : ""}></td><td>${escapeHtml(packet.id ?? packet.no)}</td><td class="m">${escapeHtml(packet.time || packet.timestamp || "")}</td><td class="m">${escapeHtml(packet.src ?? packet.source_ip ?? "")}</td><td class="m">${escapeHtml(packet.dst ?? packet.destination_ip ?? "")}</td><td><span class="tag">${escapeHtml(packet.pr ?? packet.protocol ?? "Other")}</span></td><td>${escapeHtml(packet.len ?? packet.length ?? 0)}</td><td>${escapeHtml(packet.info || "")}</td></tr>`;
}

function renderPackets() {
  const query = $("#q").value.trim().toLowerCase();
  const protocol = $("#pf").value;
  const sourceFilter = $("#sourceFilter").value.trim().toLowerCase();
  const destinationFilter = $("#destinationFilter").value.trim().toLowerCase();
  let rows;
  let total;
  if (filteredPackets) {
    rows = filteredPackets;
    total = filteredTotal;
  } else {
    rows = S.packets.filter(packet => {
      const source = String(packet.src || "").toLowerCase();
      const destination = String(packet.dst || "").toLowerCase();
      const searchable = `${source} ${destination} ${packet.info || ""} ${packet.pr || ""} ${packet.sport || ""} ${packet.dport || ""}`.toLowerCase();
      return (!query || searchable.includes(query)) &&
        (protocol === "All" || packet.pr === protocol) &&
        (!sourceFilter || source.includes(sourceFilter)) &&
        (!destinationFilter || destination.includes(destinationFilter));
    });
    total = rows.length;
  }
  const visible = filteredPackets ? rows.slice(0, 60) : rows.slice(-60).reverse();
  $("#pb").innerHTML = visible.map(packetRow).join("") || '<tr><td colspan="8">No packets match.</td></tr>';
  $("#pc").textContent = `${filteredPackets ? `Showing ${Math.min(rows.length, 2000).toLocaleString()} of ${filteredTotal.toLocaleString()} matching packets${filteredTotal > 2000 ? " (display limited to 2,000)" : ""}` : `Showing ${Math.min(60, total).toLocaleString()} of ${total.toLocaleString()} recent matching packets.`}`;
  $("#selectedCount").textContent = `${selectedPackets.size.toLocaleString()} selected`;
  const visibleKeys = new Set(visible.map(packetKey));
  $("#selectAll").checked = visible.length > 0 && visible.every(packet => selectedPackets.has(packetKey(packet)));
  $("#selectAll").indeterminate = visible.some(packet => selectedPackets.has(packetKey(packet))) && !$("#selectAll").checked;
  $("#pb").dataset.visibleKeys = [...visibleKeys].join(",");
}

function render() {
  $("#tp").textContent = S.total.toLocaleString();
  $("#td").textContent = formatBytes(S.bytes);
  $("#ta").textContent = formatBytes(S.total ? S.bytes / S.total : 0);
  topList(S.src, "#ts");
  topList(S.dst, "#tr");
  renderClients();
  renderPackets();
  graph("#g1", S.historyPackets, value => `${value}/s`);
  graph("#g2", S.historyBytes, value => `${formatBytes(value)}/s`);
  renderLiveSummary();
  updateDisplayedHealth();
  renderAdvice();
}

function setCaptureControls(running, stopping = false) {
  $("#start").disabled = running || stopping;
  $("#stop").disabled = !running || stopping;
  $("#iface").disabled = running || stopping;
  $("#discoverIpv4").disabled = running || stopping;
  $("#refreshInterfaces").disabled = running || stopping;
  $("#start").className = running ? "on" : "";
  $("#stop").className = !running && S.total ? "on" : "";
}

function showAuthGate(show, notice = "") {
  $("#authGate").hidden = !show;
  $("#authNotice").textContent = notice;
  if (show) {
    stopTimers();
    $("#resendVerification").hidden = true;
  }
}

function stopTimers() {
  if (pollTimer) clearInterval(pollTimer);
  if (renderTimer) clearInterval(renderTimer);
  if (healthTimer) clearInterval(healthTimer);
  if (discoveryTimer) clearTimeout(discoveryTimer);
  pollTimer = renderTimer = healthTimer = discoveryTimer = null;
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 && !url.startsWith("/api/auth/")) {
    showAuthGate(true, "Your sign-in expired. Please sign in again.");
  }
  if (!response.ok) {
    const error = new Error(data.error || `Request failed (${response.status})`);
    error.needsVerification = Boolean(data.needs_verification);
    throw error;
  }
  return data;
}

function setAuthTab(tab) {
  const login = tab === "login";
  $("#loginTab").setAttribute("aria-selected", String(login));
  $("#registerTab").setAttribute("aria-selected", String(!login));
  $("#loginForm").hidden = !login;
  $("#registerForm").hidden = login;
  $("#authNotice").textContent = "";
  $("#resendVerification").hidden = true;
}

async function authStatus() {
  try {
    const data = await api("/api/auth/status");
    if (!data.configured) {
      showAuthGate(true, "Firebase sign-in is not configured. Set FIREBASE_WEB_API_KEY and FIREBASE_SERVICE_ACCOUNT_PATH on the local server.");
      return;
    }
    if (!data.authenticated) {
      showAuthGate(true, data.restore_error || "");
      return;
    }
    showDashboard(data.user, data.restored);
  } catch (error) {
    showAuthGate(true, `Authentication service unavailable: ${error.message}`);
  }
}

function showDashboard(user, restored = false) {
  showAuthGate(false);
  $("#signedInUser").textContent = user ? `Signed in as ${user.username || user.email}` : "";
  if (restored) $("#servermsg").textContent = "Saved sign-in restored for this Windows session.";
  updateDisplayedHealth();
  loadInterfaces();
  checkHealth();
  healthTimer = setInterval(checkHealth, 5000);
}

async function loadInterfaces() {
  try {
    const data = await api("/api/interfaces");
    const select = $("#iface");
    select.innerHTML = "";
    data.interfaces.forEach(item => {
      const option = document.createElement("option");
      option.value = item.name;
      option.textContent = `${item.name} · ${item.ip || "no IPv4"}${item.is_default_route ? " (default route)" : ""}`;
      option.dataset.ip = item.ip || "";
      select.append(option);
    });
    if (!data.interfaces.length) select.innerHTML = '<option value="">No interfaces found</option>';
    const preferred = data.interfaces.find(item => item.is_default_route) ||
      data.interfaces.find(item => item.ip && !item.is_loopback);
    if (preferred) {
      select.value = preferred.name;
      selectedIp = preferred.ip || "";
    }
    $("#servermsg").textContent = `${data.interfaces.length} interface(s) found`;
    render();
  } catch (error) {
    $("#servermsg").textContent = error.message;
  }
}

async function startCapture() {
  try {
    const interfaceName = $("#iface").value;
    if (!interfaceName) throw new Error("No network interface is selected.");
    const result = await api("/api/capture/start", {
      method: "POST",
      body: JSON.stringify({
        interface: interfaceName,
        discover: $("#discoverIpv4").checked
      })
    });
    selectedIp = $("#iface").selectedOptions[0]?.dataset.ip || "";
    droppedPacketCount = 0;
    captureStartTotal = S.total;
    captureStartedAt = Date.now();
    S.historyPackets.fill(0);
    S.historyBytes.fill(0);
    S.intervalPackets = S.intervalBytes = 0;
    S.run = true;
    $("#pies").innerHTML = '<span class="sub">Capture in progress. Stop to review the breakdown.</span>';
    setCaptureControls(true);
    $("#servermsg").textContent = `Capturing on ${interfaceName}`;
    pollTimer = setInterval(receivePackets, 350);
    renderTimer = setInterval(advanceGraphs, 1000);
    if (result.discovery_started) {
      $("#scanmsg").textContent = "Discovering devices on the selected private IPv4 subnet…";
      pollDiscovery();
    } else if ($("#discoverIpv4").checked) {
      $("#scanmsg").textContent = result.discovery_error || "IPv4 device discovery could not be started.";
    } else {
      $("#scanmsg").textContent = "Subnet discovery is off; devices may still appear from captured packets.";
    }
    render();
  } catch (error) {
    $("#servermsg").textContent = error.message;
  }
}

function stopCapture() {
  if (!S.run || stopComplete) return stopComplete;
  stopComplete = new Promise(resolve => {
    stopResolve = resolve;
  });
  api("/api/capture/stop", { method: "POST" }).then(() => {
    setCaptureControls(false, true);
    $("#servermsg").textContent = "Stopping capture…";
  }).catch(error => {
    $("#servermsg").textContent = error.message;
    stopResolve?.();
    stopComplete = null;
  });
  return stopComplete;
}
let stopResolve = null;

async function finishStop() {
  S.run = false;
  setCaptureControls(false);
  if (pollTimer) clearInterval(pollTimer);
  if (renderTimer) clearInterval(renderTimer);
  pollTimer = renderTimer = null;
  render();
  renderPies();
  $("#servermsg").textContent = "Capture stopped";
  const resolve = stopResolve;
  stopResolve = null;
  stopComplete = null;
  if (resolve) resolve();
}

async function receivePackets() {
  try {
    const data = await api("/api/packets?limit=1000");
    data.packets.forEach(addPacket);
    droppedPacketCount = Number(data.dropped) || 0;
    if (data.dropped) $("#servermsg").textContent = `Capturing · ${data.dropped} packet(s) dropped due to queue pressure`;
    if (data.error) $("#servermsg").textContent = `Capture/storage warning: ${data.error}`;
    render();
    if (!data.capturing && !data.stopping && S.run) await finishStop();
    else if (data.stopping) setCaptureControls(false, true);
  } catch (error) {
    $("#servermsg").textContent = `Backend connection lost: ${error.message}`;
  }
}

function advanceGraphs() {
  S.historyPackets.push(S.intervalPackets);
  S.historyPackets.shift();
  S.historyBytes.push(S.intervalBytes);
  S.historyBytes.shift();
  S.intervalPackets = S.intervalBytes = 0;
  render();
}

async function clearCapture() {
  if (S.run) await stopCapture();
  try {
    await api("/api/capture/clear", { method: "POST" });
    S = blank();
    filteredPackets = null;
    filteredTotal = 0;
    currentFilters = {};
    selectedPackets.clear();
    droppedPacketCount = 0;
    clearFilterFields();
    setCaptureControls(false);
    $("#pies").innerHTML = '<span class="sub">Press Start, then Stop to see the breakdown.</span>';
    $("#servermsg").textContent = "Cleared current capture; the previous packet file was preserved.";
  } catch (error) {
    $("#servermsg").textContent = error.message;
  }
  render();
}

function readFilters() {
  const filters = {
    search: $("#q").value.trim(),
    protocol: $("#pf").value,
    source_ip: $("#sourceFilter").value.trim(),
    destination_ip: $("#destinationFilter").value.trim(),
    port: $("#portFilter").value.trim(),
    min_size: $("#minSize").value.trim(),
    max_size: $("#maxSize").value.trim(),
    start_time: $("#startTime").value,
    end_time: $("#endTime").value
  };
  for (const key of ["port", "min_size", "max_size"]) {
    if (filters[key] && (!Number.isInteger(Number(filters[key])) || Number(filters[key]) < 0)) {
      throw new Error(`${key.replace("_", " ")} must be a non-negative whole number.`);
    }
  }
  if (filters.port && Number(filters.port) > 65535) throw new Error("Port must be between 0 and 65535.");
  if (filters.min_size && filters.max_size && Number(filters.min_size) > Number(filters.max_size)) {
    throw new Error("Minimum bytes cannot be greater than maximum bytes.");
  }
  if (filters.start_time && filters.end_time && filters.start_time > filters.end_time) {
    throw new Error("Start time cannot be later than end time.");
  }
  return filters;
}

async function applyFilters() {
  try {
    currentFilters = readFilters();
    const result = await api("/api/packets/filter", {
      method: "POST",
      body: JSON.stringify({ filters: currentFilters })
    });
    filteredPackets = result.records.map(packet => ({
      ...packet,
      no: packet.id,
      time: packet.timestamp,
      src: packet.source_ip,
      dst: packet.destination_ip,
      pr: packet.protocol,
      len: packet.length
    }));
    filteredTotal = result.total;
    selectedPackets.clear();
    if (result.truncated) $("#servermsg").textContent = "Filter results are limited to the newest 2,000 packets.";
    render();
  } catch (error) {
    $("#servermsg").textContent = error.message;
  }
}

function clearFilterFields() {
  $("#filterForm").reset();
  $("#pf").value = "All";
}

function resetFilters() {
  clearFilterFields();
  filteredPackets = null;
  filteredTotal = 0;
  currentFilters = {};
  selectedPackets.clear();
  render();
}

function selectedExportRows() {
  return [...selectedPackets.values()].map(packet => [
    packet.id ?? packet.no,
    packet.timestamp || packet.time || "",
    packet.source_ip ?? packet.src ?? "",
    packet.destination_ip ?? packet.dst ?? "",
    packet.protocol ?? packet.pr ?? "",
    packet.length ?? packet.len ?? 0,
    packet.source_port ?? packet.sport ?? null,
    packet.destination_port ?? packet.dport ?? null,
    packet.info || ""
  ]);
}

async function exportPackets(fileFormat, mode, captureSource = null) {
  let password = window.prompt(`Enter a password (at least 8 characters) to protect the ${fileFormat.toUpperCase()} file:`);
  if (password === null) return;
  if (password.length < 8) {
    $("#servermsg").textContent = "Use an export password with at least 8 characters.";
    return;
  }
  const confirmation = window.prompt("Re-enter the password:");
  if (confirmation === null) return;
  if (password !== confirmation) {
    $("#servermsg").textContent = "The passwords do not match. The file was not created.";
    return;
  }
  if (mode === "selected" && !selectedPackets.size) {
    $("#servermsg").textContent = "Select one or more packet rows before exporting.";
    return;
  }
  try {
    const response = await fetch("/api/export", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        format: fileFormat,
        mode,
        password,
        filters: currentFilters,
        packets: mode === "selected" ? selectedExportRows() : undefined,
        ...(captureSource || {})
      })
    });
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.error || `Export failed (${response.status})`);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    const exportName = mode === "network_report" || mode === "saved"
      ? "network_report"
      : "network_traffic";
    link.download = `${exportName}_${new Date().toISOString().replace(/[:.]/g, "-")}.${fileFormat}`;
    document.body.append(link);
    link.click();
    link.remove();
    // Browsers do not expose a reliable "download finished" event for an
    // anchor-triggered Blob download. Keep the URL alive long enough for the
    // download manager to consume it, then release it.
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
    $("#servermsg").textContent = `Encrypted ${fileFormat.toUpperCase()} export sent to your browser. Check its Downloads list.`;
  } catch (error) {
    $("#servermsg").textContent = error.message;
  } finally {
    password = "";
  }
}

function exportSavedReport(fileFormat) {
  if (!savedReportSource) {
    $("#servermsg").textContent = "Open a saved capture before exporting its report.";
    return;
  }
  return exportPackets(fileFormat, "saved", savedReportSource);
}

function showPacketDetails(packet) {
  const fields = [
    ["Packet number", packet.id ?? packet.no],
    ["Timestamp", packet.timestamp ?? packet.time],
    ["Source IP", packet.source_ip ?? packet.src],
    ["Source MAC", packet.source_mac ?? packet.src_mac],
    ["Source port", packet.source_port ?? packet.sport],
    ["Destination IP", packet.destination_ip ?? packet.dst],
    ["Destination MAC", packet.destination_mac ?? packet.dst_mac],
    ["Destination port", packet.destination_port ?? packet.dport],
    ["Protocol", packet.protocol ?? packet.pr],
    ["Length", packet.length ?? packet.len],
    ["Info", packet.info]
  ];
  $("#packetDetails").innerHTML = fields.map(([label, value]) =>
    `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value === null || value === undefined || value === "" ? "—" : value)}</dd>`
  ).join("");
  $("#detailsDialog").showModal();
}

let healthRequestInFlight = false;

async function checkHealth() {
  // A slow request must not overlap the next 5-second poll and overwrite a
  // newer healthy result with an older congested response.
  if (healthRequestInFlight) return;
  healthRequestInFlight = true;
  try {
    const data = await api("/api/health");
    gatewayHealthState = data.state;
    gatewayHealthDescription = data.description;

    if (data.state === "congested") {
      if (!congestionAlertActive) {
        congestionAlertActive = true;
        showCongestionWarning(data.description);
      } else if ($("#congestionDialog").open) {
        // Keep an already-open warning current as the rolling health sample changes.
        showCongestionWarning(data.description);
      }
    } else {
      congestionAlertActive = false;
      const dialog = $("#congestionDialog");
      if (dialog.open) dialog.close();
    }

    updateDisplayedHealth();
    renderAdvice();
  } catch (error) {
    gatewayHealthState = "unavailable";
    gatewayHealthDescription = error.message;
    congestionAlertActive = false;
    const dialog = $("#congestionDialog");
    if (dialog.open) dialog.close();
    updateDisplayedHealth();
    renderAdvice();
  } finally {
    healthRequestInFlight = false;
  }
}

async function openSavedCaptures() {
  try {
    const data = await api("/api/sessions");
    viewerToken = "";
    savedReportSource = null;
    $("#savedReport").hidden = true;
    const select = $("#savedFiles");
    select.innerHTML = "";
    data.sessions.forEach(item => {
      const option = document.createElement("option");
      option.value = item.name;
      option.textContent = `${item.name} · ${new Date(item.modified).toLocaleString()} · ${formatBytes(item.bytes)}`;
      select.append(option);
    });
    $("#savedPackets").innerHTML = "";
    $("#savedPage").textContent = data.sessions.length ? "Choose a capture file" : "No saved captures";
    savedOffset = savedTotal = 0;
    $("#savedDialog").showModal();
  } catch (error) {
    $("#servermsg").textContent = error.message;
  }
}

async function loadSavedPage(offset = 0) {
  const filename = $("#savedFiles").value;
  if (!viewerToken && !filename) {
    $("#savedPage").textContent = "No saved captures";
    return;
  }
  if (offset === 0) {
    savedReportSource = null;
    $("#savedReport").hidden = true;
  }
  try {
    const url = viewerToken
      ? `/api/uploads/${encodeURIComponent(viewerToken)}?offset=${offset}&limit=${PAGE_SIZE}`
      : `/api/sessions/${encodeURIComponent(filename)}?offset=${offset}&limit=${PAGE_SIZE}`;
    const result = await api(url);
    savedOffset = result.offset;
    savedTotal = result.total;
    $("#savedPackets").innerHTML = result.records.map(packet =>
      `<tr data-saved-packet="${escapeHtml(JSON.stringify(packet))}">${["id", "timestamp", "source_ip", "destination_ip", "protocol", "length", "source_port", "destination_port", "info"].map(key => `<td>${escapeHtml(packet[key] ?? "")}</td>`).join("")}</tr>`
    ).join("") || '<tr><td colspan="9">This capture contains no packets.</td></tr>';
    $("#savedPage").textContent = `${savedOffset + 1}-${Math.min(savedOffset + result.records.length, savedTotal)} of ${savedTotal.toLocaleString()} packets`;
    $("#savedPrev").disabled = savedOffset <= 0;
    $("#savedNext").disabled = savedOffset + PAGE_SIZE >= savedTotal;
    if (offset === 0) loadSavedReport();
  } catch (error) {
    $("#servermsg").textContent = error.message;
  }
}

function renderSavedReport(report) {
  const header = report.header;
  const health = report.health;
  $("#savedReportTitle").textContent = header.title;
  $("#savedReportMeta").textContent =
    `${header.capture} · Generated ${header.generated} · ` +
    `${header.first_packet} to ${header.last_packet}`;
  $("#savedReportStats").innerHTML = [
    ["Packets", header.packet_count.toLocaleString()],
    ["Captured data", formatBytes(header.total_bytes)],
    ["LAN clients", header.client_count.toLocaleString()],
    ["Dropped", header.dropped_packets]
  ].map(([label, value]) =>
    `<div><span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>`
  ).join("");

  const healthClass = {
    healthy: "ok",
    congested: "bad",
    unreachable: "bad",
    unavailable: "warn",
    checking: "warn"
  }[health.state] || "";
  $("#savedHealth").className = `health ${healthClass}`;
  $("#savedHealth").innerHTML =
    `<b>Gateway health: ${escapeHtml(health.state.replace(/_/g, " ").toUpperCase())}</b>` +
    `<span>${escapeHtml(health.description)} ${escapeHtml(health.context)} ` +
    `Checked: ${escapeHtml(health.checked_at || "not recorded")}.</span>`;

  $("#savedAdvice").innerHTML = report.advice.map(item =>
    `<div class="adv ${escapeHtml(item.level)}"><b>${escapeHtml(item.title)}</b>` +
    `<p>${escapeHtml(item.detail)}</p><p><em>Do this:</em> ${escapeHtml(item.action)}</p></div>`
  ).join("");
  $("#savedProtocols").innerHTML = report.protocols.length
    ? report.protocols.map(item =>
      `<div class="row"><code>${escapeHtml(item.protocol)}</code>` +
      `<div class="meter"><i style="width:${Math.min(100, item.percentage)}%"></i></div>` +
      `<span>${item.packets.toLocaleString()} (${item.percentage.toFixed(1)}%)</span></div>`
    ).join("")
    : '<span class="sub">No protocol data.</span>';
  $("#savedClients").innerHTML = report.clients.map(client =>
    `<tr><td class="m">${escapeHtml(client.ip)}</td>` +
    `<td class="m">${escapeHtml(client.mac || "Not recorded")}</td>` +
    `<td>${client.sent_packets.toLocaleString()}</td>` +
    `<td>${client.received_packets.toLocaleString()}</td>` +
    `<td>${formatBytes(client.total_bytes)}</td>` +
    `<td>${escapeHtml(client.protocols.join(", ") || "—")}</td></tr>`
  ).join("") || '<tr><td colspan="6">No private-LAN clients observed.</td></tr>';
  $("#savedTree").innerHTML = report.tree.length
    ? `<ul>${report.tree.map(network =>
      `<li><b>Network ${escapeHtml(network.network)}</b><ul>` +
      `${network.clients.map(client =>
        `<li>${escapeHtml(client.ip)} · ${escapeHtml(client.mac || "MAC not recorded")}` +
        ` <small>${formatBytes(client.total_bytes)}</small></li>`
      ).join("")}</ul></li>`
    ).join("")}</ul>`
    : '<span class="sub">No private-LAN network tree data.</span>';
  $("#savedReport").hidden = false;
}

async function loadSavedReport() {
  const filename = $("#savedFiles").value;
  if (!viewerToken && !filename) return;
  const source = viewerToken ? { token: viewerToken } : { filename };
  savedReportSource = null;
  const url = viewerToken
    ? `/api/uploads/${encodeURIComponent(viewerToken)}/report`
    : `/api/sessions/${encodeURIComponent(filename)}/report`;
  $("#savedReport").hidden = false;
  $("#savedReportTitle").textContent = "Building network report…";
  $("#savedReportMeta").textContent = "Summarizing saved packets, clients, and protocols.";
  try {
    const result = await api(url);
    savedReportSource = source;
    renderSavedReport(result.report);
  } catch (error) {
    $("#savedReportTitle").textContent = "Network report unavailable";
    $("#savedReportMeta").textContent = error.message;
    $("#savedReportStats").innerHTML = "";
    $("#savedHealth").innerHTML = "";
    $("#savedAdvice").innerHTML = "";
    $("#savedProtocols").innerHTML = "";
    $("#savedClients").innerHTML = "";
    $("#savedTree").innerHTML = "";
  }
}

async function openLocalCapture() {
  const file = $("#localCaptureFile").files[0];
  if (!file) {
    $("#servermsg").textContent = "Choose a .msgpack file first.";
    return;
  }
  const form = new FormData();
  form.append("file", file);
  try {
    const response = await fetch("/api/sessions/open", {
      method: "POST",
      credentials: "same-origin",
      body: form
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401) showAuthGate(true, "Your sign-in expired. Please sign in again.");
      throw new Error(result.error || `Could not open capture (${response.status})`);
    }
    viewerToken = result.token;
    savedTotal = result.total;
    savedOffset = 0;
    $("#savedPage").textContent = `${result.name} · ${result.total.toLocaleString()} packets`;
    await loadSavedPage(0);
    $("#localCaptureFile").value = "";
  } catch (error) {
    $("#servermsg").textContent = error.message;
  }
}

async function logOut() {
  if (!window.confirm("Log out? Any active capture will stop, and you will need to sign in again.")) return;
  try {
    await api("/api/auth/logout", { method: "POST" });
    stopTimers();
    S = blank();
    filteredPackets = null;
    filteredTotal = 0;
    currentFilters = {};
    selectedPackets.clear();
    clearFilterFields();
    setCaptureControls(false);
    $("#pies").innerHTML = '<span class="sub">Press Start, then Stop to see the breakdown.</span>';
    render();
    showAuthGate(true, "");
  } catch (error) {
    $("#servermsg").textContent = error.message;
  }
}

$("#loginTab").addEventListener("click", () => setAuthTab("login"));
$("#registerTab").addEventListener("click", () => setAuthTab("register"));
$("#loginForm").addEventListener("submit", async event => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  try {
    const result = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        identifier: form.get("identifier"),
        password: form.get("password"),
        remember: form.get("remember") === "on"
      })
    });
    formElement.reset();
    showDashboard(result.user);
  } catch (error) {
    $("#authNotice").textContent = error.message;
    if (error.needsVerification) $("#resendVerification").hidden = false;
  }
});

function passwordRequirements(password) {
  const checks = {
    length: password.length >= 8,
    upper: /[A-Z]/.test(password),
    lower: /[a-z]/.test(password),
    number: /\d/.test(password),
    symbol: /[^A-Za-z0-9]/.test(password)
  };
  return { checks, valid: Object.values(checks).every(Boolean) };
}

function updatePasswordRequirements() {
  const password = $("#registerPassword").value;
  const checks = passwordRequirements(password).checks;
  const passwordInput = $("#registerPassword");
  passwordInput.setAttribute(
    "aria-invalid",
    String(Boolean(password) && !Object.values(checks).every(Boolean))
  );
  Object.entries(checks).forEach(([rule, passed]) => {
    const item = $(`#passwordRequirements [data-rule="${rule}"]`);
    item.classList.toggle("passed", passed);
    item.classList.toggle("failed", Boolean(password) && !passed);
  });
  const confirmation = $("#registerConfirm").value;
  const message = $("#confirmMessage");
  if (!confirmation) {
    message.textContent = "";
    message.classList.remove("passed", "failed");
  } else if (confirmation === password) {
    message.textContent = "Passwords match.";
    message.classList.add("passed");
    message.classList.remove("failed");
  } else {
    message.textContent = "Passwords do not match.";
    message.classList.add("failed");
    message.classList.remove("passed");
  }
}

$("#registerPassword").addEventListener("input", updatePasswordRequirements);
$("#registerConfirm").addEventListener("input", updatePasswordRequirements);
document.querySelectorAll(".password-toggle").forEach(button => {
  button.addEventListener("click", () => {
    const input = button.parentElement.querySelector("input");
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    button.textContent = visible ? "Hide" : "Show";
    button.setAttribute("aria-pressed", String(visible));
    button.setAttribute("aria-label", `${visible ? "Hide" : "Show"} password`);
  });
});
["loginForm", "registerForm"].forEach(formId => {
  $(`#${formId}`).addEventListener("reset", () => {
    window.setTimeout(() => {
      document.querySelectorAll(`#${formId} .password-toggle`).forEach(button => {
        const input = button.parentElement.querySelector("input");
        input.type = "password";
        button.textContent = "Show";
        button.setAttribute("aria-pressed", "false");
        button.setAttribute("aria-label", "Show password");
      });
      if (formId === "registerForm") updatePasswordRequirements();
    }, 0);
  });
});

$("#registerForm").addEventListener("submit", async event => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  if (!passwordRequirements(form.get("password")).valid) {
    $("#authNotice").textContent = "Your password does not meet all the listed requirements.";
    return;
  }
  if (form.get("password") !== form.get("confirm")) {
    $("#authNotice").textContent = "The passwords do not match.";
    return;
  }
  try {
    const result = await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        username: form.get("username"),
        email: form.get("email"),
        password: form.get("password")
      })
    });
    formElement.reset();
    updatePasswordRequirements();
    setAuthTab("login");
    $("#authNotice").textContent = result.message;
    $("#loginForm [name=identifier]").value = result.username;
  } catch (error) {
    $("#authNotice").textContent = error.message;
  }
});
$("#resendVerification").addEventListener("click", async () => {
  try {
    const result = await api("/api/auth/resend", { method: "POST" });
    $("#authNotice").textContent = result.message;
    $("#resendVerification").hidden = true;
  } catch (error) {
    $("#authNotice").textContent = error.message;
  }
});
$("#refreshInterfaces").addEventListener("click", loadInterfaces);
$("#start").addEventListener("click", startCapture);
$("#stop").addEventListener("click", stopCapture);
$("#clear").addEventListener("click", clearCapture);
$("#logout").addEventListener("click", logOut);
$("#openPackets").addEventListener("click", openSavedCaptures);
$("#filterForm").addEventListener("submit", event => {
  event.preventDefault();
  applyFilters();
});
$("#resetFilters").addEventListener("click", resetFilters);
$("#q").addEventListener("input", () => {
  if (!filteredPackets) renderPackets();
});
$("#pf").addEventListener("change", () => {
  if (!filteredPackets) renderPackets();
});
$("#sourceFilter").addEventListener("input", () => {
  if (!filteredPackets) renderPackets();
});
$("#destinationFilter").addEventListener("input", () => {
  if (!filteredPackets) renderPackets();
});
$("#exportFilteredCsv").addEventListener("click", () => exportPackets("csv", "filtered"));
$("#exportFilteredPdf").addEventListener("click", () => exportPackets("pdf", "filtered"));
$("#exportSelectedCsv").addEventListener("click", () => exportPackets("csv", "selected"));
$("#exportSelectedPdf").addEventListener("click", () => exportPackets("pdf", "selected"));
$("#exportNetworkCsv").addEventListener("click", () => exportPackets("csv", "network_report"));
$("#exportNetworkPdf").addEventListener("click", () => exportPackets("pdf", "network_report"));
$("#pb").addEventListener("change", event => {
  const checkbox = event.target.closest(".packet-select");
  if (!checkbox) return;
  const key = checkbox.dataset.key;
  if (checkbox.checked) {
    const packet = [...(filteredPackets || S.packets)].find(item => packetKey(item) === key);
    if (packet) selectedPackets.set(key, packet);
  } else selectedPackets.delete(key);
  renderPackets();
});
$("#selectAll").addEventListener("change", event => {
  const visibleKeys = ($("#pb").dataset.visibleKeys || "").split(",").filter(Boolean);
  const rows = filteredPackets || S.packets;
  visibleKeys.forEach(key => {
    const packet = rows.find(item => packetKey(item) === key);
    if (!packet) return;
    if (event.target.checked) selectedPackets.set(key, packet);
    else selectedPackets.delete(key);
  });
  renderPackets();
});
$("#pb").addEventListener("dblclick", event => {
  const row = event.target.closest("tr[data-packet-key]");
  if (!row) return;
  const rows = filteredPackets || S.packets;
  const packet = rows.find(item => packetKey(item) === row.dataset.packetKey);
  if (packet) showPacketDetails(packet);
});
[["t1", "t2", "v1", "v2"], ["t2", "t1", "v2", "v1"]].forEach(([active, inactive, shown, hidden]) => {
  $("#" + active).addEventListener("click", () => {
    $("#" + active).setAttribute("aria-selected", "true");
    $("#" + inactive).setAttribute("aria-selected", "false");
    $("#" + shown).hidden = false;
    $("#" + hidden).hidden = true;
  });
});
$("#loadSaved").addEventListener("click", () => {
  viewerToken = "";
  loadSavedPage(0);
});
$("#savedFiles").addEventListener("change", () => {
  viewerToken = "";
  savedReportSource = null;
  $("#savedReport").hidden = true;
  $("#savedPackets").innerHTML = "";
  $("#savedPage").textContent = "Open capture to view packets";
});
$("#openLocalCapture").addEventListener("click", openLocalCapture);
$("#savedReportCsv").addEventListener("click", () => exportSavedReport("csv"));
$("#savedReportPdf").addEventListener("click", () => exportSavedReport("pdf"));
$("#savedPrev").addEventListener("click", () => loadSavedPage(Math.max(0, savedOffset - PAGE_SIZE)));
$("#savedNext").addEventListener("click", () => loadSavedPage(savedOffset + PAGE_SIZE));
$("#savedPackets").addEventListener("dblclick", event => {
  const row = event.target.closest("tr[data-saved-packet]");
  if (row) showPacketDetails(JSON.parse(row.dataset.savedPacket));
});
window.addEventListener("pagehide", () => {
  if (S.run && navigator.sendBeacon) {
    navigator.sendBeacon(
      "/api/capture/stop",
      new Blob(["{}"], { type: "application/json" })
    );
  }
});

setCaptureControls(false);
render();
authStatus();
