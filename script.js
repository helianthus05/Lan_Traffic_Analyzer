const $ = selector => document.querySelector(selector);
const MAX_PACKETS = 3000;
const MAX_TRACKED_IPS = 5000;
const PAGE_SIZE = 200;
const FILTER_PAGE_SIZE = 60;
const SLOW_RENDER_INTERVAL_MS = 700;
let S;
let pollTimer = null;
let renderTimer = null;
let healthTimer = null;
let selectedIp = "";
let defaultGatewayIp = "";
let localHostname = "";
let filteredPackets = null;
let filteredTotal = 0;
let filterOffset = 0;
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
let lastPacketId = 0;
let lastSlowRenderAt = 0;
let receiveInFlight = false;
let resolveInFlight = false;
let liveViewPaused = false;
let pausedNewPackets = 0;
let activePacketTab = "packets";
let activeFlow = null;
let liveAlerts = [];
let lastAlertsSignature = "";
let lastRates = { packets: 0, bytes: 0 };
let savedSessionsList = [];
let navigatingToSubpage = false;
let activeNicknameTarget = null;
const NICKNAME_STORAGE_KEY = "lan_traffic_analyzer_nicknames";
const resolvedIdentityAttempts = new Set();

function loadNicknames() {
  try {
    const raw = localStorage.getItem(NICKNAME_STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function saveNicknames(map) {
  try {
    localStorage.setItem(NICKNAME_STORAGE_KEY, JSON.stringify(map));
  } catch {
    // Ignore storage restrictions.
  }
}

function getDeviceNickname(ip, mac) {
  const map = loadNicknames();
  const cleanMac = String(mac || "").trim().toLowerCase();
  if (cleanMac && map[`mac:${cleanMac}`]) return map[`mac:${cleanMac}`];
  if (ip && map[`ip:${ip}`]) return map[`ip:${ip}`];
  return "";
}

function setDeviceNickname(ip, mac, label) {
  const map = loadNicknames();
  const cleanMac = String(mac || "").trim().toLowerCase();
  const cleaned = String(label || "").trim();
  if (cleaned) {
    if (cleanMac) map[`mac:${cleanMac}`] = cleaned;
    if (ip) map[`ip:${ip}`] = cleaned;
  } else {
    if (cleanMac) delete map[`mac:${cleanMac}`];
    if (ip) delete map[`ip:${ip}`];
  }
  saveNicknames(map);
}

function applyTheme(theme, persist = false) {
  const mode = theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = mode;
  const button = $("#themeToggle");
  if (button) {
    const isDark = mode === "dark";
    button.setAttribute("aria-pressed", String(isDark));
    button.textContent = isDark ? "Light theme" : "Dark theme";
  }
  if (persist) {
    try {
      localStorage.setItem("lan_traffic_analyzer_theme", mode);
    } catch {
      // Ignore storage restrictions.
    }
  }
}

function initTheme() {
  let saved = "light";
  try {
    const stored =
      localStorage.getItem("lan_traffic_analyzer_theme") ??
      localStorage.getItem("lan_watch_theme");
    if (stored === "dark") saved = "dark";
  } catch {
    saved = "light";
  }
  applyTheme(saved, false);
}

const blank = () => ({
  run: false, packets: [], total: 0, bytes: 0, src: {}, dst: {}, srcBytes: {}, dstBytes: {},
  protocols: {}, domains: {}, services: {}, dnsEvents: [],
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

function isUnicastMac(mac) {
  const hex = String(mac || "").replace(/[^0-9a-f]/gi, "").toLowerCase();
  if (hex.length !== 12 || hex === "000000000000" || hex === "ffffffffffff") return false;
  return (parseInt(hex.slice(0, 2), 16) & 1) === 0;
}

function isBroadcastOrProbeDestination(packet, protocol) {
  const dstMac = String(packet.dst_mac || "").trim().toLowerCase();
  if (dstMac && !isUnicastMac(dstMac)) return true;
  if (protocol === "ARP" && String(packet.info || "").toLowerCase().includes("who-has")) return true;
  return false;
}

function client(ip, mac, found = "Traffic") {
  if (!isLan(ip)) return null;
  const cleanMac = isUnicastMac(mac) ? mac : "";
  let record = S.clients[ip];
  if (!record) {
    record = S.clients[ip] = {
      name: "", mac: cleanMac, vendor: "", network: "", sent: 0, received: 0,
      sentBytes: 0, receivedBytes: 0, protocols: new Set(), found: new Set(), first: "", last: ""
    };
  }
  if (cleanMac && !record.mac) record.mac = cleanMac;
  if (ip === selectedIp && localHostname && !record.name) record.name = localHostname;
  record.found.add(found);
  return record;
}

function incrementIpMetric(map, ip, delta, trackedSet) {
  if (Object.hasOwn(map, ip) || trackedSet.size < MAX_TRACKED_IPS || isLan(ip)) {
    map[ip] = (map[ip] || 0) + delta;
    trackedSet.add(ip);
  }
}

function inferServiceLabel(protocol, sport, dport) {
  const ports = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS",
    138: "NetBIOS", 139: "SMB", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB",
    546: "DHCPv6", 547: "DHCPv6", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
    1900: "SSDP", 3389: "RDP", 5353: "mDNS", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
  };
  for (const rawPort of [dport, sport]) {
    if (rawPort === null || rawPort === undefined || rawPort === "") continue;
    const port = Number(rawPort);
    if (protocol === "UDP" && port === 443) return "QUIC";
    if (ports[port]) return ports[port];
  }
  return "";
}

function addPacket(packet) {
  const src = packet.src || "Unknown";
  const dst = packet.dst || "Unknown";
  const protocol = packet.pr || "Other";
  const length = Number(packet.len) || 0;
  const stamp = packet.timestamp || packet.time || "";
  const timestamp = stamp.split(" ").slice(-1)[0];
  const packetNo = Number(packet.no) || S.total + 1;
  if (packetNo > lastPacketId) lastPacketId = packetNo;
  S.total++;
  S.bytes += length;
  S.intervalPackets++;
  S.intervalBytes += length;
  if (!S._srcIps) S._srcIps = new Set();
  if (!S._dstIps) S._dstIps = new Set();
  incrementIpMetric(S.src, src, 1, S._srcIps);
  incrementIpMetric(S.dst, dst, 1, S._dstIps);
  incrementIpMetric(S.srcBytes, src, length, S._srcIps);
  incrementIpMetric(S.dstBytes, dst, length, S._dstIps);
  S.protocols[protocol] = (S.protocols[protocol] || 0) + 1;
  if (protocol === "ARP") S.arp++;
  if (Number(packet.sport) === 80 || Number(packet.dport) === 80) S.http = true;

  const service = packet.service || inferServiceLabel(protocol, packet.sport, packet.dport);
  if (service) {
    S.services[service] = (S.services[service] || 0) + 1;
  }
  const infoText = String(packet.info || "");
  let domain = packet.domain || "";
  if (!domain) {
    const infoMatch = infoText.match(/\((?:DNS|mDNS|HTTPS|HTTP|HTTP-Alt|HTTPS-Alt):\s*(?:query|response)?\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
    if (infoMatch && !infoMatch[1].toLowerCase().endsWith(".arpa")) {
      domain = infoMatch[1].toLowerCase();
    }
  }
  if (domain) {
    S.domains[domain] = (S.domains[domain] || 0) + 1;
  }

  if (Number(packet.sport) === 53 || Number(packet.dport) === 53) {
    const dnsMatch = infoText.match(/\(DNS:\s*(query|response)\s*([^\s[\])]+)?(?:\s*\[([A-Z0-9]+)\])?/i);
    const kind = dnsMatch ? (dnsMatch[1].toLowerCase() === "response" ? "Response" : "Query") : (Number(packet.sport) === 53 ? "Response" : "Query");
    const qname = dnsMatch && dnsMatch[2] ? dnsMatch[2] : (domain || "—");
    const rcode = dnsMatch && dnsMatch[3] ? dnsMatch[3].toUpperCase() : "OK";
    const isError = rcode !== "OK";
    const clientIp = kind === "Response" ? dst : src;
    S.dnsEvents.push({
      time: timestamp,
      client: clientIp,
      type: kind,
      domain: qname,
      status: rcode,
      isError,
      detail: infoText,
      searchIp: clientIp
    });
    if (S.dnsEvents.length > 1000) S.dnsEvents.shift();
  }

  const sender = client(src, packet.src_mac, protocol === "ARP" ? "ARP" : "Traffic");
  if (sender) {
    if (packet.device_name && !sender.name) sender.name = packet.device_name;
    if (packet.id_source) sender.found.add(packet.id_source);
    sender.sent++;
    sender.sentBytes += length;
    sender.protocols.add(protocol);
    if (!sender.first) sender.first = timestamp;
    sender.last = timestamp;
  }
  const receiver = isBroadcastOrProbeDestination(packet, protocol)
    ? null
    : client(dst, packet.dst_mac, "Traffic");
  if (receiver) {
    receiver.received++;
    receiver.receivedBytes += length;
    receiver.protocols.add(protocol);
    if (!receiver.first) receiver.first = timestamp;
    receiver.last = timestamp;
  }
  S.packets.push({
    ...packet, no: packetNo, timestamp: stamp,
    time: timestamp, src, dst, pr: protocol, len: length, service, domain
  });
  if (S.packets.length > MAX_PACKETS) {
    const evicted = S.packets.shift();
    if (evicted && !filteredPackets) selectedPackets.delete(packetKey(evicted));
  }
}

function topList(counter, selector, roleType) {
  const entries = Object.entries(counter)
    .filter(([address]) => isIPv4Address(address))
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  const peak = entries[0]?.[1] || 1;
  $(selector).innerHTML = entries.length
    ? entries.map(([address, count]) => `<div class="row clickable" tabindex="0" role="button" data-filter-ip="${escapeHtml(address)}" data-filter-role="${escapeHtml(roleType)}" title="Click to filter ${roleType === "source" ? "packets from" : "packets to"} ${escapeHtml(address)}"><code>${escapeHtml(address)}</code><div class="meter"><i style="width:${count / peak * 100}%"></i></div><span>${count.toLocaleString()}</span></div>`).join("")
    : '<span class="sub">Nothing yet</span>';
}

function renderTopDomainsAndServices() {
  const renderCounter = (counter, selector, rowClass, emptyLabel) => {
    const el = $(selector);
    if (!el) return;
    const entries = Object.entries(counter)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);
    const peak = entries[0]?.[1] || 1;
    el.innerHTML = entries.length
      ? entries.map(([label, count]) => `<div class="row clickable ${rowClass}" tabindex="0" role="button" data-filter-query="${escapeHtml(label)}" title="Click to filter packets matching ${escapeHtml(label)}"><code>${escapeHtml(label)}</code><div class="meter"><i style="width:${count / peak * 100}%"></i></div><span>${count.toLocaleString()}</span></div>`).join("")
      : `<span class="sub">${emptyLabel}</span>`;
  };
  renderCounter(S.domains, "#topDomains", "domain-row", "No domains observed yet");
  renderCounter(S.services, "#topServices", "", "No services observed yet");
}

function graph(selector, values, format) {
  const canvas = $(selector);
  if (!canvas) return;
  const width = Math.max(1, canvas.clientWidth * 2);
  const height = 180;
  if (canvas.width !== width) canvas.width = width;
  if (canvas.height !== height) canvas.height = height;
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

function renderAlerts() {
  const banner = $("#alertsBanner");
  const list = $("#alertsList");
  if (!banner || !list) return;
  const signature = JSON.stringify(liveAlerts);
  if (signature === lastAlertsSignature) return;
  lastAlertsSignature = signature;

  if (!liveAlerts.length) {
    banner.hidden = true;
    list.innerHTML = "";
    return;
  }
  const highCount = liveAlerts.filter(item => item.severity === "bad").length;
  const warnCount = liveAlerts.length - highCount;
  banner.className = `alerts-banner${highCount ? " has-high" : ""}`;
  $("#alertsTitle").textContent = `Passive network alerts (${liveAlerts.length})`;
  const parts = [];
  if (highCount) parts.push(`${highCount} high-priority`);
  if (warnCount) parts.push(`${warnCount} warning${warnCount === 1 ? "" : "s"}`);
  $("#alertsSummary").textContent = `${parts.join(" · ")} detected passively in captured packets.`;

  list.innerHTML = liveAlerts.map(alert => {
    const levelClass = alert.severity === "bad" ? "bad" : "warn";
    const badgeText = alert.severity === "bad" ? "High" : "Warn";
    const timeText = alert.last_seen ? `Last seen ${alert.last_seen}` : "";
    const countText = alert.count > 1 ? ` · ${alert.count.toLocaleString()} events` : "";
    const actionBtn = alert.source_ip
      ? `<button type="button" data-alert-ip="${escapeHtml(alert.source_ip)}" data-alert-proto="${escapeHtml(alert.filter_protocol || "")}">Inspect traffic</button>`
      : "";
    return `<div class="alert-item ${levelClass}"><div class="alert-main"><div class="alert-top"><span class="alert-badge">${badgeText}</span><strong>${escapeHtml(alert.title)}</strong><span class="alert-meta">${escapeHtml(timeText + countText)}</span></div><p>${escapeHtml(alert.detail)}</p></div><div class="alert-actions">${actionBtn}</div></div>`;
  }).join("");
  banner.hidden = false;
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
    return [["", "Waiting for packets", "Capture is active and listening for traffic on the selected adapter.", "Verify the active adapter is selected if no traffic appears."]];
  }
  if (!S.total && gatewayHealthState !== "congested" && gatewayHealthState !== "unreachable") {
    return [["", "Ready to capture", "Select an active network adapter and press Start to inspect local traffic.", "Click Start when you are ready to monitor network activity."]];
  }
  if (gatewayHealthState === "congested") {
    result.push([
      "bad",
      "Elevated gateway latency or packet loss",
      "Recent gateway checks showed higher latency or packet loss.",
      "Review active high-volume transfers and check local network equipment or upstream connectivity."
    ]);
  } else if (gatewayHealthState === "unreachable") {
    result.push([
      "bad",
      "Gateway did not respond",
      "Recent checks to the default gateway did not receive a reply.",
      "Verify local cabling, wireless connectivity, and router ping settings."
    ]);
  } else if (gatewayHealthState === "healthy") {
    result.push([
      "ok",
      "Gateway status normal",
      "The default gateway is responding normally during monitoring.",
      "Continue monitoring and review traffic patterns if network behavior changes."
    ]);
  }

  if (S.http) {
    result.push([
      "warn",
      "Unencrypted web traffic observed",
      "HTTP traffic on port 80 was observed during this capture.",
      "Prefer HTTPS for sign-ins, administration pages, and sensitive transfers."
    ]);
  }

  if (S.total >= 20 && S.arp / S.total >= 0.25) {
    result.push([
      "warn",
      "Elevated ARP activity",
      "Address-resolution traffic accounts for a noticeable portion of observed frames.",
      "Monitor local address resolution if devices experience intermittent connectivity."
    ]);
  }

  if (droppedPacketCount > 0) {
    result.push([
      "warn",
      "Packet queue drops occurred",
      "Some frames were not queued during peak capture activity.",
      "Use shorter capture windows or reduce background load when capturing high-rate traffic."
    ]);
  }

  if (!result.length) {
    result.push([
      "ok",
      "Session monitoring active",
      "Packet activity, protocols, and observed endpoints are summarized in the panels.",
      "Use the client list, top domains, and packet filters to inspect specific activity."
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
  if (defaultGatewayIp && ip === defaultGatewayIp) return "Gateway";
  if (!defaultGatewayIp && (ip.endsWith(".1") || ip.endsWith(".254"))) return "Gateway (likely)";
  return "Client";
}

function networkOf(ip) {
  if (ip.includes(".")) return ip.split(".").slice(0, 3).join(".") + ".0/24";
  return ip.split(":").slice(0, 4).join(":") + "::/64";
}

async function resolveMissingDeviceIdentities(entries) {
  if (resolveInFlight) return;
  const batch = [];
  for (const [ip, record] of entries) {
    const attemptKey = `${ip}|${record.mac || ""}`;
    if (resolvedIdentityAttempts.has(attemptKey)) continue;
    if (!record.name || (record.mac && !record.vendor)) {
      resolvedIdentityAttempts.add(attemptKey);
      batch.push({ ip, mac: record.mac || "" });
      if (batch.length >= 24) break;
    }
  }
  if (!batch.length) return;
  resolveInFlight = true;
  try {
    const result = await api("/api/devices/resolve", {
      method: "POST",
      body: JSON.stringify({ devices: batch })
    });
    const resolved = result.resolved || {};
    let changed = false;
    Object.entries(resolved).forEach(([ip, identity]) => {
      const record = S.clients[ip];
      if (!record || !identity) return;
      if (identity.name && !record.name) {
        record.name = identity.name;
        record.found.add("rDNS");
        changed = true;
      }
      if (identity.vendor && !record.vendor) {
        record.vendor = identity.vendor;
        changed = true;
      }
    });
    if (changed) {
      renderClients();
      renderAdvice();
    }
  } catch {
    // Device identity enrichment is best-effort and silent on transient errors.
  } finally {
    resolveInFlight = false;
  }
}

function renderClients() {
  const neighborsOnly = Boolean($("#neighborsOnly")?.checked);
  const allEntries = Object.entries(S.clients)
    .filter(([ip]) => isIPv4Address(ip))
    .sort((a, b) => a[0].localeCompare(b[0]));
  const entries = neighborsOnly
    ? allEntries.filter(([ip]) => {
      const role = localRole(ip);
      return role !== "This device" && !role.startsWith("Gateway");
    })
    : allEntries;
  $("#cn").textContent = entries.length.toLocaleString();
  $("#cb").innerHTML = entries.map(([ip, record]) => {
    const data = record.sentBytes + record.receivedBytes;
    const nickname = getDeviceNickname(ip, record.mac);
    const baseName = record.name || (ip === selectedIp && localHostname ? localHostname : "");
    if (baseName && !record.name) record.name = baseName;
    const displayName = nickname || baseName || "Unknown device";
    const sources = new Set(record.found);
    if (nickname) sources.add("Nickname");
    return `<tr class="clickable-row" data-client-ip="${escapeHtml(ip)}" title="Click to filter packets involving ${escapeHtml(ip)}"><td class="m">${escapeHtml(ip)}</td><td><div class="device-cell"><span>${escapeHtml(displayName)}</span><button type="button" class="edit-nick-btn" data-nick-ip="${escapeHtml(ip)}" data-nick-mac="${escapeHtml(record.mac || "")}" title="Set custom device nickname">Edit</button></div></td><td class="m">${escapeHtml(record.mac || "—")}</td><td>${escapeHtml(record.vendor || "—")}</td><td>${localRole(ip)}</td><td>${record.sent.toLocaleString()}</td><td>${record.received.toLocaleString()}</td><td>${formatBytes(data)}</td><td>${escapeHtml([...record.protocols].sort().join(", ") || "—")}</td><td>${escapeHtml([...sources].join(" + "))}</td><td>${escapeHtml(record.first || "—")}</td><td>${escapeHtml(record.last || "—")}</td></tr>`;
  }).join("") || `<tr><td colspan="12">${neighborsOnly ? "No neighboring clients observed yet." : "No devices observed yet. Start capture to discover devices passively."}</td></tr>`;

  const networks = new Map();
  entries.forEach(([ip, record]) => {
    const network = record.network || networkOf(ip);
    if (!networks.has(network)) networks.set(network, []);
    networks.get(network).push([ip, record]);
  });
  $("#v2").innerHTML = entries.length
    ? `<ul>${[...networks].sort(([a], [b]) => a.localeCompare(b)).map(([network, devices]) =>
      `<li><b>Network ${escapeHtml(network)}</b><ul>${devices.map(([ip, record]) => {
        const displayName = getDeviceNickname(ip, record.mac) || record.name;
        const label = [displayName, localRole(ip), record.mac || "—", record.vendor].filter(Boolean).join(" · ");
        return `<li class="clickable-item" tabindex="0" role="button" data-client-ip="${escapeHtml(ip)}" title="Click to filter packets involving ${escapeHtml(ip)}">${escapeHtml(ip)} · ${escapeHtml(label)} <small>${formatBytes(record.sentBytes + record.receivedBytes)}</small></li>`;
      }).join("")}</ul></li>`
    ).join("")}</ul>`
    : '<span class="sub">No devices observed.</span>';

  resolveMissingDeviceIdentities(allEntries);
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

function setPacketTab(tab) {
  activePacketTab = tab === "flows" ? "flows" : tab === "dns" ? "dns" : "packets";
  const isPackets = activePacketTab === "packets";
  const isFlows = activePacketTab === "flows";
  const isDns = activePacketTab === "dns";
  $("#tabPackets").setAttribute("aria-selected", String(isPackets));
  $("#tabFlows").setAttribute("aria-selected", String(isFlows));
  $("#tabDns").setAttribute("aria-selected", String(isDns));
  $("#packetListView").hidden = !isPackets;
  $("#flowsView").hidden = !isFlows;
  $("#dnsView").hidden = !isDns;
  $("#flowSortLabel").hidden = !isFlows;
  $("#dnsErrorsLabel").hidden = !isDns;
  if (isPackets) {
    renderPackets({ forceRender: true });
  } else if (isFlows) {
    $("#filterPagerControls").hidden = true;
    renderFlows();
  } else {
    $("#filterPagerControls").hidden = true;
    renderDnsActivity();
  }
}

function updatePauseButton() {
  const button = $("#pausePacketView");
  if (!button) return;
  button.setAttribute("aria-pressed", String(liveViewPaused));
  button.textContent = liveViewPaused ? "Resume live view" : "Pause live view";
}

function filteredLiveRows() {
  const query = $("#q").value.trim().toLowerCase();
  const protocol = $("#pf").value;
  const sourceFilter = $("#sourceFilter").value.trim().toLowerCase();
  const destinationFilter = $("#destinationFilter").value.trim().toLowerCase();
  return S.packets.filter(packet => {
    const source = String(packet.src || "").toLowerCase();
    const destination = String(packet.dst || "").toLowerCase();
    const searchable = `${source} ${destination} ${packet.info || ""} ${packet.pr || ""} ${packet.sport || ""} ${packet.dport || ""}`.toLowerCase();
    return (!query || searchable.includes(query)) &&
      (protocol === "All" || packet.pr === protocol) &&
      (!sourceFilter || source.includes(sourceFilter)) &&
      (!destinationFilter || destination.includes(destinationFilter));
  });
}

function matchesActiveFlow(packet) {
  if (!activeFlow) return true;
  const src = String(packet.src ?? packet.source_ip ?? "");
  const dst = String(packet.dst ?? packet.destination_ip ?? "");
  const sport = packet.sport ?? packet.source_port ?? null;
  const dport = packet.dport ?? packet.destination_port ?? null;
  const proto = packet.pr ?? packet.protocol ?? "Other";
  if (proto !== activeFlow.proto) return false;
  const forward = src === activeFlow.ipA && sport === activeFlow.portA &&
    dst === activeFlow.ipB && dport === activeFlow.portB;
  const reverse = src === activeFlow.ipB && sport === activeFlow.portB &&
    dst === activeFlow.ipA && dport === activeFlow.portA;
  return forward || reverse;
}

function buildFlows(rows) {
  const flows = new Map();
  rows.forEach((packet, seq) => {
    const proto = packet.pr ?? packet.protocol ?? "Other";
    const src = String(packet.src ?? packet.source_ip ?? "Unknown");
    const dst = String(packet.dst ?? packet.destination_ip ?? "Unknown");
    const sport = packet.sport ?? packet.source_port ?? null;
    const dport = packet.dport ?? packet.destination_port ?? null;
    const ep1 = `${src}|${sport ?? ""}`;
    const ep2 = `${dst}|${dport ?? ""}`;
    const aIsSource = ep1 <= ep2;
    const ipA = aIsSource ? src : dst;
    const portA = aIsSource ? sport : dport;
    const ipB = aIsSource ? dst : src;
    const portB = aIsSource ? dport : sport;
    const key = `${proto}|${ipA}|${portA ?? ""}|${ipB}|${portB ?? ""}`;
    let flow = flows.get(key);
    if (!flow) {
      flow = {
        key,
        proto,
        ipA,
        portA,
        ipB,
        portB,
        aToB: 0,
        bToA: 0,
        bytes: 0,
        first: packet.time || packet.timestamp || "",
        last: packet.time || packet.timestamp || "",
        lastSeq: seq,
        service: ""
      };
      flows.set(key, flow);
    }
    if (aIsSource) flow.aToB++;
    else flow.bToA++;
    flow.bytes += Number(packet.len ?? packet.length ?? 0) || 0;
    const stamp = packet.time || packet.timestamp || "";
    if (!flow.first && stamp) flow.first = stamp;
    if (stamp) flow.last = stamp;
    flow.lastSeq = seq;
    if (!flow.service && typeof packet.info === "string") {
      const match = packet.info.match(/\(([^)]+)\)$/);
      if (match) flow.service = match[1];
    }
  });
  return [...flows.values()];
}

function renderFlows({ forceRender = true } = {}) {
  if (activePacketTab !== "flows") return;
  if (!forceRender && liveViewPaused && !filteredPackets) {
    $("#pc").textContent = `Live view paused (${pausedNewPackets.toLocaleString()} new packet(s) queued). Click Resume live view to update.`;
    return;
  }
  const rows = filteredPackets || filteredLiveRows();
  const sortMode = $("#flowSort")?.value || "bytes";
  const flows = buildFlows(rows);
  flows.sort((a, b) => {
    if (sortMode === "packets") return (b.aToB + b.bToA) - (a.aToB + a.bToA);
    if (sortMode === "recent") return b.lastSeq - a.lastSeq;
    return b.bytes - a.bytes;
  });
  const visible = flows.slice(0, 200);
  const formatEndpoint = (ip, port) => port !== null && port !== undefined && port !== ""
    ? `${ip}:${port}` : ip;
  $("#fb").innerHTML = visible.map(flow => {
    const totalPkts = flow.aToB + flow.bToA;
    const epALabel = formatEndpoint(flow.ipA, flow.portA);
    const epBLabel = formatEndpoint(flow.ipB, flow.portB);
    const protoLabel = flow.service ? `${flow.proto} (${flow.service})` : flow.proto;
    return `<tr class="clickable-row" tabindex="0" role="button" data-flow-key="${escapeHtml(flow.key)}" title="Click to inspect packets in this conversation"><td class="m">${escapeHtml(epALabel)}</td><td class="m">${escapeHtml(epBLabel)}</td><td><span class="tag">${escapeHtml(protoLabel)}</span></td><td>${totalPkts.toLocaleString()} (${flow.aToB.toLocaleString()} / ${flow.bToA.toLocaleString()})</td><td>${formatBytes(flow.bytes)}</td><td class="m">${escapeHtml(flow.first || "—")}</td><td class="m">${escapeHtml(flow.last || "—")}</td></tr>`;
  }).join("") || '<tr><td colspan="7">No conversations observed yet.</td></tr>';
  $("#fb")._flows = visible;
  $("#pc").textContent = `Showing ${visible.length.toLocaleString()} of ${flows.length.toLocaleString()} conversation(s) from ${rows.length.toLocaleString()} packet(s).`;
}

function renderDnsActivity({ forceRender = true } = {}) {
  if (activePacketTab !== "dns") return;
  if (!forceRender && liveViewPaused && !filteredPackets) {
    $("#pc").textContent = `Live view paused (${pausedNewPackets.toLocaleString()} new packet(s) queued). Click Resume live view to update.`;
    return;
  }
  const errorsOnly = Boolean($("#dnsErrorsOnly")?.checked);
  const query = $("#q").value.trim().toLowerCase();
  const events = S.dnsEvents.filter(item => {
    if (errorsOnly && !item.isError) return false;
    if (query) {
      const hay = `${item.client} ${item.domain} ${item.status} ${item.detail}`.toLowerCase();
      if (!hay.includes(query)) return false;
    }
    return true;
  });
  const visible = events.slice(-200).reverse();
  $("#db").innerHTML = visible.map(item =>
    `<tr class="clickable-row" tabindex="0" role="button" data-dns-domain="${escapeHtml(item.domain === "—" ? item.client : item.domain)}" title="Click to filter packets matching ${escapeHtml(item.domain === "—" ? item.client : item.domain)}"><td class="m">${escapeHtml(item.time || "—")}</td><td class="m">${escapeHtml(item.client)}</td><td>${escapeHtml(item.type)}</td><td class="m">${escapeHtml(item.domain)}</td><td><span class="dns-status${item.isError ? " bad" : ""}">${escapeHtml(item.status)}</span></td><td>${escapeHtml(item.detail)}</td></tr>`
  ).join("") || `<tr><td colspan="6">${errorsOnly ? "No failed DNS lookups observed yet." : "No DNS queries or responses observed yet."}</td></tr>`;
  $("#pc").textContent = `Showing ${visible.length.toLocaleString()} of ${events.length.toLocaleString()} DNS event(s).`;
}

function renderPackets({ forceRender = true } = {}) {
  $("#clearFlowFilter").hidden = !activeFlow;
  if (activePacketTab === "flows") {
    renderFlows({ forceRender });
    return;
  }
  if (activePacketTab === "dns") {
    renderDnsActivity({ forceRender });
    return;
  }
  if (!forceRender && liveViewPaused && !filteredPackets) {
    $("#pc").textContent = `Live view paused (${pausedNewPackets.toLocaleString()} new packet(s) queued). Click Resume live view to update.`;
    return;
  }
  let rows;
  let total;
  if (filteredPackets) {
    rows = activeFlow ? filteredPackets.filter(matchesActiveFlow) : filteredPackets;
    total = activeFlow ? rows.length : filteredTotal;
  } else {
    rows = filteredLiveRows();
    if (activeFlow) rows = rows.filter(matchesActiveFlow);
    total = rows.length;
  }
  const visible = filteredPackets && !activeFlow
    ? rows.slice(filterOffset, filterOffset + FILTER_PAGE_SIZE)
    : rows.slice(-60).reverse();
  $("#pb").innerHTML = visible.map(packetRow).join("") || '<tr><td colspan="8">No packets match.</td></tr>';
  const pager = $("#filterPagerControls");
  if (activeFlow) {
    pager.hidden = true;
    $("#pc").textContent = `Showing ${visible.length.toLocaleString()} of ${total.toLocaleString()} packet(s) for flow ${activeFlow.label}.`;
  } else if (filteredPackets) {
    pager.hidden = rows.length <= FILTER_PAGE_SIZE;
    $("#filterPrev").disabled = filterOffset <= 0;
    $("#filterNext").disabled = filterOffset + FILTER_PAGE_SIZE >= rows.length;
    if (!rows.length) {
      $("#pc").textContent = "0 matching packets.";
    } else {
      const end = Math.min(filterOffset + visible.length, rows.length);
      const capNote = filteredTotal > rows.length ? ` (newest ${rows.length.toLocaleString()} loaded)` : "";
      $("#pc").textContent = `Showing ${filterOffset + 1}-${end} of ${filteredTotal.toLocaleString()} matching packets${capNote}.`;
    }
  } else {
    pager.hidden = true;
    $("#pc").textContent = `Showing ${Math.min(60, total).toLocaleString()} of ${total.toLocaleString()} recent matching packets.`;
  }
  $("#selectedCount").textContent = `${selectedPackets.size.toLocaleString()} selected`;
  const visibleKeys = new Set(visible.map(packetKey));
  $("#selectAll").checked = visible.length > 0 && visible.every(packet => selectedPackets.has(packetKey(packet)));
  $("#selectAll").indeterminate = visible.some(packet => selectedPackets.has(packetKey(packet))) && !$("#selectAll").checked;
  $("#pb").dataset.visibleKeys = [...visibleKeys].join(",");
}

function render(options = {}) {
  const { packets = true, graphs = true, forceSlow = true, forcePacketView = false } = options;
  $("#tp").textContent = S.total.toLocaleString();
  $("#td").textContent = formatBytes(S.bytes);
  $("#ta").textContent = formatBytes(S.total ? S.bytes / S.total : 0);
  $("#trate").textContent = S.run
    ? `${lastRates.packets.toLocaleString()} pkt/s · ${formatBytes(lastRates.bytes)}/s`
    : "0 pkt/s · 0 B/s";
  if (packets) {
    renderPackets({ forceRender: forcePacketView || !S.run });
  }
  if (graphs) {
    graph("#g1", S.historyPackets, value => `${value}/s`);
    graph("#g2", S.historyBytes, value => `${formatBytes(value)}/s`);
  }
  const now = Date.now();
  if (forceSlow || now - lastSlowRenderAt >= SLOW_RENDER_INTERVAL_MS) {
    lastSlowRenderAt = now;
    topList(S.src, "#ts", "source");
    topList(S.dst, "#tr", "destination");
    renderTopDomainsAndServices();
    renderClients();
    renderLiveSummary();
    updateDisplayedHealth();
    renderAdvice();
  }
}

function setCaptureControls(running, stopping = false) {
  $("#start").disabled = running || stopping;
  $("#stop").disabled = !running || stopping;
  $("#iface").disabled = running || stopping;
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
  pollTimer = renderTimer = healthTimer = null;
}

function hasDesktopBridge() {
  return Boolean(window.pywebview?.api?.request);
}

function waitForDesktopBridgeIfNeeded() {
  if (hasDesktopBridge() || window.location.protocol !== "file:") {
    return Promise.resolve();
  }
  return new Promise(resolve => {
    const finish = () => {
      window.removeEventListener("pywebviewready", onReady);
      clearInterval(poll);
      clearTimeout(timer);
      resolve();
    };
    const onReady = () => finish();
    const poll = setInterval(() => {
      if (hasDesktopBridge()) finish();
    }, 25);
    const timer = setTimeout(finish, 3000);
    window.addEventListener("pywebviewready", onReady, { once: true });
  });
}

async function blobToBase64(blob) {
  const buffer = await blob.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 8192) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(binary);
}

function base64ToBlob(b64, mimetype = "application/octet-stream") {
  const binary = atob(b64 || "");
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new Blob([bytes], { type: mimetype });
}

async function api(url, options = {}) {
  if (hasDesktopBridge()) {
    const method = (options.method || "GET").toUpperCase();
    const res = await window.pywebview.api.request(
      method,
      url,
      options.body ?? null,
      null,
      null
    );
    const data = res?.json || {};
    const status = Number(res?.status) || 500;
    if (status === 401 && !url.startsWith("/api/auth/")) {
      showAuthGate(true, "Your sign-in expired. Please sign in again.");
    }
    if (status < 200 || status >= 300) {
      const error = new Error(data.error || `Request failed (${status})`);
      error.needsVerification = Boolean(data.needs_verification);
      throw error;
    }
    return data;
  }
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
      showAuthGate(
        true,
        data.config_error ||
          "Firebase sign-in is not configured. Set FIREBASE_WEB_API_KEY and FIREBASE_SERVICE_ACCOUNT_PATH (or FIREBASE_SERVICE_ACCOUNT_JSON / GOOGLE_APPLICATION_CREDENTIALS) in your system environment variables."
      );
      return;
    }
    if (!data.authenticated) {
      showAuthGate(true, data.restore_error || "");
      return;
    }
    showDashboard(data.user);
  } catch (error) {
    showAuthGate(true, `Authentication service unavailable: ${error.message}`);
  }
}

async function syncCaptureStatus() {
  try {
    const status = await api("/api/status");
    droppedPacketCount = Number(status.dropped) || 0;
    liveAlerts = Array.isArray(status.alerts) ? status.alerts : [];
    renderAlerts();
    if (!status.capturing && !status.stopping) {
      return;
    }

    if (status.interface) {
      const select = $("#iface");
      const matchingOption = [...select.options].find(option => option.value === status.interface);
      if (matchingOption) {
        select.value = status.interface;
        selectedIp = matchingOption.dataset.ip || "";
      }
    }

    S.run = Boolean(status.capturing);
    setCaptureControls(Boolean(status.capturing), Boolean(status.stopping));
    if (!pollTimer) pollTimer = setInterval(receivePackets, 350);
    if (status.capturing) {
      if (!renderTimer) renderTimer = setInterval(advanceGraphs, 1000);
      $("#pies").innerHTML = '<span class="sub">Capture in progress. Stop to review the breakdown.</span>';
      $("#servermsg").textContent = `Capturing on ${status.interface || $("#iface").value}`;
    } else if (status.stopping) {
      $("#servermsg").textContent = "Stopping capture…";
    }
    render();
  } catch (error) {
    $("#servermsg").textContent = `Could not sync capture status: ${error.message}`;
  }
}

async function showDashboard(user) {
  showAuthGate(false);
  $("#signedInUser").textContent = user ? `Signed in as ${user.username || user.email}` : "";
  updateDisplayedHealth();
  await loadInterfaces();
  await syncCaptureStatus();
  checkHealth();
  healthTimer = setInterval(checkHealth, 5000);
}

async function loadInterfaces() {
  try {
    const data = await api("/api/interfaces");
    localHostname = data.hostname || "";
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
    await api("/api/capture/start", {
      method: "POST",
      body: JSON.stringify({
        interface: interfaceName
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
  lastRates = { packets: 0, bytes: 0 };
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
  if (receiveInFlight) return;
  receiveInFlight = true;
  try {
    const data = await api(`/api/packets?limit=1000&after=${lastPacketId}`);
    const prevDropped = droppedPacketCount;
    const receivedCount = data.packets.length;
    data.packets.forEach(addPacket);
    if (liveViewPaused && !filteredPackets && receivedCount > 0) {
      pausedNewPackets += receivedCount;
    }
    droppedPacketCount = Number(data.dropped) || 0;
    if (Array.isArray(data.alerts)) {
      liveAlerts = data.alerts;
      renderAlerts();
    }
    if (data.dropped) $("#servermsg").textContent = `Capturing · ${data.dropped} packet(s) dropped due to queue pressure`;
    if (data.error) $("#servermsg").textContent = `Capture/storage warning: ${data.error}`;
    if (receivedCount > 0 || droppedPacketCount !== prevDropped) {
      render({ packets: receivedCount > 0, graphs: false, forceSlow: false });
    }
    if (!data.capturing && !data.stopping && S.run) await finishStop();
    else if (data.stopping) setCaptureControls(false, true);
  } catch (error) {
    $("#servermsg").textContent = `Backend connection lost: ${error.message}`;
  } finally {
    receiveInFlight = false;
  }
}

function advanceGraphs() {
  const pktRate = S.intervalPackets;
  const byteRate = S.intervalBytes;
  S.historyPackets.push(pktRate);
  S.historyPackets.shift();
  S.historyBytes.push(byteRate);
  S.historyBytes.shift();
  S.intervalPackets = S.intervalBytes = 0;
  lastRates = { packets: pktRate, bytes: byteRate };
  render({ packets: false, graphs: true, forceSlow: false });
}

async function clearCapture() {
  if (S.run) await stopCapture();
  try {
    await api("/api/capture/clear", { method: "POST" });
    S = blank();
    lastPacketId = 0;
    lastRates = { packets: 0, bytes: 0 };
    filteredPackets = null;
    filteredTotal = 0;
    filterOffset = 0;
    currentFilters = {};
    selectedPackets.clear();
    resolvedIdentityAttempts.clear();
    liveViewPaused = false;
    pausedNewPackets = 0;
    activeFlow = null;
    liveAlerts = [];
    renderAlerts();
    updatePauseButton();
    droppedPacketCount = 0;
    clearFilterFields();
    setCaptureControls(false);
    $("#pies").innerHTML = '<span class="sub">Press Start, then Stop to see the breakdown.</span>';
    $("#servermsg").textContent = "Cleared current capture; the previous packet file was preserved.";
  } catch (error) {
    $("#servermsg").textContent = error.message;
  }
  render({ forcePacketView: true });
}

async function filterByDevice(ip, mode = "any", protocol = null) {
  if (!ip) return;
  activeFlow = null;
  filterOffset = 0;
  if (protocol !== null) {
    $("#pf").value = protocol || "All";
  }
  if (mode === "source") {
    $("#sourceFilter").value = ip;
    $("#destinationFilter").value = "";
    $("#q").value = "";
  } else if (mode === "destination") {
    $("#destinationFilter").value = ip;
    $("#sourceFilter").value = "";
    $("#q").value = "";
  } else {
    $("#q").value = ip;
    $("#sourceFilter").value = "";
    $("#destinationFilter").value = "";
  }
  setPacketTab("packets");
  if (filteredPackets) {
    await applyFilters();
  } else {
    renderPackets({ forceRender: true });
    renderFlows();
  }
  $("#packetsSection")?.scrollIntoView({ behavior: "smooth", block: "start" });
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
  activeFlow = null;
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
    filterOffset = 0;
    selectedPackets.clear();
    if (result.truncated) $("#servermsg").textContent = "Filter results are limited to the newest 2,000 packets.";
    render({ forcePacketView: true });
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
  filterOffset = 0;
  currentFilters = {};
  activeFlow = null;
  selectedPackets.clear();
  render({ forcePacketView: true });
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

function resetFormPasswordToggles(formElement) {
  formElement.querySelectorAll(".password-toggle").forEach(button => {
    const input = button.parentElement.querySelector("input");
    input.type = "password";
    button.textContent = "Show";
    button.setAttribute("aria-pressed", "false");
    button.setAttribute("aria-label", "Show password");
  });
}

function promptExportPassword(fileFormat) {
  const dialog = $("#exportPasswordDialog");
  const form = $("#exportPasswordForm");
  const passwordInput = $("#exportPassword");
  const confirmInput = $("#exportPasswordConfirm");
  const message = $("#exportPasswordMessage");
  $("#exportPasswordTitle").textContent = `Protect ${fileFormat.toUpperCase()} export`;
  form.reset();
  resetFormPasswordToggles(form);
  message.textContent = "";

  return new Promise(resolve => {
    const cleanup = value => {
      form.removeEventListener("submit", onSubmit);
      $("#exportPasswordCancel").removeEventListener("click", onCancel);
      dialog.removeEventListener("close", onDialogClose);
      passwordInput.value = "";
      confirmInput.value = "";
      resetFormPasswordToggles(form);
      message.textContent = "";
      if (dialog.open) dialog.close();
      resolve(value);
    };

    const onSubmit = event => {
      event.preventDefault();
      const password = passwordInput.value;
      const confirmation = confirmInput.value;
      if (password.length < 8) {
        message.textContent = "Use an export password with at least 8 characters.";
        passwordInput.focus();
        return;
      }
      if (password !== confirmation) {
        message.textContent = "The passwords do not match.";
        confirmInput.focus();
        return;
      }
      cleanup(password);
    };

    const onCancel = () => cleanup(null);
    const onDialogClose = () => cleanup(null);

    form.addEventListener("submit", onSubmit);
    $("#exportPasswordCancel").addEventListener("click", onCancel);
    dialog.addEventListener("close", onDialogClose);
    dialog.showModal();
    passwordInput.focus();
  });
}

async function triggerBlobDownload(blob, filename) {
  if (window.pywebview?.api?.save_file) {
    const result = await window.pywebview.api.save_file(filename, await blobToBase64(blob));
    if (result?.error) throw new Error(result.error);
    return {
      desktop: true,
      saved: Boolean(result?.saved),
      cancelled: Boolean(result?.cancelled),
      path: result?.path || ""
    };
  }
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  // Browsers do not expose a reliable "download finished" event for an
  // anchor-triggered Blob download. Keep the URL alive long enough for the
  // download manager to consume it, then release it.
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
  return { desktop: false, saved: true, cancelled: false, path: "" };
}

async function exportPackets(fileFormat, mode, captureSource = null) {
  if (mode === "selected" && !selectedPackets.size) {
    $("#servermsg").textContent = "Select one or more packet rows before exporting.";
    return;
  }
  let password = await promptExportPassword(fileFormat);
  if (password === null) return;
  const payload = JSON.stringify({
    format: fileFormat,
    mode,
    password,
    filters: currentFilters,
    packets: mode === "selected" ? selectedExportRows() : undefined,
    ...(captureSource || {})
  });
  try {
    let blob;
    if (hasDesktopBridge()) {
      const res = await window.pywebview.api.request("POST", "/api/export", payload, null, null);
      const status = Number(res?.status) || 500;
      if (status === 401) showAuthGate(true, "Your sign-in expired. Please sign in again.");
      if (status < 200 || status >= 300) {
        throw new Error(res?.json?.error || `Export failed (${status})`);
      }
      blob = base64ToBlob(res.body_b64, res.mimetype || "application/octet-stream");
    } else {
      const response = await fetch("/api/export", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: payload
      });
      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.error || `Export failed (${response.status})`);
      }
      blob = await response.blob();
    }
    const exportName = mode === "network_report" || mode === "saved"
      ? "network_report"
      : "network_traffic";
    const outcome = await triggerBlobDownload(
      blob,
      `${exportName}_${new Date().toISOString().replace(/[:.]/g, "-")}.${fileFormat}`
    );
    if (outcome.desktop) {
      $("#servermsg").textContent = outcome.saved
        ? `Encrypted ${fileFormat.toUpperCase()} export saved to ${outcome.path}.`
        : "Export save cancelled.";
    } else {
      $("#servermsg").textContent = `Encrypted ${fileFormat.toUpperCase()} export sent to your browser. Check its Downloads list.`;
    }
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

function openDecryptCsvDialog() {
  const form = $("#decryptCsvForm");
  form.reset();
  resetFormPasswordToggles(form);
  $("#decryptCsvMessage").textContent = "";
  $("#decryptCsvDialog").showModal();
  $("#decryptCsvFile").focus();
}

async function submitDecryptCsv(event) {
  event.preventDefault();
  const file = $("#decryptCsvFile").files[0];
  const passwordInput = $("#decryptCsvPassword");
  const password = passwordInput.value;
  const message = $("#decryptCsvMessage");
  if (!file) {
    message.textContent = "Choose an encrypted .csv file first.";
    return;
  }
  if (!password) {
    message.textContent = "Enter the export password.";
    return;
  }
  message.textContent = "Decrypting…";
  try {
    let blob;
    if (hasDesktopBridge()) {
      const data_b64 = await blobToBase64(file);
      const res = await window.pywebview.api.request(
        "POST",
        "/api/export/decrypt-csv",
        null,
        { password },
        { field: "file", filename: file.name, data_b64 }
      );
      const status = Number(res?.status) || 500;
      if (status === 401) showAuthGate(true, "Your sign-in expired. Please sign in again.");
      if (status < 200 || status >= 300) {
        throw new Error(res?.json?.error || `Could not decrypt CSV (${status})`);
      }
      blob = base64ToBlob(res.body_b64, res.mimetype || "text/csv");
    } else {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("password", password);
      const response = await fetch("/api/export/decrypt-csv", {
        method: "POST",
        credentials: "same-origin",
        body: formData
      });
      if (!response.ok) {
        if (response.status === 401) showAuthGate(true, "Your sign-in expired. Please sign in again.");
        const error = await response.json().catch(() => ({}));
        throw new Error(error.error || `Could not decrypt CSV (${response.status})`);
      }
      blob = await response.blob();
    }
    const baseName = file.name.replace(/\.csv$/i, "") || "lan_traffic_analyzer_export";
    const outcome = await triggerBlobDownload(blob, `${baseName}_decrypted.csv`);
    $("#decryptCsvForm").reset();
    resetFormPasswordToggles($("#decryptCsvForm"));
    message.textContent = "";
    $("#decryptCsvDialog").close();
    $("#servermsg").textContent = outcome.desktop
      ? (outcome.saved ? `Decrypted CSV saved to ${outcome.path}.` : "Decrypted CSV save cancelled.")
      : "Decrypted CSV downloaded. Check your browser's Downloads list.";
  } catch (error) {
    message.textContent = error.message;
  } finally {
    passwordInput.value = "";
  }
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
    const prevGateway = defaultGatewayIp;
    defaultGatewayIp = data.gateway || "";
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
    if (defaultGatewayIp !== prevGateway) renderClients();
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

function resetSavedInlineActions(clearMessage = true) {
  $("#renameSavedRow").hidden = true;
  $("#deleteSavedRow").hidden = true;
  if (clearMessage) $("#savedActionMsg").textContent = "";
}

function updateSavedActionButtons() {
  const selectedName = $("#savedFiles").value;
  const selectedItem = savedSessionsList.find(item => item.name === selectedName);
  const hasSelection = Boolean(selectedItem);
  $("#loadSaved").disabled = !hasSelection;
  $("#renameSaved").disabled = !hasSelection;
  $("#deleteSaved").disabled = !hasSelection || Boolean(selectedItem?.active);
  $("#deleteSaved").title = selectedItem?.active
    ? "Clear the active capture on the main toolbar before deleting this file."
    : "";
}

function populateSavedFilesSelect(sessions, preferredName = "") {
  savedSessionsList = Array.isArray(sessions) ? sessions : [];
  const select = $("#savedFiles");
  select.innerHTML = "";
  savedSessionsList.forEach(item => {
    const option = document.createElement("option");
    option.value = item.name;
    const activeNote = item.active ? " (current session)" : "";
    option.textContent = `${item.name}${activeNote} · ${new Date(item.modified).toLocaleString()} · ${formatBytes(item.bytes)}`;
    select.append(option);
  });
  if (preferredName && savedSessionsList.some(item => item.name === preferredName)) {
    select.value = preferredName;
  }
  updateSavedActionButtons();
}

function populateCompareSelect() {
  const compareSelect = $("#compareBaseline");
  const currentFile = viewerToken ? "" : $("#savedFiles").value;
  const candidates = savedSessionsList.filter(item => item.name !== currentFile);
  compareSelect.innerHTML = "";
  candidates.forEach(item => {
    const option = document.createElement("option");
    option.value = item.name;
    option.textContent = `${item.name} · ${formatBytes(item.bytes)}`;
    compareSelect.append(option);
  });
  $("#savedCompareBar").hidden = candidates.length === 0;
  $("#savedCompareResult").hidden = true;
  $("#savedCompareResult").innerHTML = "";
}

async function openSavedCaptures() {
  try {
    const data = await api("/api/sessions");
    viewerToken = "";
    savedReportSource = null;
    $("#savedReport").hidden = true;
    resetSavedInlineActions(true);
    populateSavedFilesSelect(data.sessions);
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
    resetSavedInlineActions(false);
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
    $("#savedPage").textContent = savedTotal === 0
      ? "0 packets"
      : `${savedOffset + 1}-${Math.min(savedOffset + result.records.length, savedTotal)} of ${savedTotal.toLocaleString()} packets`;
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
  const savedServices = $("#savedServices");
  if (savedServices) {
    savedServices.innerHTML = Array.isArray(report.top_services) && report.top_services.length
      ? report.top_services.map(item =>
        `<div class="row"><code>${escapeHtml(item.service)}</code>` +
        `<div class="meter"><i style="width:${Math.min(100, item.percentage)}%"></i></div>` +
        `<span>${item.packets.toLocaleString()} (${item.percentage.toFixed(1)}%)</span></div>`
      ).join("")
      : '<span class="sub">No service data.</span>';
  }
  const savedDomains = $("#savedDomains");
  if (savedDomains) {
    const domPeak = report.top_domains?.[0]?.packets || 1;
    savedDomains.innerHTML = Array.isArray(report.top_domains) && report.top_domains.length
      ? report.top_domains.map(item =>
        `<div class="row domain-row"><code>${escapeHtml(item.domain)}</code>` +
        `<div class="meter"><i style="width:${Math.min(100, item.packets / domPeak * 100)}%"></i></div>` +
        `<span>${item.packets.toLocaleString()}</span></div>`
      ).join("")
      : '<span class="sub">No domains observed.</span>';
  }
  $("#savedClients").innerHTML = report.clients.map(client =>
    `<tr><td class="m">${escapeHtml(client.ip)}</td>` +
    `<td>${escapeHtml(client.name || "Unknown device")}</td>` +
    `<td class="m">${escapeHtml(client.mac || "Not recorded")}</td>` +
    `<td>${escapeHtml(client.vendor || "—")}</td>` +
    `<td>${client.sent_packets.toLocaleString()}</td>` +
    `<td>${client.received_packets.toLocaleString()}</td>` +
    `<td>${formatBytes(client.total_bytes)}</td>` +
    `<td>${escapeHtml(client.protocols.join(", ") || "—")}</td></tr>`
  ).join("") || '<tr><td colspan="8">No private-LAN clients observed.</td></tr>';
  $("#savedTree").innerHTML = report.tree.length
    ? `<ul>${report.tree.map(network =>
      `<li><b>Network ${escapeHtml(network.network)}</b><ul>` +
      `${network.clients.map(client => {
        const label = [client.name, client.mac || "MAC not recorded", client.vendor].filter(Boolean).join(" · ");
        return `<li>${escapeHtml(client.ip)} · ${escapeHtml(label)} <small>${formatBytes(client.total_bytes)}</small></li>`;
      }).join("")}</ul></li>`
    ).join("")}</ul>`
    : '<span class="sub">No private-LAN network tree data.</span>';
  populateCompareSelect();
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
    $("#savedCompareBar").hidden = true;
    $("#savedCompareResult").hidden = true;
    $("#savedReportStats").innerHTML = "";
    $("#savedHealth").innerHTML = "";
    $("#savedAdvice").innerHTML = "";
    $("#savedProtocols").innerHTML = "";
    if ($("#savedServices")) $("#savedServices").innerHTML = "";
    if ($("#savedDomains")) $("#savedDomains").innerHTML = "";
    $("#savedClients").innerHTML = "";
    $("#savedTree").innerHTML = "";
  }
}

async function compareSavedSessions() {
  if (!savedReportSource) return;
  const baseline = $("#compareBaseline").value;
  if (!baseline) return;
  const container = $("#savedCompareResult");
  container.hidden = false;
  container.innerHTML = '<span class="sub">Comparing captures…</span>';
  try {
    const result = await api("/api/sessions/compare", {
      method: "POST",
      body: JSON.stringify({ ...savedReportSource, baseline })
    });
    const cmp = result.comparison;
    const fmtDelta = (val, fmt = v => v.toLocaleString()) => `${val >= 0 ? "+" : ""}${fmt(val)}`;
    const deviceItem = d => `<li><code>${escapeHtml(d.ip)}</code>${d.name ? ` · ${escapeHtml(d.name)}` : ""}${d.vendor ? ` (${escapeHtml(d.vendor)})` : ""}</li>`;
    const newHtml = cmp.new_devices.length
      ? `<ul>${cmp.new_devices.map(deviceItem).join("")}</ul>`
      : '<p class="sub">None</p>';
    const missingHtml = cmp.missing_devices.length
      ? `<ul>${cmp.missing_devices.map(deviceItem).join("")}</ul>`
      : '<p class="sub">None</p>';
    const protoHtml = cmp.protocol_changes.length
      ? `<ul>${cmp.protocol_changes.map(p => `<li><b>${escapeHtml(p.protocol)}</b>: ${fmtDelta(p.delta_packets)} pkt(s) (${p.baseline_packets.toLocaleString()} → ${p.current_packets.toLocaleString()})</li>`).join("")}</ul>`
      : '<p class="sub">No protocol differences.</p>';
    container.innerHTML =
      `<h4>Comparison: ${escapeHtml(cmp.current_name)} vs ${escapeHtml(cmp.baseline_name)}</h4>` +
      `<p class="sub">Packets: <b>${fmtDelta(cmp.packet_delta)}</b> (${cmp.baseline_packets.toLocaleString()} → ${cmp.current_packets.toLocaleString()}) · ` +
      `Data: <b>${cmp.bytes_delta >= 0 ? "+" : "-"}${formatBytes(Math.abs(cmp.bytes_delta))}</b> · ` +
      `LAN clients: <b>${fmtDelta(cmp.client_delta)}</b> (${cmp.baseline_clients} → ${cmp.current_clients})</p>` +
      `<div class="compare-grid"><div><b>New devices (${cmp.new_devices.length})</b>${newHtml}</div>` +
      `<div><b>No longer seen (${cmp.missing_devices.length})</b>${missingHtml}</div>` +
      `<div><b>Protocol shifts</b>${protoHtml}</div></div>`;
  } catch (error) {
    container.innerHTML = `<span class="sub">${escapeHtml(error.message)}</span>`;
  }
}

async function openLocalCapture() {
  const file = $("#localCaptureFile").files[0];
  if (!file) {
    $("#servermsg").textContent = "Choose a .msgpack file first.";
    return;
  }
  try {
    let result;
    if (hasDesktopBridge()) {
      const data_b64 = await blobToBase64(file);
      const res = await window.pywebview.api.request(
        "POST",
        "/api/sessions/open",
        null,
        {},
        { field: "file", filename: file.name, data_b64 }
      );
      result = res?.json || {};
      const status = Number(res?.status) || 500;
      if (status === 401) showAuthGate(true, "Your sign-in expired. Please sign in again.");
      if (status < 200 || status >= 300) {
        throw new Error(result.error || `Could not open capture (${status})`);
      }
    } else {
      const form = new FormData();
      form.append("file", file);
      const response = await fetch("/api/sessions/open", {
        method: "POST",
        credentials: "same-origin",
        body: form
      });
      result = await response.json().catch(() => ({}));
      if (!response.ok) {
        if (response.status === 401) showAuthGate(true, "Your sign-in expired. Please sign in again.");
        throw new Error(result.error || `Could not open capture (${response.status})`);
      }
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
    lastPacketId = 0;
    lastRates = { packets: 0, bytes: 0 };
    filteredPackets = null;
    filteredTotal = 0;
    filterOffset = 0;
    currentFilters = {};
    selectedPackets.clear();
    resolvedIdentityAttempts.clear();
    liveViewPaused = false;
    pausedNewPackets = 0;
    activeFlow = null;
    liveAlerts = [];
    renderAlerts();
    updatePauseButton();
    clearFilterFields();
    setCaptureControls(false);
    $("#pies").innerHTML = '<span class="sub">Press Start, then Stop to see the breakdown.</span>';
    render({ forcePacketView: true });
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
        password: form.get("password")
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
["loginForm", "registerForm", "exportPasswordForm", "decryptCsvForm"].forEach(formId => {
  $(`#${formId}`).addEventListener("reset", () => {
    window.setTimeout(() => {
      resetFormPasswordToggles($(`#${formId}`));
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
$("#filterPrev").addEventListener("click", () => {
  filterOffset = Math.max(0, filterOffset - FILTER_PAGE_SIZE);
  renderPackets();
});
$("#filterNext").addEventListener("click", () => {
  if (filteredPackets && filterOffset + FILTER_PAGE_SIZE < filteredPackets.length) {
    filterOffset += FILTER_PAGE_SIZE;
    renderPackets();
  }
});
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
$("#exportPdfPackets").addEventListener("click", () => exportPackets("pdf", selectedPackets.size ? "selected" : "filtered"));
$("#exportCsvPackets").addEventListener("click", () => exportPackets("csv", selectedPackets.size ? "selected" : "filtered"));
$("#exportPdfReport").addEventListener("click", () => exportPackets("pdf", "network_report"));
$("#openDecryptCsv").addEventListener("click", openDecryptCsvDialog);
$("#decryptCsvForm").addEventListener("submit", submitDecryptCsv);
$("#decryptCsvCancel").addEventListener("click", () => {
  $("#decryptCsvForm").reset();
  resetFormPasswordToggles($("#decryptCsvForm"));
  $("#decryptCsvMessage").textContent = "";
  $("#decryptCsvDialog").close();
});
$("#decryptCsvDialog").addEventListener("close", () => {
  $("#decryptCsvPassword").value = "";
  resetFormPasswordToggles($("#decryptCsvForm"));
  $("#decryptCsvMessage").textContent = "";
});
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
$("#tabPackets").addEventListener("click", () => setPacketTab("packets"));
$("#tabFlows").addEventListener("click", () => setPacketTab("flows"));
$("#tabDns").addEventListener("click", () => setPacketTab("dns"));
$("#dnsErrorsOnly").addEventListener("change", () => renderDnsActivity({ forceRender: true }));
$("#flowSort").addEventListener("change", () => renderFlows({ forceRender: true }));
$("#pausePacketView").addEventListener("click", () => {
  liveViewPaused = !liveViewPaused;
  updatePauseButton();
  if (!liveViewPaused) {
    pausedNewPackets = 0;
    renderPackets({ forceRender: true });
  } else {
    renderPackets({ forceRender: false });
  }
});
$("#clearFlowFilter").addEventListener("click", () => {
  activeFlow = null;
  renderPackets({ forceRender: true });
});
$("#neighborsOnly").addEventListener("change", renderClients);
["#ts", "#tr"].forEach(selector => {
  const container = $(selector);
  const handleTalker = event => {
    const row = event.target.closest("[data-filter-ip]");
    if (!row) return;
    filterByDevice(row.dataset.filterIp, row.dataset.filterRole);
  };
  container.addEventListener("click", handleTalker);
  container.addEventListener("keydown", event => {
    if (event.key === "Enter" || event.key === " ") {
      const row = event.target.closest("[data-filter-ip]");
      if (!row) return;
      event.preventDefault();
      filterByDevice(row.dataset.filterIp, row.dataset.filterRole);
    }
  });
});
["#topDomains", "#topServices"].forEach(selector => {
  const container = $(selector);
  if (!container) return;
  const handleQuery = event => {
    const row = event.target.closest("[data-filter-query]");
    if (!row) return;
    filterByDevice(row.dataset.filterQuery, "any");
  };
  container.addEventListener("click", handleQuery);
  container.addEventListener("keydown", event => {
    if (event.key === "Enter" || event.key === " ") {
      const row = event.target.closest("[data-filter-query]");
      if (!row) return;
      event.preventDefault();
      filterByDevice(row.dataset.filterQuery, "any");
    }
  });
});
$("#db").addEventListener("click", event => {
  const row = event.target.closest("tr[data-dns-domain]");
  if (row) filterByDevice(row.dataset.dnsDomain, "any");
});
$("#db").addEventListener("keydown", event => {
  if (event.key === "Enter" || event.key === " ") {
    const row = event.target.closest("tr[data-dns-domain]");
    if (!row) return;
    event.preventDefault();
    filterByDevice(row.dataset.dnsDomain, "any");
  }
});
function openNicknameModal(ip, mac) {
  activeNicknameTarget = { ip, mac };
  const record = S.clients[ip];
  const current = getDeviceNickname(ip, mac) || record?.name || "";
  $("#nicknameTarget").textContent = [ip, mac || "MAC not recorded"].filter(Boolean).join(" · ");
  $("#nicknameInput").value = current;
  $("#nicknameDialog").showModal();
  $("#nicknameInput").focus();
  $("#nicknameInput").select();
}
$("#nicknameForm").addEventListener("submit", event => {
  event.preventDefault();
  if (!activeNicknameTarget) return;
  setDeviceNickname(activeNicknameTarget.ip, activeNicknameTarget.mac, $("#nicknameInput").value);
  $("#nicknameDialog").close();
  renderClients();
});
$("#nicknameClear").addEventListener("click", () => {
  if (!activeNicknameTarget) return;
  setDeviceNickname(activeNicknameTarget.ip, activeNicknameTarget.mac, "");
  $("#nicknameDialog").close();
  renderClients();
});
$("#nicknameCancel").addEventListener("click", () => $("#nicknameDialog").close());
["#cb", "#v2"].forEach(selector => {
  const container = $(selector);
  const handleClient = event => {
    const editBtn = event.target.closest(".edit-nick-btn");
    if (editBtn) {
      event.stopPropagation();
      openNicknameModal(editBtn.dataset.nickIp, editBtn.dataset.nickMac || "");
      return;
    }
    const row = event.target.closest("[data-client-ip]");
    if (!row) return;
    filterByDevice(row.dataset.clientIp, "any");
  };
  container.addEventListener("click", handleClient);
  container.addEventListener("keydown", event => {
    if (event.key === "Enter" || event.key === " ") {
      const editBtn = event.target.closest(".edit-nick-btn");
      if (editBtn) {
        event.stopPropagation();
        event.preventDefault();
        openNicknameModal(editBtn.dataset.nickIp, editBtn.dataset.nickMac || "");
        return;
      }
      const row = event.target.closest("[data-client-ip]");
      if (!row) return;
      event.preventDefault();
      filterByDevice(row.dataset.clientIp, "any");
    }
  });
});
function activateFlowRow(row) {
  const flow = ($("#fb")._flows || []).find(item => item.key === row.dataset.flowKey);
  if (!flow) return;
  const epA = flow.portA !== null && flow.portA !== undefined && flow.portA !== "" ? `${flow.ipA}:${flow.portA}` : flow.ipA;
  const epB = flow.portB !== null && flow.portB !== undefined && flow.portB !== "" ? `${flow.ipB}:${flow.portB}` : flow.ipB;
  activeFlow = {
    proto: flow.proto,
    ipA: flow.ipA,
    portA: flow.portA,
    ipB: flow.ipB,
    portB: flow.portB,
    label: `${flow.proto} ${epA} ↔ ${epB}`
  };
  setPacketTab("packets");
}
$("#fb").addEventListener("click", event => {
  const row = event.target.closest("tr[data-flow-key]");
  if (row) activateFlowRow(row);
});
$("#fb").addEventListener("keydown", event => {
  if (event.key === "Enter" || event.key === " ") {
    const row = event.target.closest("tr[data-flow-key]");
    if (!row) return;
    event.preventDefault();
    activateFlowRow(row);
  }
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
  resetSavedInlineActions(true);
  updateSavedActionButtons();
  $("#savedReport").hidden = true;
  $("#savedPackets").innerHTML = "";
  $("#savedPage").textContent = "Open capture to view packets";
});
$("#renameSaved").addEventListener("click", () => {
  const filename = $("#savedFiles").value;
  if (!filename) return;
  resetSavedInlineActions(true);
  $("#renameSavedInput").value = filename.replace(/\.msgpack$/i, "");
  $("#renameSavedRow").hidden = false;
  $("#renameSavedInput").focus();
  $("#renameSavedInput").select();
});
$("#cancelRenameSaved").addEventListener("click", () => resetSavedInlineActions(false));
$("#renameSavedRow").addEventListener("submit", async event => {
  event.preventDefault();
  const filename = $("#savedFiles").value;
  const newName = $("#renameSavedInput").value.trim();
  if (!filename || !newName) return;
  try {
    const result = await api(`/api/sessions/${encodeURIComponent(filename)}`, {
      method: "PATCH",
      body: JSON.stringify({ name: newName })
    });
    const listData = await api("/api/sessions");
    populateSavedFilesSelect(listData.sessions, result.name);
    resetSavedInlineActions(false);
    $("#savedActionMsg").textContent = `Renamed ${filename} to ${result.name}.`;
    if (savedReportSource?.filename === filename) {
      loadSavedPage(0);
    }
  } catch (error) {
    $("#savedActionMsg").textContent = error.message;
  }
});
$("#deleteSaved").addEventListener("click", () => {
  const filename = $("#savedFiles").value;
  if (!filename) return;
  resetSavedInlineActions(true);
  $("#deleteSavedPrompt").textContent = `Delete ${filename}? This cannot be undone.`;
  $("#deleteSavedRow").hidden = false;
});
$("#cancelDeleteSaved").addEventListener("click", () => resetSavedInlineActions(false));
$("#confirmDeleteSaved").addEventListener("click", async () => {
  const filename = $("#savedFiles").value;
  if (!filename) return;
  try {
    await api(`/api/sessions/${encodeURIComponent(filename)}`, { method: "DELETE" });
    const listData = await api("/api/sessions");
    populateSavedFilesSelect(listData.sessions);
    resetSavedInlineActions(false);
    $("#savedActionMsg").textContent = `Deleted ${filename}.`;
    if (savedReportSource?.filename === filename) {
      savedReportSource = null;
      $("#savedReport").hidden = true;
      $("#savedPackets").innerHTML = "";
      $("#savedPage").textContent = listData.sessions.length ? "Choose a capture file" : "No saved captures";
    }
  } catch (error) {
    $("#savedActionMsg").textContent = error.message;
  }
});
$("#compareSavedBtn").addEventListener("click", compareSavedSessions);
$("#openLocalCapture").addEventListener("click", openLocalCapture);
$("#savedReportPdf").addEventListener("click", () => exportSavedReport("pdf"));
$("#savedPrev").addEventListener("click", () => loadSavedPage(Math.max(0, savedOffset - PAGE_SIZE)));
$("#savedNext").addEventListener("click", () => loadSavedPage(savedOffset + PAGE_SIZE));
$("#savedPackets").addEventListener("dblclick", event => {
  const row = event.target.closest("tr[data-saved-packet]");
  if (row) showPacketDetails(JSON.parse(row.dataset.savedPacket));
});
$("#themeToggle").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(next, true);
  render({ packets: false, graphs: true, forceSlow: false });
});
document.querySelectorAll('a[href="about.html"]').forEach(link => {
  link.addEventListener("click", () => {
    navigatingToSubpage = true;
  });
});
window.addEventListener("pagehide", () => {
  if (S.run && !navigatingToSubpage && !hasDesktopBridge() && navigator.sendBeacon) {
    navigator.sendBeacon(
      "/api/capture/stop",
      new Blob(["{}"], { type: "application/json" })
    );
  }
});

$("#clearAlerts").addEventListener("click", async () => {
  try {
    await api("/api/alerts/clear", { method: "POST" });
    liveAlerts = [];
    renderAlerts();
  } catch (error) {
    $("#servermsg").textContent = error.message;
  }
});
$("#alertsList").addEventListener("click", event => {
  const button = event.target.closest("button[data-alert-ip]");
  if (!button) return;
  filterByDevice(button.dataset.alertIp, "any", button.dataset.alertProto || "All");
});

initTheme();
setCaptureControls(false);
renderAlerts();
render();
waitForDesktopBridgeIfNeeded().then(authStatus);
