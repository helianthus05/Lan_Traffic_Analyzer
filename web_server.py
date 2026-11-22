"""Local web front end for the Scapy packet capture engine."""

import atexit
from collections import deque
from datetime import datetime
from functools import wraps
import io
import ipaddress
import json
import os
from pathlib import Path
from queue import Empty, Full, Queue
import re
import secrets
import shutil
import statistics
import tempfile
from threading import Event, Lock, Thread
import time
from urllib.parse import urlsplit

from flask import Flask, jsonify, request, send_file, send_from_directory, session
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

import capture
import database
import export
import network_report
from auth import FirebaseAuthClient

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__, static_folder=None)
app.secret_key = secrets.token_bytes(32)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)

# The capture callback must never wait for the browser or disk I/O.
ui_packets = deque(maxlen=5000)
persist_queue = Queue(maxsize=30000)
state_lock = Lock()
auth_lock = Lock()
capture_lifecycle_lock = Lock()
stop_finished = Event()
stop_finished.set()
sniffer = None
capture_interface = None
capturing = False
stopping = False
capture_error = None
database_error = None
dropped_packets = 0
packet_number = 0
auth_client = None
auth_sessions = {}
pending_verifications = {}
_desktop_bridge_secret = None
_desktop_auth_id = None
_desktop_pending_verification = None
opened_uploads = {}
upload_lock = Lock()
health_gateway = None
health_samples = deque(maxlen=5)
health_report_snapshot = {
    "state": "checking",
    "description": "No gateway health check has completed in this server session.",
    "checked_at": "",
    "context": (
        "Live gateway health at report generation; historical health is not "
        "stored in packet captures."
    ),
}
def _set_health_report_snapshot(state, description, gateway=None):
    global health_report_snapshot
    snapshot = {
        "state": state,
        "description": description,
        "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "context": (
            "Live gateway health at report generation; historical health is not "
            "stored in packet captures."
        ),
    }
    with state_lock:
        health_report_snapshot = snapshot
    return jsonify(state=state, description=description, gateway=gateway or "")


def _strip_env_quotes(value):
    cleaned = str(value or "").strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {'"', "'"}:
        cleaned = cleaned[1:-1].strip()
    return cleaned


def _read_windows_env_var(name):
    if os.name != "nt":
        return ""
    try:
        import winreg
    except ImportError:
        return ""

    locations = (
        (winreg.HKEY_CURRENT_USER, r"Environment"),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        ),
    )
    for root, subkey in locations:
        try:
            with winreg.OpenKey(root, subkey) as key:
                value, _ = winreg.QueryValueEx(key, name)
        except OSError:
            continue
        cleaned = _strip_env_quotes(value)
        if cleaned:
            return os.path.expandvars(cleaned)
    return ""


def _get_env_var(name):
    value = _strip_env_quotes(os.environ.get(name, ""))
    if value:
        return value
    return _read_windows_env_var(name)


def _auth_config():
    api_key = _get_env_var("FIREBASE_WEB_API_KEY")

    raw_json = _get_env_var("FIREBASE_SERVICE_ACCOUNT_JSON")
    if raw_json:
        try:
            parsed = json.loads(raw_json)
        except ValueError:
            return (
                api_key,
                None,
                "FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON.",
            )
        if not isinstance(parsed, dict) or not parsed:
            return (
                api_key,
                None,
                "FIREBASE_SERVICE_ACCOUNT_JSON must contain a JSON object.",
            )
        if not api_key:
            return (
                api_key,
                parsed,
                "Set the FIREBASE_WEB_API_KEY system environment variable before signing in.",
            )
        return api_key, parsed, ""

    for var_name in ("FIREBASE_SERVICE_ACCOUNT_PATH", "GOOGLE_APPLICATION_CREDENTIALS"):
        raw_value = _get_env_var(var_name)
        if not raw_value:
            continue
        if raw_value.lstrip().startswith("{"):
            try:
                parsed = json.loads(raw_value)
            except ValueError:
                return api_key, None, f"{var_name} does not contain valid JSON."
            if not isinstance(parsed, dict) or not parsed:
                return api_key, None, f"{var_name} must contain a JSON object."
            if not api_key:
                return (
                    api_key,
                    parsed,
                    "Set the FIREBASE_WEB_API_KEY system environment variable before signing in.",
                )
            return api_key, parsed, ""

        expanded = os.path.expanduser(os.path.expandvars(raw_value))
        candidate = Path(expanded)
        if not candidate.is_file():
            return (
                api_key,
                None,
                f"Firebase service-account JSON file set in {var_name} was not found: {candidate}",
            )
        if not api_key:
            return (
                api_key,
                str(candidate),
                "Set the FIREBASE_WEB_API_KEY system environment variable before signing in.",
            )
        return api_key, str(candidate), ""

    if not api_key:
        return (
            api_key,
            None,
            "Set FIREBASE_WEB_API_KEY and FIREBASE_SERVICE_ACCOUNT_PATH "
            "(or FIREBASE_SERVICE_ACCOUNT_JSON / GOOGLE_APPLICATION_CREDENTIALS) "
            "in your system environment variables.",
        )
    return (
        api_key,
        None,
        "Set FIREBASE_SERVICE_ACCOUNT_PATH (or FIREBASE_SERVICE_ACCOUNT_JSON / "
        "GOOGLE_APPLICATION_CREDENTIALS) in your system environment variables.",
    )


def _get_auth_client():
    global auth_client
    with auth_lock:
        if auth_client is None:
            api_key, service_account_source, config_error = _auth_config()
            if config_error or not api_key or service_account_source is None:
                raise RuntimeError(
                    config_error
                    or "Firebase system environment variables are not configured."
                )
            auth_client = FirebaseAuthClient(api_key, service_account_source)
        return auth_client


def enable_desktop_bridge():
    """Enable in-process session binding exclusively for desktop_app.py."""
    global _desktop_bridge_secret, _desktop_auth_id, _desktop_pending_verification
    with auth_lock:
        _desktop_bridge_secret = secrets.token_urlsafe(32)
        _desktop_auth_id = None
        _desktop_pending_verification = None
        return _desktop_bridge_secret


def _is_desktop_bridge_request():
    with auth_lock:
        expected = _desktop_bridge_secret
    if not expected:
        return False
    provided = request.headers.get("X-LANWatch-Desktop-Bridge", "")
    return bool(provided) and secrets.compare_digest(provided, expected)


def _current_auth_id():
    auth_id = session.get("auth_id")
    if auth_id:
        return auth_id
    if _is_desktop_bridge_request():
        with auth_lock:
            return _desktop_auth_id
    return None


def _current_pending_verification_id():
    pending_id = session.get("pending_verification")
    if pending_id:
        return pending_id
    if _is_desktop_bridge_request():
        with auth_lock:
            return _desktop_pending_verification
    return None


def _current_auth():
    auth_id = _current_auth_id()
    if not auth_id:
        return None
    return auth_sessions.get(auth_id)


def _set_authenticated_user(result):
    global _desktop_auth_id, _desktop_pending_verification
    old_id = _current_auth_id()
    if old_id:
        auth_sessions.pop(old_id, None)
        _remove_opened_uploads(old_id)
    pending_id = _current_pending_verification_id()
    if pending_id:
        pending_verifications.pop(pending_id, None)
    auth_id = secrets.token_urlsafe(32)
    auth_sessions[auth_id] = {
        "uid": result.get("uid", ""),
        "username": result.get("username", ""),
        "email": result.get("email", ""),
    }
    session.clear()
    session["auth_id"] = auth_id
    if _is_desktop_bridge_request():
        with auth_lock:
            _desktop_auth_id = auth_id
            _desktop_pending_verification = None


def require_auth(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        if _current_auth() is None:
            return jsonify(error="Please sign in to use LAN Traffic Analyzer."), 401
        return handler(*args, **kwargs)
    return wrapped


ALLOWED_LOCAL_PORTS = {5000}


@app.before_request
def restrict_to_local_browser():
    parsed_host = urlsplit("//" + request.host)
    if parsed_host.hostname not in {"127.0.0.1", "localhost"} or parsed_host.port not in (None, *ALLOWED_LOCAL_PORTS):
        return jsonify(error="LAN Traffic Analyzer only accepts local browser requests."), 403
    origin = request.headers.get("Origin")
    if origin:
        parsed_origin = urlsplit(origin)
        if (
            parsed_origin.scheme != "http"
            or parsed_origin.netloc.casefold() != request.host.casefold()
        ):
            return jsonify(error="Cross-origin requests are not allowed."), 403
    sec_fetch_site = request.headers.get("Sec-Fetch-Site")
    if sec_fetch_site and sec_fetch_site not in {"same-origin", "none"}:
        return jsonify(error="Cross-site requests are not allowed."), 403
    return None


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.errorhandler(RequestEntityTooLarge)
def request_too_large(error):
    return jsonify(error="Capture files must be smaller than 256 MB."), 413


def _record_database_error(error):
    global database_error
    with state_lock:
        database_error = str(error)
    print(f"Database write error: {error}")


_FLUSH = object()


def _flush_pending_packets(timeout=3.0):
    with state_lock:
        active = capturing or stopping
    if not active:
        persist_queue.join()
        return
    done = Event()
    try:
        persist_queue.put((_FLUSH, done), timeout=0.5)
    except Full:
        return
    done.wait(timeout=timeout)


def flush_worker():
    """Persist small batches and acknowledge records only after each write."""
    batch = []

    def _flush_batch():
        if not batch:
            return
        try:
            database.save_packets(batch)
        except Exception as exc:
            _record_database_error(exc)
        finally:
            for _ in batch:
                persist_queue.task_done()
            batch.clear()

    while True:
        try:
            item = persist_queue.get(timeout=0.5)
        except Empty:
            item = ...
        if item is None:
            _flush_batch()
            persist_queue.task_done()
            return
        if isinstance(item, tuple) and len(item) == 2 and item[0] is _FLUSH:
            _flush_batch()
            persist_queue.task_done()
            item[1].set()
            continue
        if item is not ...:
            batch.append(item)
        if batch and (len(batch) >= 100 or item is ...):
            _flush_batch()


Thread(target=flush_worker, name="PacketDatabaseWriter", daemon=True).start()


_ALERT_SCAN_WINDOW = 15.0
_ALERT_HTTP_WINDOW = 20.0
_ALERT_DNS_FAIL_WINDOW = 30.0
_ALERT_DNS_BURST_WINDOW = 20.0
_MAX_ALERT_TRACKERS = 2048
_MAX_ACTIVE_ALERTS = 50
_PRIVATE_LAN_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
)
_DNS_ERROR_RE = re.compile(r"\[(FORMERR|SERVFAIL|NXDOMAIN|NOTIMP|REFUSED)\]")
_DNS_QUERY_RE = re.compile(r"\(DNS:\s*query\s+([^\s)]+)")


def _is_valid_unicast_mac(mac_text):
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(mac_text or "")).lower()
    if len(cleaned) != 12 or cleaned in ("000000000000", "ffffffffffff"):
        return ""
    try:
        if int(cleaned[:2], 16) & 0x01:
            return ""
    except ValueError:
        return ""
    return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))


def _is_private_lan_ipv4(ip_text):
    try:
        addr = ipaddress.IPv4Address(str(ip_text or "").strip())
    except (ipaddress.AddressValueError, ValueError):
        return False
    return any(addr in net for net in _PRIVATE_LAN_NETS)


def _is_unicast_ip(ip_text):
    text = str(ip_text or "").strip()
    if not text or text in ("Unknown", "0.0.0.0", "255.255.255.255", "::"):
        return False
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not (addr.is_multicast or addr.is_unspecified)


def _format_byte_size(num_bytes):
    value = float(max(0, num_bytes))
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024


class PassiveAlertMonitor:
    """Passively inspects parsed packet summaries for anomalies (call under state_lock)."""

    def __init__(self):
        self.reset()

    def reset(self):
        self._alerts = {}
        self._seq = 0
        self._ip_macs = {}
        self._port_probes = {}
        self._host_probes = {}
        self._http_windows = {}
        self._dns_fail_windows = {}
        self._dns_query_windows = {}

    @staticmethod
    def _cap_dict(mapping):
        while len(mapping) >= _MAX_ALERT_TRACKERS:
            mapping.pop(next(iter(mapping)))

    @staticmethod
    def _prune_window(queue, cutoff):
        while queue and queue[0][0] < cutoff:
            queue.popleft()

    def _raise_alert(
        self,
        alert_id,
        severity,
        category,
        title,
        detail,
        stamp,
        source_ip="",
        filter_protocol="",
    ):
        self._seq += 1
        existing = self._alerts.get(alert_id)
        if existing is not None:
            existing["severity"] = severity
            existing["title"] = title
            existing["detail"] = detail
            existing["count"] += 1
            existing["last_seen"] = stamp or existing["last_seen"]
            existing["updated_seq"] = self._seq
            return

        if len(self._alerts) >= _MAX_ACTIVE_ALERTS:
            oldest_key = min(
                self._alerts,
                key=lambda k: (
                    0 if self._alerts[k]["severity"] == "warn" else 1,
                    self._alerts[k]["updated_seq"],
                ),
            )
            self._alerts.pop(oldest_key, None)

        self._alerts[alert_id] = {
            "id": alert_id,
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "source_ip": source_ip,
            "filter_protocol": filter_protocol,
            "count": 1,
            "first_seen": stamp,
            "last_seen": stamp,
            "updated_seq": self._seq,
        }

    def snapshot(self):
        ordered = sorted(
            self._alerts.values(),
            key=lambda item: (
                0 if item["severity"] == "bad" else 1,
                -item["updated_seq"],
            ),
        )
        return [dict(item) for item in ordered]

    def dismiss_all(self):
        self._alerts.clear()

    def observe(self, packet, now=None):
        now = time.monotonic() if now is None else float(now)
        src = str(packet.get("src") or packet.get("source_ip") or "")
        dst = str(packet.get("dst") or packet.get("destination_ip") or "")
        proto = str(packet.get("pr") or packet.get("protocol") or "Other")
        info = str(packet.get("info") or "")
        stamp = str(packet.get("time") or packet.get("timestamp") or "")
        if " " in stamp:
            stamp = stamp.split(" ")[-1]
        length = int(packet.get("len") or packet.get("length") or 0)
        sport = packet.get("sport") if "sport" in packet else packet.get("source_port")
        dport = packet.get("dport") if "dport" in packet else packet.get("destination_port")
        src_mac = _is_valid_unicast_mac(packet.get("src_mac") or packet.get("source_mac"))

        # 1. IP-to-MAC conflicts / possible ARP spoofing
        if src_mac and _is_unicast_ip(src) and (proto == "ARP" or _is_private_lan_ipv4(src)):
            entry = self._ip_macs.get(src)
            if entry is None:
                self._cap_dict(self._ip_macs)
                self._ip_macs[src] = {"last": src_mac, "seen": [src_mac]}
            elif src_mac != entry["last"]:
                previous = entry["last"]
                if src_mac not in entry["seen"] and len(entry["seen"]) < 8:
                    entry["seen"].append(src_mac)
                entry["last"] = src_mac
                self._raise_alert(
                    f"arp_spoof:{src}",
                    "bad",
                    "arp_spoof",
                    f"IP-to-MAC change on {src}",
                    f"{src} switched MAC from {previous} to {src_mac} ({len(entry['seen'])} MAC(s) observed). Possible ARP spoofing or IP conflict.",
                    stamp,
                    source_ip=src,
                    filter_protocol="ARP" if proto == "ARP" else "",
                )

        # 2. Port-scan / host-sweep detection
        if _is_unicast_ip(src) and _is_unicast_ip(dst):
            is_server_reply = (
                sport is not None
                and dport is not None
                and ((sport < 1024 and dport >= 1024) or sport in (5353, 8080, 8443))
            )
            if proto in ("TCP", "UDP") and dport is not None and not is_server_reply and dport not in (5353, 1900):
                pair = (src, dst)
                queue = self._port_probes.get(pair)
                if queue is None:
                    self._cap_dict(self._port_probes)
                    queue = self._port_probes[pair] = deque(maxlen=256)
                queue.append((now, int(dport)))
                self._prune_window(queue, now - _ALERT_SCAN_WINDOW)
                distinct_ports = len({port for _, port in queue})
                if distinct_ports >= 12:
                    self._raise_alert(
                        f"port_scan:{src}:{dst}",
                        "bad",
                        "port_scan",
                        f"Possible port scan from {src}",
                        f"{src} probed {distinct_ports} distinct {proto} ports on {dst} within {int(_ALERT_SCAN_WINDOW)}s.",
                        stamp,
                        source_ip=src,
                        filter_protocol=proto,
                    )

            sweep_candidate = (
                (proto == "ARP" and "who-has" in info)
                or (proto == "ICMP" and "echo-request" in info)
                or (
                    proto in ("TCP", "UDP")
                    and dport is not None
                    and _is_private_lan_ipv4(dst)
                    and not is_server_reply
                    and dport not in (5353, 1900)
                )
            )
            if sweep_candidate:
                queue = self._host_probes.get(src)
                if queue is None:
                    self._cap_dict(self._host_probes)
                    queue = self._host_probes[src] = deque(maxlen=512)
                queue.append((now, dst))
                self._prune_window(queue, now - _ALERT_SCAN_WINDOW)
                distinct_hosts = len({target for _, target in queue})
                if distinct_hosts >= 12:
                    self._raise_alert(
                        f"host_sweep:{src}",
                        "bad",
                        "host_sweep",
                        f"Possible host sweep from {src}",
                        f"{src} probed {distinct_hosts} distinct local hosts within {int(_ALERT_SCAN_WINDOW)}s.",
                        stamp,
                        source_ip=src,
                    )

        # 3. Cleartext / noisy anomalies
        if proto == "TCP" and (sport in (21, 23) or dport in (21, 23)):
            service = "Telnet" if (sport == 23 or dport == 23) else "FTP"
            port_num = 23 if service == "Telnet" else 21
            pair_a, pair_b = sorted((src, dst))
            self._raise_alert(
                f"cleartext:{service}:{pair_a}:{pair_b}",
                "warn",
                "cleartext",
                f"Unencrypted {service} traffic observed",
                f"Cleartext {service} session (port {port_num}) between {src} and {dst}. Credentials and traffic are sent unencrypted.",
                stamp,
                source_ip=src,
                filter_protocol="TCP",
            )

        if proto == "TCP" and (sport in (80, 8080) or dport in (80, 8080)):
            http_peer = dst if sport in (80, 8080) else src
            remote_host = src if sport in (80, 8080) else dst
            key = (http_peer, remote_host)
            queue = self._http_windows.get(key)
            if queue is None:
                self._cap_dict(self._http_windows)
                queue = self._http_windows[key] = deque(maxlen=512)
            queue.append((now, max(0, length)))
            self._prune_window(queue, now - _ALERT_HTTP_WINDOW)
            pkt_count = len(queue)
            byte_total = sum(size for _, size in queue)
            if pkt_count >= 25 or byte_total >= 65536:
                self._raise_alert(
                    f"http_spike:{http_peer}:{remote_host}",
                    "warn",
                    "cleartext",
                    "Unencrypted HTTP traffic spike",
                    f"{pkt_count} HTTP packets ({_format_byte_size(byte_total)}) observed between {http_peer} and {remote_host} within {int(_ALERT_HTTP_WINDOW)}s.",
                    stamp,
                    source_ip=http_peer,
                    filter_protocol="TCP",
                )

        if proto in ("UDP", "TCP") and (sport == 53 or dport == 53):
            err_match = _DNS_ERROR_RE.search(info)
            if err_match:
                err_code = err_match.group(1)
                queue = self._dns_fail_windows.get(dst)
                if queue is None:
                    self._cap_dict(self._dns_fail_windows)
                    queue = self._dns_fail_windows[dst] = deque(maxlen=128)
                queue.append((now, err_code))
                self._prune_window(queue, now - _ALERT_DNS_FAIL_WINDOW)
                if len(queue) >= 5:
                    self._raise_alert(
                        f"dns_fail:{dst}",
                        "warn",
                        "dns_anomaly",
                        f"Repeated failed DNS lookups for {dst}",
                        f"{len(queue)} failed DNS responses ({err_code}) sent to {dst} within {int(_ALERT_DNS_FAIL_WINDOW)}s.",
                        stamp,
                        source_ip=dst,
                        filter_protocol=proto,
                    )

            query_match = _DNS_QUERY_RE.search(info)
            if query_match or dport == 53:
                qname = query_match.group(1).lower() if query_match else ""
                queue = self._dns_query_windows.get(src)
                if queue is None:
                    self._cap_dict(self._dns_query_windows)
                    queue = self._dns_query_windows[src] = deque(maxlen=256)
                queue.append((now, qname))
                self._prune_window(queue, now - _ALERT_DNS_BURST_WINDOW)
                same_domain_hits = sum(1 for _, name in queue if qname and name == qname)
                if len(queue) >= 60 or (qname and same_domain_hits >= 25):
                    detail = (
                        f"{src} sent {same_domain_hits} repeated DNS queries for {qname} within {int(_ALERT_DNS_BURST_WINDOW)}s."
                        if qname and same_domain_hits >= 25
                        else f"{src} sent {len(queue)} DNS queries within {int(_ALERT_DNS_BURST_WINDOW)}s."
                    )
                    self._raise_alert(
                        f"dns_burst:{src}",
                        "warn",
                        "dns_anomaly",
                        f"High-rate DNS query burst from {src}",
                        detail,
                        stamp,
                        source_ip=src,
                        filter_protocol=proto,
                    )


alert_monitor = PassiveAlertMonitor()


def on_packet(packet):
    global dropped_packets, packet_number
    with state_lock:
        next_packet_id = packet_number + 1
        db_packet = {**packet, "id": next_packet_id}
        try:
            persist_queue.put_nowait(db_packet)
        except Full:
            dropped_packets += 1
            return
        packet_number = next_packet_id
        timestamp = packet.get("timestamp", "")
        ui_item = {
            "no": next_packet_id,
            "timestamp": timestamp,
            "time": timestamp.split(" ")[-1],
            "src": packet.get("source_ip", "Unknown"),
            "dst": packet.get("destination_ip", "Unknown"),
            "pr": packet.get("protocol", "Other"),
            "len": packet.get("length", 0),
            "info": packet.get("info", ""),
            "sport": packet.get("source_port"),
            "dport": packet.get("destination_port"),
            "src_mac": packet.get("source_mac", ""),
            "dst_mac": packet.get("destination_mac", ""),
        }
        if packet.get("device_name"):
            ui_item["device_name"] = packet["device_name"]
        if packet.get("id_source"):
            ui_item["id_source"] = packet["id_source"]
        if packet.get("domain"):
            ui_item["domain"] = packet["domain"]
        if packet.get("service"):
            ui_item["service"] = packet["service"]
        ui_packets.append(ui_item)
        alert_monitor.observe(ui_item)


def _normalize_filters(values):
    if not isinstance(values, dict):
        raise ValueError("Filters must be provided as an object.")
    filters = {
        key: str(values.get(key, "") or "").strip()
        for key in (
            "protocol", "source_ip", "destination_ip", "port", "keyword",
            "min_size", "max_size", "start_time", "end_time", "search",
        )
    }
    for key in ("port", "min_size", "max_size"):
        if not filters[key]:
            continue
        try:
            value = int(filters[key])
        except ValueError as exc:
            raise ValueError(f"{key.replace('_', ' ').title()} must be a whole number.") from exc
        if value < 0:
            raise ValueError(f"{key.replace('_', ' ').title()} cannot be negative.")
        if key == "port" and value > 65535:
            raise ValueError("Port must be between 0 and 65535.")

    for key in ("start_time", "end_time"):
        value = filters[key].replace("T", " ")
        if not value:
            continue
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(
                f"{key.replace('_', ' ').title()} must use YYYY-MM-DD HH:MM[:SS] format."
            ) from exc
        if len(value) == 10:
            value += " 23:59:59.999999" if key == "end_time" else " 00:00:00.000000"
        elif len(value) == 16:
            value += ":59.999999" if key == "end_time" else ":00.000000"
        elif len(value) == 19:
            base = parsed.strftime("%Y-%m-%d %H:%M:%S")
            value = f"{base}.999999" if key == "end_time" else f"{base}.000000"
        else:
            value = parsed.strftime("%Y-%m-%d %H:%M:%S.%f")
        filters[key] = value

    if filters["protocol"] in ("", "All"):
        filters["protocol"] = ""
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


def _record_dict(row):
    return {
        "id": row[0],
        "timestamp": row[1],
        "source_ip": row[2],
        "destination_ip": row[3],
        "protocol": row[4],
        "length": row[5],
        "source_port": row[6],
        "destination_port": row[7],
        "info": row[8],
    }


def _session_file(filename):
    if (
        not isinstance(filename, str)
        or not filename
        or Path(filename).name != filename
        or not filename.endswith(".msgpack")
    ):
        raise ValueError("Choose a valid saved packet file.")
    root = database.SESSION_DIRECTORY.resolve()
    target = (root / filename).resolve()
    if target.parent != root or not target.is_file():
        raise FileNotFoundError("The saved packet file no longer exists.")
    return target


def _build_network_report(records, capture_name, dropped=None):
    with state_lock:
        health = dict(health_report_snapshot)
    return network_report.build_network_report(
        records,
        capture_name,
        health,
        dropped_packets=dropped,
    )


@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/about")
def about():
    return send_from_directory(BASE_DIR, "about.html")


@app.get("/<path:asset>")
def assets(asset):
    if asset not in {"style.css", "script.js", "index.html", "about.html"}:
        return jsonify(error="Not found"), 404
    return send_from_directory(BASE_DIR, asset)


@app.get("/api/auth/status")
def auth_status():
    user = _current_auth()
    if user:
        return jsonify(
            configured=True,
            authenticated=True,
            user=user,
        )

    api_key, service_account_source, config_error = _auth_config()
    configured = bool(
        api_key and service_account_source is not None and not config_error
    )
    return jsonify(
        configured=configured,
        authenticated=False,
        config_error=config_error,
    )


@app.post("/api/auth/register")
def register():
    body = request.get_json(silent=True) or {}
    try:
        result = _get_auth_client().register_user(
            body.get("username", ""),
            body.get("email", ""),
            body.get("password", ""),
        )
    except Exception as exc:
        return jsonify(error=str(exc)), 503
    if not result.get("ok"):
        return jsonify(error=result.get("error", "Registration failed.")), 400
    return jsonify(ok=True, username=result.get("username"), message=result.get("message"))


@app.post("/api/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    try:
        result = _get_auth_client().sign_in(
            body.get("identifier", ""),
            body.get("password", ""),
        )
    except Exception as exc:
        return jsonify(error=str(exc)), 503
    if not result.get("ok"):
        if result.get("needs_verification"):
            global _desktop_pending_verification
            previous_pending = _current_pending_verification_id()
            pending_id = secrets.token_urlsafe(32)
            is_desktop = _is_desktop_bridge_request()
            with auth_lock:
                if previous_pending:
                    pending_verifications.pop(previous_pending, None)
                while len(pending_verifications) >= 64:
                    pending_verifications.pop(next(iter(pending_verifications)))
                pending_verifications[pending_id] = result.get("id_token", "")
                if is_desktop:
                    _desktop_pending_verification = pending_id
            session["pending_verification"] = pending_id
            return jsonify(
                error=result.get("error", "Verify your Gmail before signing in."),
                needs_verification=True,
            ), 403
        return jsonify(error=result.get("error", "Sign-in failed.")), 401

    _set_authenticated_user(result)
    return jsonify(ok=True, user=_current_auth())


@app.post("/api/auth/resend")
def resend_verification():
    pending_id = _current_pending_verification_id()
    with auth_lock:
        id_token = pending_verifications.get(pending_id)
    if not id_token:
        return jsonify(error="Sign in again before requesting a verification email."), 400
    try:
        sent, message = _get_auth_client().send_verification_email(id_token)
    except Exception as exc:
        return jsonify(error=str(exc)), 503
    if not sent:
        return jsonify(error=message), 400
    return jsonify(ok=True, message=message)


@app.post("/api/auth/logout")
@require_auth
def logout():
    global sniffer, capturing, stopping, capture_error
    with capture_lifecycle_lock:
        with state_lock:
            current = sniffer
            was_capturing = capturing
            was_stopping = stopping
            if was_capturing:
                sniffer = None
                capturing = False
                stopping = True
                stop_finished.clear()
        try:
            if was_capturing and current is not None:
                try:
                    capture.stop_capture(current)
                finally:
                    with state_lock:
                        stopping = False
                    stop_finished.set()
            elif was_stopping:
                stop_finished.wait()
            persist_queue.join()
        except Exception as exc:
            with state_lock:
                capture_error = str(exc)
            return jsonify(error=f"Could not finish logout cleanly: {exc}"), 500
    global _desktop_auth_id, _desktop_pending_verification
    auth_id = _current_auth_id()
    if auth_id:
        auth_sessions.pop(auth_id, None)
        _remove_opened_uploads(auth_id)
    pending_id = _current_pending_verification_id()
    if pending_id:
        pending_verifications.pop(pending_id, None)
    if _is_desktop_bridge_request():
        with auth_lock:
            _desktop_auth_id = None
            _desktop_pending_verification = None
    session.clear()
    return jsonify(ok=True)


@app.get("/api/interfaces")
@require_auth
def interfaces():
    try:
        return jsonify(
            interfaces=capture.get_interface_details(),
            hostname=capture.get_local_hostname(),
        )
    except Exception as exc:
        return jsonify(error=str(exc)), 500


@app.post("/api/devices/resolve")
@require_auth
def resolve_devices():
    body = request.get_json(silent=True) or {}
    devices = body.get("devices", [])
    if not isinstance(devices, list):
        return jsonify(error="Devices must be provided as a list."), 400
    try:
        return jsonify(resolved=capture.identify_devices(devices))
    except Exception as exc:
        return jsonify(error=f"Could not resolve devices: {exc}"), 500


@app.get("/api/status")
@require_auth
def status():
    with state_lock:
        return jsonify(
            capturing=capturing,
            stopping=stopping,
            dropped=dropped_packets,
            interface=capture_interface or getattr(sniffer, "iface", None),
            error=capture_error or database_error,
            alerts=alert_monitor.snapshot(),
        )


@app.post("/api/alerts/clear")
@require_auth
def clear_alerts():
    with state_lock:
        alert_monitor.dismiss_all()
    return jsonify(ok=True, alerts=[])


@app.post("/api/capture/start")
@require_auth
def start_capture():
    global sniffer, capture_interface, capturing, stopping, capture_error, dropped_packets
    body = request.get_json(silent=True) or {}
    interface = body.get("interface")
    if not interface:
        return jsonify(error="Choose a network interface first."), 400
    with capture_lifecycle_lock:
        with state_lock:
            if capturing or stopping:
                return jsonify(error="A capture is already running or stopping."), 409
            try:
                dropped_packets = 0
                sniffer = capture.start_capture(interface, on_packet)
                capture_interface = interface
                capturing = True
                capture_error = None
            except Exception as exc:
                sniffer = None
                capture_interface = None
                capturing = False
                capture_error = str(exc)
                return jsonify(error=str(exc)), 400
    return jsonify(
        ok=True,
        message=f"Capturing on {interface}",
    )


@app.post("/api/capture/stop")
@require_auth
def stop_capture():
    global sniffer, capturing, stopping
    with capture_lifecycle_lock:
        with state_lock:
            current = sniffer
            if stopping:
                return jsonify(ok=True, message="Capture is already stopping.")
            if not capturing or current is None:
                capturing = False
                return jsonify(ok=True, message="Capture is already stopped.")
            capturing = False
            stopping = True
            sniffer = None
            stop_finished.clear()

        def stop_worker():
            global capture_error, stopping, capture_interface
            try:
                capture.stop_capture(current)
            except Exception as exc:
                with state_lock:
                    capture_error = str(exc)
                print(f"Capture stop error: {exc}")
            finally:
                with state_lock:
                    stopping = False
                    capture_interface = None
                stop_finished.set()

        Thread(target=stop_worker, name="CaptureStop", daemon=True).start()
    return jsonify(ok=True, message="Stopping capture…")


@app.get("/api/packets")
@require_auth
def packets():
    limit = min(max(request.args.get("limit", default=500, type=int), 1), 1000)
    after = request.args.get("after", default=None, type=int)
    result = []
    with state_lock:
        if after is not None:
            for packet in ui_packets:
                if packet["no"] > after:
                    result.append(packet)
                    if len(result) >= limit:
                        break
        else:
            for _ in range(min(limit, len(ui_packets))):
                result.append(ui_packets.popleft())
        is_running = capturing
        is_stopping = stopping
        dropped = dropped_packets
        error = capture_error or database_error
        alerts = alert_monitor.snapshot()
    return jsonify(
        packets=result,
        capturing=is_running,
        stopping=is_stopping,
        dropped=dropped,
        error=error,
        alerts=alerts,
    )


@app.post("/api/packets/filter")
@require_auth
def filter_packets():
    body = request.get_json(silent=True) or {}
    try:
        filters = _normalize_filters(body.get("filters", {}))
        _flush_pending_packets()
        with state_lock:
            if database_error:
                return jsonify(error=f"Packet storage is unavailable: {database_error}"), 500
        records = database.get_filtered_packets(**filters)
    except (ValueError, OSError) as exc:
        return jsonify(error=str(exc)), 400
    except Exception as exc:
        return jsonify(error=f"Could not filter packet data: {exc}"), 500
    return jsonify(
        total=len(records),
        records=[_record_dict(record) for record in records[:2000]],
        truncated=len(records) > 2000,
    )


@app.post("/api/capture/clear")
@require_auth
def clear_capture():
    global packet_number, dropped_packets, database_error
    with capture_lifecycle_lock:
        with state_lock:
            if capturing or stopping:
                return jsonify(error="Stop capture before clearing the current session."), 409
            ui_packets.clear()
        persist_queue.join()
        try:
            database.clear_session()
        except Exception as exc:
            return jsonify(error=f"Could not start a fresh packet file: {exc}"), 500
        with state_lock:
            packet_number = 0
            dropped_packets = 0
            database_error = None
            alert_monitor.reset()
    return jsonify(ok=True)


@app.get("/api/summary")
@require_auth
def summary():
    try:
        _flush_pending_packets()
        with state_lock:
            if database_error:
                return jsonify(error=f"Packet storage is unavailable: {database_error}"), 500
        total, total_bytes = database.get_session_summary()
        return jsonify(total=total, bytes=total_bytes)
    except Exception as exc:
        return jsonify(error=str(exc)), 500


@app.get("/api/health")
@require_auth
def gateway_health():
    global health_gateway
    try:
        gateway = capture.get_default_gateway()
    except Exception as exc:
        return _set_health_report_snapshot(
            "unavailable", f"Could not determine the default gateway: {exc}"
        )
    if not gateway:
        return _set_health_report_snapshot(
            "unavailable", "No IPv4 default gateway is available to test."
        )
    if gateway != health_gateway:
        health_gateway = gateway
        health_samples.clear()
    try:
        health_samples.append(capture.ping_gateway(gateway))
    except OSError as exc:
        return _set_health_report_snapshot(
            "unavailable",
            f"Could not run the gateway response check: {exc}",
            gateway=gateway,
        )

    successful = [sample for sample in health_samples if sample is not None]
    lost = len(health_samples) - len(successful)
    if not successful:
        if len(health_samples) < 3:
            return _set_health_report_snapshot(
                "checking",
                f"No response from {gateway} yet; collecting more checks.",
                gateway=gateway,
            )
        return _set_health_report_snapshot(
            "unreachable",
            (
                f"No ping replies from {gateway} in {len(health_samples)} consecutive "
                "checks. It may be unreachable or filter ping requests."
            ),
            gateway=gateway,
        )

    median_ms = statistics.median(successful)
    loss_percent = lost / len(health_samples) * 100
    details = (
        f"Gateway {gateway}: median response {median_ms:.1f} ms; "
        f"{loss_percent:.0f}% loss over {len(health_samples)} check(s)."
    )
    if loss_percent >= 20 or median_ms >= 150:
        return _set_health_report_snapshot(
            "congested",
            f"Possible congestion or path degradation. {details}",
            gateway=gateway,
        )
    return _set_health_report_snapshot(
        "healthy",
        f"No obvious congestion to the default gateway. {details}",
        gateway=gateway,
    )


@app.get("/api/sessions")
@require_auth
def sessions():
    try:
        database.SESSION_DIRECTORY.mkdir(parents=True, exist_ok=True)
        with database._db_lock:
            active_path = os.path.abspath(database.FILE_NAME)
        files = sorted(
            database.SESSION_DIRECTORY.glob("*.msgpack"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        result = []
        for path in files:
            stat = path.stat()
            result.append({
                "name": path.name,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(
                    timespec="seconds"
                ),
                "bytes": stat.st_size,
                "active": os.path.abspath(path) == active_path,
            })
        return jsonify(sessions=result)
    except OSError as exc:
        return jsonify(error=f"Could not list saved captures: {exc}"), 500


def _normalize_session_filename(raw_name):
    text = str(raw_name or "").strip()
    if text.lower().endswith(".msgpack"):
        text = text[:-8]
    text = re.sub(r"\s+", "_", text)
    cleaned = secure_filename(text)
    if not cleaned or cleaned in (".", ".."):
        raise ValueError("Enter a valid capture name using letters, numbers, dashes, or underscores.")
    if len(cleaned) > 80:
        raise ValueError("Capture name must be 80 characters or fewer.")
    return f"{cleaned}.msgpack"


@app.patch("/api/sessions/<filename>")
@require_auth
def rename_session(filename):
    body = request.get_json(silent=True) or {}
    try:
        target = _session_file(filename)
        new_filename = _normalize_session_filename(body.get("name", ""))
        root = database.SESSION_DIRECTORY.resolve()
        destination = (root / new_filename).resolve()
        if destination.parent != root:
            raise ValueError("Choose a valid capture name.")
        if destination == target:
            return jsonify(ok=True, old_name=filename, name=target.name)
        with capture_lifecycle_lock, state_lock, database._db_lock:
            if destination.exists():
                return jsonify(error="A saved capture with that name already exists."), 409
            is_active = os.path.abspath(target) == os.path.abspath(database.FILE_NAME)
            if is_active and (capturing or stopping):
                return jsonify(error="Stop the active capture before renaming its session file."), 409
            target.rename(destination)
            if is_active:
                database.FILE_NAME = str(destination)
        return jsonify(ok=True, old_name=filename, name=destination.name)
    except FileNotFoundError as exc:
        return jsonify(error=str(exc)), 404
    except (ValueError, OSError) as exc:
        return jsonify(error=str(exc)), 400


@app.delete("/api/sessions/<filename>")
@require_auth
def delete_session(filename):
    try:
        target = _session_file(filename)
        with capture_lifecycle_lock, state_lock, database._db_lock:
            if os.path.abspath(target) == os.path.abspath(database.FILE_NAME):
                return jsonify(
                    error="This is the current active session file. Click Clear on the main toolbar before deleting it."
                ), 409
            target.unlink()
        return jsonify(ok=True, deleted=filename)
    except FileNotFoundError as exc:
        return jsonify(error=str(exc)), 404
    except (ValueError, OSError) as exc:
        return jsonify(error=str(exc)), 400


@app.post("/api/sessions/compare")
@require_auth
def compare_sessions():
    body = request.get_json(silent=True) or {}
    baseline_name = body.get("baseline", "")
    current_name = body.get("filename", "")
    token = body.get("token", "")
    try:
        baseline_path = _session_file(baseline_name)
        if token:
            if not isinstance(token, str):
                raise ValueError("The uploaded capture token is invalid.")
            with upload_lock:
                uploaded = opened_uploads.get(token)
            if uploaded is None or uploaded[1] != _current_auth_id():
                return jsonify(error="The uploaded capture is no longer available."), 404
            current_path, _, current_label = uploaded
            if not current_path.is_file():
                return jsonify(error="The uploaded capture is no longer available."), 404
        else:
            current_path = _session_file(current_name)
            current_label = current_path.name

        current_report = _build_network_report(
            database.read_records(str(current_path)), current_label
        )
        baseline_report = _build_network_report(
            database.read_records(str(baseline_path)), baseline_path.name
        )

        cur_hdr = current_report["header"]
        base_hdr = baseline_report["header"]
        cur_clients = {c["ip"]: c for c in current_report["clients"]}
        base_clients = {c["ip"]: c for c in baseline_report["clients"]}

        new_devices = [
            {
                "ip": ip,
                "name": cur_clients[ip].get("name", ""),
                "mac": cur_clients[ip].get("mac", ""),
                "vendor": cur_clients[ip].get("vendor", ""),
                "total_bytes": cur_clients[ip].get("total_bytes", 0),
            }
            for ip in sorted(set(cur_clients) - set(base_clients))
        ]
        missing_devices = [
            {
                "ip": ip,
                "name": base_clients[ip].get("name", ""),
                "mac": base_clients[ip].get("mac", ""),
                "vendor": base_clients[ip].get("vendor", ""),
                "total_bytes": base_clients[ip].get("total_bytes", 0),
            }
            for ip in sorted(set(base_clients) - set(cur_clients))
        ]

        cur_protos = {p["protocol"]: p["packets"] for p in current_report["protocols"]}
        base_protos = {p["protocol"]: p["packets"] for p in baseline_report["protocols"]}
        protocol_changes = [
            {
                "protocol": proto,
                "current_packets": cur_protos.get(proto, 0),
                "baseline_packets": base_protos.get(proto, 0),
                "delta_packets": cur_protos.get(proto, 0) - base_protos.get(proto, 0),
            }
            for proto in sorted(set(cur_protos) | set(base_protos))
        ]
        protocol_changes.sort(key=lambda item: abs(item["delta_packets"]), reverse=True)

        return jsonify(
            comparison={
                "current_name": current_label,
                "baseline_name": baseline_path.name,
                "current_packets": cur_hdr["packet_count"],
                "baseline_packets": base_hdr["packet_count"],
                "packet_delta": cur_hdr["packet_count"] - base_hdr["packet_count"],
                "current_bytes": cur_hdr["total_bytes"],
                "baseline_bytes": base_hdr["total_bytes"],
                "bytes_delta": cur_hdr["total_bytes"] - base_hdr["total_bytes"],
                "current_clients": cur_hdr["client_count"],
                "baseline_clients": base_hdr["client_count"],
                "client_delta": cur_hdr["client_count"] - base_hdr["client_count"],
                "new_devices": new_devices,
                "missing_devices": missing_devices,
                "protocol_changes": protocol_changes[:8],
            }
        )
    except FileNotFoundError as exc:
        return jsonify(error=str(exc)), 404
    except (ValueError, OSError) as exc:
        return jsonify(error=str(exc)), 400
    except Exception as exc:
        return jsonify(error=f"Could not compare captures: {exc}"), 500


@app.get("/api/sessions/<filename>")
@require_auth
def read_session(filename):
    try:
        path = _session_file(filename)
        limit = min(max(request.args.get("limit", 500, type=int), 1), 1000)
        offset = max(request.args.get("offset", 0, type=int), 0)
        page, total = database.read_records_page(str(path), offset=offset, limit=limit)
        return jsonify(
            name=path.name,
            total=total,
            offset=offset,
            records=page,
        )
    except (ValueError, OSError) as exc:
        return jsonify(error=str(exc)), 400
    except Exception as exc:
        return jsonify(error=f"Could not read the selected packet file: {exc}"), 500


@app.get("/api/sessions/<filename>/report")
@require_auth
def read_session_report(filename):
    try:
        path = _session_file(filename)
        records = database.read_records(str(path))
        return jsonify(report=_build_network_report(records, path.name))
    except (ValueError, OSError) as exc:
        return jsonify(error=str(exc)), 400
    except Exception as exc:
        return jsonify(error=f"Could not build the saved capture report: {exc}"), 500


@app.post("/api/sessions/open")
@require_auth
def open_uploaded_session():
    upload = request.files.get("file")
    filename = secure_filename(upload.filename or "") if upload else ""
    if upload is None or not filename.lower().endswith(".msgpack"):
        return jsonify(error="Choose a MessagePack packet capture (.msgpack)."), 400

    output_path = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="lan_watch_capture_", suffix=".msgpack", delete=False
        ) as temporary:
            output_path = Path(temporary.name)
            shutil.copyfileobj(upload.stream, temporary)
        total, _ = database.get_session_summary(str(output_path))
        token = secrets.token_urlsafe(32)
        auth_id = _current_auth_id()
        _remove_opened_uploads(auth_id)
        with upload_lock:
            opened_uploads[token] = (output_path, auth_id, filename)
        return jsonify(token=token, name=filename, total=total)
    except Exception as exc:
        if output_path is not None:
            output_path.unlink(missing_ok=True)
        return jsonify(error=f"Could not open the selected packet file: {exc}"), 400


@app.get("/api/uploads/<token>")
@require_auth
def read_uploaded_session(token):
    with upload_lock:
        uploaded = opened_uploads.get(token)
    if uploaded is None or uploaded[1] != _current_auth_id():
        return jsonify(error="The uploaded capture is no longer available."), 404
    path, _, filename = uploaded
    try:
        if not path.is_file():
            return jsonify(error="The uploaded capture is no longer available."), 404
        limit = min(max(request.args.get("limit", 500, type=int), 1), 1000)
        offset = max(request.args.get("offset", 0, type=int), 0)
        page, total = database.read_records_page(str(path), offset=offset, limit=limit)
        return jsonify(
            name=filename,
            total=total,
            offset=offset,
            records=page,
        )
    except Exception as exc:
        return jsonify(error=f"Could not read the uploaded packet file: {exc}"), 500


@app.get("/api/uploads/<token>/report")
@require_auth
def read_uploaded_session_report(token):
    with upload_lock:
        uploaded = opened_uploads.get(token)
    if uploaded is None or uploaded[1] != _current_auth_id():
        return jsonify(error="The uploaded capture is no longer available."), 404
    path, _, filename = uploaded
    try:
        if not path.is_file():
            return jsonify(error="The uploaded capture is no longer available."), 404
        records = database.read_records(str(path))
        return jsonify(report=_build_network_report(records, filename))
    except Exception as exc:
        return jsonify(error=f"Could not build the uploaded capture report: {exc}"), 500


def _remove_opened_uploads(auth_id=None):
    with upload_lock:
        tokens = [
            token for token, (_, owner_id, _) in opened_uploads.items()
            if auth_id is None or owner_id == auth_id
        ]
        paths = [opened_uploads.pop(token)[0] for token in tokens]
    for path in paths:
        path.unlink(missing_ok=True)


@app.post("/api/export")
@require_auth
def export_packets():
    body = request.get_json(silent=True) or {}
    file_format = str(body.get("format", "")).lower()
    mode = str(body.get("mode", ""))
    password = body.get("password", "")
    if file_format not in {"csv", "pdf"}:
        return jsonify(error="Choose CSV or PDF export."), 400
    if mode in {"network_report", "saved"} and file_format != "pdf":
        return jsonify(error="Network reports are exported as password-protected PDF."), 400
    if not isinstance(password, str) or len(password) < 8:
        return jsonify(error="Use an export password with at least 8 characters."), 400
    try:
        report_records = None
        report_dropped = None
        capture_name = Path(database.FILE_NAME).name
        if mode == "filtered":
            filters = _normalize_filters(body.get("filters", {}))
            _flush_pending_packets()
            with state_lock:
                if database_error:
                    return jsonify(error=f"Packet storage is unavailable: {database_error}"), 500
            packets_to_export = database.get_filtered_packets(**filters)
        elif mode == "selected":
            packets_to_export = body.get("packets")
            if not isinstance(packets_to_export, list) or not packets_to_export:
                return jsonify(error="Select one or more packet rows before exporting."), 400
            if len(packets_to_export) > 10000:
                return jsonify(error="Select no more than 10,000 packets per export."), 413
            if any(not isinstance(row, list) or len(row) != 9 for row in packets_to_export):
                return jsonify(error="Selected packet data has an invalid format."), 400
        elif mode == "network_report":
            _flush_pending_packets()
            with state_lock:
                if database_error:
                    return jsonify(error=f"Packet storage is unavailable: {database_error}"), 500
                report_dropped = dropped_packets
            report_records = database.read_records()
            packets_to_export = database.get_export_packets()
        elif mode == "saved":
            token = body.get("token")
            filename = body.get("filename")
            if token:
                if not isinstance(token, str):
                    return jsonify(error="The uploaded capture token is invalid."), 400
                with upload_lock:
                    uploaded = opened_uploads.get(token)
                if uploaded is None or uploaded[1] != _current_auth_id():
                    return jsonify(error="The uploaded capture is no longer available."), 404
                capture_path, _, capture_name = uploaded
                if not capture_path.is_file():
                    return jsonify(error="The uploaded capture is no longer available."), 404
            else:
                capture_path = _session_file(filename)
                capture_name = capture_path.name
            report_records = database.read_records(str(capture_path))
            report_dropped = None
            packets_to_export = [
                (
                    record.get("id"),
                    record.get("timestamp"),
                    record.get("source_ip"),
                    record.get("destination_ip"),
                    record.get("protocol"),
                    record.get("length"),
                    record.get("source_port"),
                    record.get("destination_port"),
                    record.get("info"),
                )
                for record in report_records
            ]
        else:
            return jsonify(error="Choose packet export or PDF report export."), 400
        if not packets_to_export and mode not in {"network_report", "saved"}:
            return jsonify(error="No packets match the selected export scope."), 400

        report = None
        if mode in {"network_report", "saved"}:
            report = _build_network_report(
                report_records,
                capture_name,
                dropped=report_dropped,
            )
            report["header"]["packet_scope"] = (
                "The overview and packet records cover the full capture."
            )

        suffix = "." + file_format
        with tempfile.NamedTemporaryFile(
            prefix="lan_watch_export_", suffix=suffix, delete=False
        ) as temporary:
            output_path = Path(temporary.name)
        try:
            if file_format == "csv":
                export.export_csv(
                    str(output_path), password, packets_to_export, report=None
                )
                mimetype = "application/octet-stream"
            else:
                export.export_pdf(
                    str(output_path), password, packets_to_export, report=report
                )
                mimetype = "application/pdf"
            download_prefix = (
                "network_report" if mode in {"network_report", "saved"}
                else "packets"
            )
            response = send_file(
                output_path,
                mimetype=mimetype,
                as_attachment=True,
                download_name=f"{download_prefix}_{datetime.now():%Y%m%d_%H%M%S}{suffix}",
            )
            response.call_on_close(lambda: output_path.unlink(missing_ok=True))
            return response
        except Exception:
            output_path.unlink(missing_ok=True)
            raise
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except Exception as exc:
        return jsonify(error=f"Could not export the network report: {exc}"), 500


@app.post("/api/export/decrypt-csv")
@require_auth
def decrypt_exported_csv():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify(error="Choose an encrypted CSV file to decrypt."), 400
    password = request.form.get("password", "")
    if not password:
        return jsonify(error="Enter the export password for this CSV file."), 400

    payload = uploaded.read()
    if not payload:
        return jsonify(error="The uploaded CSV file is empty."), 400
    try:
        plaintext = export.decrypt_csv_bytes(payload, password)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except RuntimeError as exc:
        return jsonify(error=str(exc)), 500
    except Exception as exc:
        return jsonify(error=f"Could not decrypt CSV file: {exc}"), 500

    safe_name = secure_filename(uploaded.filename) or "lan_watch_export.csv"
    stem = Path(safe_name).stem or "lan_watch_export"
    return send_file(
        io.BytesIO(plaintext),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"{stem}_decrypted.csv",
    )


_shutdown_lock = Lock()
_shutdown_completed = False


def init_session():
    """Initialize a fresh MessagePack session file and packet ID sequence."""
    database.start_session()
    database.init_db()


def shutdown():
    global sniffer, capturing, stopping, _shutdown_completed
    with _shutdown_lock:
        if _shutdown_completed:
            return
        _shutdown_completed = True
    with state_lock:
        current = sniffer
        sniffer = None
        capturing = False
        stopping = False
    if current is not None:
        try:
            capture.stop_capture(current)
        except Exception as exc:
            print(f"Capture stop error during shutdown: {exc}")
    try:
        persist_queue.put(None, timeout=1.0)
        persist_queue.join()
    except Exception as exc:
        print(f"Packet database shutdown error: {exc}")
    _remove_opened_uploads()


atexit.register(shutdown)

if __name__ == "__main__":
    init_session()
    print("LAN Traffic Analyzer is running at http://127.0.0.1:5000")
    print("Keep this server local; do not expose it to the internet.")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
