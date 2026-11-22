"""Local web front end for the Scapy packet capture engine."""

import atexit
from collections import deque
from datetime import datetime
from functools import wraps
import os
from pathlib import Path
from queue import Empty, Full, Queue
import secrets
import shutil
import statistics
import tempfile
from threading import Event, Lock, Thread
from urllib.parse import urlsplit

from flask import Flask, jsonify, request, send_file, send_from_directory, session
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

import capture
import database
import export
import network_report
from auth import FirebaseAuthClient
from auth_session import AuthSessionStore

BASE_DIR = Path(__file__).resolve().parent
SERVICE_ACCOUNT_FILENAME = (
    "packet-sniffer-auth-firebase-adminsdk-fbsvc-fce9c28df6.json"
)
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
capturing = False
stopping = False
capture_error = None
database_error = None
dropped_packets = 0
packet_number = 0
auth_client = None
auth_sessions = {}
pending_verifications = {}
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
discovery_lock = Lock()
discovery_state = {
    "running": False,
    "complete": False,
    "interface": "",
    "network": "",
    "hosts": [],
    "error": "",
    "warning": "",
}


def _set_health_report_snapshot(state, description):
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
    return jsonify(state=state, description=description)


def _discover_hosts_worker(interface, run_id):
    try:
        result = capture.discover_ipv4_hosts(interface)
        error = ""
    except Exception as exc:
        result = {"network": "", "hosts": [], "warning": ""}
        error = str(exc)
    with discovery_lock:
        if discovery_state.get("run_id") != run_id:
            return
        discovery_state.update(
            running=False,
            complete=True,
            network=result["network"],
            hosts=result["hosts"],
            error=error,
            warning=result.get("warning", ""),
        )


def _start_host_discovery(interface):
    with discovery_lock:
        if discovery_state["running"]:
            return False, "A previous local subnet discovery scan is still finishing."
        run_id = secrets.token_urlsafe(12)
        discovery_state.update(
            run_id=run_id,
            running=True,
            complete=False,
            interface=interface,
            network="",
            hosts=[],
            error="",
            warning="",
        )
    worker = Thread(
        target=_discover_hosts_worker,
        args=(interface, run_id),
        name="IPv4HostDiscovery",
        daemon=True,
    )
    try:
        worker.start()
    except RuntimeError as exc:
        with discovery_lock:
            if discovery_state.get("run_id") == run_id:
                discovery_state.update(running=False, complete=True, error=str(exc))
        return False, f"Could not start the IPv4 discovery scan: {exc}"
    return True, ""


def _auth_config():
    api_key = os.environ.get("FIREBASE_WEB_API_KEY", "").strip()
    service_account_path = os.environ.get(
        "FIREBASE_SERVICE_ACCOUNT_PATH",
        str(BASE_DIR.parent / SERVICE_ACCOUNT_FILENAME),
    )
    return api_key, Path(service_account_path)


def _get_auth_client():
    global auth_client
    with auth_lock:
        if auth_client is None:
            api_key, service_account_path = _auth_config()
            if not api_key:
                raise RuntimeError("Set FIREBASE_WEB_API_KEY before signing in.")
            if not service_account_path.is_file():
                raise RuntimeError(
                    "Firebase service-account JSON was not found. Set "
                    "FIREBASE_SERVICE_ACCOUNT_PATH to its location."
                )
            auth_client = FirebaseAuthClient(api_key, str(service_account_path))
        return auth_client


def _auth_store():
    return AuthSessionStore()


def _current_auth():
    auth_id = session.get("auth_id")
    if not auth_id:
        return None
    return auth_sessions.get(auth_id)


def _set_authenticated_user(result):
    old_id = session.get("auth_id")
    if old_id:
        auth_sessions.pop(old_id, None)
        _remove_opened_uploads(old_id)
    pending_id = session.get("pending_verification")
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


def require_auth(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        if _current_auth() is None:
            return jsonify(error="Please sign in to use LAN Watch."), 401
        return handler(*args, **kwargs)
    return wrapped


@app.before_request
def restrict_to_local_browser():
    parsed_host = urlsplit("//" + request.host)
    if parsed_host.hostname not in {"127.0.0.1", "localhost"} or parsed_host.port not in (None, 5000):
        return jsonify(error="LAN Watch only accepts local browser requests."), 403
    origin = request.headers.get("Origin")
    if origin:
        parsed_origin = urlsplit(origin)
        if (
            parsed_origin.scheme != "http"
            or parsed_origin.netloc.casefold() != request.host.casefold()
        ):
            return jsonify(error="Cross-origin requests are not allowed."), 403
    return None


@app.errorhandler(RequestEntityTooLarge)
def request_too_large(error):
    return jsonify(error="Capture files must be smaller than 256 MB."), 413


def _record_database_error(error):
    global database_error
    with state_lock:
        database_error = str(error)
    print(f"Database write error: {error}")


def flush_worker():
    """Persist small batches and acknowledge records only after each write."""
    batch = []
    while True:
        try:
            item = persist_queue.get(timeout=0.5)
        except Empty:
            item = ...
        if item is None:
            try:
                if batch:
                    database.save_packets(batch)
            except Exception as exc:
                _record_database_error(exc)
            finally:
                for _ in batch:
                    persist_queue.task_done()
                persist_queue.task_done()
            return
        if item is not ...:
            batch.append(item)
        if batch and (len(batch) >= 100 or item is ...):
            try:
                database.save_packets(batch)
            except Exception as exc:
                _record_database_error(exc)
            finally:
                for _ in batch:
                    persist_queue.task_done()
                batch.clear()


Thread(target=flush_worker, name="PacketDatabaseWriter", daemon=True).start()


def on_packet(packet):
    global dropped_packets
    try:
        persist_queue.put_nowait(packet)
    except Full:
        with state_lock:
            dropped_packets += 1
    with state_lock:
        ui_packets.append(packet)


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
            value += " 23:59:59" if key == "end_time" else " 00:00:00"
        elif len(value) == 16:
            value += ":00"
        else:
            value = parsed.strftime("%Y-%m-%d %H:%M:%S")
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


@app.get("/<path:asset>")
def assets(asset):
    if asset not in {"style.css", "script.js"}:
        return jsonify(error="Not found"), 404
    return send_from_directory(BASE_DIR, asset)


@app.get("/api/auth/status")
def auth_status():
    user = _current_auth()
    if user:
        return jsonify(configured=True, authenticated=True, user=user)

    restore_error = ""
    api_key, service_account_path = _auth_config()
    configured = bool(api_key and service_account_path.is_file())
    if configured and os.name == "nt":
        try:
            refresh_token = _auth_store().load()
            if refresh_token:
                result = _get_auth_client().restore_session(refresh_token)
                if result.get("ok"):
                    _set_authenticated_user(result)
                    _auth_store().save(result.get("refresh_token", refresh_token))
                    return jsonify(
                        configured=True,
                        authenticated=True,
                        user=_current_auth(),
                        restored=True,
                    )
                _auth_store().clear()
                restore_error = result.get("error", "Saved sign-in could not be restored.")
        except (OSError, RuntimeError, ValueError) as exc:
            restore_error = str(exc)
    return jsonify(
        configured=configured,
        authenticated=False,
        restore_error=restore_error,
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
            previous_pending = session.get("pending_verification")
            if previous_pending:
                pending_verifications.pop(previous_pending, None)
            pending_id = secrets.token_urlsafe(32)
            pending_verifications[pending_id] = result.get("id_token", "")
            session["pending_verification"] = pending_id
            return jsonify(
                error=result.get("error", "Verify your Gmail before signing in."),
                needs_verification=True,
            ), 403
        return jsonify(error=result.get("error", "Sign-in failed.")), 401

    remember = bool(body.get("remember"))
    try:
        if remember:
            _auth_store().save(result.get("refresh_token", ""))
        elif os.name == "nt":
            _auth_store().clear()
    except (OSError, RuntimeError, ValueError) as exc:
        return jsonify(error=f"Sign-in succeeded, but the saved session could not be secured: {exc}"), 500
    _set_authenticated_user(result)
    return jsonify(ok=True, user=_current_auth())


@app.post("/api/auth/resend")
def resend_verification():
    pending_id = session.get("pending_verification")
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
            if os.name == "nt":
                _auth_store().clear()
        except Exception as exc:
            with state_lock:
                capture_error = str(exc)
            return jsonify(error=f"Could not finish logout cleanly: {exc}"), 500
    auth_id = session.get("auth_id")
    if auth_id:
        auth_sessions.pop(auth_id, None)
        _remove_opened_uploads(auth_id)
    pending_id = session.get("pending_verification")
    if pending_id:
        pending_verifications.pop(pending_id, None)
    session.clear()
    return jsonify(ok=True)


@app.get("/api/interfaces")
@require_auth
def interfaces():
    try:
        return jsonify(interfaces=capture.get_interface_details())
    except Exception as exc:
        return jsonify(error=str(exc)), 500


@app.get("/api/status")
@require_auth
def status():
    with state_lock:
        return jsonify(
            capturing=capturing,
            stopping=stopping,
            dropped=dropped_packets,
            interface=getattr(sniffer, "iface", None),
            error=capture_error or database_error,
        )


@app.post("/api/capture/start")
@require_auth
def start_capture():
    global sniffer, capturing, stopping, capture_error, dropped_packets
    body = request.get_json(silent=True) or {}
    interface = body.get("interface")
    if not interface:
        return jsonify(error="Choose a network interface first."), 400
    discover = body.get("discover", False) is True
    with capture_lifecycle_lock:
        with state_lock:
            if capturing or stopping:
                return jsonify(error="A capture is already running or stopping."), 409
            try:
                dropped_packets = 0
                sniffer = capture.start_capture(interface, on_packet)
                capturing = True
                capture_error = None
            except Exception as exc:
                sniffer = None
                capturing = False
                capture_error = str(exc)
                return jsonify(error=str(exc)), 400
    discovery_started, discovery_error = (
        _start_host_discovery(interface)
        if discover
        else (False, "")
    )
    return jsonify(
        ok=True,
        message=f"Capturing on {interface}",
        discovery_started=discovery_started,
        discovery_error=discovery_error,
    )


@app.get("/api/discovery")
@require_auth
def discovery_status():
    with discovery_lock:
        return jsonify({
            key: value
            for key, value in discovery_state.items()
            if key != "run_id"
        })


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
            global capture_error, stopping
            try:
                capture.stop_capture(current)
            except Exception as exc:
                with state_lock:
                    capture_error = str(exc)
                print(f"Capture stop error: {exc}")
            finally:
                with state_lock:
                    stopping = False
                stop_finished.set()

        Thread(target=stop_worker, name="CaptureStop", daemon=True).start()
    return jsonify(ok=True, message="Stopping capture…")


@app.get("/api/packets")
@require_auth
def packets():
    global packet_number
    try:
        limit = min(max(request.args.get("limit", default=500, type=int), 1), 1000)
    except (TypeError, ValueError):
        limit = 500
    result = []
    with state_lock:
        for _ in range(min(limit, len(ui_packets))):
            packet = ui_packets.popleft()
            packet_number += 1
            timestamp = packet.get("timestamp", "")
            result.append({
                "no": packet_number,
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
            })
        is_running = capturing
        is_stopping = stopping
        dropped = dropped_packets
        error = capture_error or database_error
    return jsonify(
        packets=result,
        capturing=is_running,
        stopping=is_stopping,
        dropped=dropped,
        error=error,
    )


@app.post("/api/packets/filter")
@require_auth
def filter_packets():
    body = request.get_json(silent=True) or {}
    try:
        filters = _normalize_filters(body.get("filters", {}))
        persist_queue.join()
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
    return jsonify(ok=True)


@app.get("/api/summary")
@require_auth
def summary():
    try:
        persist_queue.join()
        with state_lock:
            if database_error:
                return jsonify(error=f"Packet storage is unavailable: {database_error}"), 500
        records = database.read_records()
        return jsonify(total=len(records), bytes=sum(int(x.get("length", 0)) for x in records))
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
            "unavailable", f"Could not run the gateway response check: {exc}"
        )

    successful = [sample for sample in health_samples if sample is not None]
    lost = len(health_samples) - len(successful)
    if not successful:
        if len(health_samples) < 3:
            return _set_health_report_snapshot(
                "checking",
                f"No response from {gateway} yet; collecting more checks.",
            )
        return _set_health_report_snapshot(
            "unreachable",
            (
                f"No ping replies from {gateway} in {len(health_samples)} consecutive "
                "checks. It may be unreachable or filter ping requests."
            ),
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
        )
    return _set_health_report_snapshot(
        "healthy",
        f"No obvious congestion to the default gateway. {details}",
    )


@app.get("/api/sessions")
@require_auth
def sessions():
    try:
        database.SESSION_DIRECTORY.mkdir(parents=True, exist_ok=True)
        files = sorted(
            database.SESSION_DIRECTORY.glob("*.msgpack"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        result = []
        for path in files:
            result.append({
                "name": path.name,
                "modified": datetime.fromtimestamp(path.stat().st_mtime).isoformat(
                    timespec="seconds"
                ),
                "bytes": path.stat().st_size,
            })
        return jsonify(sessions=result)
    except OSError as exc:
        return jsonify(error=f"Could not list saved captures: {exc}"), 500


@app.get("/api/sessions/<filename>")
@require_auth
def read_session(filename):
    try:
        path = _session_file(filename)
        records = database.read_records(str(path))
        total = len(records)
        limit = min(max(request.args.get("limit", 500, type=int), 1), 1000)
        offset = max(request.args.get("offset", 0, type=int), 0)
        page = records[offset:offset + limit]
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
        records = database.read_records(str(output_path))
        token = secrets.token_urlsafe(32)
        with upload_lock:
            opened_uploads[token] = (output_path, session["auth_id"], filename)
        return jsonify(token=token, name=filename, total=len(records))
    except Exception as exc:
        if output_path is not None:
            output_path.unlink(missing_ok=True)
        return jsonify(error=f"Could not open the selected packet file: {exc}"), 400


@app.get("/api/uploads/<token>")
@require_auth
def read_uploaded_session(token):
    with upload_lock:
        uploaded = opened_uploads.get(token)
    if uploaded is None or uploaded[1] != session.get("auth_id"):
        return jsonify(error="The uploaded capture is no longer available."), 404
    path, _, filename = uploaded
    try:
        if not path.is_file():
            return jsonify(error="The uploaded capture is no longer available."), 404
        records = database.read_records(str(path))
        limit = min(max(request.args.get("limit", 500, type=int), 1), 1000)
        offset = max(request.args.get("offset", 0, type=int), 0)
        return jsonify(
            name=filename,
            total=len(records),
            offset=offset,
            records=records[offset:offset + limit],
        )
    except Exception as exc:
        return jsonify(error=f"Could not read the uploaded packet file: {exc}"), 500


@app.get("/api/uploads/<token>/report")
@require_auth
def read_uploaded_session_report(token):
    with upload_lock:
        uploaded = opened_uploads.get(token)
    if uploaded is None or uploaded[1] != session.get("auth_id"):
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
    if not isinstance(password, str) or len(password) < 8:
        return jsonify(error="Use an export password with at least 8 characters."), 400
    try:
        if mode == "filtered":
            filters = _normalize_filters(body.get("filters", {}))
            persist_queue.join()
            with state_lock:
                if database_error:
                    return jsonify(error=f"Packet storage is unavailable: {database_error}"), 500
            packets_to_export = database.get_filtered_packets(**filters)
            report_records = database.read_records()
            capture_name = Path(database.FILE_NAME).name
            with state_lock:
                report_dropped = dropped_packets
        elif mode == "selected":
            packets_to_export = body.get("packets")
            if not isinstance(packets_to_export, list) or not packets_to_export:
                return jsonify(error="Select one or more packet rows before exporting."), 400
            if len(packets_to_export) > 10000:
                return jsonify(error="Select no more than 10,000 packets per export."), 413
            if any(not isinstance(row, list) or len(row) != 9 for row in packets_to_export):
                return jsonify(error="Selected packet data has an invalid format."), 400
            persist_queue.join()
            report_records = database.read_records()
            capture_name = Path(database.FILE_NAME).name
            with state_lock:
                report_dropped = dropped_packets
        elif mode == "network_report":
            persist_queue.join()
            with state_lock:
                if database_error:
                    return jsonify(error=f"Packet storage is unavailable: {database_error}"), 500
                report_dropped = dropped_packets
            report_records = database.read_records()
            capture_name = Path(database.FILE_NAME).name
            packets_to_export = database.get_export_packets()
        elif mode == "saved":
            token = body.get("token")
            filename = body.get("filename")
            if token:
                if not isinstance(token, str):
                    return jsonify(error="The uploaded capture token is invalid."), 400
                with upload_lock:
                    uploaded = opened_uploads.get(token)
                if uploaded is None or uploaded[1] != session.get("auth_id"):
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
            return jsonify(error="Choose filtered, selected, or network report export."), 400
        if not packets_to_export and mode not in {"network_report", "saved"}:
            return jsonify(error="No packets match the selected export scope."), 400
        report = _build_network_report(
            report_records,
            capture_name,
            dropped=report_dropped,
        )
        report["header"]["packet_scope"] = (
            "The overview covers the full capture; packet records below reflect "
            "the selected or filtered export scope."
            if mode in {"filtered", "selected"}
            else "The overview and packet records cover the full capture."
        )

        suffix = "." + file_format
        with tempfile.NamedTemporaryFile(
            prefix="lan_watch_export_", suffix=suffix, delete=False
        ) as temporary:
            output_path = Path(temporary.name)
        try:
            if file_format == "csv":
                export.export_csv(
                    str(output_path), password, packets_to_export, report=report
                )
                mimetype = "application/octet-stream"
            else:
                export.export_pdf(
                    str(output_path), password, packets_to_export, report=report
                )
                mimetype = "application/pdf"
            download_prefix = (
                "network_report" if mode in {"network_report", "saved"}
                else "network_traffic"
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


def shutdown():
    global sniffer, capturing, stopping
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
        persist_queue.join()
    except Exception as exc:
        print(f"Packet database shutdown error: {exc}")
    _remove_opened_uploads()


atexit.register(shutdown)

if __name__ == "__main__":
    database.start_session()
    database.init_db()
    print("LAN Watch is running at http://127.0.0.1:5000")
    print("Keep this server local; do not expose it to the internet.")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
