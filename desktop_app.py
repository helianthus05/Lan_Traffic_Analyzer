"""Standalone desktop window launcher for LAN Traffic Analyzer using pywebview (Approach B: no HTTP server)."""

import base64
import io
from pathlib import Path
from threading import Lock

import web_server

BASE_DIR = Path(__file__).resolve().parent


class DesktopBridge:
    """In-process JavaScript-to-Python bridge (no localhost HTTP server or open ports)."""

    def __init__(self, webview_module):
        self._webview = webview_module
        self._window = None
        self._cookie_lock = Lock()
        self._cookies = {}
        self._bridge_secret = (
            web_server.enable_desktop_bridge()
            if hasattr(web_server, "enable_desktop_bridge")
            else ""
        )

    def attach(self, window):
        self._window = window

    def _cookie_header(self):
        with self._cookie_lock:
            return "; ".join(f"{name}={value}" for name, value in self._cookies.items())

    def _update_cookies(self, set_cookie_headers):
        if not set_cookie_headers:
            return
        with self._cookie_lock:
            for header in set_cookie_headers:
                parts = [segment.strip() for segment in str(header).split(";") if segment.strip()]
                if not parts or "=" not in parts[0]:
                    continue
                name, value = parts[0].split("=", 1)
                name = name.strip()
                if not name:
                    continue
                attrs = {}
                for attr in parts[1:]:
                    if "=" in attr:
                        k, v = attr.split("=", 1)
                        attrs[k.strip().lower()] = v.strip()
                    else:
                        attrs[attr.strip().lower()] = ""
                if value == "" or attrs.get("max-age") == "0":
                    self._cookies.pop(name, None)
                else:
                    self._cookies[name] = value

    def request(self, method, url, body_json=None, form_fields=None, file_payload=None):
        """Dispatch an API call directly against the Flask app in memory."""
        method_name = str(method or "GET").upper()
        headers = {
            "Origin": "http://127.0.0.1:5000",
            "Sec-Fetch-Site": "same-origin",
        }
        if self._bridge_secret:
            headers["X-LANWatch-Desktop-Bridge"] = self._bridge_secret
        cookie_header = self._cookie_header()
        if cookie_header:
            headers["Cookie"] = cookie_header

        kwargs = {
            "method": method_name,
            "base_url": "http://127.0.0.1:5000",
            "headers": headers,
        }

        if isinstance(file_payload, dict) and file_payload.get("data_b64") is not None:
            field_name = str(file_payload.get("field") or "file")
            filename = str(file_payload.get("filename") or "upload.bin")
            raw_bytes = base64.b64decode(str(file_payload.get("data_b64") or ""), validate=True)
            multipart = dict(form_fields) if isinstance(form_fields, dict) else {}
            multipart[field_name] = (io.BytesIO(raw_bytes), filename)
            kwargs["data"] = multipart
            kwargs["content_type"] = "multipart/form-data"
        elif body_json is not None:
            kwargs["data"] = body_json
            kwargs["content_type"] = "application/json"

        try:
            client = web_server.app.test_client(use_cookies=False)
        except TypeError:
            client = web_server.app.test_client()
        with client:
            response = client.open(str(url or "/"), **kwargs)
            self._update_cookies(response.headers.getlist("Set-Cookie"))
            status = int(response.status_code)
            mimetype = response.mimetype or ""
            if mimetype == "application/json":
                payload = response.get_json(silent=True)
                return {
                    "status": status,
                    "json": payload if payload is not None else {},
                }
            return {
                "status": status,
                "mimetype": mimetype,
                "body_b64": base64.b64encode(response.get_data()).decode("ascii"),
            }

    def save_file(self, filename, b64_payload):
        if self._window is None:
            return {"saved": False, "error": "Desktop window is not ready."}

        safe_name = Path(str(filename or "lan_watch_export.bin")).name or "lan_watch_export.bin"
        ext = Path(safe_name).suffix.lower()
        if ext == ".csv":
            file_types = ("CSV files (*.csv)", "All files (*.*)")
        elif ext == ".pdf":
            file_types = ("PDF files (*.pdf)", "All files (*.*)")
        else:
            file_types = ("All files (*.*)",)

        save_mode = getattr(
            getattr(self._webview, "FileDialog", None),
            "SAVE",
            getattr(self._webview, "SAVE_DIALOG", None),
        )
        selection = self._window.create_file_dialog(
            save_mode,
            save_filename=safe_name,
            file_types=file_types,
        )
        if not selection:
            return {"saved": False, "cancelled": True}

        target = Path(selection[0] if isinstance(selection, (list, tuple)) else selection)
        try:
            raw_bytes = base64.b64decode(str(b64_payload or ""), validate=True)
            target.write_bytes(raw_bytes)
        except (OSError, ValueError) as exc:
            return {"saved": False, "error": str(exc)}
        return {"saved": True, "path": str(target)}


def main():
    try:
        import webview
    except ImportError as exc:
        raise SystemExit(
            "pywebview is required for desktop mode. Install it with: py -m pip install pywebview"
        ) from exc

    index_file = BASE_DIR / "index.html"
    if not index_file.is_file():
        raise SystemExit(f"Could not find {index_file}")

    web_server.init_session()
    bridge = DesktopBridge(webview)
    window = webview.create_window(
        "LAN Traffic Analyzer",
        index_file.as_uri(),
        js_api=bridge,
        width=1320,
        height=860,
        min_size=(960, 640),
    )
    bridge.attach(window)

    try:
        webview.start(http_server=False)
    finally:
        web_server.shutdown()


if __name__ == "__main__":
    main()
