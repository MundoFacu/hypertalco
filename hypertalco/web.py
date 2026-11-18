"""WSGI HTTP boundary. Production is served by distro-packaged Gunicorn/TLS."""
import hmac
from http.cookies import SimpleCookie
import json
import logging
import mimetypes
import os
from pathlib import Path
import re
import secrets
import threading
import shutil
import uuid
from urllib.parse import parse_qs, urlsplit, unquote

from . import __version__
from .broker import AgentClient, AgentError
from .metrics import Metrics
from .security import LoginLimiter, check_password, hash_password
from .store import Store
from .validation import Invalid, create, limits
from .media import MAX_ISO

STATIC = Path(__file__).with_name("static")


class HTTPError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


class App:
    def __init__(self, config, agent=None):
        self.config = config
        self.store = Store(config.get("data_dir", "/var/lib/hypertalco"))
        self.agent = agent or AgentClient(config.get("agent_socket", "/run/hypertalco-agent/agent.sock"))
        self.metrics = Metrics()
        self.limiter = LoginLimiter(self.store)
        self.dummy = hash_password(secrets.token_urlsafe(32))

    def __call__(self, environ, start_response):
        headers = [("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
                   ("Referrer-Policy", "same-origin"), ("Cache-Control", "no-store"),
                   ("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")]
        if environ.get("wsgi.url_scheme") == "https":
            headers.append(("Strict-Transport-Security", "max-age=31536000"))
        try:
            status, body, mime, extra = self.route(environ)
            headers.extend(extra)
            if isinstance(body, (dict, list)):
                body = json.dumps(body).encode()
            elif isinstance(body, str):
                body = body.encode()
        except HTTPError as error:
            status, body, mime = error.status, json.dumps({"error": error.message}).encode(), "application/json"
        except (Invalid, ValueError) as error:
            status, body, mime = 400, json.dumps({"error": str(error)[:1000]}).encode(), "application/json"
        except AgentError as error:
            status, body, mime = 503, json.dumps({"error": str(error)[:1200]}).encode(), "application/json"
        except Exception:
            logging.exception("HTTP request failed")
            status, body, mime = 500, b'{"error":"Internal error. Check the service journal."}', "application/json"
        reason = {200: "OK", 202: "Accepted", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 413: "Content Too Large", 429: "Too Many Requests", 500: "Internal Server Error", 503: "Service Unavailable"}[status]
        headers += [("Content-Type", mime), ("Content-Length", str(len(body)))]
        start_response(f"{status} {reason}", headers)
        return [b"" if environ["REQUEST_METHOD"] == "HEAD" else body]

    def session(self, environ):
        cookie = SimpleCookie()
        try:
            cookie.load(environ.get("HTTP_COOKIE", ""))
            token = cookie["hypertalco_session"].value if "hypertalco_session" in cookie else ""
        except Exception:
            token = ""
        session = self.store.session(token)
        if not session:
            raise HTTPError(401, "Sign in to continue")
        return session, token

    def body(self, environ):
        if environ.get("CONTENT_TYPE", "").split(";", 1)[0] != "application/json":
            raise HTTPError(400, "Expected application/json")
        try:
            length = int(environ.get("CONTENT_LENGTH", "0"))
        except ValueError:
            raise HTTPError(400, "Invalid Content-Length") from None
        if length > 65536 or length < 0:
            raise HTTPError(413, "Request exceeds 64 KiB")
        raw = environ["wsgi.input"].read(length)
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            raise HTTPError(400, "Invalid JSON") from None
        if not isinstance(body, dict):
            raise HTTPError(400, "Expected a JSON object")
        return body

    def origin(self, environ):
        expected = environ.get("wsgi.url_scheme", "https") + "://" + environ.get("HTTP_HOST", "")
        if environ.get("HTTP_ORIGIN") != expected:
            raise HTTPError(403, "Cross-origin request rejected")

    def route(self, e):
        method, path = e["REQUEST_METHOD"], e.get("PATH_INFO", "/")
        host = (urlsplit("//" + e.get("HTTP_HOST", "")).hostname or "").lower()
        allowed = self.config.get("allowed_hosts", [])
        if allowed and host not in allowed:
            raise HTTPError(403, "Host not in allowed_hosts")
        if method not in {"GET", "HEAD", "POST"}:
            raise HTTPError(405, "Method not allowed")
        if method in {"GET", "HEAD"} and path in {"/", "/console"}:
            name = "index.html" if path == "/" else "console.html"
            return 200, (STATIC / name).read_bytes(), "text/html; charset=utf-8", []
        if method in {"GET", "HEAD"} and path.startswith("/static/"):
            candidate = (STATIC / path.removeprefix("/static/")).resolve()
            if not candidate.is_relative_to(STATIC.resolve()) or not candidate.is_file() or candidate.suffix not in {".css", ".js", ".svg", ".png", ".ico"}:
                raise HTTPError(404, "Not found")
            mime = "application/javascript" if candidate.suffix == ".js" else mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
            return 200, candidate.read_bytes(), mime, []
        if path == "/api/health" and method == "GET":
            return 200, {"ok": True}, "application/json", []
        if path == "/api/login" and method == "POST":
            self.origin(e)
            address = e.get("REMOTE_ADDR", "unknown")
            if not self.limiter.allow(address):
                raise HTTPError(429, "Too many attempts. Try again in 15 minutes")
            body = self.body(e)
            name, password = body.get("username", ""), body.get("password", "")
            if not isinstance(name, str) or len(name) > 64:
                raise HTTPError(401, "Invalid credentials")
            encoded = self.store.user(name)
            valid = check_password(password, encoded or self.dummy)
            if not valid or not encoded:
                self.store.audit(name[:64], "login.failed", address)
                raise HTTPError(401, "Invalid credentials")
            self.limiter.clear(address)
            token, csrf = self.store.new_session(name)
            self.store.audit(name, "login.succeeded", address)
            cookie = f"hypertalco_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"
            if not self.config.get("demo"):
                cookie += "; Secure"
            return 200, {"username": name, "csrf": csrf}, "application/json", [("Set-Cookie", cookie)]
        session, token = self.session(e)
        if path.startswith("/novnc/") and method in {"GET", "HEAD"}:
            root = Path(self.config.get("novnc_dir", "/usr/share/novnc")).resolve()
            candidate = (root / path.removeprefix("/novnc/")).resolve()
            if not candidate.is_relative_to(root) or not candidate.is_file() or candidate.suffix not in {".js", ".css", ".svg", ".png"}:
                raise HTTPError(404, "noVNC asset not available. Check the console service installation")
            return 200, candidate.read_bytes(), mimetypes.guess_type(candidate.name)[0] or "application/javascript", []
        if method in {"GET", "HEAD"}:
            data = None
            if path == "/api/me":
                data = {**session, "version": __version__, "demo": bool(self.config.get("demo"))}
            elif path == "/api/overview":
                data = {"host": self.metrics.snapshot(), **self.agent.call("inventory"), "demo": bool(self.config.get("demo"))}
            elif path == "/api/jobs":
                data = self.store.jobs()
            elif path == "/api/audit":
                data = self.store.audit_rows()
            elif path in {"/api/networks", "/api/storage", "/api/media", "/api/images", "/api/templates", "/api/registries"}:
                data = self.agent.call(path.removeprefix("/api/"))
            elif path == "/api/images/search":
                term = parse_qs(e.get("QUERY_STRING", "")).get("q", [""])[0]
                data = self.agent.call("images.search", {"term": term})
            elif re.fullmatch(r"/api/resources/[a-f0-9-]{36}/(?:logs|stats)", path):
                data = self.agent.call(path.rsplit("/", 1)[1], {"id": path.split("/")[3]})
            if data is not None:
                return 200, data, "application/json", []
            raise HTTPError(404, "Not found")
        self.origin(e)
        if not hmac.compare_digest(e.get("HTTP_X_CSRF_TOKEN", ""), session["csrf"]):
            raise HTTPError(403, "CSRF token missing or invalid")
        if path in {'/api/media/upload', '/api/templates/upload'}:
            return self.upload_file(e, session, path == '/api/templates/upload')
        data = self.body(e)
        if path == "/api/logout":
            self.store.logout(token)
            return 200, {"ok": True}, "application/json", [("Set-Cookie", "hypertalco_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")]
        if path == "/api/password":
            if not check_password(data.get("current", ""), self.store.user(session["username"])):
                raise HTTPError(403, "Current password is incorrect")
            self.store.set_user(session["username"], hash_password(data.get("password")), reset=True)
            self.store.audit(session["username"], "password.changed")
            return 200, {"ok": True}, "application/json", []
        if path in {"/api/registries/login", "/api/registries/delete"}:
            operation = "registries." + path.rsplit("/", 1)[1]
            result = self.agent.call(operation, data)
            self.store.audit(session["username"], operation, str(data.get("server", ""))[:100])
            return 200, result, "application/json", []
        match = re.fullmatch(r"/api/resources/([a-f0-9-]{36})/(action|resize|console)", path)
        if match:
            identifier, operation = match.groups()
            data["id"] = identifier
            if operation == "console":
                return 200, self.agent.call("console", data), "application/json", []
            if operation == "resize":
                limits(data)
        elif path == "/api/resources":
            create(data)  # Validate now; the agent validates again before any host operation.
            operation = "create"
        else:
            operation = {"/api/media/import": "media.import", "/api/media/delete": "media.delete", "/api/templates/delete": "templates.delete",
                         "/api/networks/create": "networks.create", "/api/networks/delete": "networks.delete",
                         "/api/images/pull": "images.pull"}.get(path)
            if not operation:
                raise HTTPError(404, "Not found")
        job_id = self.store.enqueue(operation, data, session["username"])
        return 202, {"job_id": job_id}, "application/json", []

    def upload_file(self, environ, session, is_template=False):
        if environ.get('CONTENT_TYPE', '').split(';', 1)[0] != 'application/octet-stream':
            raise HTTPError(400, 'Expected a file')
        try:
            length = int(environ.get('CONTENT_LENGTH', '0'))
        except ValueError:
            raise HTTPError(400, 'Invalid Content-Length') from None
        if length < 1 or length > MAX_ISO:
            raise HTTPError(413, 'File must be between 1 byte and 32 GiB')
        name = unquote(environ.get('HTTP_X_UPLOAD_NAME', ''))
        suffix = next((x for x in ('.tar.zst', '.tar.xz', '.tar.gz') if name.endswith(x)), '') if is_template else ('.iso' if name.endswith('.iso') else '')
        if not suffix or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._ -]{0,110}', name):
            raise HTTPError(400, 'Choose a supported file with a simple filename')
        folder = self.store.folder / 'uploads'
        folder.mkdir(mode=0o700, exist_ok=True)
        identifier = str(uuid.uuid4())
        path = folder / (identifier + suffix)
        try:
            with path.open('xb') as out:
                remaining = length
                while remaining:
                    chunk = environ['wsgi.input'].read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise HTTPError(400, 'Upload interrupted')
                    if shutil.disk_usage(folder).free < len(chunk) + 2 * 1024**3:
                        raise HTTPError(413, 'Upload would leave less than 2 GiB free')
                    out.write(chunk)
                    remaining -= len(chunk)
                out.flush()
                os.fsync(out.fileno())
            operation = 'templates.upload' if is_template else 'media.upload'
            result = self.agent.call(operation, {'id': identifier, 'name': name}, timeout=1800)
            self.store.audit(session['username'], operation, name)
            return 200, result, 'application/json', []
        finally:
            path.unlink(missing_ok=True)


_app = None
_lock = threading.Lock()


def application(environ, start_response):
    global _app
    if _app is None:
        with _lock:
            if _app is None:
                path = Path(os.environ.get("HYPERTALCO_CONFIG", "/etc/hypertalco/config.json"))
                _app = App(json.loads(path.read_text()))
    return _app(environ, start_response)
