"""ISO imports from administrator-selected URLs or approved host mount roots."""
import hashlib
import http.client
import ipaddress
import os
from pathlib import Path
import re
import shutil
import stat
import time
from urllib.parse import urljoin, urlsplit
import uuid

from .validation import Invalid

MAX_ISO = 32 * 1024**3


def iso_header(handle):
    handle.seek(32768)
    header = handle.read(32768)
    handle.seek(0)
    return any(marker in header for marker in (b"CD001", b"NSR02", b"NSR03"))


def local_source(source, roots):
    path = Path(source)
    if not path.is_absolute() or path.suffix.lower() != ".iso":
        raise Invalid("Select an absolute .iso path inside an approved media root")
    # Walk with directory FDs and O_NOFOLLOW so a symlink cannot escape a mount root.
    for root_value in roots:
        root = Path(root_value)
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part in {"..", "."} for part in relative.parts) or not relative.parts:
            raise Invalid("Invalid media path")
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in relative.parts[:-1]:
                following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory); directory = following
            fd = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise Invalid("Media source must be a regular file")
            return os.fdopen(fd, "rb")
        finally:
            os.close(directory)
    raise Invalid("Path is outside the approved media roots")


def remote_source(url):
    """HTTP(S), no embedded credentials, restricted destinations checked after connect."""
    for _ in range(6):
        parsed = urlsplit(url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise Invalid("Use an HTTP(S) URL without embedded credentials or fragments")
        conn_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        conn = conn_class(parsed.hostname, parsed.port, timeout=30)
        try:
            conn.connect()
            peer = ipaddress.ip_address(conn.sock.getpeername()[0])
            if peer.is_loopback or peer.is_link_local or peer.is_multicast or peer.is_unspecified:
                raise Invalid("Loopback, link-local and metadata destinations are not media sources")
            conn.request("GET", parsed.path + (("?" + parsed.query) if parsed.query else ""), headers={"User-Agent": "Hypertalco/0.1"})
            response = conn.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                url = urljoin(url, response.getheader("Location", "")); conn.close(); continue
            if response.status != 200:
                raise Invalid(f"Media server returned HTTP {response.status}")
            if int(response.getheader("Content-Length", "0")) > MAX_ISO:
                raise Invalid("ISO exceeds the 32 GiB import limit")
            return conn, response
        except BaseException:
            conn.close()
            raise
    raise Invalid("Too many media redirects")


def import_iso(payload, folder, roots):
    if set(payload) - {"source", "kind", "name", "sha256", "job_id"}:
        raise Invalid("Unsupported media options")
    source = payload.get("source", "")
    if not isinstance(source, str) or not 1 <= len(source) <= 2048:
        raise Invalid("Provide a URL or absolute host path")
    name = payload.get("name", "")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,95}\.iso", name):
        raise Invalid("Give the ISO a filename such as debian-13.iso")
    expected = payload.get("sha256", "").lower()
    if expected and not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise Invalid("SHA256 must contain 64 hexadecimal characters")
    folder.mkdir(parents=True, exist_ok=True, mode=0o755)
    identifier = str(uuid.uuid4())
    temporary, final = folder / (identifier + ".part"), folder / (identifier + ".iso")
    conn = None
    handle = None
    try:
        if payload.get("kind") == "path":
            handle = local_source(source, roots)
        elif payload.get("kind") == "url":
            conn, handle = remote_source(source)
        else:
            raise Invalid("Choose URL or host path")
        hasher, size, deadline = hashlib.sha256(), 0, time.monotonic() + 3600
        with temporary.open("xb") as out:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ISO or time.monotonic() > deadline:
                    raise Invalid("Media exceeded its size/time limit")
                if shutil.disk_usage(folder).free < len(chunk) + 2 * 1024**3:
                    raise Invalid("Import would leave less than 2 GiB free storage")
                out.write(chunk); hasher.update(chunk)
            out.flush(); os.fsync(out.fileno())
        with temporary.open("rb") as f:
            if not iso_header(f):
                raise Invalid("Source does not contain ISO9660/UDF installation media")
        if expected and hasher.hexdigest() != expected:
            raise Invalid("ISO checksum does not match; import discarded")
        temporary.chmod(0o644); temporary.replace(final)
        # Do not retain signed URL query strings or URL credentials in audit/catalog data.
        origin = source if payload["kind"] == "path" else source.split("?", 1)[0]
        return {"id": identifier, "name": name, "path": str(final), "source": origin,
                "kind": payload["kind"], "size": size, "sha256": hasher.hexdigest(), "created": time.time()}
    finally:
        if handle:
            handle.close()
        if conn:
            conn.close()
        if temporary.exists():
            temporary.unlink()
