"""Root agent: Linux peer credentials, fixed operations and a private registry."""
import json
import logging
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import shutil
import socket
import socketserver
import stat
import struct
import tempfile
import threading
import time
from urllib.parse import urlencode
import urllib.request
import uuid

from .engines import Docker, LABEL, Libvirt, LXC, Runner, registry_for
from .media import import_iso
from .ct_archive import validate_archive
from .networks import Networks
from .validation import Invalid, create, limits


def peer_allowed(sock, allowed_uid):
    _, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    return uid in {0, allowed_uid}


class Agent:
    def __init__(self, config, runner=None, docker=None):
        self.config = config
        self.folder = Path(config.get("state_dir", "/var/lib/hypertalco-agent"))
        self.folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.folder.chmod(0o700)
        self.path = self.folder / "registry.json"
        self.state = json.loads(self.path.read_text()) if self.path.exists() else {"resources": {}, "media": {}, "auth": {}}
        self.state.setdefault('uploaded_templates', {})
        self.runner = runner or Runner()
        self.docker = docker or Docker()
        self.libvirt = Libvirt(self.runner)
        self.lxc = LXC(self.runner, config.get("lxc_dir", "/var/lib/hypertalco-agent/lxc"), int(config.get("idmap_base", 20000000)), config.get("template_cache", "/var/cache/lxc"))
        self.networks = Networks(self.runner, self.docker, self.libvirt)
        self.storage = Path(config.get("storage_dir", "/var/lib/libvirt/images/hypertalco"))
        self.vm_dir = Path(config.get("vm_dir", str(self.storage / "guests")))
        self.iso_dir = Path(config.get("iso_dir", str(self.storage / "iso")))
        self.uploads = Path(config.get('upload_dir', '/var/lib/hypertalco/uploads'))
        self.logs = self.folder / "logs"; self.logs.mkdir(exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.catalog_cache = None
        self.console_tokens = {}
        self.console_lock = threading.RLock()
        self.counter_cache = {}

    def save(self):
        fd, temporary = tempfile.mkstemp(dir=self.folder, prefix=".registry-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self.state, f); f.flush(); os.fsync(f.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def record(self, identifier):
        try:
            identifier = str(uuid.UUID(identifier))
        except (ValueError, TypeError, AttributeError):
            raise Invalid("Invalid managed resource ID") from None
        record = self.state["resources"].get(identifier)
        if not record:
            raise Invalid("This resource is not managed by Hypertalco")
        return record

    def inventory(self):
        resources, engines = [], {}
        records = {k: dict(v) for k, v in self.state["resources"].copy().items()}
        seen = set()
        for kind in ("docker", "lxc", "qemu"):
            try:
                if kind == "docker":
                    rows = self.docker.inventory()
                    for row in rows:
                        labels = row.get("Labels") or {}
                        identifier = labels.get("io.hypertalco.id")
                        own = records.get(identifier, {})
                        managed = labels.get(LABEL) == "true" and own.get("physical") == row["Id"] and own.get("engine") == kind
                        if managed:
                            seen.add(identifier)
                        ips = [n.get("IPAddress") for n in row.get("NetworkSettings", {}).get("Networks", {}).values() if n.get("IPAddress")]
                        resources.append({"id": identifier if managed else "external-docker-" + row["Id"], "engine": kind,
                                          "name": own.get("name") if managed else (row.get("Names") or [row["Id"][:12]])[0].lstrip("/"),
                                          "status": "stopped" if row.get("State") in {"created", "exited"} else row.get("State", "unknown"),
                                          "image": row.get("Image"), "ips": ips, "managed": managed,
                                          "cpus": own.get("cpus"), "memory_mib": own.get("memory_mib"),
                                          "network": own.get("network"), "ports": row.get("Ports", []), "physical": row["Id"][:12]})
                elif kind == "lxc":
                    if not shutil.which("lxc-ls"):
                        raise RuntimeError("LXC is not installed")
                    rows = [(r, True) for r in self.lxc.inventory_at(self.lxc.folder)]
                    if self.lxc.folder != Path("/var/lib/lxc"):
                        rows += [(r, False) for r in self.lxc.inventory_at(Path("/var/lib/lxc"))]
                    for row, local in rows:
                        match = next(((k, v) for k, v in records.items() if local and v.get("engine") == kind and v.get("physical") == row["physical"]), None)
                        identifier, own = match if match else ("external-lxc-" + row["physical"], {})
                        if match:
                            seen.add(identifier)
                        resources.append({**row, "id": identifier, "engine": kind, "managed": bool(match),
                                          "name": own.get("name", row["name"]), "cpus": own.get("cpus"),
                                          "memory_mib": own.get("memory_mib"), "network": own.get("network")})
                else:
                    for row in self.libvirt.domains():
                        own = records.get(row["physical"], {})
                        managed = own.get("engine") == kind and row["name"] == "ht-" + own.get("name", "")
                        identifier = row["physical"] if managed else "external-qemu-" + row["physical"]
                        if managed:
                            seen.add(identifier)
                        row.pop("xml")
                        resources.append({**row, "id": identifier, "engine": kind, "managed": managed,
                                          "name": own.get("name", row["name"]), "network": own.get("network"), "disk_gib": own.get("disk_gib")})
                engines[kind] = {"available": True, "error": None}
            except Exception as error:
                engines[kind] = {"available": False, "error": str(error)[:300]}
        for identifier, own in records.items():
            if identifier not in seen:
                resources.append({k: own.get(k) for k in ("engine", "name", "cpus", "memory_mib", "image", "network", "disk_gib")} |
                                 {"id": identifier, "managed": True, "status": "error", "ips": [], "error": own.get("last_error", "Runtime object unavailable")})
        return {"resources": resources, "engines": engines, "kvm": Path("/dev/kvm").exists()}

    def check_owned(self, record):
        physical = record.get("physical")
        if not physical:
            raise Invalid("Creation did not complete; inspect the failed resource")
        if record["engine"] == "docker":
            info = self.docker.inspect(physical)
            labels = info.get("Config", {}).get("Labels") or {}
            if labels.get(LABEL) != "true" or labels.get("io.hypertalco.id") != record["id"]:
                raise Invalid("Container ownership metadata changed")
            return "running" if info["State"].get("Running") else "stopped"
        if record["engine"] == "qemu":
            xml = self.libvirt.virsh("dumpxml", physical)
            import xml.etree.ElementTree as ET
            node = ET.fromstring(xml)
            if node.findtext("uuid") != record["id"] or node.findtext("name") != "ht-" + record["name"]:
                raise Invalid("VM ownership metadata changed")
            return "stopped" if self.libvirt.virsh("domstate", physical).strip() == "shut off" else "running"
        if physical != "ht-" + record["name"]:
            raise Invalid("LXC ownership metadata changed")
        config = self.lxc.folder / physical / "config"
        if config.is_symlink() or config.stat().st_uid != 0:
            raise Invalid("LXC configuration ownership changed")
        return self.lxc.command("lxc-info", physical, "-sH").strip().lower()

    def create(self, payload):
        spec = create({k: v for k, v in payload.items() if k != "job_id"})
        total_mib = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:"))) // 1024
        if spec["cpus"] > (os.cpu_count() or 1) or spec["memory_mib"] > total_mib - 512:
            raise Invalid("Guest allocation exceeds this host; leave at least 512 MiB for the host")
        if any(r["name"] == spec["name"] and r["engine"] == spec["engine"] for r in self.state["resources"].values()):
            raise Invalid("A managed guest with that name already exists")
        network = self.networks.resolve(spec["engine"], spec["network"])
        if spec["engine"] == "qemu":
            if not Path("/dev/kvm").exists():
                raise Invalid("KVM is unavailable. Enable CPU virtualization in firmware")
            media = self.state["media"].get(spec["image"])
            if not media or not Path(media["path"]).is_file():
                raise Invalid("The selected ISO is not available")
            if shutil.disk_usage(self.vm_dir).free < 2 * 1024**3:
                raise Invalid("VM storage has less than 2 GiB free")
        if spec["engine"] == "lxc":
            if network["mode"] == "isolated":
                raise Invalid("Initial Debian/Ubuntu SSH provisioning needs an internet-capable NAT or bridge network")
            if spec['image'].startswith('upload-'):
                template = self.state['uploaded_templates'].get(spec['image'])
                if not template or not Path(template['path']).is_file():
                    raise Invalid('Uploaded template is not available')
                if shutil.disk_usage(self.lxc.folder).free < template['expanded_bytes'] + 2 * 1024**3:
                    raise Invalid('Not enough free space to extract the template and retain 2 GiB')
            elif not any(t["id"] == spec["image"] for t in self.templates()["templates"]):
                raise Invalid("Template is not in the current official catalog")
        identifier = str(uuid.uuid4())
        # Store no SSH key or environment secret in the resource inventory.
        record = {k: v for k, v in spec.items() if k not in {"env", "ssh_keys"}}
        record.update(id=identifier, physical=None, created=time.time(), last_error="Creation is incomplete")
        self.state["resources"][identifier] = record; self.save()
        try:
            if spec["engine"] == "docker":
                server = registry_for(spec["image"])
                auth = self.state["auth"].get(server)
                record["physical"] = self.docker.create(spec, identifier, auth)
                self.save()
                self.docker.action(record["physical"], "start")
            elif spec["engine"] == "qemu":
                # UUID/name are deterministic for recovery if virt-install fails midway.
                record["physical"] = identifier; self.save()
                self.libvirt.create(spec, identifier, self.vm_dir, Path(media["path"]), network["name"])
            else:
                record["physical"] = "ht-" + spec["name"]; self.save()
                self.lxc.create(spec, identifier, network["bridge"], self.logs,
                                archive=Path(template['path']) if spec['image'].startswith('upload-') else None)
            record.pop("last_error", None); self.save()
            return {"id": identifier, "name": spec["name"]}
        except Exception as error:
            record["last_error"] = str(error)[:1000]; self.save()
            raise

    def action(self, data):
        if set(data) - {"id", "action", "confirm", "job_id"}:
            raise Invalid("Unsupported action fields")
        action = data.get("action")
        if action not in {"start", "stop", "restart", "delete", "force-stop"}:
            raise Invalid("Unsupported action")
        record = self.record(data.get("id"))
        if action == 'force-stop' and (record['engine'] != 'qemu' or data.get('confirm') != record['name']):
            raise Invalid('Type the exact VM name to force power off')
        if action == "delete" and data.get("confirm") != record["name"]:
            raise Invalid("Type the exact guest name to delete it")
        state = self.check_owned(record)
        if action == "delete" and state != "stopped":
            raise Invalid("Stop the guest before deleting it")
        engine = {"docker": self.docker, "lxc": self.lxc, "qemu": self.libvirt}[record["engine"]]
        engine.action(record["physical"], action)
        if action == "delete":
            if record["engine"] == "qemu":
                folder = self.vm_dir / record["id"]
                if folder.is_symlink() or folder.resolve().parent != self.vm_dir.resolve():
                    raise Invalid("Unexpected VM storage path; guest definition removed, files retained")
                if folder.exists():
                    shutil.rmtree(folder)
            # Docker named volumes are deliberately retained when removing a container.
            del self.state["resources"][record["id"]]; self.save()
        return {"id": record["id"], "action": action, "state": "requested" if action in {"stop", "restart"} else "completed"}

    def resize(self, data):
        if set(data) - {"id", "cpus", "memory_mib", "job_id"}:
            raise Invalid("Unsupported resize fields")
        record = self.record(data.get("id")); spec = limits(data)
        if self.check_owned(record) != "stopped":
            raise Invalid("Stop the guest before changing CPU or memory")
        {"docker": self.docker, "lxc": self.lxc, "qemu": self.libvirt}[record["engine"]].resize(record["physical"], spec)
        record.update(spec); self.save()
        return {"id": record["id"], **spec}

    def upload_template(self, data):
        if set(data) != {'id', 'name'}:
            raise Invalid('Unsupported upload options')
        try:
            identifier = str(uuid.UUID(data['id']))
        except (ValueError, TypeError, AttributeError):
            raise Invalid('Invalid upload ID') from None
        name = data['name']
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._ -]{0,110}', name):
            raise Invalid('Invalid template name')
        suffix = next((x for x in ('.tar.zst', '.tar.xz', '.tar.gz') if name.endswith(x)), None)
        if not suffix:
            raise Invalid('Template must be .tar.zst, .tar.xz or .tar.gz')
        self.uploads.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory = os.open(self.uploads, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open(identifier + suffix, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        finally:
            os.close(directory)
        folder = Path(self.lxc.template_cache) / 'hypertalco-uploads'
        folder.mkdir(mode=0o755, parents=True, exist_ok=True)
        if folder.is_symlink() or folder.stat().st_uid != 0:
            os.close(fd)
            raise Invalid('Unexpected template storage ownership')
        folder.chmod(0o755)
        target = folder / (identifier + suffix)
        try:
            with os.fdopen(fd, 'rb') as source, target.open('xb') as out:
                source_stat = os.fstat(source.fileno())
                if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_uid != int(self.config['service_uid']) or source_stat.st_nlink != 1:
                    raise Invalid('Template upload is not a regular file')
                total = 0
                while chunk := source.read(1024 * 1024):
                    total += len(chunk)
                    if total > 32 * 1024**3 or shutil.disk_usage(folder).free < len(chunk) + 2 * 1024**3:
                        raise Invalid('Template exceeds size or free-space limits')
                    out.write(chunk)
                out.flush(); os.fsync(out.fileno())
            details = validate_archive(target)
            target.chmod(0o644)
            record = {'id': 'upload-' + identifier, 'name': name, 'path': str(target), 'arch': platform.machine(),
                      'variant': 'browser upload', 'build': 'Uploaded template', **details}
            self.state['uploaded_templates'][record['id']] = record
            self.save()
            return {k: v for k, v in record.items() if k != 'path'}
        except BaseException:
            target.unlink(missing_ok=True)
            raise

    def templates(self):
        if self.catalog_cache and time.time() - self.catalog_cache[0] < 3600:
            remote = self.catalog_cache[1]
            return {**remote, 'templates': remote['templates'] + [{k: v for k, v in row.items() if k != 'path'} for row in self.state['uploaded_templates'].values() if Path(row['path']).is_file()]}
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), "amd64")
        try:
            with urllib.request.urlopen("https://images.linuxcontainers.org/meta/1.0/index-system", timeout=15) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
        except (OSError, TimeoutError):
            uploaded = [{k: v for k, v in row.items() if k != 'path'} for row in self.state['uploaded_templates'].values() if Path(row['path']).is_file()]
            return {'templates': uploaded, 'source': 'Official catalog unavailable; showing uploaded templates', 'fetched': time.time()}
        if len(raw) > 4 * 1024 * 1024:
            raise Invalid("Template index exceeds its limit")
        templates = {}
        for line in raw.decode().splitlines():
            parts = line.split(";")
            if len(parts) < 5:
                continue
            dist, release, architecture, variant, build = parts[:5]
            if dist not in {"debian", "ubuntu"} or architecture != arch or variant != "default":
                continue
            identifier = "/".join(parts[:4])
            if not re.fullmatch(r"(?:debian|ubuntu)/[a-z0-9.-]+/(?:amd64|arm64)/default", identifier):
                continue
            templates[identifier] = {"id": identifier, "name": f"{dist.title()} {release}", "dist": dist,
                                     "release": release, "arch": architecture, "variant": variant, "build": build}
        result = {"templates": list(templates.values()), "source": "images.linuxcontainers.org", "fetched": time.time()}
        self.catalog_cache = (time.time(), result)
        return {**result, 'templates': result['templates'] + [{k: v for k, v in row.items() if k != 'path'} for row in self.state['uploaded_templates'].values() if Path(row['path']).is_file()]}

    def logs_for(self, identifier):
        record = self.record(identifier); self.check_owned(record)
        if record["engine"] == "docker":
            return {"text": self.docker.logs(record["physical"])}
        path = self.logs / (record["id"] + ".log") if record["engine"] == "lxc" else Path("/var/log/libvirt/qemu") / ("ht-" + record["name"] + ".log")
        if not path.exists():
            return {"text": "No runtime log is available yet."}
        if path.is_symlink():
            raise Invalid("Unexpected log symlink")
        with path.open("rb") as f:
            f.seek(max(0, path.stat().st_size - 65536))
            return {"text": f.read(65536).decode("utf-8", "replace")}

    def stats(self, identifier):
        record = self.record(identifier)
        if self.check_owned(record) != "running":
            return {"running": False}
        result = {"running": True, "cpu_percent": None, "memory_bytes": None, "rx_bytes": None, "tx_bytes": None}
        if record["engine"] == "docker":
            x = self.docker.request("GET", f"/v1.41/containers/{record['physical']}/stats?stream=false", timeout=10)
            current, previous = x.get("cpu_stats", {}), x.get("precpu_stats", {})
            used = current.get("cpu_usage", {}).get("total_usage", 0) - previous.get("cpu_usage", {}).get("total_usage", 0)
            system = current.get("system_cpu_usage", 0) - previous.get("system_cpu_usage", 0)
            if system > 0:
                result["cpu_percent"] = round(100 * used / system * current.get("online_cpus", 1) / record["cpus"], 1)
            memory = x.get("memory_stats", {})
            result["memory_bytes"] = max(0, memory.get("usage", 0) - memory.get("stats", {}).get("inactive_file", 0))
            result["rx_bytes"] = sum(n.get("rx_bytes", 0) for n in x.get("networks", {}).values())
            result["tx_bytes"] = sum(n.get("tx_bytes", 0) for n in x.get("networks", {}).values())
            result["pids"] = x.get("pids_stats", {}).get("current")
            return result
        if record["engine"] == "qemu":
            text = self.libvirt.virsh("domstats", record["physical"], "--cpu-total", "--balloon", "--interface", "--block", "--raw")
            values = {k.strip(): int(v) for k, v in re.findall(r"([\w.]+)=(\d+)", text)}
            cpu_ns = values.get("cpu.time")
            result["memory_bytes"] = values.get("balloon.rss", 0) * 1024 or None
            result["rx_bytes"] = sum(v for k, v in values.items() if re.fullmatch(r"net\.\d+\.rx\.bytes", k))
            result["tx_bytes"] = sum(v for k, v in values.items() if re.fullmatch(r"net\.\d+\.tx\.bytes", k))
            result["disk_read_bytes"] = sum(v for k, v in values.items() if re.fullmatch(r"block\.\d+\.rd\.bytes", k))
            result["disk_write_bytes"] = sum(v for k, v in values.items() if re.fullmatch(r"block\.\d+\.wr\.bytes", k))
        else:
            text = self.lxc.command("lxc-info", record["physical"])
            cpu = re.search(r"CPU use:\s+([\d.]+)", text)
            cpu_ns = float(cpu[1]) * 10**9 if cpu else None
            for label, field in (("Memory use", "memory_bytes"), ("RX bytes", "rx_bytes"), ("TX bytes", "tx_bytes")):
                match = re.search(re.escape(label) + r":\s+([\d.]+)\s+(\w+)", text)
                if match:
                    multiplier = {"bytes": 1, "B": 1, "KiB": 1024, "MiB": 2**20, "GiB": 2**30}.get(match[2])
                    result[field] = int(float(match[1]) * multiplier) if multiplier else None
        if cpu_ns is not None:
            previous = self.counter_cache.get(identifier)
            now = time.monotonic()
            if previous and now > previous[0] and cpu_ns >= previous[1]:
                result["cpu_percent"] = round(100 * (cpu_ns - previous[1]) / 10**9 / (now - previous[0]) / record["cpus"], 1)
            self.counter_cache[identifier] = (now, cpu_ns)
        return result

    def console(self, identifier):
        record = self.record(identifier)
        if record["engine"] != "qemu" or self.check_owned(record) != "running":
            raise Invalid("The VNC console requires a running managed VM")
        import xml.etree.ElementTree as ET
        xml = ET.fromstring(self.libvirt.virsh("dumpxml", record["physical"]))
        graphics = xml.find("./devices/graphics[@type='vnc']")
        if graphics is None or graphics.get("listen") != "127.0.0.1":
            raise Invalid("VM graphics must listen on loopback")
        port = int(graphics.get("port", "-1"))
        if not 5900 <= port <= 65535:
            raise Invalid("VNC port is not allocated yet")
        token = secrets.token_urlsafe(32)
        with self.console_lock:
            self.console_tokens[token] = (time.time() + 120, port)
            self.write_console_tokens()
        return {"token": token, "expires_in": 120, "path": "/websockify"}

    def write_console_tokens(self):
        self.console_tokens = {k: v for k, v in self.console_tokens.items() if v[0] > time.time()}
        target = Path(self.config.get("console_tokens", "/run/hypertalco-agent/vnc-tokens"))
        fd, temporary = tempfile.mkstemp(dir=target.parent, prefix=".vnc-")
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write("".join(f"{k}: 127.0.0.1:{v[1]}\n" for k, v in self.console_tokens.items()))
                handle.flush(); os.fsync(handle.fileno())
            os.chmod(temporary, 0o640)
            if self.config.get("service_gid") is not None:
                os.chown(temporary, 0, int(self.config["service_gid"]))
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def dispatch(self, operation, data):
        if not isinstance(data, dict):
            raise Invalid("Expected an object")
        if operation == "inventory":
            return self.inventory()
        if operation == "logs":
            return self.logs_for(data.get("id"))
        if operation == "stats":
            return self.stats(data.get("id"))
        if operation == "templates":
            return self.templates()
        if operation == "images":
            images = self.docker.request("GET", "/v1.41/images/json")
            return [{"id": x["Id"], "tags": x.get("RepoTags") or [], "size": x["Size"], "created": x["Created"]} for x in images]
        if operation == "images.search":
            term = data.get("term", "")
            if not isinstance(term, str) or not re.fullmatch(r"[A-Za-z0-9_./-]{1,80}", term):
                raise Invalid("Invalid Docker Hub search")
            return self.docker.request("GET", "/v1.41/images/search?" + urlencode({"term": term, "limit": 20}))
        if operation == "media":
            return [{k: v for k, v in x.items() if k != "path"} | {"available": Path(x["path"]).is_file()} for x in self.state["media"].values()]
        if operation == "networks":
            result = self.networks.interfaces(); result["networks"] = []; result["errors"] = {}
            for engine, getter in (("docker", self.networks.docker_networks), ("libvirt", self.networks.libvirt_networks)):
                try:
                    result["networks"] += getter()
                except Exception as error:
                    result["errors"][engine] = str(error)[:300]
            return result
        if operation == "storage":
            return {"devices": json.loads(self.runner.run(["lsblk", "-J", "-b", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL"])),
                    "filesystems": json.loads(self.runner.run(["findmnt", "-J", "-b", "-o", "TARGET,SOURCE,FSTYPE,SIZE,AVAIL,USE%"])),
                    "media_roots": self.config.get("media_roots", ["/mnt", "/media", "/srv/iso"]),
                    "guest_storage": str(self.vm_dir), "lxc_storage": str(self.lxc.folder),
                    "iso_storage": str(self.iso_dir), "template_cache": self.lxc.template_cache}
        if operation == "registries":
            return [{"server": key, "username": val["username"]} for key, val in self.state["auth"].items()]
        if operation == "console":
            return self.console(data.get("id"))
        with self.lock:
            if operation in {"create", "action", "resize"}:
                return getattr(self, operation)(data)
            if operation == "console":
                return self.console(data.get("id"))
            if operation == "media.import":
                media = import_iso(data, self.iso_dir, self.config.get("media_roots", ["/mnt", "/media", "/srv/iso"]))
                self.state["media"][media["id"]] = media; self.save()
                return {k: v for k, v in media.items() if k != "path"}
            if operation == 'media.upload':
                if set(data) != {'id', 'name'}:
                    raise Invalid('Unsupported upload options')
                try:
                    identifier = str(uuid.UUID(data['id']))
                except (ValueError, TypeError, AttributeError):
                    raise Invalid('Invalid upload ID') from None
                folder = self.uploads
                media = import_iso({'source': str(folder / (identifier + '.iso')), 'kind': 'path', 'name': data['name']}, self.iso_dir, [str(folder)])
                media['source'] = 'browser upload'
                media['kind'] = 'upload'
                self.state['media'][media['id']] = media; self.save()
                return {k: v for k, v in media.items() if k != 'path'}
            if operation == 'templates.upload':
                return self.upload_template(data)
            if operation == 'templates.delete':
                if set(data) - {'id', 'confirm', 'job_id'}:
                    raise Invalid('Unsupported template options')
                identifier = data.get('id', '')
                template = self.state['uploaded_templates'].get(identifier)
                if not template or data.get('confirm') != template['name']:
                    raise Invalid('Type the exact template filename to remove it')
                if any(r.get('image') == identifier for r in self.state['resources'].values()):
                    raise Invalid('A container still references this template')
                folder = Path(self.lxc.template_cache) / 'hypertalco-uploads'
                path = Path(template['path'])
                if path.parent != folder or path.is_symlink():
                    raise Invalid('Unexpected template storage path')
                path.unlink(missing_ok=True)
                del self.state['uploaded_templates'][identifier]
                self.save()
                return {'deleted': identifier}
            if operation == "media.delete":
                identifier = str(uuid.UUID(data.get("id", "")))
                media = self.state["media"].get(identifier)
                if not media or data.get("confirm") != media["name"]:
                    raise Invalid("Type the exact ISO filename to remove it")
                if any(r.get("image") == identifier for r in self.state["resources"].values()):
                    raise Invalid("A VM still references this ISO")
                path = self.iso_dir / (identifier + ".iso")
                if path.is_symlink():
                    raise Invalid("Unexpected media symlink")
                path.unlink(missing_ok=True); del self.state["media"][identifier]; self.save()
                return {"deleted": identifier}
            if operation == "networks.create":
                return self.networks.create(data)
            if operation == "networks.delete":
                if data.get("engine") not in {"docker", "libvirt"}:
                    raise Invalid("Invalid network engine")
                return self.networks.delete(data.get("name"), data["engine"], list(self.state["resources"].values()))
            if operation == "images.pull":
                image = data.get("image", "")
                if not isinstance(image, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,199}", image):
                    raise Invalid("Invalid image reference")
                registry = registry_for(image)
                return self.docker.pull(image, self.state["auth"].get(registry))
            if operation == "registries.login":
                server, username, password = data.get("server", ""), data.get("username", ""), data.get("password", "")
                if not isinstance(server, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?", server):
                    raise Invalid("Registry server must be a hostname, optionally with a port")
                if not isinstance(username, str) or not 1 <= len(username) <= 100 or not isinstance(password, str) or not 1 <= len(password) <= 4096:
                    raise Invalid("Provide registry username and password/token")
                auth = {"username": username, "password": password, "serveraddress": "https://index.docker.io/v1/" if server == "docker.io" else "https://" + server}
                self.docker.request("POST", "/v1.41/auth", auth)
                self.state["auth"][server] = auth; self.save()
                return {"server": server, "username": username}
            if operation == "registries.delete":
                self.state["auth"].pop(data.get("server", ""), None); self.save(); return {"removed": True}
        raise Invalid("Unsupported host operation")


def serve(config):
    if os.geteuid() != 0:
        raise SystemExit("The host agent must run as root; use the local preview instead")
    allowed_uid = int(config["service_uid"])
    path = Path(config.get("socket", "/run/hypertalco-agent/agent.sock"))
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(path.parent, 0, int(config["service_gid"]))
    if path.exists():
        if not stat.S_ISSOCK(path.lstat().st_mode):
            raise SystemExit("Refusing to replace a non-socket agent path")
        # systemd guarantees one agent. Never remove the socket of a live instance.
        with socket.socket(socket.AF_UNIX) as probe:
            if probe.connect_ex(str(path)) == 0:
                raise SystemExit("An agent is already running")
        path.unlink()
    agent = Agent(config)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(10)
            if not peer_allowed(self.connection, allowed_uid):
                self.wfile.write(b'{"ok":false,"error":"Peer not authorized"}\n'); return
            try:
                raw = self.rfile.readline(65537)
                if len(raw) > 65536 or not raw.endswith(b"\n"):
                    raise Invalid("Invalid agent message size")
                request = json.loads(raw)
                if set(request) != {"operation", "payload"} or not isinstance(request["operation"], str):
                    raise Invalid("Invalid agent request")
                operation = request["operation"]
                self.connection.settimeout(7300)
                result = agent.dispatch(operation, request["payload"])
                response = {"ok": True, "result": result}
                if operation not in {"inventory", "logs", "stats", "media", "images", "templates", "networks", "storage", "registries", "images.search"}:
                    logging.info("Host operation succeeded: %s", operation)
            except Exception as error:
                # No payload, registry token, command input or traceback is emitted.
                response = {"ok": False, "error": str(error)[:1200]}
            self.wfile.write(json.dumps(response).encode() + b"\n")

    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True
        request_queue_size = 32
        slots = threading.BoundedSemaphore(16)

        def process_request(self, request, address):
            if not self.slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, address)
            except BaseException:
                self.slots.release()
                raise

        def process_request_thread(self, request, address):
            try:
                super().process_request_thread(request, address)
            finally:
                self.slots.release()

    server = Server(str(path), Handler)
    os.chmod(path, 0o660); os.chown(path, 0, int(config["service_gid"]))

    def expire_tokens():
        while True:
            with agent.console_lock:
                agent.write_console_tokens()
            time.sleep(15)
    threading.Thread(target=expire_tokens, daemon=True).start()
    try:
        server.serve_forever()
    finally:
        server.server_close(); path.unlink(missing_ok=True)
