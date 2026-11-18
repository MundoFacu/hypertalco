#!/usr/bin/env python3
"""Installer support. `check` is read-only; `install` is explicitly root-only."""
import argparse
import datetime
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from hypertalco.validation import network
from hypertalco.engines import Docker, LABEL, NS

UNITS = ["hypertalco-agent", "hypertalco-web", "hypertalco-worker", "hypertalco-console", "hypertalco-network", "hypertalco-lxc"]
APPLICATION = ["hypertalco-web", "hypertalco-worker", "hypertalco-console", "hypertalco-agent"]


def run(args, **kw):
    return subprocess.run(args, check=True, text=True, **kw)


def output(args):
    return subprocess.check_output(args, text=True).strip()


def os_release(path=Path("/etc/os-release")):
    return {k: v.strip('"') for k, v in (line.split("=", 1) for line in path.read_text().splitlines() if "=" in line and not line.startswith("#"))}


def add_settings_arguments(parser):
    parser.add_argument("--network-mode", choices=["nat", "isolated", "bridge"], default="nat")
    parser.add_argument("--bridge", default="")
    parser.add_argument("--docker-mode", choices=["nat", "isolated"], default="nat")
    parser.add_argument("--guests-dir", default="/var/lib/hypertalco-guests")
    parser.add_argument("--iso-dir", default="/var/lib/libvirt/images/hypertalco/iso")
    parser.add_argument("--template-cache", default="/var/cache/lxc")
    parser.add_argument("--docker-dir", default="/var/lib/docker")
    parser.add_argument("--docker-existing", action="store_true")


def validate_settings(args):
    ipaddress.IPv4Address(args.bind)
    guest, docker = network(args.guest_subnet), network(args.docker_subnet)
    if args.network_mode != "bridge" and guest.overlaps(docker):
        raise ValueError("Guest and Docker subnets overlap")
    if args.network_mode not in {"nat", "isolated", "bridge"} or args.docker_mode not in {"nat", "isolated"}:
        raise ValueError("Invalid network mode")
    if args.network_mode == "bridge":
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", args.bridge):
            raise ValueError("Select an existing bridge")
        links = json.loads(output(["ip", "-j", "-d", "link", "show"]))
        if not any(x.get("ifname") == args.bridge and x.get("linkinfo", {}).get("info_kind") == "bridge" for x in links):
            raise ValueError("The selected interface is not an existing bridge; host addressing is never moved automatically")
    if not 1024 <= args.port <= 65535 or args.port in {6080, 8765}:
        raise ValueError("Choose an HTTPS port from 1024 to 65535, excluding internal ports 6080/8765")
    paths = [Path(getattr(args, name)) for name in ("guests_dir", "iso_dir", "template_cache", "docker_dir")]
    reserved = [Path(x) for x in ["/etc", "/usr", "/proc", "/sys", "/dev", "/run", "/tmp", "/home", "/root", "/var/lib/hypertalco", "/var/lib/hypertalco-agent", "/opt/hypertalco"]]
    for path in paths:
        if not path.is_absolute() or len(path.parts) < 3 or ".." in path.parts or not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)):
            raise ValueError("Storage paths must be absolute, without spaces, parent traversal or shell characters")
        if any(path == x or path.is_relative_to(x) for x in reserved):
            raise ValueError(f"Reserved storage location: {path}")
        for ancestor in [*reversed(path.parents), path]:
            if ancestor.is_symlink():
                raise ValueError(f"Storage path contains a symlink: {ancestor}")
            if ancestor.exists() and (not ancestor.is_dir() or ancestor.stat().st_uid != 0 or ancestor.stat().st_mode & 0o022):
                raise ValueError(f"Storage ancestor must be a root-owned directory without group/other write access: {ancestor}")
    for i, path in enumerate(paths):
        if any(path == other or path.is_relative_to(other) or other.is_relative_to(path) for other in paths[i + 1:]):
            raise ValueError("Guest, ISO, template-cache and Docker locations must not overlap")
    receipt = Path("/etc/hypertalco/install.json")
    if args.upgrade and receipt.exists():
        old = json.loads(receipt.read_text())
        for field in ("guests_dir", "iso_dir", "template_cache", "docker_dir", "network_mode", "bridge", "docker_mode", "guest_subnet", "docker_subnet"):
            if field in old and old[field] != getattr(args, field):
                raise ValueError(f"Upgrade cannot change {field}; storage/network migration is a separate operation")
    if args.docker_existing:
        daemon_path = Path("/etc/docker/daemon.json")
        daemon = json.loads(daemon_path.read_text()) if daemon_path.exists() else {}
        if daemon.get("data-root", "/var/lib/docker") != args.docker_dir:
            raise ValueError("Existing Docker storage must stay at its current data-root")


def probe_kvm():
    try:
        with open('/dev/kvm', 'rb', buffering=0) as device:
            if fcntl.ioctl(device.fileno(), 0xAE00, 0) != 12:
                raise RuntimeError('KVM API version is unsupported')
            return True
    except PermissionError:
        if os.geteuid() == 0:
            raise RuntimeError('Cannot access /dev/kvm as root') from None
        return False
    except OSError as error:
        raise RuntimeError(f'KVM API probe failed: {error}') from error


def preflight(args):
    osinfo = os_release()
    supported = (osinfo.get("ID") == "debian" and osinfo.get("VERSION_ID", "").split(".")[0] in {"12", "13"}) or (osinfo.get("ID") == "ubuntu" and osinfo.get("VERSION_ID") in {"22.04", "24.04", "26.04"})
    if not supported:
        raise RuntimeError("Supported targets: Debian 12/13 or Ubuntu 22.04/24.04/26.04")
    if platform.machine() not in {"x86_64", "aarch64"}:
        raise RuntimeError("Supported architectures: x86_64 and aarch64")
    for tool in ('apt-get', 'ip', 'systemctl', 'systemd-detect-virt'):
        if not shutil.which(tool):
            raise RuntimeError(f'Required host command missing: {tool}')
    if not Path("/run/systemd/system").is_dir():
        raise RuntimeError("A booted systemd host is required")
    if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
        raise RuntimeError("A cgroup v2 host is required")
    if not Path("/dev/kvm").exists():
        raise RuntimeError("/dev/kvm is missing. Enable AMD-V/Intel VT-x; containers are not a bare-metal target")
    kvm_checked = probe_kvm()
    detected = subprocess.run(["systemd-detect-virt", "--container", "--quiet"], capture_output=True)
    if detected.returncode == 0:
        raise RuntimeError("Install on a host, not inside a container")
    validate_settings(args)
    ipaddress.IPv4Address(args.bind)
    guest, docker = network(args.guest_subnet), network(args.docker_subnet)
    if guest.overlaps(docker):
        raise RuntimeError("Guest and Docker subnets overlap")
    if shutil.disk_usage("/var/lib").free < 10 * 1024**3:
        raise RuntimeError("At least 10 GiB free in /var/lib is required")
    if not args.upgrade:
        routes = json.loads(output(["ip", "-j", "route", "show"]))
        for row in routes:
            if row.get("dst") in {None, "default"}:
                continue
            existing = ipaddress.ip_network(row["dst"], strict=False)
            if existing.version == 4 and ((args.network_mode != "bridge" and guest.overlaps(existing)) or docker.overlaps(existing)):
                raise RuntimeError(f"A selected subnet overlaps host route {existing}; choose different subnets")
        for host, port in [(args.bind, args.port), ("127.0.0.1", 8765), ("127.0.0.1", 6080)]:
            with socket.socket() as probe:
                try:
                    probe.bind((host, port))
                except OSError:
                    raise RuntimeError(f"Required listener {host}:{port} is already in use") from None
    warnings = []
    for setting in ('guests_dir', 'iso_dir', 'template_cache', 'docker_dir'):
        path = Path(getattr(args, setting))
        while not path.exists():
            path = path.parent
        if shutil.disk_usage(path).free < 10 * 1024**3:
            warnings.append(f'{setting} is on {path} with less than 10 GiB free; guest and media storage may fill quickly.')
    if not kvm_checked:
        warnings.append('KVM API could not be probed as this user; root installation will check it.')
    try:
        memory_kib = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:')))
        if memory_kib < 8 * 1024 * 1024:
            warnings.append('Less than 8 GiB RAM detected; 8 GiB is recommended for an initial lab, plus guest needs.')
    except (OSError, StopIteration, ValueError):
        warnings.append('Could not determine total RAM.')
    if (os.cpu_count() or 0) < 4:
        warnings.append('Fewer than 4 logical CPUs detected; 4 are recommended for an initial lab.')
    if not any(row.get('dst') in {None, 'default'} for row in json.loads(output(['ip', '-j', 'route', 'show', 'default']))):
        warnings.append('No IPv4 default route detected; package downloads may fail. Check network or configured mirrors.')
    warnings.append('Network access and package mirror availability are not verified until apt runs.')
    return {"os": osinfo["PRETTY_NAME"], "architecture": platform.machine(), "kvm": kvm_checked,
            "guest_subnet": str(guest), "docker_subnet": str(docker), "listen": f"{args.bind}:{args.port}",
            "warnings": warnings, "status": "preflight_passed", "changes_made": False}


def atomic(path, text, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".hypertalco-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text); f.flush(); os.fsync(f.fileno())
        os.chmod(temp, mode); os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def restore_file(path, text, metadata):
    """Restore the content and access controls of a replaced host file."""
    atomic(path, text, metadata["mode"])
    os.chown(path, metadata["uid"], metadata["gid"])


def copy_release(source, release, files):
    """Create a service-readable release even when the bootstrap uses umask 077."""
    release.mkdir(mode=0o755, parents=True)
    release.chmod(0o755)
    for path in files:
        dest = release / path.relative_to(source)
        dest.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        for parent in (dest.parent, *dest.parent.parents):
            if parent == release:
                break
            parent.chmod(0o755)
        shutil.copyfile(path, dest)
        dest.chmod(0o644)


def mkdir_traversable(path):
    """Create missing managed directories with traversal despite a strict umask."""
    missing = []
    while not path.exists():
        missing.append(path)
        path = path.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)


def idmap_base(uid_text, gid_text):
    def entries(text):
        out = []
        for line in text.splitlines():
            if line and not line.startswith("#"):
                user, start, count = line.split(":")
                out.append((user, int(start), int(count)))
        return out
    uid, gid = entries(uid_text), entries(gid_text)
    for user, start, count in uid:
        if user == "root" and count >= 65536 and any(u == "root" and s == start and c >= 65536 for u, s, c in gid):
            return start, False
    start = 20000000
    while any(start < s + c and s < start + 65536 for _, s, c in uid + gid):
        start += 65536
    return start, True


def network_xml(subnet, mode="nat", bridge=""):
    net = network(subnet)
    xml = ET.Element("network")
    ET.SubElement(xml, "name").text = "hypertalco"
    ET.SubElement(ET.SubElement(xml, "metadata"), f"{{{NS}}}managed").text = "true"
    if mode == "bridge":
        ET.SubElement(xml, "forward", mode="bridge")
        ET.SubElement(xml, "bridge", name=bridge)
        return ET.tostring(xml, encoding="unicode")
    if mode == "nat":
        ET.SubElement(xml, "forward", mode="nat")
    ET.SubElement(xml, "bridge", name="virbr-ht", stp="on", delay="0")
    ip = ET.SubElement(xml, "ip", address=str(net[1]), netmask=str(net.netmask))
    ET.SubElement(ET.SubElement(ip, "dhcp"), "range", start=str(net[10]), end=str(net[250]))
    return ET.tostring(xml, encoding="unicode")


def nginx_config(bind, port):
    ipaddress.IPv4Address(bind)
    if not 1024 <= port <= 65535:
        raise ValueError("Invalid HTTPS port")
    return f"""# Hypertalco managed virtual host
server {{
    listen {bind}:{port} ssl;
    server_name _;
    ssl_certificate /etc/hypertalco/tls/cert.pem;
    ssl_certificate_key /etc/hypertalco/tls/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 64k;
    location = /api/media/upload {{
        client_max_body_size 32g;
        proxy_request_buffering off;
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}
    location = /api/templates/upload {{
        client_max_body_size 32g;
        proxy_request_buffering off;
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}
    location /websockify {{
        proxy_pass http://127.0.0.1:6080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_set_header Origin $http_origin;
        proxy_read_timeout 3600s;
        access_log off;
    }}
    location / {{
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 90s;
    }}
}}
"""


def install(args):
    if os.geteuid() != 0:
        raise RuntimeError("Installation requires root")
    preflight(args)
    source = Path(args.source).resolve()
    version = (source / "VERSION").read_text().strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise RuntimeError("Invalid source version")
    config_dir = Path("/etc/hypertalco")
    current = Path("/opt/hypertalco/current")
    if config_dir.exists() and not args.upgrade:
        raise RuntimeError("Existing configuration requires --upgrade")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    backup = Path("/var/backups/hypertalco") / stamp
    backup.mkdir(mode=0o700, parents=True)
    if config_dir.exists():
        shutil.copytree(config_dir, backup / "config")
    targets = [Path("/etc/nginx/sites-available/hypertalco"), Path("/etc/subuid"), Path("/etc/subgid"), Path("/etc/sysctl.d/90-hypertalco.conf"), Path("/etc/docker/daemon.json")]
    targets += [Path("/etc/systemd/system") / (unit + ".service") for unit in UNITS]
    previous = {}
    previous_metadata = {}
    for path in targets:
        previous[str(path)] = path.read_text() if path.is_file() else None
        if path.is_file():
            info = path.stat()
            previous_metadata[str(path)] = {"mode": info.st_mode & 0o7777, "uid": info.st_uid, "gid": info.st_gid}
    atomic(backup / "files.json", json.dumps(previous), 0o600)
    atomic(backup / "metadata.json", json.dumps(previous_metadata), 0o600)
    old_current = str(current.resolve()) if current.exists() else None
    atomic(backup / "receipt.json", json.dumps({"old_current": old_current, "version": version}), 0o600)
    if args.upgrade:
        run(["systemctl", "stop", *[x + ".service" for x in APPLICATION]])
        database = Path("/var/lib/hypertalco/hypertalco.sqlite3")
        if database.exists():
            with sqlite3.connect(database) as src, sqlite3.connect(backup / "hypertalco.sqlite3") as dst:
                src.backup(dst)
    try:
        try:
            user = pwd.getpwnam("hypertalco")
            if not args.upgrade:
                raise RuntimeError("The hypertalco account already exists outside an installation")
            if user.pw_uid == 0 or user.pw_dir != "/var/lib/hypertalco" or not user.pw_shell.endswith("/nologin"):
                raise RuntimeError("The existing hypertalco identity is not the expected nologin service account")
            membership = set(os.getgrouplist("hypertalco", user.pw_gid))
            if any(g.gr_gid in membership and g.gr_name in {"sudo", "wheel", "docker", "libvirt"} for g in grp.getgrall()):
                raise RuntimeError("The hypertalco service account must not have privileged group membership")
        except KeyError:
            run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/var/lib/hypertalco", "--shell", "/usr/sbin/nologin", "hypertalco"])
            user = pwd.getpwnam("hypertalco")
        gid = grp.getgrnam("hypertalco").gr_gid
        whitelist = ["hypertalco", "scripts", "packaging", "docs", "README.md", "VERSION", "LICENSE"]
        files = []
        for name in whitelist:
            path = source / name
            files += sorted(p for p in path.rglob("*") if p.is_file() and "__pycache__" not in p.parts) if path.is_dir() else [path]
        digest = hashlib.sha256()
        for path in files:
            if path.is_symlink():
                raise RuntimeError("Source symlinks are not allowed")
            digest.update(str(path.relative_to(source)).encode() + b"\0" + path.read_bytes())
        release = Path("/opt/hypertalco/releases") / (version + "-" + digest.hexdigest()[:12])
        mkdir_traversable(release.parent)
        if not release.exists():
            copy_release(source, release, files)
        if current.is_symlink():
            current.unlink()
        elif current.exists():
            raise RuntimeError("Unexpected non-symlink release pointer")
        current.symlink_to(release)
        config_dir.mkdir(mode=0o750, exist_ok=True)
        config_dir.chmod(0o750); os.chown(config_dir, 0, gid)
        data = Path("/var/lib/hypertalco"); data.mkdir(mode=0o700, exist_ok=True); os.chown(data, user.pw_uid, gid)
        roots = ["/mnt", "/media", "/srv/iso"]
        vm_dir, lxc_dir = Path(args.guests_dir) / "qemu", Path(args.guests_dir) / "lxc"
        for path in [lxc_dir, vm_dir, Path(args.iso_dir), Path(args.template_cache), Path("/srv/iso")]:
            mkdir_traversable(path)
        uid_path, gid_path = Path("/etc/subuid"), Path("/etc/subgid")
        uid_text = uid_path.read_text() if uid_path.exists() else ""
        gid_text = gid_path.read_text() if gid_path.exists() else ""
        base, add = idmap_base(uid_text, gid_text)
        if add:
            atomic(uid_path, uid_text.rstrip() + f"\nroot:{base}:65536\n")
            atomic(gid_path, gid_text.rstrip() + f"\nroot:{base}:65536\n")
        addresses = json.loads(output(["ip", "-j", "address", "show"]))
        ips = [a["local"] for n in addresses for a in n.get("addr_info", []) if a["family"] == "inet"]
        hostname = socket.gethostname()
        hosts = sorted(set([hostname, "localhost", "127.0.0.1", *ips]))
        if not (config_dir / "config.json").exists():
            atomic(config_dir / "config.json", json.dumps({"data_dir": str(data), "agent_socket": "/run/hypertalco-agent/agent.sock", "allowed_hosts": hosts, "demo": False}, indent=2), 0o640)
        if not (config_dir / "agent.json").exists():
            atomic(config_dir / "agent.json", json.dumps({"service_uid": user.pw_uid, "service_gid": gid, "idmap_base": base, "media_roots": roots, "vm_dir": str(vm_dir), "lxc_dir": str(lxc_dir), "iso_dir": args.iso_dir, "template_cache": args.template_cache, "console_tokens": "/run/hypertalco-agent/vnc-tokens"}, indent=2), 0o600)
        os.chown(config_dir / "config.json", 0, gid)
        tls = config_dir / "tls"; tls.mkdir(mode=0o700, exist_ok=True)
        if not (tls / "key.pem").exists():
            sans = "DNS:localhost," + ",".join("IP:" + ip for ip in ips)
            if re.fullmatch(r"[A-Za-z0-9.-]+", hostname):
                sans += ",DNS:" + hostname
            run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "825", "-subj", "/CN=Hypertalco", "-addext", "subjectAltName=" + sans, "-keyout", str(tls / "key.pem"), "-out", str(tls / "cert.pem")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (tls / "key.pem").chmod(0o600)
        download_helper = Path("/usr/share/lxc/templates/lxc-download").read_text()
        if args.template_cache != "/var/cache/lxc" and "LXC_CACHE_PATH:-" not in download_helper:
            raise RuntimeError("Installed LXC download helper does not support a custom cache path")
        daemon_path = Path("/etc/docker/daemon.json")
        daemon = json.loads(daemon_path.read_text()) if daemon_path.exists() else {}
        if daemon.get("data-root", "/var/lib/docker") != args.docker_dir:
            if args.docker_existing:
                raise RuntimeError("Changing an existing Docker data-root requires a separate storage migration")
            daemon["data-root"] = args.docker_dir
            atomic(daemon_path, json.dumps(daemon, indent=2), 0o600)
            run(["systemctl", "restart", "docker.service"])
        libvirt_units = ["libvirtd.service"] if Path("/lib/systemd/system/libvirtd.service").exists() or Path("/usr/lib/systemd/system/libvirtd.service").exists() else ["virtqemud.socket", "virtnetworkd.socket", "virtstoraged.socket"]
        run(["systemctl", "enable", "--now", "docker.service", *libvirt_units])
        chain = subprocess.run(["iptables", "-w", "5", "-S", "DOCKER-USER"], capture_output=True)
        if chain.returncode:
            raise RuntimeError("Docker must use its iptables firewall backend with DOCKER-USER enabled")
        for unit in UNITS:
            text = (release / "packaging" / (unit + ".service")).read_text().replace("libvirtd.service", " ".join(libvirt_units)).replace("@@LXC_DIR@@", str(lxc_dir))
            atomic(Path("/etc/systemd/system") / (unit + ".service"), text)
        atomic(Path("/etc/sysctl.d/90-hypertalco.conf"), "# Hypertalco guest NAT\nnet.ipv4.ip_forward = 1\n")
        run(["sysctl", "-p", "/etc/sysctl.d/90-hypertalco.conf"])
        virsh = ["virsh", "--connect", "qemu:///system"]
        defined = output(virsh + ["net-list", "--all", "--name"]).split()
        if "hypertalco" not in defined:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".xml") as f:
                f.write(network_xml(args.guest_subnet, args.network_mode, args.bridge)); f.flush(); run(virsh + ["net-define", f.name])
        else:
            xml = ET.fromstring(output(virsh + ["net-dumpxml", "hypertalco"]))
            if xml.find(f"./metadata/{{{NS}}}managed") is None:
                raise RuntimeError("A foreign libvirt network already uses the hypertalco name")
        run(virsh + ["net-autostart", "hypertalco"])
        if "hypertalco" not in output(virsh + ["net-list", "--name"]).split():
            run(virsh + ["net-start", "hypertalco"])
        docker = Docker()
        existing = next((n for n in docker.request("GET", "/v1.41/networks") if n["Name"] == "hypertalco"), None)
        if existing and (existing.get("Labels") or {}).get(LABEL) != "true":
            raise RuntimeError("A foreign Docker network already uses the hypertalco name")
        if not existing:
            docker.request("POST", "/v1.41/networks/create", {"Name": "hypertalco", "Driver": "bridge", "Internal": args.docker_mode == "isolated", "Labels": {LABEL: "true"}, "Options": {"com.docker.network.bridge.name": "ht-docker0"}, "IPAM": {"Config": [{"Subnet": args.docker_subnet}]}})
        atomic(Path("/etc/nginx/sites-available/hypertalco"), nginx_config(args.bind, args.port))
        enabled = Path("/etc/nginx/sites-enabled/hypertalco")
        if not enabled.exists():
            enabled.symlink_to("/etc/nginx/sites-available/hypertalco")
        run(["nginx", "-t"])
        run(["systemctl", "daemon-reload"])
        atomic(config_dir / "install.json", json.dumps({"version": version, "release": str(release), "source_sha256": digest.hexdigest(), "backup": str(backup), "port": args.port, "bind": args.bind, "guest_subnet": args.guest_subnet, "docker_subnet": args.docker_subnet, "network_mode": args.network_mode, "bridge": args.bridge, "docker_mode": args.docker_mode, "guests_dir": args.guests_dir, "iso_dir": args.iso_dir, "template_cache": args.template_cache, "docker_dir": args.docker_dir}, indent=2), 0o600)
        print(json.dumps({"status": "configured", "backup": str(backup), "release": str(release)}))
    except BaseException:
        # Roll back configuration/pointer, retain all guest data and installed packages.
        for name, text in previous.items():
            path = Path(name)
            if text is not None:
                restore_file(path, text, previous_metadata[name])
            elif path.exists() and path.is_file():
                path.unlink()
        if current.is_symlink():
            current.unlink()
        if old_current:
            current.symlink_to(old_current)
        run(["systemctl", "daemon-reload"])
        if args.upgrade and old_current:
            subprocess.run(["systemctl", "start", *[x + ".service" for x in APPLICATION]], check=False)
        print(f"Installation failed; configuration backup: {backup}. Packages, networks and guest data were retained.", file=sys.stderr)
        raise


def main():
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["check", "install"])
    p.add_argument("--source", default=str(ROOT))
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--guest-subnet", default="10.77.0.0/24")
    p.add_argument("--docker-subnet", default="10.78.0.0/24")
    p.add_argument("--upgrade", action="store_true")
    add_settings_arguments(p)
    args = p.parse_args()
    if args.command == "check":
        print(json.dumps(preflight(args), indent=2))
    else:
        install(args)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
