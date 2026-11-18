"""Runtime adapters. No shell interpolation and no access through the HTTP API."""
import base64
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import secrets
import struct
import subprocess
import tempfile
import time
from urllib.parse import urlencode
import xml.etree.ElementTree as ET

LABEL = "io.hypertalco.managed"
NS = "urn:hypertalco"


def registry_for(image):
    first, slash, _ = image.partition("/")
    return first if slash and ("." in first or ":" in first or first == "localhost") else "docker.io"


class RuntimeError_(RuntimeError):
    pass


def reset_uploaded_identity(rootfs, uid, gid):
    """Replace cloned identity using directory FDs without following guest links."""
    root = os.open(rootfs, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    identity = (secrets.token_hex(16) + '\n').encode()

    def open_path(parts):
        fd = os.dup(root)
        try:
            for part in parts:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = nxt
            return fd
        except BaseException:
            os.close(fd)
            raise

    def replace_id(directory):
        try:
            os.unlink('machine-id', dir_fd=directory)
        except FileNotFoundError:
            pass
        fd = os.open('machine-id', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444, dir_fd=directory)
        try:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o444)
            os.write(fd, identity)
            os.fsync(fd)
        finally:
            os.close(fd)

    try:
        etc = open_path(['etc'])
        try:
            replace_id(etc)
            try:
                ssh = os.open('ssh', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=etc)
            except FileNotFoundError:
                ssh = None
            if ssh is not None:
                try:
                    for entry in os.listdir(ssh):
                        if entry.startswith('ssh_host_') and (entry.endswith('_key') or entry.endswith('_key.pub')):
                            os.unlink(entry, dir_fd=ssh)
                finally:
                    os.close(ssh)
        finally:
            os.close(etc)
        try:
            dbus = open_path(['var', 'lib', 'dbus'])
        except FileNotFoundError:
            dbus = None
        if dbus is not None:
            try:
                replace_id(dbus)
            finally:
                os.close(dbus)
    finally:
        os.close(root)


class Runner:
    def succeeds(self, argv):
        try:
            self.run(argv, timeout=15)
            return True
        except (RuntimeError_, OSError):
            return False

    def run(self, argv, timeout=120, input=None, check=True, env=None):
        binary = shutil.which(argv[0], path="/usr/sbin:/usr/bin:/sbin:/bin")
        if not binary:
            raise RuntimeError_(f"Required executable not installed: {argv[0]}")
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as source:
            if input is not None:
                source.write(input.encode() if isinstance(input, str) else input)
                source.seek(0)
            proc = subprocess.Popen([binary, *map(str, argv[1:])], stdin=source, stdout=output,
                                    stderr=subprocess.STDOUT, start_new_session=True,
                                    env={**os.environ, **(env or {}), "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
            deadline = time.monotonic() + timeout
            try:
                while proc.poll() is None:
                    if time.monotonic() > deadline or os.fstat(output.fileno()).st_size > 2 * 1024 * 1024:
                        raise RuntimeError_(f"{argv[0]} exceeded its time/output limit")
                    time.sleep(0.05)
                output.seek(0)
                text = output.read(2 * 1024 * 1024).decode("utf-8", "replace")
                if check and proc.returncode:
                    # Commands never contain passwords; input and full argv are not logged.
                    raise RuntimeError_(f"{argv[0]} failed: {text[-1200:].strip()}")
                return text
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGTERM)
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait()


class DockerConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Docker:
    def __init__(self, socket_path="/var/run/docker.sock"):
        self.socket_path = socket_path
        self.api_version = None

    def request(self, method, path, body=None, timeout=30, headers=None, stream=False):
        if path.startswith("/v1.41/"):
            if self.api_version is None:
                version = self.request("GET", "/version")
                import re
                api = version.get("ApiVersion", "")
                if not re.fullmatch(r"1\.\d{2,3}", api) or tuple(map(int, api.split("."))) < (1, 41):
                    raise RuntimeError_("Docker Engine API 1.41 or newer is required")
                self.api_version = api
            path = "/v" + self.api_version + path[len("/v1.41"):]
        conn = DockerConnection(self.socket_path, timeout)
        try:
            conn.request(method, path, json.dumps(body).encode() if body is not None else None,
                         {"Content-Type": "application/json", **(headers or {})})
            response = conn.getresponse()
            if stream:
                error = None
                total = 0
                while True:
                    line = response.readline(65537)
                    if not line:
                        break
                    total += len(line)
                    if len(line) > 65536 or total > 16 * 1024 * 1024:
                        raise RuntimeError_("Docker response exceeded its limit")
                    try:
                        event = json.loads(line)
                        if event.get("error"):
                            error = event["error"][:1000]
                    except ValueError:
                        pass
                if response.status >= 400 or error:
                    raise RuntimeError_(error or f"Docker returned HTTP {response.status}")
                return {"pulled": True}
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise RuntimeError_("Docker response exceeded its limit")
            if response.status >= 400:
                try:
                    detail = json.loads(raw).get("message", "Docker operation failed")
                except ValueError:
                    detail = "Docker operation failed"
                raise RuntimeError_(str(detail)[:1000])
            if response.getheader("Content-Type", "").startswith("application/json") and raw:
                return json.loads(raw)
            return raw
        finally:
            conn.close()

    def inventory(self):
        return self.request("GET", "/v1.41/containers/json?all=1")

    def inspect(self, identifier):
        return self.request("GET", f"/v1.41/containers/{identifier}/json")

    def pull(self, image, auth=None):
        # Docker's API pulls every tag if none is supplied, unlike `docker pull`.
        if "@" not in image and ":" not in image.rsplit("/", 1)[-1]:
            image += ":latest"
        headers = {}
        if auth:
            headers["X-Registry-Auth"] = base64.urlsafe_b64encode(json.dumps(auth).encode()).decode()
        return self.request("POST", "/v1.41/images/create?" + urlencode({"fromImage": image}),
                            timeout=1800, headers=headers, stream=True)

    def create(self, spec, identifier, auth=None):
        # Cached images work offline. Explicit pull in the image library refreshes tags.
        reference = spec["image"]
        if "@" not in reference and ":" not in reference.rsplit("/", 1)[-1]:
            reference += ":latest"
        images = self.request("GET", "/v1.41/images/json?" + urlencode({"filters": json.dumps({"reference": [reference]})}))
        if not images:
            self.pull(spec["image"], auth)
        bindings = {}
        for p in spec["ports"]:
            bindings.setdefault(f"{p['container']}/{p['protocol']}", []).append({"HostIp": p["bind"], "HostPort": str(p["host"])})
        host = {"Memory": spec["memory_mib"] * 1024 * 1024,
                "MemorySwap": spec["memory_mib"] * 1024 * 1024,
                "NanoCpus": spec["cpus"] * 10**9, "PidsLimit": 512,
                "SecurityOpt": ["no-new-privileges:true"], "CapDrop": ["NET_RAW"],
                "NetworkMode": spec["network"], "PortBindings": bindings,
                "RestartPolicy": {"Name": "unless-stopped" if spec["autostart"] else "no"}}
        if spec["volume_path"]:
            host["Mounts"] = [{"Type": "volume", "Source": "ht-" + identifier,
                               "Target": spec["volume_path"]}]
        body = {"Image": spec["image"], "Hostname": spec["name"], "HostConfig": host,
                "Env": [f"{k}={v}" for k, v in spec["env"].items()],
                "ExposedPorts": {p: {} for p in bindings},
                "Labels": {LABEL: "true", "io.hypertalco.id": identifier, "io.hypertalco.name": spec["name"]}}
        return self.request("POST", "/v1.41/containers/create?" + urlencode({"name": "ht-" + spec["name"]}), body)["Id"]

    def action(self, identifier, action):
        if action == "delete":
            return self.request("DELETE", f"/v1.41/containers/{identifier}")
        endpoint = {"start": "start", "stop": "stop?t=30", "restart": "restart?t=30"}[action]
        return self.request("POST", f"/v1.41/containers/{identifier}/{endpoint}", timeout=90)

    def resize(self, identifier, spec):
        return self.request("POST", f"/v1.41/containers/{identifier}/update",
                            {"Memory": spec["memory_mib"] * 2**20,
                             "MemorySwap": spec["memory_mib"] * 2**20, "NanoCpus": spec["cpus"] * 10**9})

    def logs(self, identifier):
        raw = self.request("GET", f"/v1.41/containers/{identifier}/logs?stdout=1&stderr=1&tail=200&timestamps=1")
        out = bytearray()
        while len(raw) >= 8 and raw[0] in (0, 1, 2) and raw[1:4] == b"\x00\x00\x00":
            length = struct.unpack(">I", raw[4:8])[0]
            if length > len(raw) - 8:
                break
            out.extend(raw[8:8 + length])
            raw = raw[8 + length:]
        return (bytes(out) + raw)[-65536:].decode("utf-8", "replace")


class Libvirt:
    def __init__(self, runner):
        self.runner = runner

    def virsh(self, *args, **kwargs):
        return self.runner.run(["virsh", "--connect", "qemu:///system", *args], **kwargs)

    def domains(self):
        out = []
        for identifier in self.virsh("list", "--all", "--uuid").split():
            xml = ET.fromstring(self.virsh("dumpxml", identifier))
            state = self.virsh("domstate", identifier).strip()
            addresses = self.virsh("domifaddr", identifier, "--source", "lease", check=False)
            import re
            ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d+", addresses)
            graphics = xml.find("./devices/graphics")
            out.append({"physical": identifier, "name": xml.findtext("name"),
                        "status": "running" if state == "running" else ("stopped" if state == "shut off" else state),
                        "cpus": int(xml.findtext("vcpu", "0")),
                        "memory_mib": int(xml.findtext("memory", "0")) // 1024,
                        "ips": [x.split("/")[0] for x in ips], "xml": xml,
                        "console": graphics is not None and graphics.get("type") == "vnc"})
        return out

    def create(self, spec, identifier, disk_dir, iso, network):
        folder = disk_dir / identifier
        folder.mkdir(mode=0o755)
        # The agent's restrictive umask otherwise makes this directory 0700,
        # preventing libvirt's unprivileged QEMU from traversing to the disk.
        folder.chmod(0o711)
        disk = folder / "disk.qcow2"
        self.runner.run(["qemu-img", "create", "-f", "qcow2", str(disk), f"{spec['disk_gib']}G"])
        argv = ["virt-install", "--connect", "qemu:///system", "--name", "ht-" + spec["name"],
                "--uuid", identifier, "--virt-type", "kvm", "--memory", str(spec["memory_mib"]),
                "--vcpus", str(spec["cpus"]), "--cpu", "host-passthrough",
                "--disk", f"path={disk},format=qcow2,bus=virtio", "--cdrom", str(iso),
                "--install", "no_install=yes",
                "--network", f"network={network},model=virtio", "--graphics", "vnc,listen=127.0.0.1",
                "--console", "pty,target_type=serial", "--osinfo", "detect=on,require=off",
                "--boot", "uefi,hd,cdrom,menu=on" if spec["firmware"] == "uefi" else "hd,cdrom,menu=on",
                "--noautoconsole", "--wait", "0"]
        if spec["autostart"]:
            argv.append("--autostart")
        cache = Path('/var/lib/hypertalco-agent/cache')
        cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.runner.run(argv, timeout=300, env={'XDG_CACHE_HOME': str(cache)})
        return identifier

    def action(self, physical, action):
        return self.virsh({"start": "start", "stop": "shutdown", "restart": "reboot", "delete": "undefine", "force-stop": "destroy"}[action], physical,
                          *( ["--nvram"] if action == "delete" else []))

    def resize(self, physical, spec):
        xml = ET.fromstring(self.virsh("dumpxml", physical, "--inactive"))
        for tag in ("memory", "currentMemory"):
            node = xml.find(tag)
            if node is None:
                node = ET.SubElement(xml, tag)
            node.set("unit", "KiB")
            node.text = str(spec["memory_mib"] * 1024)
        xml.find("vcpu").text = str(spec["cpus"])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml") as f:
            f.write(ET.tostring(xml, encoding="unicode")); f.flush()
            self.virsh("define", f.name)


class LXC:
    def __init__(self, runner, folder, idmap_base, template_cache="/var/cache/lxc"):
        self.runner, self.folder, self.idmap_base = runner, Path(folder), idmap_base
        self.template_cache = str(template_cache)

    def command(self, binary, name, *args, **kwargs):
        return self.runner.run([binary, "-P", str(self.folder), "-n", name, *args], **kwargs)

    def inventory_at(self, folder):
        names = self.runner.run(["lxc-ls", "-P", str(folder), "-1"], check=False).splitlines()
        out = []
        import re
        for name in names[:200]:
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
                continue
            raw = self.runner.run(["lxc-info", "-P", str(folder), "-n", name, "-sH"], check=False).strip()
            ips = self.runner.run(["lxc-info", "-P", str(folder), "-n", name, "-iH"], check=False).split()
            out.append({"physical": name, "name": name, "status": raw.lower() if raw else "unknown", "ips": ips})
        return out

    def create(self, spec, identifier, bridge, log_dir, archive=None):
        name = "ht-" + spec["name"]
        self.folder.mkdir(parents=True, exist_ok=True, mode=0o755)
        if (self.folder / name).exists():
            raise RuntimeError_("An LXC with that physical name already exists")
        if archive is None:
            dist, release, arch, variant = spec["image"].split("/")
        # lxc-download runs as mapped container root, not host root. Keep its
        # writable cache in a dedicated directory rather than chowning the
        # configured cache root or granting all users write access.
        cache = Path(self.template_cache) / ("hypertalco-idmap-" + str(self.idmap_base))
        if cache.is_symlink():
            raise RuntimeError_("LXC cache directory must not be a symlink")
        if not cache.exists():
            cache.mkdir(mode=0o700)
            os.chown(cache, self.idmap_base, self.idmap_base)
        stat = cache.stat()
        if stat.st_uid != self.idmap_base or stat.st_gid != self.idmap_base or stat.st_mode & 0o077:
            raise RuntimeError_("LXC cache directory has unexpected ownership or permissions")
        config = ("lxc.include = /usr/share/lxc/config/common.conf\n"
                  "lxc.include = /usr/share/lxc/config/userns.conf\n"
                  f"lxc.idmap = u 0 {self.idmap_base} 65536\n"
                  f"lxc.idmap = g 0 {self.idmap_base} 65536\n"
                  "lxc.apparmor.profile = generated\n"
                  "lxc.net.0.type = veth\nlxc.net.0.flags = up\n"
                  f"lxc.net.0.link = {bridge}\nlxc.net.0.name = eth0\n"
                  f"lxc.uts.name = {spec['name']}\n"
                  f"lxc.cgroup2.memory.max = {spec['memory_mib'] * 2**20}\n"
                  f"lxc.cgroup2.cpu.max = {spec['cpus'] * 100000} 100000\n"
                  f"lxc.start.auto = {1 if spec['autostart'] else 0}\n")
        with tempfile.NamedTemporaryFile(mode="w") as f:
            f.write(config); f.flush()
            if archive is None:
                self.command("lxc-create", name, "-f", f.name, "-t", "download", "--", "--dist", dist,
                             "--release", release, "--arch", arch, "--variant", variant, timeout=1800,
                             env={"LXC_CACHE_PATH": str(cache)})
            else:
                self.command('lxc-create', name, '-f', f.name, '-t', 'none', timeout=120)
                container_dir = self.folder / name
                rootfs = container_dir / 'rootfs'
                if container_dir.is_symlink() or rootfs.is_symlink() or rootfs.exists():
                    raise RuntimeError_('Unexpected LXC rootfs path')
                container_dir.chmod(0o755)
                rootfs.mkdir(mode=0o755)
                os.chown(rootfs, self.idmap_base, self.idmap_base)
                with (container_dir / 'config').open('a') as config_file:
                    config_file.write(f'\nlxc.rootfs.path = dir:{rootfs}\n')
                self.runner.run(['lxc-usernsexec', '-m', f'u:0:{self.idmap_base}:65536',
                                 '-m', f'g:0:{self.idmap_base}:65536', '--', 'tar',
                                 '--extract', '--file', str(archive), '--directory', str(rootfs),
                                 '--numeric-owner', '--same-owner', '--preserve-permissions'], timeout=1800)
                reset_uploaded_identity(rootfs, self.idmap_base, self.idmap_base)
        created = (self.folder / name / "config").read_text()
        if f"lxc.idmap = u 0 {self.idmap_base} 65536" not in created:
            raise RuntimeError_("Template did not retain the unprivileged UID mapping")
        self.command("lxc-start", name, "-o", str(log_dir / (identifier + ".log")), "-l", "WARN")
        self.command("lxc-wait", name, "-s", "RUNNING", "-t", "60", timeout=65)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            state = self.command('lxc-attach', name, '--clear-env', '--', '/bin/systemctl',
                                 'is-system-running', check=False, timeout=10).strip()
            if state in {'starting', 'running', 'degraded'}:
                break
            time.sleep(1)
        else:
            raise RuntimeError_('Container systemd did not become ready within 120 seconds')
        if archive is not None:
            # Proxmox rootfs images often ship loopback-only networking and rely
            # on the manager to configure DHCP. The fixed script runs inside the
            # unprivileged guest; it never interpolates user input.
            network_setup = ("if ip -4 addr show dev eth0 | grep -q 'inet '; then exit 0; fi; "
                             "if command -v ifup >/dev/null && [ -f /etc/network/interfaces ]; then "
                             "grep -q 'iface eth0 ' /etc/network/interfaces || "
                             "printf '\\nauto eth0\\niface eth0 inet dhcp\\n' >> /etc/network/interfaces; "
                             "ifup eth0 || { n=0; while [ $n -lt 30 ]; do "
                             "ip -4 addr show dev eth0 | grep -q 'inet ' && exit 0; "
                             "n=$((n+1)); sleep 1; done; exit 1; }; "
                             "elif command -v networkctl >/dev/null; then "
                             "mkdir -p /etc/systemd/network; "
                             "printf '[Match]\\nName=eth0\\n[Network]\\nDHCP=yes\\n' > /etc/systemd/network/10-hypertalco.network; "
                             "systemctl enable --now systemd-networkd; "
                             "else echo 'No supported DHCP client in uploaded template' >&2; exit 1; fi")
            self.command('lxc-attach', name, '--clear-env', '--', '/bin/sh', '-c', network_setup, timeout=120)
        self.command("lxc-attach", name, "--clear-env", "--", "/usr/bin/apt-get", "update", timeout=600)
        self.command("lxc-attach", name, "--clear-env", "--", "/usr/bin/apt-get", "install", "-y", "openssh-server", "sudo", "python3", timeout=1200)
        if archive is not None:
            self.command('lxc-attach', name, '--clear-env', '--', '/usr/bin/ssh-keygen', '-A', timeout=120)
        self.command("lxc-attach", name, "--clear-env", "--", "/usr/sbin/useradd", "-m", "-s", "/bin/bash", "-G", "sudo", "talco")
        # Fixed program runs inside the unprivileged container, never in a host shell.
        program = ("import os,pwd,pathlib,json,sys; u=pwd.getpwnam('talco'); "
                   "p=pathlib.Path('/home/talco/.ssh'); p.mkdir(mode=0o700,exist_ok=True); "
                   "f=p/'authorized_keys'; f.write_text('\\n'.join(json.load(sys.stdin))+'\\n'); "
                   "os.chown(p,u.pw_uid,u.pw_gid); os.chown(f,u.pw_uid,u.pw_gid); f.chmod(0o600); "
                   "s=pathlib.Path('/etc/sudoers.d/90-talco'); s.write_text('talco ALL=(ALL) NOPASSWD:ALL\\n'); s.chmod(0o440)")
        self.command("lxc-attach", name, "--clear-env", "--", "/usr/bin/python3", "-c", program,
                     input=json.dumps(spec["ssh_keys"]))
        self.command("lxc-attach", name, "--clear-env", "--", "/bin/systemctl", "enable", "--now", "ssh")
        return name

    def action(self, physical, action):
        binary, extra = {"start": ("lxc-start", []), "stop": ("lxc-stop", ["-t", "30"]),
                         "restart": ("lxc-stop", ["-r", "-t", "30"]), "delete": ("lxc-destroy", [])}[action]
        return self.command(binary, physical, *extra, timeout=90)

    def resize(self, physical, spec):
        path = self.folder / physical / "config"
        lines = [line for line in path.read_text().splitlines()
                 if not line.lstrip().startswith(("lxc.cgroup2.memory.max", "lxc.cgroup2.cpu.max"))]
        lines += [f"lxc.cgroup2.memory.max = {spec['memory_mib'] * 2**20}",
                  f"lxc.cgroup2.cpu.max = {spec['cpus'] * 100000} 100000"]
        path.write_text("\n".join(lines) + "\n")
