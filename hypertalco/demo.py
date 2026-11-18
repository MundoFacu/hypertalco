"""Explicit local preview: never imports or calls a real runtime adapter."""
import copy
import threading
import time
import uuid
from .validation import create


class DemoAgent:
    def __init__(self):
        self.lock = threading.RLock()
        self.uploaded_templates = []
        self.resources = [
            {"id": "10000000-0000-4000-8000-000000000001", "name": "edge-proxy", "engine": "docker", "status": "running", "image": "nginx:alpine", "cpus": 1, "memory_mib": 256, "network": "hypertalco", "ips": ["10.78.0.10"], "managed": True},
            {"id": "10000000-0000-4000-8000-000000000002", "name": "debian-lab", "engine": "lxc", "status": "running", "image": "debian/trixie/amd64/default", "cpus": 2, "memory_mib": 2048, "network": "hypertalco", "ips": ["10.77.0.20"], "managed": True},
            {"id": "10000000-0000-4000-8000-000000000003", "name": "build-machine", "engine": "qemu", "status": "stopped", "image": "Debian installer", "cpus": 4, "memory_mib": 4096, "disk_gib": 40, "network": "hypertalco", "ips": [], "managed": True},
        ]
        self.media = [{"id": "20000000-0000-4000-8000-000000000001", "name": "debian-13-netinst.iso", "source": "/mnt/iso/debian-13-netinst.iso", "kind": "path", "size": 720 * 2**20, "sha256": "preview—no file imported", "available": True, "created": time.time()}]
        self.networks = [{"name": "hypertalco", "id": "libvirt:hypertalco", "engine": "libvirt", "mode": "nat", "cidr": "10.77.0.0/24", "bridge": "virbr-ht", "active": True, "managed": True}, {"name": "hypertalco", "id": "docker:preview", "engine": "docker", "mode": "nat", "cidr": "10.78.0.0/24", "bridge": "ht-docker0", "active": True, "managed": True}]
        self.registries = []

    def call(self, operation, payload=None, timeout=30):
        with self.lock:
            p = payload or {}
            if operation == "inventory":
                return {"resources": copy.deepcopy(self.resources), "engines": {k: {"available": True, "error": None} for k in ("docker", "lxc", "qemu")}, "kvm": True}
            if operation == "networks":
                return {"networks": copy.deepcopy(self.networks), "errors": {}, "links": [{"ifname": "eno1", "mtu": 1500, "operstate": "UP", "address": "02:00:00:00:00:01", "link_type": "ether"}, {"ifname": "virbr-ht", "mtu": 1500, "operstate": "UP", "linkinfo": {"info_kind": "bridge"}}], "addresses": [{"ifname": "eno1", "addr_info": [{"family": "inet", "local": "192.0.2.10", "prefixlen": 24}]}], "routes": [{"dst": "default", "gateway": "192.0.2.1", "dev": "eno1"}]}
            if operation == "storage":
                return {"devices": {"blockdevices": [{"name": "nvme0n1", "size": 512 * 10**9, "type": "disk", "model": "Preview disk", "children": [{"name": "nvme0n1p1", "size": 512 * 10**9, "type": "part", "fstype": "ext4", "mountpoints": ["/"]}]}]}, "filesystems": {"filesystems": [{"target": "/", "source": "/dev/nvme0n1p1", "fstype": "ext4", "size": 512 * 10**9, "avail": 320 * 10**9, "use%": "38%"}]}, "media_roots": ["/mnt", "/media", "/srv/iso"], "guest_storage": "/var/lib/libvirt/images/hypertalco"}
            if operation == "templates":
                return {"templates": [{"id": "debian/trixie/amd64/default", "name": "Debian trixie", "arch": "amd64", "variant": "default", "build": "preview"}, {"id": "ubuntu/noble/amd64/default", "name": "Ubuntu noble", "arch": "amd64", "variant": "default", "build": "preview"}, *self.uploaded_templates], "source": "Preview catalog"}
            if operation == "media":
                return copy.deepcopy(self.media)
            if operation == "images":
                return [{"id": "sha256:preview", "tags": ["nginx:alpine"], "size": 56 * 2**20, "created": time.time()}]
            if operation == "images.search":
                return [{"name": p.get("term", "nginx"), "description": "Simulated Docker Hub search result", "star_count": 1250, "is_official": True}]
            if operation == "registries":
                return copy.deepcopy(self.registries)
            if operation == "registries.login":
                self.registries = [{"server": p["server"], "username": p["username"]}]; return {"ok": True}
            if operation == "registries.delete":
                self.registries = []; return {"ok": True}
            if operation == "create":
                spec = create({k: v for k, v in p.items() if k != "job_id"})
                record = {k: v for k, v in spec.items() if k not in {"env", "ssh_keys"}}
                record.update(id=str(uuid.uuid4()), status="running", managed=True, ips=[])
                self.resources.append(record); return {"id": record["id"], "name": record["name"]}
            if operation in {"action", "resize", "logs", "stats", "console"}:
                record = next((r for r in self.resources if r["id"] == p.get("id")), None)
                if not record:
                    raise ValueError("Resource not found")
                if operation == "logs":
                    return {"text": "[LOCAL PREVIEW — simulated log]\nGuest initialized. Runtime is healthy.\nNo real host command was executed.\n"}
                if operation == "stats":
                    return {"running": record["status"] == "running", "cpu_percent": 4.2, "memory_bytes": 170 * 2**20, "rx_bytes": 12 * 2**20, "tx_bytes": 4 * 2**20}
                if operation == "console":
                    raise ValueError("The preview does not run a VM or a VNC server")
                if operation == "resize":
                    if record["status"] != "stopped":
                        raise ValueError("Stop the guest first")
                    record.update(cpus=p["cpus"], memory_mib=p["memory_mib"])
                elif p["action"] == "delete":
                    if p.get("confirm") != record["name"] or record["status"] != "stopped":
                        raise ValueError("Stop the guest and type its exact name")
                    self.resources.remove(record)
                else:
                    record["status"] = "stopped" if p["action"] == "stop" else "running"
                return {"id": record["id"]}
            if operation == 'templates.upload':
                row = {'id': 'upload-' + str(uuid.uuid4()), 'name': p['name'], 'arch': 'amd64', 'variant': 'browser upload', 'build': 'Preview'}
                self.uploaded_templates.append(row); return row
            if operation == 'templates.delete':
                row = next(x for x in self.uploaded_templates if x['id'] == p['id'])
                if p.get('confirm') != row['name']:
                    raise ValueError('Filename does not match')
                self.uploaded_templates.remove(row); return {'deleted': p['id']}
            if operation == 'media.upload':
                row = {'id': str(uuid.uuid4()), 'name': p['name'], 'source': 'preview browser upload', 'kind': 'upload', 'size': 0, 'available': True, 'created': time.time(), 'sha256': 'preview—not stored'}
                self.media.append(row); return row
            if operation == "media.import":
                row = {"id": str(uuid.uuid4()), "name": p["name"], "source": p["source"], "kind": p["kind"], "size": 640 * 2**20, "available": True, "created": time.time(), "sha256": "preview—no download performed"}
                self.media.append(row); return row
            if operation == "media.delete":
                row = next(x for x in self.media if x["id"] == p["id"])
                if p.get("confirm") != row["name"]:
                    raise ValueError("Filename does not match")
                self.media.remove(row); return {"deleted": p["id"]}
            if operation == "networks.create":
                self.networks.append({**p, "name": "ht-" + p["name"], "id": str(uuid.uuid4()), "active": True, "managed": True, "bridge": "vhtpreview"}); return {"created": True}
            if operation == "networks.delete":
                self.networks = [n for n in self.networks if not (n["name"] == p["name"] and n["engine"] == p["engine"])]; return {"deleted": True}
            if operation == "images.pull":
                return {"pulled": True}
            raise ValueError("Unsupported preview operation")
