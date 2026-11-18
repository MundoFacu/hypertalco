import ipaddress
import json
import re
import tempfile
import xml.etree.ElementTree as ET

from .engines import LABEL, NS
from .validation import Invalid, network


class Networks:
    def __init__(self, runner, docker, libvirt):
        self.runner, self.docker, self.libvirt = runner, docker, libvirt

    def interfaces(self):
        return {"links": json.loads(self.runner.run(["ip", "-j", "-d", "link", "show"])),
                "addresses": json.loads(self.runner.run(["ip", "-j", "address", "show"])),
                "routes": json.loads(self.runner.run(["ip", "-j", "route", "show"]))}

    def forwarding(self, bridge, cidr, mode, remove=False):
        if mode not in {"nat", "isolated"}:
            return
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", bridge):
            raise Invalid("Invalid owned bridge")
        cidr = str(network(cidr))
        rules = [["-i", bridge, "-o", bridge, "-s", cidr, "-d", cidr, "-j", "ACCEPT"]]
        if mode == "nat":
            rules += [["-i", bridge, "-s", cidr, "-j", "ACCEPT"],
                      ["-o", bridge, "-d", cidr, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]]
        for rule in rules:
            exists = self.runner.succeeds(["iptables", "-w", "5", "-C", "DOCKER-USER", *rule])
            if remove and exists:
                self.runner.run(["iptables", "-w", "5", "-D", "DOCKER-USER", *rule])
            elif not remove and not exists:
                self.runner.run(["iptables", "-w", "5", "-I", "DOCKER-USER", "1", *rule])

    def docker_networks(self):
        out = []
        for net in self.docker.request("GET", "/v1.41/networks"):
            if net.get("Driver") != "bridge":
                continue
            cfg = net.get("IPAM", {}).get("Config", [])
            out.append({"id": "docker:" + net["Id"], "name": net["Name"], "engine": "docker",
                        "mode": "isolated" if net.get("Internal") else "nat",
                        "cidr": next((x.get("Subnet") for x in cfg if x.get("Subnet")), ""),
                        "bridge": net.get("Options", {}).get("com.docker.network.bridge.name", ""),
                        "managed": (net.get("Labels") or {}).get(LABEL) == "true",
                        "active": True, "attached": len(net.get("Containers") or {})})
        return out

    def libvirt_networks(self):
        out = []
        active = set(self.libvirt.virsh("net-list", "--name").split())
        for name in self.libvirt.virsh("net-list", "--all", "--name").split():
            xml = ET.fromstring(self.libvirt.virsh("net-dumpxml", name))
            bridge, ip, forward = xml.find("bridge"), xml.find("ip"), xml.find("forward")
            cidr = ""
            if ip is not None:
                cidr = str(ipaddress.ip_network(ip.get("address") + "/" + (ip.get("prefix") or ip.get("netmask")), strict=False))
            out.append({"id": "libvirt:" + name, "name": name, "engine": "libvirt",
                        "mode": forward.get("mode") if forward is not None else "isolated",
                        "cidr": cidr, "bridge": bridge.get("name", "") if bridge is not None else "",
                        "managed": xml.find(f"./metadata/{{{NS}}}managed") is not None,
                        "active": name in active})
        return out

    def resolve(self, engine, name):
        options = self.docker_networks() if engine == "docker" else self.libvirt_networks()
        match = next((n for n in options if n["name"] == name and n["active"]), None)
        if not match:
            raise Invalid("Select an active network from the host inventory")
        return match

    def validate_subnet(self, value):
        subnet = network(value)
        # Refuse overlap with connected/routed destinations and either engine.
        candidates = [r.get("dst") for r in self.interfaces()["routes"] if r.get("dst") not in {None, "default"}]
        for getter in (self.docker_networks, self.libvirt_networks):
            try:
                candidates += [n["cidr"] for n in getter() if n.get("cidr")]
            except (OSError, RuntimeError):
                pass
        for existing in candidates:
            try:
                other = ipaddress.ip_network(existing, strict=False)
            except ValueError:
                continue
            if other.version == subnet.version and other.overlaps(subnet):
                raise Invalid(f"Subnet overlaps an existing route or network: {other}")
        return subnet

    def create(self, data):
        if set(data) - {"name", "engine", "mode", "cidr", "bridge", "job_id"}:
            raise Invalid("Unsupported network fields")
        name = data.get("name", "")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,24}", name):
            raise Invalid("Network names use 2–25 lowercase letters, numbers or hyphens")
        physical = "ht-" + name
        mode, engine = data.get("mode"), data.get("engine")
        if engine not in {"docker", "libvirt"} or mode not in {"nat", "isolated", "bridge"}:
            raise Invalid("Invalid network engine or mode")
        if engine == "docker" and mode == "bridge":
            raise Invalid("External bridges are available to VM/LXC networks")
        subnet = None if mode == "bridge" else self.validate_subnet(data.get("cidr", ""))
        if engine == "docker":
            body = {"Name": physical, "Driver": "bridge", "CheckDuplicate": True, "Internal": mode == "isolated",
                    "Labels": {LABEL: "true"}, "IPAM": {"Config": [{"Subnet": str(subnet)}]}}
            return self.docker.request("POST", "/v1.41/networks/create", body)
        if physical in self.libvirt.virsh("net-list", "--all", "--name").split():
            raise Invalid("Network already exists")
        xml = ET.Element("network")
        ET.SubElement(xml, "name").text = physical
        ET.SubElement(ET.SubElement(xml, "metadata"), f"{{{NS}}}managed").text = "true"
        if mode == "bridge":
            bridge = data.get("bridge", "")
            if not isinstance(bridge, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", bridge):
                raise Invalid("Select an existing host bridge")
            links = self.interfaces()["links"]
            if not any(n.get("ifname") == bridge and n.get("linkinfo", {}).get("info_kind") == "bridge" for n in links):
                raise Invalid("The selected interface is not an existing bridge")
            ET.SubElement(xml, "forward", mode="bridge")
            ET.SubElement(xml, "bridge", name=bridge)
        else:
            if mode == "nat":
                ET.SubElement(xml, "forward", mode="nat")
            import hashlib
            ET.SubElement(xml, "bridge", name="vht" + hashlib.sha256(physical.encode()).hexdigest()[:8], stp="on", delay="0")
            ip = ET.SubElement(xml, "ip", address=str(subnet[1]), netmask=str(subnet.netmask))
            ET.SubElement(ET.SubElement(ip, "dhcp"), "range", start=str(subnet[10]), end=str(subnet[250]))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml") as f:
            f.write(ET.tostring(xml, encoding="unicode")); f.flush()
            self.libvirt.virsh("net-define", f.name)
        self.libvirt.virsh("net-autostart", physical)
        self.libvirt.virsh("net-start", physical)
        if subnet is not None:
            self.forwarding(xml.find("bridge").get("name"), str(subnet), mode)
        return {"name": physical}

    def delete(self, name, engine, resources):
        items = self.docker_networks() if engine == "docker" else self.libvirt_networks()
        item = next((n for n in items if n["name"] == name), None)
        if not item or not item["managed"] or name == "hypertalco":
            raise Invalid("Only additional Hypertalco networks can be deleted")
        if any(r.get("network") == name for r in resources):
            raise Invalid("A managed guest still references this network")
        if engine == "docker":
            self.docker.request("DELETE", "/v1.41/networks/" + item["id"].split(":", 1)[1])
            return {"deleted": name}
        for guest in self.libvirt.domains():
            if any(n.get("network") == name for n in guest["xml"].findall("./devices/interface/source")):
                raise Invalid("A VM still references this network")
        if item["mode"] in {"nat", "isolated"} and item["bridge"]:
            attached = json.loads(self.runner.run(["ip", "-j", "link", "show", "master", item["bridge"]]))
            if attached:
                raise Invalid("An interface is still attached to this network bridge")
        if item["active"]:
            self.libvirt.virsh("net-destroy", name)
        self.libvirt.virsh("net-undefine", name)
        if item["cidr"]:
            self.forwarding(item["bridge"], item["cidr"], item["mode"], remove=True)
        return {"deleted": name}
