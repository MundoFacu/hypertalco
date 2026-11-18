"""The web process and privileged agent share the same restrictive contract."""
import base64
import ipaddress
import re

ENGINES = ("docker", "lxc", "qemu")
TEMPLATES = {
    "debian-12": {"name": "Debian 12", "dist": "debian", "release": "bookworm"},
    "debian-13": {"name": "Debian 13", "dist": "debian", "release": "trixie"},
    "ubuntu-24.04": {"name": "Ubuntu 24.04 LTS", "dist": "ubuntu", "release": "noble"},
}


class Invalid(ValueError):
    pass


def text(value, field, maximum=200):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise Invalid(f"Invalid {field}")
    return value.strip()


def integer(value, field, low, high):
    if type(value) is not int or not low <= value <= high:
        raise Invalid(f"{field} must be between {low} and {high}")
    return value


def limits(data):
    return {"cpus": integer(data.get("cpus", 2), "CPUs", 1, 128),
            "memory_mib": integer(data.get("memory_mib", 1024), "Memory MiB", 128, 1048576)}


def ssh_keys(value):
    if not isinstance(value, str) or len(value) > 16384:
        raise Invalid("Provide at least one OpenSSH public key")
    keys = []
    for line in value.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        if len(parts) < 2 or parts[0] not in {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}:
            raise Invalid("Only plain OpenSSH public keys are accepted")
        try:
            raw = base64.b64decode(parts[1], validate=True)
            size = int.from_bytes(raw[:4], "big")
            if len(raw) < 20 or raw[4:4 + size].decode("ascii") != parts[0]:
                raise ValueError()
        except (ValueError, UnicodeError):
            raise Invalid("Malformed SSH public key") from None
        keys.append(line.strip())
    if not 1 <= len(keys) <= 16:
        raise Invalid("Provide 1–16 SSH public keys")
    return keys


def create(data):
    if not isinstance(data, dict):
        raise Invalid("Expected an object")
    unknown = set(data) - {"engine", "name", "cpus", "memory_mib", "image", "disk_gib", "ssh_keys", "ports", "env", "volume_path", "autostart", "network", "firmware"}
    if unknown:
        raise Invalid("Unsupported fields: " + ", ".join(sorted(unknown)))
    engine = data.get("engine")
    if engine not in ENGINES:
        raise Invalid("Choose Docker, LXC or QEMU")
    name = text(data.get("name"), "name", 32)
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,31}", name):
        raise Invalid("Names use 2–32 lowercase letters, numbers or hyphens; start with a letter")
    auto = data.get("autostart", True)
    if type(auto) is not bool:
        raise Invalid("autostart must be a boolean")
    net = text(data.get("network", "hypertalco"), "network", 64)
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", net):
        raise Invalid("Invalid network name")
    result = {"engine": engine, "name": name, **limits(data), "autostart": auto, "network": net}
    image = text(data.get("image"), "image", 200)
    if engine == "docker":
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,199}", image):
            raise Invalid("Invalid Docker image reference")
        result.update(image=image, ports=[], env={}, volume_path="")
        ports = data.get("ports", [])
        if not isinstance(ports, list) or len(ports) > 16:
            raise Invalid("At most 16 port mappings are allowed")
        seen = set()
        for port in ports:
            if not isinstance(port, dict) or set(port) - {"host", "container", "protocol", "bind"}:
                raise Invalid("Invalid port mapping")
            host = integer(port.get("host"), "Host port", 1024, 65535)
            container = integer(port.get("container"), "Container port", 1, 65535)
            proto = port.get("protocol", "tcp")
            bind = port.get("bind", "0.0.0.0")
            if proto not in {"tcp", "udp"} or bind not in {"0.0.0.0", "127.0.0.1"}:
                raise Invalid("Invalid port protocol or bind address")
            if (host, proto, bind) in seen:
                raise Invalid("Duplicate host port")
            seen.add((host, proto, bind))
            result["ports"].append(dict(host=host, container=container, protocol=proto, bind=bind))
        env = data.get("env", {})
        if not isinstance(env, dict) or len(env) > 64:
            raise Invalid("At most 64 environment variables are allowed")
        for key, value in env.items():
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", key) or not isinstance(value, str) or len(value) > 4096 or "\x00" in value:
                raise Invalid("Invalid environment variable")
            result["env"][key] = value
        path = data.get("volume_path", "")
        if not isinstance(path, str) or (path and (not re.fullmatch(r"/[A-Za-z0-9_./-]{1,160}", path) or ".." in path.split("/") or path in {"/", "/proc", "/sys", "/dev"})):
            raise Invalid("Use a normal container directory such as /data")
        result["volume_path"] = path
    elif engine == "lxc":
        if not (re.fullmatch(r"(?:debian|ubuntu)/[a-z0-9.-]+/(?:amd64|arm64)/default", image) or
                re.fullmatch(r'upload-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', image)):
            raise Invalid("Choose a Debian or Ubuntu LXC template from the catalog")
        result["image"] = image
        result["ssh_keys"] = ssh_keys(data.get("ssh_keys", ""))
    else:
        try:
            import uuid
            image = str(uuid.UUID(image))
        except ValueError:
            raise Invalid("Choose an ISO from the media library") from None
        firmware = data.get("firmware", "uefi")
        if firmware not in {"bios", "uefi"}:
            raise Invalid("Invalid firmware")
        result.update(image=image, firmware=firmware, disk_gib=integer(data.get("disk_gib", 32), "Disk GiB", 8, 2048))
    return result


def network(value):
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise Invalid("Invalid guest subnet") from None
    if net.version != 4 or net.prefixlen != 24 or not net.is_private or net.is_loopback or net.is_link_local:
        raise Invalid("Guest networks must be private IPv4 /24 subnets")
    return net
