#!/usr/bin/env python3
"""Only add idempotent forwarding rules for Hypertalco-owned guest networks."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hypertalco.engines import Docker, Libvirt, Runner
from hypertalco.networks import Networks


def main():
    runner = Runner()
    networks = Networks(runner, Docker(), Libvirt(runner))
    for n in networks.libvirt_networks():
        if n["managed"] and n["mode"] in {"nat", "isolated"} and n["active"]:
            networks.forwarding(n["bridge"], n["cidr"], n["mode"])


if __name__ == "__main__":
    main()
