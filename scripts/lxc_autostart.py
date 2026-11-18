#!/usr/bin/env python3
"""Run LXC autostart, treating a newly installed empty inventory as a no-op."""
from pathlib import Path
import subprocess
import sys


def main(action, directory):
    root = Path(directory)
    if action not in {"start", "stop"} or not root.is_dir():
        raise ValueError("Invalid action or LXC directory")
    if not any(item.is_dir() and (item / "config").is_file() for item in root.iterdir()):
        return 0
    command = ["/usr/bin/lxc-autostart", "-P", str(root), "-a"]
    if action == "stop":
        command += ["-s", "-t", "30"]
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: lxc_autostart.py start|stop DIRECTORY")
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
