import os
from pathlib import Path
import platform
import shutil
import socket
import threading
import time


class Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.previous = None

    def snapshot(self):
        with self.lock:
            values = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:9]]
            total, idle = sum(values), values[3] + values[4]
            cpu = None
            if self.previous and total > self.previous[0]:
                cpu = round(100 * (1 - (idle - self.previous[1]) / (total - self.previous[0])), 1)
            self.previous = (total, idle)
        mem = {line.split(":")[0]: int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines() if line.split()[1].isdigit()}
        disk = shutil.disk_usage("/var/lib" if Path("/var/lib").exists() else "/")
        return {"hostname": socket.gethostname(), "kernel": platform.release(), "architecture": platform.machine(),
                "cpu_count": os.cpu_count(), "cpu_percent": cpu, "memory_total": mem["MemTotal"],
                "memory_used": mem["MemTotal"] - mem["MemAvailable"], "memory_available": mem["MemAvailable"],
                "disk_total": disk.total, "disk_used": disk.used, "disk_free": disk.free,
                "uptime": float(Path("/proc/uptime").read_text().split()[0]), "load": list(os.getloadavg()), "ts": time.time()}
