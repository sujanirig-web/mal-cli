"""
Higher-level ADB commands.
"""

from typing import List, Dict, Optional, Tuple
from mal_cli.adb.client import ADBClient


class ADBCommands:
    """Convenience functions combining multiple ADB calls."""

    def __init__(self, client: ADBClient, device_serial: str):
        self.client = client
        self.serial = device_serial

    def get_package_info(self, package: str) -> Dict:
        """Return dict with version, installer, targetSdk, minSdk, etc."""
        # Use dumpsys package
        out = self.client.dumpsys("package", package, self.serial)
        info = {
            "name": package,
            "version": "",
            "installer": "",
            "target_sdk": 0,
            "min_sdk": 0,
        }
        lines = out.splitlines()
        for i, line in enumerate(lines):
            if "versionName=" in line:
                info["version"] = line.split("versionName=")[1].split()[0]
            if "installerPackageName=" in line:
                info["installer"] = line.split("installerPackageName=")[1].split()[0]
            if "targetSdk=" in line:
                info["target_sdk"] = int(line.split("targetSdk=")[1].split()[0])
            if "minSdk=" in line:
                info["min_sdk"] = int(line.split("minSdk=")[1].split()[0])
        return info

    def list_packages(self) -> List[str]:
        return self.client.pm_list_packages(self.serial)

    def get_permissions(self, package: str) -> List[str]:
        """Extract requested permissions from dumpsys package."""
        out = self.client.dumpsys("package", package, self.serial)
        perms = []
        in_perms = False
        for line in out.splitlines():
            if "requested permissions:" in line:
                in_perms = True
                continue
            if in_perms and line.strip():
                if line.startswith("  "):
                    perm = line.strip()
                    if perm and not perm.startswith("android.permission."):
                        # Sometimes includes full names
                        pass
                    perms.append(perm)
                else:
                    in_perms = False
        return perms

    def get_services(self, package: str) -> List[str]:
        """Extract service names from dumpsys package."""
        out = self.client.dumpsys("package", package, self.serial)
        services = []
        in_services = False
        for line in out.splitlines():
            if "Service:" in line:
                in_services = True
                continue
            if in_services and line.strip():
                if line.startswith("  "):
                    # Extract service name
                    parts = line.strip().split()
                    if parts:
                        svc = parts[0]
                        if svc.startswith(package):
                            services.append(svc)
                else:
                    in_services = False
        return services

    def get_running_processes(self) -> List[Dict]:
        """Return list of running processes with package mapping."""
        # Use ps -A or ps
        out = self.client.shell("ps -A", self.serial)
        processes = []
        lines = out.splitlines()
        if not lines:
            return processes
        # Header line: USER PID PPID VSZ RSS WCHAN ADDR S NAME
        # We'll parse all lines
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 9:
                user = parts[0]
                pid = int(parts[1])
                ppid = int(parts[2])
                vsz = int(parts[3])
                rss = int(parts[4])
                name = parts[-1]
                # Try to map name to package (if starts with package name)
                # For simplicity we just store name
                processes.append({
                    "pid": pid,
                    "ppid": ppid,
                    "user": user,
                    "name": name,
                    "vsz": vsz,
                    "rss": rss,
                })
        return processes

    def get_foreground_activity(self) -> Optional[str]:
        """Get the package of the current foreground activity."""
        out = self.client.dumpsys("activity", "activities", self.serial)
        # Look for mResumedActivity or mFocusedApp
        for line in out.splitlines():
            if "mResumedActivity" in line or "mFocusedApp" in line:
                # Example: mResumedActivity: ActivityRecord{... com.example/.MainActivity}
                if "ActivityRecord" in line:
                    parts = line.split()
                    for part in parts:
                        if "/" in part and not part.startswith("{"):
                            # part might be "com.example/.MainActivity"
                            pkg = part.split("/")[0]
                            return pkg
        return None

    def get_battery_info(self) -> Dict:
        """Get battery status."""
        out = self.client.dumpsys("battery", "", self.serial)
        info = {}
        for line in out.splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                info[key.strip()] = val.strip()
        return info

    def get_memory_info(self) -> Dict:
        """Get memory info from dumpsys meminfo."""
        out = self.client.dumpsys("meminfo", "", self.serial)
        # Simple parse for total RAM
        info = {}
        for line in out.splitlines():
            if "Total RAM" in line:
                # "Total RAM: 5,908,584 kB"
                parts = line.split(":")
                if len(parts) > 1:
                    info["total_ram"] = parts[1].strip()
            if "Free RAM" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    info["free_ram"] = parts[1].strip()
        return info

    def get_network_stats(self) -> Dict:
        """Get network statistics per package (if available)."""
        # Use /proc/net/xt_qtaguid/stats
        try:
            out = self.client.shell("cat /proc/net/xt_qtaguid/stats", self.serial)
        except:
            return {}
        stats = {}
        for line in out.splitlines():
            # Format: idx iface acct_tag_hex uid cnt_set rx_bytes rx_packets tx_bytes tx_packets
            parts = line.split()
            if len(parts) >= 9:
                uid = int(parts[3])
                rx_bytes = int(parts[5])
                tx_bytes = int(parts[7])
                # We need mapping uid->package; we can get via dumpsys package
                # For now we just aggregate by UID
                stats[uid] = stats.get(uid, 0) + rx_bytes + tx_bytes
        return stats

    def get_logcat(self, pid: Optional[int] = None) -> List[str]:
        """Get logcat output, optionally filtered by PID."""
        cmd = "logcat -d"
        if pid:
            cmd += f" --pid={pid}"
        out = self.client.shell(cmd, self.serial)
        return out.splitlines()