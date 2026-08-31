"""
Low-level ADB client using subprocess.
"""

import subprocess
import shlex
from typing import List, Optional, Tuple


class ADBError(Exception):
    """Raised when ADB command fails."""


class ADBClient:
    """Wrapper for adb commands."""

    def __init__(self, adb_path: str = "adb"):
        self.adb_path = adb_path

    def _run(self, args: List[str], device_serial: Optional[str] = None) -> Tuple[str, str, int]:
        """Run adb command with optional device specification."""
        cmd = [self.adb_path]
        if device_serial:
            cmd.extend(["-s", device_serial])
        cmd.extend(args)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode

    def devices(self) -> List[dict]:
        """List connected devices."""
        out, err, code = self._run(["devices", "-l"])
        if code != 0:
            raise ADBError(f"adb devices failed: {err}")
        lines = out.splitlines()
        result = []
        for line in lines:
            if not line.strip() or line.startswith("List of devices"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                serial = parts[0]
                status = parts[1]
                model = ""
                for part in parts[2:]:
                    if part.startswith("model:"):
                        model = part.split(":", 1)[1]
                        break
                result.append({
                    "serial": serial,
                    "status": status,
                    "model": model,
                })
        return result

    def shell(self, command: str, device_serial: Optional[str] = None) -> str:
        """Run a shell command and return stdout."""
        out, err, code = self._run(["shell", command], device_serial)
        if code != 0:
            raise ADBError(f"shell command failed: {err}")
        return out

    def pm_list_packages(self, device_serial: Optional[str] = None) -> List[str]:
        """List all package names."""
        out = self.shell("pm list packages", device_serial)
        packages = []
        for line in out.splitlines():
            if line.startswith("package:"):
                packages.append(line[8:].strip())
        return packages

    def pm_path(self, package: str, device_serial: Optional[str] = None) -> Optional[str]:
        """Get APK path of package."""
        out = self.shell(f"pm path {package}", device_serial)
        for line in out.splitlines():
            if line.startswith("package:"):
                return line[8:].strip()
        return None

    def pull(self, remote_path: str, local_path: str, device_serial: Optional[str] = None) -> bool:
        """Pull a file from device."""
        out, err, code = self._run(["pull", remote_path, local_path], device_serial)
        return code == 0

    def uninstall(self, package: str, device_serial: Optional[str] = None) -> bool:
        """Uninstall a package."""
        out, err, code = self._run(["uninstall", package], device_serial)
        return code == 0

    def disable(self, package: str, device_serial: Optional[str] = None) -> bool:
        """Disable a package."""
        out, err, code = self._run(["shell", "pm", "disable", package], device_serial)
        return code == 0

    def enable(self, package: str, device_serial: Optional[str] = None) -> bool:
        """Enable a package."""
        out, err, code = self._run(["shell", "pm", "enable", package], device_serial)
        return code == 0

    def install(self, apk_path: str, device_serial: Optional[str] = None) -> bool:
        """Install an APK."""
        out, err, code = self._run(["install", apk_path], device_serial)
        return code == 0

    def getprop(self, prop: str, device_serial: Optional[str] = None) -> str:
        """Get a system property."""
        return self.shell(f"getprop {prop}", device_serial).strip()

    def dumpsys(self, service: str, args: str = "", device_serial: Optional[str] = None) -> str:
        """Run dumpsys command."""
        cmd = f"dumpsys {service}"
        if args:
            cmd += f" {args}"
        return self.shell(cmd, device_serial)