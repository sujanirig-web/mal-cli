"""
Device management and selection.
"""

from typing import List, Optional
from mal_cli.adb.client import ADBClient, ADBError
from mal_cli.models.device import Device


class DeviceManager:
    """Manage ADB devices."""

    def __init__(self, client: ADBClient):
        self.client = client
        self._cache: List[Device] = []

    def list_devices(self) -> List[Device]:
        """Return list of connected devices."""
        raw = self.client.devices()
        devices = []
        for d in raw:
            device = Device(
                serial=d["serial"],
                model=d.get("model", "unknown"),
                android_version=self.client.getprop("ro.build.version.release", d["serial"]),
                sdk_version=int(self.client.getprop("ro.build.version.sdk", d["serial"]) or 0),
                is_online=(d["status"] == "device")
            )
            devices.append(device)
        self._cache = devices
        return devices

    def get_device(self, serial: Optional[str] = None) -> Device:
        """Get a specific device by serial, or the first online device."""
        devices = self.list_devices()
        if not devices:
            raise ADBError("No devices connected")
        if serial:
            for d in devices:
                if d.serial == serial:
                    if not d.is_online:
                        raise ADBError(f"Device {serial} is not online")
                    return d
            raise ADBError(f"Device {serial} not found")
        # Return first online
        for d in devices:
            if d.is_online:
                return d
        raise ADBError("No online devices found")