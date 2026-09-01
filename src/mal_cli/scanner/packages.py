"""
Package discovery and static info gathering.
"""

import re
from typing import List, Optional
from mal_cli.adb.client import ADBClient
from mal_cli.adb.commands import ADBCommands
from mal_cli.models.device import Device
from mal_cli.models.package import Package
from mal_cli.scanner.permissions import PermissionScanner
from mal_cli.scanner.services import ServiceScanner
from mal_cli.scanner.apk import APKScanner


class PackageScanner:
    """Main scanner for installed packages."""

    def __init__(self, client: ADBClient, device: Device):
        self.client = client
        self.device = device
        self.cmds = ADBCommands(client, device.serial)
        self.perm_scanner = PermissionScanner(client, device.serial)
        self.svc_scanner = ServiceScanner(client, device.serial)
        self.apk_scanner = APKScanner(client, device.serial)

    def list_packages_light(self) -> List[Package]:
        """Return list of all packages with just name + version + SDKs.

        Fast path: reads every package and its versionName/SDK levels from a
        single `dumpsys package packages` call. Avoids the slow per-package APK
        pull/hash that get_all_packages() performs, so listing all apps is
        near-instant instead of taking minutes.
        """
        out = self.client.dumpsys("package", "packages", self.device.serial)
        packages = []
        name = None
        version = ""
        target_sdk = 0
        min_sdk = 0
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("Package [") and "] (" in stripped:
                if name:
                    packages.append(Package(
                        name=name, version=version,
                        target_sdk=target_sdk, min_sdk=min_sdk,
                    ))
                name = stripped.split("[")[1].split("]")[0].strip()
                version = ""
                target_sdk = 0
                min_sdk = 0
                continue
            if not name:
                continue
            if "versionName=" in stripped:
                version = stripped.split("versionName=")[1].split()[0]
            m = re.search(r"minSdk=(\d+)", stripped)
            if m:
                min_sdk = int(m.group(1))
            m = re.search(r"targetSdk=(\d+)", stripped)
            if m:
                target_sdk = int(m.group(1))
        if name:
            packages.append(Package(
                name=name, version=version,
                target_sdk=target_sdk, min_sdk=min_sdk,
            ))
        return packages

    def get_all_packages(self) -> List[Package]:
        """Return list of all packages with static info."""
        names = self.cmds.list_packages()
        packages = []
        for name in names:
            try:
                pkg = self.get_package_info(name)
                packages.append(pkg)
            except Exception as e:
                # Skip failed packages
                continue
        return packages

    def get_package_info(self, package_name: str) -> Optional[Package]:
        """Fetch full static info for a single package.

        Returns None when the package is not installed. Per-step sub-scans
        (permissions/services/APK) are guarded so a single failure degrades
        gracefully instead of silently losing the whole package.
        """
        info = self.cmds.get_package_info(package_name)
        if not info.get("found"):
            return None
        try:
            permissions = self.perm_scanner.get_permissions(package_name)
        except Exception:
            permissions = []
        try:
            services = self.svc_scanner.get_services(package_name)
        except Exception:
            services = []
        apk_path = None
        apk_hash = None
        signer = None
        try:
            apk_path = self.client.pm_path(package_name, self.device.serial)
            if apk_path:
                apk_hash, signer = self.apk_scanner.get_apk_info(package_name, apk_path)
        except Exception:
            apk_hash = None
            signer = None

        return Package(
            name=package_name,
            version=info.get("version", ""),
            installer=info.get("installer", ""),
            target_sdk=info.get("target_sdk", 0),
            min_sdk=info.get("min_sdk", 0),
            permissions=permissions,
            services=services,
            apk_hash=apk_hash,
            signer_info=signer,
        )