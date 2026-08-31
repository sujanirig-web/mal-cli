"""
Package discovery and static info gathering.
"""

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
        """Fetch full static info for a single package."""
        try:
            info = self.cmds.get_package_info(package_name)
            permissions = self.perm_scanner.get_permissions(package_name)
            services = self.svc_scanner.get_services(package_name)
            apk_path = self.client.pm_path(package_name, self.device.serial)
            apk_hash = None
            signer = None
            if apk_path:
                apk_hash, signer = self.apk_scanner.get_apk_info(package_name, apk_path)

            pkg = Package(
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
            return pkg
        except Exception:
            return None