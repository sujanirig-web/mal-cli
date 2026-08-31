"""
Uninstall a package.
"""

import sys
from mal_cli.adb.client import ADBClient
from mal_cli.models.device import Device
from mal_cli.database.database import Database
from mal_cli.output.terminal import Terminal


class Uninstaller:
    def __init__(self, client: ADBClient, device: Device, db: Database):
        self.client = client
        self.device = device
        self.db = db

    def uninstall(self, package: str, force: bool = False):
        # Check if system package
        info = self.db.get_package(package)
        if not info:
            Terminal.print_warning(f"Package '{package}' not in database; proceed with caution.")

        if not force:
            Terminal.print_warning(f"WARNING: You are about to UNINSTALL {package}.")
            confirm = input("Continue? [y/N] ").strip().lower()
            if confirm != 'y':
                Terminal.print("Aborted.")
                sys.exit(0)

        success = self.client.uninstall(package, self.device.serial)
        if success:
            Terminal.print_success(f"Package {package} uninstalled.")
            self.db.update_remediation_state(package, "uninstalled")
        else:
            Terminal.print_error(f"Failed to uninstall {package}")