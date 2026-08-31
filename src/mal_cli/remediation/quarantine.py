"""
Quarantine a package (backup APK and disable).
"""

import os
import shutil
import tempfile
from pathlib import Path
import sys
from mal_cli.adb.client import ADBClient
from mal_cli.models.device import Device
from mal_cli.database.database import Database
from mal_cli.output.terminal import Terminal


class QuarantineManager:
    def __init__(self, client: ADBClient, device: Device, db: Database):
        self.client = client
        self.device = device
        self.db = db
        self.quarantine_dir = Path.home() / ".mal_cli" / "quarantine"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def quarantine(self, package: str, force: bool = False):
        if not force:
            Terminal.print_warning(f"WARNING: You are about to QUARANTINE {package}.")
            confirm = input("Continue? [y/N] ").strip().lower()
            if confirm != 'y':
                Terminal.print("Aborted.")
                sys.exit(0)

        # Get APK path
        apk_path = self.client.pm_path(package, self.device.serial)
        if not apk_path:
            Terminal.print_error(f"Could not locate APK for {package}")
            sys.exit(1)

        # Pull APK to quarantine directory
        dest = self.quarantine_dir / f"{package}.apk"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            local_tmp = tmp.name
        success = self.client.pull(apk_path, local_tmp, self.device.serial)
        if not success:
            Terminal.print_error(f"Failed to pull APK for {package}")
            sys.exit(1)
        # Move to quarantine
        shutil.move(local_tmp, dest)
        Terminal.print_success(f"APK backed up to {dest}")

        # Disable package
        disable_success = self.client.disable(package, self.device.serial)
        if disable_success:
            Terminal.print_success(f"Package {package} disabled.")
            self.db.update_remediation_state(package, "quarantined")
        else:
            Terminal.print_error(f"Failed to disable {package}; APK still backed up.")