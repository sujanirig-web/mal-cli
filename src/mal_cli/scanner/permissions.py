"""
Permission extraction from packages.
"""

from typing import List
from mal_cli.adb.client import ADBClient
from mal_cli.adb.commands import ADBCommands


class PermissionScanner:
    def __init__(self, client: ADBClient, device_serial: str):
        self.client = client
        self.cmds = ADBCommands(client, device_serial)

    def get_permissions(self, package: str) -> List[str]:
        return self.cmds.get_permissions(package)