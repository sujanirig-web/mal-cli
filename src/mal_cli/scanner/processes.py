"""
Process listing for static scanning (snapshot).
"""

from typing import List, Dict
from mal_cli.adb.client import ADBClient
from mal_cli.adb.commands import ADBCommands


class ProcessScanner:
    def __init__(self, client: ADBClient, device_serial: str):
        self.client = client
        self.cmds = ADBCommands(client, device_serial)

    def get_all_processes(self) -> List[Dict]:
        return self.cmds.get_running_processes()

    def get_processes_for_package(self, package: str) -> List[Dict]:
        all_procs = self.get_all_processes()
        return [p for p in all_procs if p["name"].startswith(package)]