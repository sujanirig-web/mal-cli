"""
APK hashing and signature extraction.
"""

import hashlib
import os
import tempfile
from typing import Optional, Tuple
from mal_cli.adb.client import ADBClient


class APKScanner:
    def __init__(self, client: ADBClient, device_serial: str):
        self.client = client
        self.serial = device_serial

    def get_apk_info(self, package: str, apk_path: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Return (sha256_hash, signer_info).
        """
        # Pull APK to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
            local_path = tmp.name
        try:
            success = self.client.pull(apk_path, local_path, self.serial)
            if not success:
                return None, None
            # Compute hash
            sha256 = hashlib.sha256()
            with open(local_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            apk_hash = sha256.hexdigest()
            # Get signer info using keytool or apksigner (simplified)
            # For now, we just return the hash and placeholder signer
            signer = self._extract_signer(local_path)
            return apk_hash, signer
        finally:
            os.unlink(local_path)

    def _extract_signer(self, apk_path: str) -> Optional[str]:
        """Extract signer certificate subject (simplified)."""
        # Use keytool if available (requires JDK)
        try:
            import subprocess
            # Use 'keytool -printcert -jarfile apk_path'
            result = subprocess.run(
                ["keytool", "-printcert", "-jarfile", apk_path],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                # Look for "Owner: CN=..."
                for line in result.stdout.splitlines():
                    if "Owner:" in line:
                        return line.strip()
            return None
        except:
            return None