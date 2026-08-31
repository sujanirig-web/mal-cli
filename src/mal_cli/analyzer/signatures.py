"""
Signature and hash matching for known malware.
"""

import json
import os
from typing import Tuple, List
from mal_cli.models.package import Package

# Load signatures from data/signatures.json
SIGNATURES_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "signatures.json")


def load_signatures():
    try:
        with open(SIGNATURES_FILE, "r") as f:
            return json.load(f)
    except:
        return {"hashes": {}, "signers": {}}


def check_signatures(pkg: Package) -> Tuple[int, List[str], str]:
    """
    Check package against known signatures.
    Returns (score, indicators, explanation).
    """
    sigs = load_signatures()
    score = 0
    indicators = []
    explanation = ""

    # Check APK hash
    if pkg.apk_hash and pkg.apk_hash in sigs.get("hashes", {}):
        score = 100
        indicators.append("Known malicious hash")
        explanation = f"APK hash matches known malware: {sigs['hashes'][pkg.apk_hash]}"
        return score, indicators, explanation

    # Check signer
    if pkg.signer_info:
        # Compare with known bad signers (simplified)
        for bad_signer in sigs.get("signers", []):
            if bad_signer in pkg.signer_info:
                score = 90
                indicators.append("Known malicious signer")
                explanation = "Package signed with known malicious certificate"
                return score, indicators, explanation

    return 0, [], ""