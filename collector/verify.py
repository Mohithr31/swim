"""
JOCKY Forensic Manifest & Evidence Verifier
"""
import os
import json
import hashlib
from typing import Dict, Any, Tuple, List
from collector.manifest import calculate_sha256


class EvidenceVerificationResult:
    def __init__(self, valid: bool, message: str, tampered_files: List[str] = None):
        self.valid = valid
        self.message = message
        self.tampered_files = tampered_files if tampered_files else []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "message": self.message,
            "tampered_files": self.tampered_files
        }


def verify_manifest_and_evidence(manifest_path: str, evidence_dir: str) -> EvidenceVerificationResult:
    """Verifies evidence directory files against manifest.json SHA-256 signatures."""
    if not os.path.exists(manifest_path):
        return EvidenceVerificationResult(False, f"Manifest file not found: {manifest_path}")

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as e:
        return EvidenceVerificationResult(False, f"Invalid manifest JSON: {str(e)}")

    files_entry = manifest.get("files", [])
    tampered_files: List[str] = []

    for entry in files_entry:
        rel_path = entry.get("path")
        expected_hash = entry.get("sha256")
        expected_size = entry.get("size")

        full_path = os.path.join(evidence_dir, rel_path)

        if not os.path.exists(full_path):
            tampered_files.append(f"MISSING: {rel_path}")
            continue

        actual_size = os.path.getsize(full_path)
        if actual_size != expected_size:
            tampered_files.append(f"SIZE_MISMATCH ({rel_path}): expected {expected_size}, got {actual_size}")
            continue

        actual_hash = calculate_sha256(full_path)
        if actual_hash != expected_hash:
            tampered_files.append(f"HASH_MISMATCH ({rel_path}): expected {expected_hash}, got {actual_hash}")

    if tampered_files:
        return EvidenceVerificationResult(
            valid=False,
            message=f"Evidence verification failed for {len(tampered_files)} file(s).",
            tampered_files=tampered_files
        )

    return EvidenceVerificationResult(
        valid=True,
        message=f"All {len(files_entry)} file(s) successfully verified against SHA-256 manifest signatures."
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python -m collector.verify <manifest.json> <evidence_dir>")
        sys.exit(1)

    result = verify_manifest_and_evidence(sys.argv[1], sys.argv[2])
    print(f"Status: {'PASS' if result.valid else 'FAIL'}")
    print(f"Message: {result.message}")
    if result.tampered_files:
        print("Tampered files:")
        for t in result.tampered_files:
            print(f" - {t}")
    sys.exit(0 if result.valid else 1)
