"""Backup encryption scanner skeleton.

Inventories backup software configuration and classifies the encryption
algorithms used to protect backup tapes, object-store snapshots, and
database recovery backups. This is a skeleton implementation: it does not
connect to live backup management servers but accepts an inventory list or
raw configuration text and surfaces quantum-vulnerable choices.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Common backup products encountered in enterprise estates.
_BACKUP_SOFTWARE = {
    "veeam": "Veeam Backup & Replication",
    "commvault": "Commvault",
    "rman": "Oracle RMAN",
    "sqlbackup": "SQL Server Backup",
    "tsm": "IBM Spectrum Protect / TSM",
    "rubrik": "Rubrik",
    "cohesity": "Cohesity",
    "netbackup": "Veritas NetBackup",
    "native": "Native OS / Cloud snapshot",
}

# Signature algorithms that are considered quantum-vulnerable for backup encryption.
_VULNERABLE_ALGORITHMS = {
    "3des",
    "tripledes",
    "des",
    "rc4",
    "rc2",
    "blowfish",
    "md5",
    "sha1",
    "sha-1",
}

# Algorithms treated as acceptable today but not post-quantum.
_CLASSICAL_OK = {"aes-128", "aes-192", "aes-256", "aes", "rsa", "ec", "ecc"}


def _normalize(name: Optional[str]) -> str:
    return (name or "").strip().lower().replace("_", "-").replace(" ", "-")


def classify_backup_algorithm(algorithm: Optional[str]) -> Dict[str, Any]:
    """Classify a backup encryption algorithm string for PQC readiness."""
    norm = _normalize(algorithm)
    # Strong symmetric / PQC algorithms are treated as "ready" today.
    if "ml-kem" in norm or "kyber" in norm or "aes-256-gcm" in norm:
        return {
            "pqc_status": "pqc_ready",
            "name": algorithm or "unknown",
            "notes": "PQC or strong symmetric",
        }
    if any(v in norm for v in _VULNERABLE_ALGORITHMS):
        return {
            "pqc_status": "vulnerable",
            "name": algorithm or "unknown",
            "notes": "Legacy/weak algorithm",
        }
    if any(c in norm for c in _CLASSICAL_OK):
        return {
            "pqc_status": "vulnerable",
            "name": algorithm or "unknown",
            "notes": "Classically secure, not PQC",
        }
    return {
        "pqc_status": "unknown",
        "name": algorithm or "unknown",
        "notes": "Could not classify",
    }


def _detect_software(config_text: Optional[str]) -> str:
    """Infer backup software from configuration text."""
    if not config_text:
        return "unknown"
    text_lower = config_text.lower()
    for key, label in _BACKUP_SOFTWARE.items():
        if key in text_lower:
            return label
    return "unknown"


def scan_backup_inventory(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Scan a list of backup inventory records.

    Each record is expected to contain at least:
      - source (str): hostname, bucket, or job name
      - software (str): backup product name
      - encryption_enabled (bool)
      - algorithm (str): encryption algorithm in use
      - key_store (str, optional): where the encryption key is stored
    """
    assets: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    errors: List[str] = []

    for idx, record in enumerate(records):
        try:
            source = record.get("source") or f"backup-{idx}"
            software = record.get("software") or "unknown"
            encryption_enabled = bool(record.get("encryption_enabled", False))
            algorithm = record.get("algorithm")
            classification = classify_backup_algorithm(algorithm)

            asset = {
                "name": source,
                "asset_type": "backup_encryption",
                "discovery_source": "backup_scanner",
                "software": software,
                "encryption_enabled": encryption_enabled,
                "algorithm": algorithm,
                "key_store": record.get("key_store"),
                "pqc_status": (
                    "vulnerable"
                    if not encryption_enabled
                    else classification["pqc_status"]
                ),
            }
            assets.append(asset)

            if not encryption_enabled:
                findings.append(
                    {
                        "title": f"Backup {source} is not encrypted",
                        "severity": "critical",
                        "finding_type": "backup_unencrypted",
                        "asset": source,
                        "pqc_status": "vulnerable",
                    }
                )
            elif classification["pqc_status"] == "vulnerable":
                findings.append(
                    {
                        "title": f"Backup {source} uses quantum-vulnerable algorithm {algorithm}",
                        "severity": "high",
                        "finding_type": "backup_weak_encryption",
                        "asset": source,
                        "algorithm": algorithm,
                        "pqc_status": "vulnerable",
                    }
                )
        except Exception as exc:
            errors.append(f"Record {idx}: {exc}")

    return {
        "status": "success" if not errors else "partial",
        "assets_found": len(assets),
        "findings_found": len(findings),
        "assets": assets,
        "findings": findings,
        "errors": errors,
    }


def scan_veeam_config(config_text: str) -> Dict[str, Any]:
    """Parse Veeam-style configuration text for encryption settings.

    This is a regex-based skeleton that looks for common keywords without
    requiring the Veeam PowerShell module.
    """
    if not config_text or not isinstance(config_text, str):
        return {"status": "error", "errors": ["Empty or invalid config text"]}

    software = _detect_software(config_text)
    encryption_enabled = bool(
        re.search(
            r"\bEnable\-?Encryption\s*[:=]\s*(true|yes|1)", config_text, re.IGNORECASE
        )
        or re.search(
            r"\bEncryption\s+Enabled\s*[:=]\s*(true|yes|1)", config_text, re.IGNORECASE
        )
    )

    algo_match = re.search(
        r"(?:Encryption\s+Algorithm|Algorithm)\s*[:=]\s*([A-Za-z0-9\-_\/]+)",
        config_text,
        re.IGNORECASE,
    )
    algorithm = algo_match.group(1) if algo_match else None

    classification = classify_backup_algorithm(algorithm)
    source = "veeam-config"

    asset = {
        "name": source,
        "asset_type": "backup_encryption",
        "discovery_source": "backup_scanner",
        "software": software,
        "encryption_enabled": encryption_enabled,
        "algorithm": algorithm,
        "pqc_status": (
            "vulnerable" if not encryption_enabled else classification["pqc_status"]
        ),
    }

    findings: List[Dict[str, Any]] = []
    if not encryption_enabled:
        findings.append(
            {
                "title": "Veeam backup encryption is not enabled",
                "severity": "critical",
                "finding_type": "backup_unencrypted",
                "asset": source,
                "pqc_status": "vulnerable",
            }
        )
    elif classification["pqc_status"] == "vulnerable":
        findings.append(
            {
                "title": f"Veeam backup uses quantum-vulnerable algorithm {algorithm}",
                "severity": "high",
                "finding_type": "backup_weak_encryption",
                "asset": source,
                "algorithm": algorithm,
                "pqc_status": "vulnerable",
            }
        )

    return {
        "status": "success",
        "software": software,
        "assets_found": 1,
        "findings_found": len(findings),
        "asset": asset,
        "findings": findings,
        "errors": [],
    }
