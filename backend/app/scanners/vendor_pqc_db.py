import logging
import shutil
from typing import Any, Dict

logger = logging.getLogger(__name__)

VENDOR_PQC_DB: Dict[str, Dict[str, Dict[str, Any]]] = {
    "openssl": {
        "3.0": {"ml_kem": False, "ml_dsa": False, "notes": "No PQC support"},
        "3.1": {"ml_kem": False, "ml_dsa": False, "notes": "No PQC support"},
        "3.2": {"ml_kem": False, "ml_dsa": False, "notes": "No PQC support"},
        "3.4": {"ml_kem": True, "ml_dsa": False, "notes": "ML-KEM via oqs-provider"},
        "3.5": {"ml_kem": True, "ml_dsa": True, "notes": "Native ML-KEM/ML-DSA support"},
    },
    "boringssl": {
        "2024-09": {"ml_kem": True, "ml_dsa": False, "notes": "X25519MLKEM768 enabled by default"},
    },
    "nss": {
        "3.101": {"ml_kem": True, "ml_dsa": False, "notes": "ML-KEM support added"},
    },
    "libressl": {
        "3.9": {"ml_kem": False, "ml_dsa": False, "notes": "No PQC support yet"},
    },
    "mbedtls": {
        "3.6": {"ml_kem": False, "ml_dsa": False, "notes": "No PQC support yet"},
    },
    "thales_luna": {
        "7.9": {"ml_kem": True, "ml_dsa": True, "notes": "PQC firmware update available"},
    },
    "aws_kms": {
        "2024-11": {"ml_kem": True, "ml_dsa": False, "notes": "ML-KEM key types available"},
    },
    "aws_cloudhsm": {
        "5.8": {"ml_kem": True, "ml_dsa": True, "notes": "Full PQC support"},
    },
    "azure_keyvault": {
        "2025-01": {"ml_kem": True, "ml_dsa": False, "notes": "ML-KEM preview"},
    },
    "windows": {
        "11_24H2": {"ml_kem": True, "ml_dsa": False, "notes": "ML-KEM via CNG"},
        "server_2025": {"ml_kem": True, "ml_dsa": True, "notes": "Full PQC via CNG"},
    },
    "openssh": {
        "8.9": {"ml_kem": False, "ml_dsa": False, "notes": "sntrup761x25519 experimental"},
        "9.0": {"ml_kem": False, "ml_dsa": False, "notes": "sntrup761x25519 experimental"},
        "9.5": {"ml_kem": False, "ml_dsa": False, "notes": "sntrup761x25519 available"},
        "9.9": {"ml_kem": True, "ml_dsa": False, "notes": "mlkem768x25519 support"},
    },
    "strongswan": {
        "5.9": {"ml_kem": False, "ml_dsa": False, "notes": "No PQC support yet"},
    },
    "libreswan": {
        "4.9": {"ml_kem": False, "ml_dsa": False, "notes": "No PQC support yet"},
    },
}


def _build_result(software: str, version: str, matched_version: str, info: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "software": software,
        "version": version,
        "matched_version": matched_version,
        "ml_kem": info["ml_kem"],
        "ml_dsa": info["ml_dsa"],
        "notes": info["notes"],
        "pqc_ready": info["ml_kem"] and info["ml_dsa"],
    }


def _unknown_result(software: str, version: str) -> Dict[str, Any]:
    return {
        "software": software,
        "version": version,
        "matched_version": None,
        "ml_kem": None,
        "ml_dsa": None,
        "notes": "Unknown — not in vendor database",
        "pqc_ready": None,
    }


def get_pqc_readiness(software: str, version: str) -> Dict[str, Any]:
    from packaging.version import Version, InvalidVersion

    sw_db = VENDOR_PQC_DB.get(software.lower(), {})

    try:
        target = Version(version)
    except InvalidVersion:
        # Fall back to string prefix matching for non-semver versions
        for db_version, info in sorted(sw_db.items(), reverse=True):
            if version.startswith(db_version) or db_version in version:
                return _build_result(software, version, db_version, info)
        return _unknown_result(software, version)

    best_match = None
    best_version = None
    for db_version, info in sw_db.items():
        try:
            dv = Version(db_version)
        except InvalidVersion:
            # Fall back to string checks if the database entry isn't valid semver
            if version.startswith(db_version) or db_version in version:
                # We prioritize valid semver matches, but keep track of this one
                if best_match is None:
                    best_match = (db_version, info)
            continue
        if dv <= target and (best_version is None or dv > best_version):
            best_version = dv
            best_match = (db_version, info)

    if best_match:
        return _build_result(software, version, best_match[0], best_match[1])
    return _unknown_result(software, version)

