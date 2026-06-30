"""Code-signing verification skeleton.

Extracts and classifies embedded CMS/PKCS#7 signer certificates from
binaries (PE/EFI Authenticode, Mach-O, detached .p7s, etc.). This is a
skeleton: it surfaces the certificate chain and signature algorithms but
does not yet perform full Authenticode signature verification against a
trusted root or file hash.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from app.scanners.cert_parser import parse_certificate

logger = logging.getLogger(__name__)


def _extract_pem_blocks(text: str) -> List[str]:
    pattern = re.compile(
        r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
        re.DOTALL,
    )
    blocks: List[str] = []
    for match in pattern.finditer(text):
        body = match.group(1).replace(" ", "").replace("\r", "").replace("\n", "")
        blocks.append(
            "-----BEGIN CERTIFICATE-----\n"
            + "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
            + "\n-----END CERTIFICATE-----"
        )
    return blocks


def _load_cms_certificates(data: bytes) -> List[x509.Certificate]:
    """Try to load certificates from a DER CMS/PKCS#7 blob."""
    try:
        return pkcs7.load_der_pkcs7_certificates(data)
    except Exception:
        return []


def _find_pkcs7_blob(data: bytes) -> Optional[bytes]:
    """Heuristically locate a DER PKCS#7 blob inside a binary.

    Looks for an ASN.1 SEQUENCE (0x30 0x82) followed by the OID for
    signedData (1.2.840.113549.1.7.2). This is intentionally simple.
    """
    signed_data_oid = bytes.fromhex("06 09 2A 86 48 86 F7 0D 01 07 02".replace(" ", ""))
    idx = data.find(signed_data_oid)
    if idx == -1:
        return None
    # Walk back to find the enclosing SEQUENCE tag.
    start = max(0, idx - 4)
    while start > 0:
        if data[start] == 0x30 and data[start + 1] == 0x82:
            break
        start -= 1
    else:
        start = max(0, idx - 4)

    # Read length from the DER length bytes (0x82 means two-byte length).
    if start + 3 >= len(data):
        return None
    length = int.from_bytes(data[start + 2 : start + 4], "big")
    end = start + 4 + length
    if end > len(data):
        return data[start:]
    return data[start:end]


def verify_code_signature(
    file_path: str,
    trusted_root_certs: Optional[List[str]] = None,
    detached_content: Optional[bytes] = None,
) -> Dict[str, Any]:
    """Inspect a binary or detached signature for embedded certificates.

    Parameters
    ----------
    file_path: Path to the file to inspect.
    trusted_root_certs: Optional PEM strings of trusted roots. Not used yet
        by this skeleton but reserved for full chain verification.
    detached_content: Optional detached signed content for .p7s files.
        Not verified yet but reserved for future use.

    Returns
    -------
    Dictionary containing status, certificate chain metadata, and a PQC
    status summary.
    """
    path = Path(file_path)
    if not path.exists():
        return {
            "status": "error",
            "file_path": str(file_path),
            "signature_present": False,
            "certificates": [],
            "algorithms": [],
            "pqc_status": "unknown",
            "verification": "not_run",
            "errors": ["File not found"],
        }

    raw = path.read_bytes()
    certs: List[x509.Certificate] = []
    errors: List[str] = []

    # Try the whole file as a DER PKCS#7 (typical for .p7s).
    certs = _load_cms_certificates(raw)

    # If that fails, try to find an embedded signedData blob.
    if not certs:
        blob = _find_pkcs7_blob(raw)
        if blob:
            certs = _load_cms_certificates(blob)

    # Fallback: plain PEM certificates.
    if not certs:
        try:
            text = raw.decode("utf-8", errors="ignore")
            pem_blocks = _extract_pem_blocks(text)
            for pem in pem_blocks:
                try:
                    certs.append(x509.load_pem_x509_certificate(pem.encode("utf-8")))
                except Exception as exc:
                    errors.append(f"PEM parse failed: {exc}")
        except Exception as exc:
            errors.append(f"PEM extraction failed: {exc}")

    if not certs:
        return {
            "status": "success",
            "file_path": str(file_path),
            "signature_present": False,
            "certificates": [],
            "algorithms": [],
            "pqc_status": "unknown",
            "verification": "not_run",
            "errors": errors or ["No code-signing certificates found"],
        }

    parsed_certs: List[Dict[str, Any]] = []
    algorithms: List[str] = []
    statuses: List[str] = []

    for cert in certs:
        try:
            pem_bytes = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            meta = parse_certificate(pem_bytes)
            parsed_certs.append(meta)
            algo = meta.get("sig_algorithm") or "unknown"
            if algo not in algorithms:
                algorithms.append(algo)
            status = meta.get("pqc_details", {}).get("pqc_status", "unknown")
            if status not in statuses:
                statuses.append(status)
        except Exception as exc:
            errors.append(f"Certificate classification failed: {exc}")

    worst = "unknown"
    for candidate in ("disallowed_now", "vulnerable", "hybrid", "pqc_ready", "safe"):
        if candidate in statuses:
            worst = candidate
            break

    return {
        "status": "success" if not errors else "partial",
        "file_path": str(file_path),
        "signature_present": True,
        "certificates": parsed_certs,
        "algorithms": algorithms,
        "pqc_status": worst,
        "verification": "not_implemented",
        "errors": errors,
        "trusted_root_count": len(trusted_root_certs or []),
        "detached_content_provided": detached_content is not None,
    }
