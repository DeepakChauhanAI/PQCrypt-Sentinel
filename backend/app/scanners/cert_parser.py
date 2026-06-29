from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.x509.oid import ExtensionOID

from app.analysis.algo_classifier import (
    PQC_SIGNATURE_OIDS,
    HYBRID_SIGNATURE_OIDS,
    CLASSICAL_EDDSA_OIDS,
    CLASSICAL_X_OIDS,
    CLASSICAL_SIGNATURE_OIDS,
    CLASSICAL_KEX_OIDS,
)
from app.services.risk_service import is_disallowed_now


def _extract_key_usage(cert: x509.Certificate) -> List[str]:
    """Extract the X.509 Key Usage extension as a list of short names.

    Returns an empty list when the extension is absent. The order is
    stable: digitalSignature, nonRepudiation, keyEncipherment,
    dataEncipherment, keyAgreement, keyCertSign, cRLSign,
    encipherOnly, decipherOnly (only the enabled ones are included).
    """
    flags = [
        ("digitalSignature", "digital_signature"),
        ("nonRepudiation", "content_commitment"),
        ("keyEncipherment", "key_encipherment"),
        ("dataEncipherment", "data_encipherment"),
        ("keyAgreement", "key_agreement"),
        ("keyCertSign", "key_cert_sign"),
        ("cRLSign", "crl_sign"),
    ]
    result: List[str] = []
    try:
        ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    except x509.ExtensionNotFound:
        return result
    ku_val = ku_ext.value
    for short, attr in flags:
        if getattr(ku_val, attr, False):
            result.append(short)
    # encipherOnly / decipherOnly only meaningful when keyAgreement is set
    if getattr(ku_val, "key_agreement", False):
        if getattr(ku_val, "encipher_only", False):
            result.append("encipherOnly")
        if getattr(ku_val, "decipher_only", False):
            result.append("decipherOnly")
    return result


def classify_signature_algorithm(oid: str) -> Dict[str, Any]:
    """Classify signature algorithm OID as PQC, hybrid, safe classical, or vulnerable."""
    if oid in PQC_SIGNATURE_OIDS:
        return {
            "is_pqc": True,
            "is_hybrid": False,
            "name": PQC_SIGNATURE_OIDS[oid],
            "pqc_status": "pqc_ready",
        }
    elif oid in HYBRID_SIGNATURE_OIDS:
        return {
            "is_pqc": True,
            "is_hybrid": True,
            "name": HYBRID_SIGNATURE_OIDS[oid],
            "pqc_status": "hybrid",
        }
    elif oid in CLASSICAL_EDDSA_OIDS:
        return {
            "is_pqc": False,
            "is_hybrid": False,
            "name": CLASSICAL_EDDSA_OIDS[oid],
            "pqc_status": "vulnerable",
        }
    elif oid in CLASSICAL_X_OIDS:
        return {
            "is_pqc": False,
            "is_hybrid": False,
            "name": CLASSICAL_X_OIDS[oid],
            "pqc_status": "vulnerable",
        }
    elif oid in CLASSICAL_SIGNATURE_OIDS or oid in CLASSICAL_KEX_OIDS:
        return {
            "is_pqc": False,
            "is_hybrid": False,
            "name": CLASSICAL_SIGNATURE_OIDS.get(oid, CLASSICAL_KEX_OIDS.get(oid, f"unknown ({oid})")),
            "pqc_status": "vulnerable",
        }
    else:
        # Default unknown OIDs to "unknown" rather than "vulnerable"
        return {
            "is_pqc": False,
            "is_hybrid": False,
            "name": f"unknown ({oid})",
            "pqc_status": "unknown",
        }


def analyze_public_key(public_key: Any) -> Dict[str, Any]:
    """Analyze a public key for algorithm type, size, curve, and PQC status."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return {
            "pub_key_algorithm": "RSA",
            "pub_key_size": public_key.key_size,
            "curve_name": None,
            "pqc_capable": False,
            "pqc_status": "vulnerable",
        }
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return {
            "pub_key_algorithm": "EC",
            "pub_key_size": public_key.key_size,
            "curve_name": public_key.curve.name,
            "pqc_capable": False,
            "pqc_status": "vulnerable",
        }
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        return {
            "pub_key_algorithm": "Ed25519",
            "pub_key_size": 256,
            "curve_name": "curve25519",
            "pqc_capable": False,
            "pqc_status": "vulnerable",
        }
    elif isinstance(public_key, ed448.Ed448PublicKey):
        return {
            "pub_key_algorithm": "Ed448",
            "pub_key_size": 456,
            "curve_name": "curve448",
            "pqc_capable": False,
            "pqc_status": "vulnerable",
        }
    else:
        # PQC keys might be loaded as Generic or not fully typed depending on OpenSSL version
        try:
            der_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            # Basic fallback detection
            return {
                "pub_key_algorithm": "unknown_algo",
                "pub_key_size": len(der_bytes) * 8,
                "curve_name": None,
                "pqc_capable": False,
                "pqc_status": "unknown",
            }
        except Exception:
            return {
                "pub_key_algorithm": "unknown_algo",
                "pub_key_size": 0,
                "curve_name": None,
                "pqc_capable": False,
                "pqc_status": "unknown",
            }


def parse_certificate(pem_data: str) -> Dict[str, Any]:
    """Parse certificate PEM and return metadata compatible with database schemas."""
    # Ensure bytes
    pem_bytes = pem_data.encode("utf-8") if isinstance(pem_data, str) else pem_data
    cert = x509.load_pem_x509_certificate(pem_bytes)

    # Compute SHA-256 thumbprint
    thumbprint = cert.fingerprint(hashes.SHA256()).hex()

    # Signature OID
    sig_oid = cert.signature_algorithm_oid.dotted_string
    sig_classification = classify_signature_algorithm(sig_oid)

    # Public key info
    pub_key_info = analyze_public_key(cert.public_key())

    # Determine PQC-capable flag (signature OR pubkey is PQC)
    pqc_capable: bool = bool(sig_classification.get("is_pqc") or pub_key_info.get("pqc_capable"))

    # pqc_status: take signature status, but allow the pubkey to lift it
    pqc_status: str = sig_classification["pqc_status"]
    if pqc_status == "vulnerable" and pub_key_info.get("pqc_status") != "vulnerable":
        pqc_status = pub_key_info["pqc_status"]

    # Disallowed-now override: any signature algorithm that is broken
    # today (MD5, SHA-1, etc.) must be surfaced as disallowed_now,
    # not vulnerable.
    sig_algo_name = sig_classification.get("name", "")
    if is_disallowed_now(sig_algo_name) or is_disallowed_now(sig_oid):
        pqc_status = "disallowed_now"
        pqc_capable = False

    # Subject Alternative Names (SANs)
    san_dns: list[str] = []
    san_ip: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:  # type: ignore[attr-defined]
            if isinstance(name, x509.DNSName):
                san_dns.append(name.value)
            elif isinstance(name, x509.IPAddress):
                san_ip.append(str(name.value))
    except x509.ExtensionNotFound:
        pass

    # Basic constraints (CA)
    is_ca = False
    try:
        bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = bc_ext.value.ca  # type: ignore[attr-defined]
    except x509.ExtensionNotFound:
        pass

    # Key usages
    key_usage = _extract_key_usage(cert)

    pqc_details = {
        "oid": sig_oid,
        "algorithm_name": sig_classification["name"],
        "is_hybrid": sig_classification["is_hybrid"],
        "pqc_status": pqc_status,
        "hybrid_partner": "classical" if sig_classification["is_hybrid"] else None,
        "pqc_standard": "FIPS 204/205" if sig_classification["is_pqc"] else None,
    }

    # Validity timestamps
    # Prefer the UTC properties introduced in cryptography >= 3.2; fall back to naive
    # timestamps only for older versions (and explicitly mark them UTC rather than
    # silently trusting the local-timezone assumption of the old API).
    _cryptography_utc_supported = hasattr(x509.Certificate, "not_valid_before_utc")
    if _cryptography_utc_supported:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    else:
        # cryptography < 3.2 — naive timestamps; treat as UTC explicitly
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    # Check self-signed
    is_self_signed = cert.subject == cert.issuer

    return {
        "thumbprint": thumbprint,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": str(cert.serial_number),
        "sig_algorithm": sig_classification["name"],
        "pub_key_algorithm": pub_key_info["pub_key_algorithm"],
        "pub_key_size": pub_key_info["pub_key_size"],
        "curve_name": pub_key_info["curve_name"],
        "not_before": not_before,
        "not_after": not_after,
        "is_self_signed": is_self_signed,
        "is_ca": is_ca,
        "key_usage": key_usage,
        "san_dns": san_dns,
        "san_ip": san_ip,
        "pqc_capable": pqc_capable,
        "pqc_details": pqc_details,
        "raw_certificate": pem_data,
    }
