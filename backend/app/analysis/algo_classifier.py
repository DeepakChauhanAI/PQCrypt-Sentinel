import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

# --- Pre-populated fallback dictionaries for tests and backward compatibility ---
PQC_KEX_GROUPS = {
    0x01FC: "ML-KEM-512",
    0x01FD: "ML-KEM-768",
    0x0200: "ML-KEM-1024",
    0x2B92: "SecP256r1MLKEM768",
    0x2B93: "X25519MLKEM768",
    0x2B94: "SecP384r1MLKEM1024",
    0xFE30: "X25519Kyber768Draft00",
    0x639A: "X25519Kyber768Draft00",
}

HYBRID_KEX_GROUPS = {
    0x2B92: "SecP256r1MLKEM768",
    0x2B93: "X25519MLKEM768",
    0x2B94: "SecP384r1MLKEM1024",
    0xFE30: "X25519Kyber768Draft00",
    0x639A: "X25519Kyber768Draft00",
}

PQC_SIGNATURE_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
    "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
    "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
    "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
    "1.3.6.1.4.1.62253.25642": "Falcon-512",
    "1.3.6.1.4.1.62253.25643": "Falcon-1024",
}

HYBRID_SIGNATURE_OIDS = {
    "2.16.840.1.114027.80.4.1": "RSA-3072 + ML-DSA-65",
    "2.16.840.1.114027.80.4.2": "P-384 + ML-DSA-65",
    "2.16.840.1.114027.80.4.3": "P-521 + ML-DSA-87",
}

CLASSICAL_EDDSA_OIDS = {
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

CLASSICAL_X_OIDS = {
    "1.3.101.110": "X25519",
    "1.3.101.111": "X448",
}

CLASSICAL_SIGNATURE_OIDS = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
}

CLASSICAL_KEX_OIDS = {
    "1.2.840.113549.1.3.1": "dhKeyAgreement",
    "1.3.132.1.12": "dhpublicnumber",
}

# --- Dynamic Registry Loading ---
REGISTRY_DATA: Dict[str, Any] = {}


def load_registry_file() -> Dict[str, Any]:
    possible_paths = [
        Path(__file__).resolve().parent.parent.parent.parent
        / "pqc_algorithm_registry.json",
        Path(__file__).resolve().parent.parent.parent / "pqc_algorithm_registry.json",
        Path.cwd() / "pqc_algorithm_registry.json",
        Path.cwd().parent / "pqc_algorithm_registry.json",
        Path("d:/Project Files/PQC_Scanner/pqc_algorithm_registry.json"),
    ]
    for path in possible_paths:
        if path.is_file():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
    return {}


REGISTRY_DATA = load_registry_file()


def update_mappings_from_registry():
    if not REGISTRY_DATA:
        return

    # 1. Update TLS groups
    tls_groups = REGISTRY_DATA.get("tls_iana_groups", {}).get("groups", {})
    for hex_id, group in tls_groups.items():
        try:
            int_id = int(hex_id, 16)
        except ValueError:
            continue
        name = group.get("name")
        status = group.get("status")
        gtype = group.get("type")
        if status in ("pqc_ready", "pqc_candidate", "hybrid") or gtype == "hybrid":
            PQC_KEX_GROUPS[int_id] = name
            if status == "hybrid" or gtype == "hybrid":
                HYBRID_KEX_GROUPS[int_id] = name

    # 2. Update IKEv2 groups
    ike_groups = REGISTRY_DATA.get("ikev2_groups", {}).get("groups", {})
    for dec_id, group in ike_groups.items():
        try:
            int_id = int(dec_id)
        except ValueError:
            continue
        name = group.get("name")
        status = group.get("status")
        if status in ("pqc_ready", "pqc_candidate", "hybrid"):
            PQC_KEX_GROUPS[int_id] = name
            if status == "hybrid":
                HYBRID_KEX_GROUPS[int_id] = name

    # 3. Update signature OIDs
    sig_oids = REGISTRY_DATA.get("signature_oids", {})
    for oid, details in sig_oids.items():
        name = details.get("name")
        status = details.get("status")
        if status in ("pqc_ready", "pqc_candidate"):
            PQC_SIGNATURE_OIDS[oid] = name
        elif status == "hybrid":
            clean_name = name.split(" (")[0]
            HYBRID_SIGNATURE_OIDS[oid] = clean_name
        elif status == "vulnerable" and any(
            kw in name.upper() for kw in ["ED25519", "ED448"]
        ):
            CLASSICAL_EDDSA_OIDS[oid] = name
        elif status in (
            "vulnerable",
            "disallowed_now",
            "deprecated_now",
            "safe_until_2030",
            "safe_until_2035",
        ):
            CLASSICAL_SIGNATURE_OIDS[oid] = name

    # 4. Update KEX OIDs
    kex_oids = REGISTRY_DATA.get("kex_oids", {})
    for oid, details in kex_oids.items():
        name = details.get("name")
        status = details.get("status")
        if status == "vulnerable" and any(
            kw in name.upper() for kw in ["X25519", "X448"]
        ):
            CLASSICAL_X_OIDS[oid] = name
        elif status in (
            "vulnerable",
            "disallowed_now",
            "deprecated_now",
            "safe_until_2030",
            "safe_until_2035",
        ):
            CLASSICAL_KEX_OIDS[oid] = name


update_mappings_from_registry()


def resolve_key_size_status(key_sizes_dict: dict, key_size: int) -> Optional[dict]:
    """Helper to match a key size against registry ranges/specifics."""
    for k, details in key_sizes_dict.items():
        if k.startswith("<"):
            try:
                val = int(k[1:])
                if key_size < val:
                    return details
            except ValueError:
                pass
        elif k.endswith("+"):
            try:
                val = int(k[:-1])
                if key_size >= val:
                    return details
            except ValueError:
                pass
        elif "-" in k:
            try:
                parts = k.split("-")
                low = int(parts[0])
                high = int(parts[1])
                if low <= key_size <= high:
                    return details
            except ValueError:
                pass
        else:
            try:
                val = int(k)
                if key_size == val:
                    return details
            except ValueError:
                pass
    return None


def resolve_curve_status(curves_dict: dict, name: str) -> Optional[dict]:
    """Helper to match a curve name against registry curves."""
    name_upper = name.upper()
    for curve_key, details in curves_dict.items():
        ck_clean = curve_key.upper().replace("-", "")
        if curve_key.upper() in name_upper or ck_clean in name_upper:
            return details
        if curve_key == "P-256" and "SECP256" in name_upper:
            return details
        if curve_key == "P-384" and "SECP384" in name_upper:
            return details
        if curve_key == "P-521" and "SECP521" in name_upper:
            return details
    return None


def _classify_cipher_suite(name: str, normalized_name: str) -> Optional[Dict[str, Any]]:
    """Detect and classify TLS cipher-suite names as a single logical algorithm.

    Cipher suites bundle a key-exchange/auth scheme with symmetric primitives.
    We classify the *most vulnerable* part that determines quantum risk:

    * TLS 1.3 suites (TLS_AES_*, TLS_CHACHA20_*) are safe because they only
      name symmetric AEAD primitives; the PQC risk lives in the negotiated
      key-exchange group, which is classified separately.
    * TLS 1.2 / static suites that use ECDHE, DHE, RSA, ECDSA, or DH for
      key exchange or authentication are quantum-vulnerable.

    Without this helper the generic parser extracts the AES key size and
    misattributes it to the RSA/ECDSA substring, causing e.g.
    ``ECDHE-RSA-AES256-GCM-SHA384`` to be reported as ``disallowed_now``.
    """
    if not normalized_name:
        return None

    upper = normalized_name

    # TLS 1.3 suites: symmetric-only names.
    if upper.startswith("TLS_") and any(
        upper.startswith(p) for p in ("TLS_AES_", "TLS_CHACHA20_")
    ):
        return {
            "pqc_status": "safe",
            "is_quantum_vulnerable": False,
            "is_pqc": False,
            "is_hybrid": False,
            "variant": name,
        }

    # OpenSSL/IANA short cipher-suite names that omit the key-exchange prefix,
    # e.g. ``AES256-GCM-SHA384`` (meaning TLS_RSA_WITH_AES_256_GCM_SHA384) or
    # ``AES128-SHA256``.  The regex matches AES[ -_]xxx-(GCM|CCM|CBC)-SHAxxx,
    # AES[ -_]xxx-SHAxxx patterns, plus ChaCha20-Poly1305-SHA256.
    short_suite_patterns = [
        r"\bAES[-_]?\d+[-_](?:GCM|CCM|CBC|CTR)[-_](?:SHA\d+|SHA|MD5)\b",
        r"\bAES[-_]?\d+[-_](?:SHA\d+|SHA|MD5)\b",
        r"\bCHACHA20[-_]POLY1305[-_](?:SHA\d+|SHA)\b",
    ]
    if any(re.search(p, upper) for p in short_suite_patterns):
        return {
            "pqc_status": "vulnerable",
            "is_quantum_vulnerable": True,
            "is_pqc": False,
            "is_hybrid": False,
            "variant": name,
        }

    # Any suite-like name that contains both a classical key-exchange/auth
    # primitive and a symmetric/MAC primitive is treated as vulnerable.
    has_key_exchange_or_auth = any(
        kw in upper
        for kw in ["_WITH_", "ECDHE", "DHE", "ECDH", "DH", "RSA", "ECDSA", "DSA"]
    )
    has_symmetric_or_mac = any(
        kw in upper
        for kw in [
            "AES",
            "CHACHA20",
            "3DES",
            "TRIPLEDES",
            "DES",
            "RC4",
            "CAMELLIA",
            "ARIA",
            "GCM",
            "CCM",
            "CBC",
            "SHA",
            "MD5",
        ]
    )

    if has_key_exchange_or_auth and has_symmetric_or_mac:
        # TLS 1.2 suites rely on classical key exchange / authentication.
        return {
            "pqc_status": "vulnerable",
            "is_quantum_vulnerable": True,
            "is_pqc": False,
            "is_hybrid": False,
            "variant": name,
        }

    return None


def classify_algorithm(
    name: str,
    oid: Optional[str] = None,
    algorithm_type: Optional[str] = None,
    kex_group_id: Optional[int] = None,
    key_size: Optional[int] = None,
) -> Dict[str, Any]:
    """Classify algorithm details into standard status flags using the PQC algorithm registry.

    Returns a dict with:
      * pqc_status: vulnerable | safe_until_2030 | safe | pqc_ready | hybrid | unknown | disallowed_now | deprecated_now
      * is_quantum_vulnerable: bool
      * is_pqc: bool
      * is_hybrid: bool
      * variant: per-spec parameterSetIdentifier (e.g. ML-KEM-768, ML-DSA-65,
        RSA-2048, ECDSA-P256, AES-128) — CBOM compliance
    """
    normalized_name = name.upper().strip() if name else ""

    # Treat cipher suites as a logical unit before decomposing individual tokens.
    cipher_classification = _classify_cipher_suite(name, normalized_name)
    if cipher_classification:
        return cipher_classification

    # Parse key size from name if not provided
    if key_size is None and normalized_name:
        m = re.search(r"RSA[_\-]?(\d{3,5})", normalized_name)
        if m:
            key_size = int(m.group(1))
        else:
            m = re.search(r"AES[-_]?(\d{3})", normalized_name)
            if m:
                key_size = int(m.group(1))
            else:
                m = re.search(r"DH[_\-]?(\d{3,5})", normalized_name)
                if m:
                    key_size = int(m.group(1))
                else:
                    m = re.search(
                        r"\b(512|1024|2048|3072|4096|8192)\b", normalized_name
                    )
                    if m:
                        key_size = int(m.group(1))

    # Parse curve from name if not provided
    curve_val = None
    if normalized_name:
        m = re.search(r"(?:SECP|P)(?:-|_)?(\d{3})", normalized_name)
        if m:
            curve_val = f"P-{m.group(1)}"
        elif "X25519" in normalized_name or "CURVE25519" in normalized_name:
            curve_val = "X25519"
        elif "X448" in normalized_name or "CURVE448" in normalized_name:
            curve_val = "X448"
        elif "ED25519" in normalized_name:
            curve_val = "Ed25519"
        elif "ED448" in normalized_name:
            curve_val = "Ed448"

    # Map key_size to standard curves for ECC if curve not found
    if (
        curve_val is None
        and key_size is not None
        and any(kw in normalized_name for kw in ("ECDSA", "ECDH", "EC"))
    ):
        if key_size == 192:
            curve_val = "P-192"
        elif key_size == 224:
            curve_val = "P-224"
        elif key_size == 256:
            curve_val = "P-256"
        elif key_size == 384:
            curve_val = "P-384"
        elif key_size == 521:
            curve_val = "P-521"

    # --- 1. Check by KEX group ID ---
    if kex_group_id is not None:
        tls_groups = REGISTRY_DATA.get("tls_iana_groups", {}).get("groups", {})
        ike_groups = REGISTRY_DATA.get("ikev2_groups", {}).get("groups", {})

        group_details = None
        hex_key = f"0x{kex_group_id:04X}"
        if hex_key in tls_groups:
            group_details = tls_groups[hex_key]
        elif str(kex_group_id) in ike_groups:
            group_details = ike_groups[str(kex_group_id)]

        if group_details:
            name_val = group_details.get("name")
            status = group_details.get("status", "unknown")
            gtype = group_details.get("type", "")

            is_pqc = (
                status in ("pqc_ready", "pqc_candidate", "hybrid") or gtype == "hybrid"
            )
            is_hybrid = status == "hybrid" or gtype == "hybrid"
            is_qv = status in (
                "vulnerable",
                "deprecated_now",
                "disallowed_now",
                "safe_until_2030",
                "safe_until_2035",
            )

            return {
                "pqc_status": status,
                "is_quantum_vulnerable": is_qv,
                "is_pqc": is_pqc,
                "is_hybrid": is_hybrid,
                "variant": name_val,
            }

        # Fallback to hardcoded groups
        if kex_group_id in PQC_KEX_GROUPS:
            is_hybrid = kex_group_id in HYBRID_KEX_GROUPS
            return {
                "pqc_status": "hybrid" if is_hybrid else "pqc_ready",
                "is_quantum_vulnerable": False,
                "is_pqc": True,
                "is_hybrid": is_hybrid,
                "variant": PQC_KEX_GROUPS[kex_group_id],
            }

    # --- 2. Check by OID ---
    if oid:
        sig_oids = REGISTRY_DATA.get("signature_oids", {})
        kex_oids = REGISTRY_DATA.get("kex_oids", {})

        oid_details = sig_oids.get(oid) or kex_oids.get(oid)
        if oid_details:
            name_val = oid_details.get("name")
            status = oid_details.get("status", "unknown")
            is_pqc = status in ("pqc_ready", "pqc_candidate", "hybrid")
            is_hybrid = status == "hybrid"
            is_qv = status in (
                "vulnerable",
                "deprecated_now",
                "disallowed_now",
                "safe_until_2030",
                "safe_until_2035",
            )

            return {
                "pqc_status": status,
                "is_quantum_vulnerable": is_qv,
                "is_pqc": is_pqc,
                "is_hybrid": is_hybrid,
                "variant": name_val,
            }

        # Fallback to hardcoded OID lookups
        if oid in PQC_SIGNATURE_OIDS:
            name_val = PQC_SIGNATURE_OIDS[oid]
            is_candidate = any(
                kw in name_val.upper()
                for kw in [
                    "FALCON",
                    "FN-DSA",
                    "HQC",
                    "BIKE",
                    "MCELIECE",
                    "FRODO",
                    "NTRU",
                    "SNTRUP761",
                ]
            )
            return {
                "pqc_status": "pqc_candidate" if is_candidate else "pqc_ready",
                "is_quantum_vulnerable": False,
                "is_pqc": True,
                "is_hybrid": False,
                "variant": name_val,
            }
        elif oid in HYBRID_SIGNATURE_OIDS:
            return {
                "pqc_status": "hybrid",
                "is_quantum_vulnerable": False,
                "is_pqc": True,
                "is_hybrid": True,
                "variant": HYBRID_SIGNATURE_OIDS[oid],
            }
        elif oid in CLASSICAL_EDDSA_OIDS:
            return {
                "pqc_status": "vulnerable",
                "is_quantum_vulnerable": True,
                "is_pqc": False,
                "is_hybrid": False,
                "variant": CLASSICAL_EDDSA_OIDS[oid],
            }
        elif oid in CLASSICAL_X_OIDS:
            return {
                "pqc_status": "vulnerable",
                "is_quantum_vulnerable": True,
                "is_pqc": False,
                "is_hybrid": False,
                "variant": CLASSICAL_X_OIDS[oid],
            }
        elif oid in CLASSICAL_SIGNATURE_OIDS:
            return {
                "pqc_status": "vulnerable",
                "is_quantum_vulnerable": True,
                "is_pqc": False,
                "is_hybrid": False,
                "variant": CLASSICAL_SIGNATURE_OIDS[oid],
            }
        elif oid in CLASSICAL_KEX_OIDS:
            return {
                "pqc_status": "vulnerable",
                "is_quantum_vulnerable": True,
                "is_pqc": False,
                "is_hybrid": False,
                "variant": CLASSICAL_KEX_OIDS[oid],
            }
        else:
            return {
                "pqc_status": "unknown",
                "is_quantum_vulnerable": False,
                "is_pqc": False,
                "is_hybrid": False,
            }

    # --- 3. Check common_misclassifications ---
    if normalized_name:
        for entry in REGISTRY_DATA.get("common_misclassifications", {}).get(
            "entries", []
        ):
            algo_entry = entry.get("algorithm", "").upper()
            if normalized_name == algo_entry or normalized_name.replace(
                "-", ""
            ) == algo_entry.replace("-", ""):
                status = entry.get("correct_classification", "unknown")
                is_pqc = status in ("pqc_ready", "pqc_candidate", "hybrid")
                is_hybrid = status == "hybrid"
                is_qv = status in (
                    "vulnerable",
                    "deprecated_now",
                    "disallowed_now",
                    "safe_until_2030",
                    "safe_until_2035",
                )
                return {
                    "pqc_status": status,
                    "is_quantum_vulnerable": is_qv,
                    "is_pqc": is_pqc,
                    "is_hybrid": is_hybrid,
                    "variant": entry.get("algorithm"),
                }

    # --- 4. Check OID registry names ---
    if normalized_name:
        for oid_map in (
            REGISTRY_DATA.get("signature_oids", {}),
            REGISTRY_DATA.get("kex_oids", {}),
        ):
            for oid_key, details in oid_map.items():
                name_val = details.get("name", "")
                if normalized_name == name_val.upper() or normalized_name.replace(
                    "-", ""
                ) == name_val.upper().replace("-", ""):
                    status = details.get("status", "unknown")
                    is_pqc = status in ("pqc_ready", "pqc_candidate", "hybrid")
                    is_hybrid = status == "hybrid"
                    is_qv = status in (
                        "vulnerable",
                        "deprecated_now",
                        "disallowed_now",
                        "safe_until_2030",
                        "safe_until_2035",
                    )
                    return {
                        "pqc_status": status,
                        "is_quantum_vulnerable": is_qv,
                        "is_pqc": is_pqc,
                        "is_hybrid": is_hybrid,
                        "variant": name_val,
                    }

    # --- 5. Check by Name in registry algorithms lists ---
    if normalized_name:
        all_categories = REGISTRY_DATA.get("algorithms", {})
        for cat_name, cat_data in all_categories.items():
            for algo in cat_data.get("algorithms", []):
                algo_name = algo.get("name", "")
                aliases = [a.upper() for a in algo.get("also_known_as", [])]

                match_found = False
                if normalized_name == algo_name.upper():
                    match_found = True
                elif normalized_name.replace("-", "") == algo_name.upper().replace(
                    "-", ""
                ):
                    match_found = True
                elif normalized_name in aliases:
                    match_found = True
                elif algo_name.upper() in normalized_name:
                    if algo_name.upper() in (
                        "RSA",
                        "ECDSA",
                        "ECDH",
                        "DSA",
                        "DH",
                        "AES",
                        "SHA",
                        "CAMELLIA",
                        "ARIA",
                        "HMAC",
                    ):
                        # Avoid mis-matching DSA for ECDSA or DH for ECDH
                        if algo_name.upper() == "DSA" and any(
                            kw in normalized_name
                            for kw in (
                                "ECDSA",
                                "ML-DSA",
                                "SLH-DSA",
                                "MLDSA",
                                "SLHDSA",
                                "FN-DSA",
                                "FNDSA",
                            )
                        ):
                            pass
                        elif algo_name.upper() == "DH" and "ECDH" in normalized_name:
                            pass
                        else:
                            match_found = True

                if match_found:
                    status_details = None
                    if "key_sizes" in algo and key_size is not None:
                        status_details = resolve_key_size_status(
                            algo["key_sizes"], key_size
                        )
                    elif "curves" in algo and curve_val is not None:
                        status_details = resolve_curve_status(algo["curves"], curve_val)

                    target_details = status_details if status_details else algo
                    status = target_details.get("status", "unknown")

                    # Default generic public-key algorithms to "vulnerable" if not specified/resolved
                    if (status == "unknown" or not status) and algo_name.upper() in (
                        "RSA",
                        "ECDSA",
                        "ECDH",
                        "DH",
                    ):
                        status = "vulnerable"

                    is_pqc = (
                        cat_name
                        in (
                            "post_quantum_key_encapsulation",
                            "post_quantum_signatures",
                            "hybrids",
                        )
                        or "pqc" in status
                    )
                    is_hybrid = cat_name == "hybrids" or status == "hybrid"
                    is_qv = status in (
                        "vulnerable",
                        "deprecated_now",
                        "disallowed_now",
                        "safe_until_2030",
                        "safe_until_2035",
                    )

                    variant_val = algo_name
                    if key_size:
                        variant_val = f"{algo_name}-{key_size}"
                    elif curve_val:
                        variant_val = f"{algo_name}-{curve_val}"
                    else:
                        variant_val = name

                    # Normalize variant names to match standard CBOM / test conventions
                    variant_upper = (
                        variant_val.upper().replace("-", "").replace("_", "")
                    )
                    if "AES" in variant_upper:
                        m = re.search(r"AES[_\-]?(\d{3})", variant_val.upper())
                        if m:
                            variant_val = f"AES-{m.group(1)}"
                    elif "ECDSA" in variant_upper and curve_val:
                        variant_val = f"ECDSA-{curve_val.replace('-', '')}"
                    elif "ECDH" in variant_upper and curve_val:
                        variant_val = f"ECDH-{curve_val.replace('-', '')}"
                    elif any(
                        kw in variant_upper
                        for kw in ("3DES", "TRIPLEDES", "DESEDE", "TDEA")
                    ):
                        variant_val = "3DES"

                    return {
                        "pqc_status": status,
                        "is_quantum_vulnerable": is_qv,
                        "is_pqc": is_pqc,
                        "is_hybrid": is_hybrid,
                        "variant": variant_val,
                    }

    # --- 5. Fallback to hardcoded / original classification logic ---
    pqc_keywords = [
        "ML-KEM",
        "KYBER",
        "ML-DSA",
        "DILITHIUM",
        "FALCON",
        "SLH-DSA",
        "SPHINCS",
        "FN-DSA",
        "HQC",
        "BIKE",
        "MCELIECE",
        "FRODO",
        "NTRU",
        "SNTRUP",
    ]
    is_pqc = any(kw in normalized_name for kw in pqc_keywords)
    is_hybrid = False

    if is_pqc:
        if (
            "X25519" in normalized_name
            or "SECP" in normalized_name
            or "P256" in normalized_name
            or "P384" in normalized_name
        ):
            is_hybrid = True
        elif "+" in name or "COMPOSITE" in normalized_name:
            is_hybrid = True

    if any(
        group in normalized_name
        for group in ["X25519MLKEM768", "SECP256R1MLKEM768", "SECP384R1MLKEM1024"]
    ):
        is_pqc = True
        is_hybrid = True

    if is_hybrid:
        return {
            "pqc_status": "hybrid",
            "is_quantum_vulnerable": False,
            "is_pqc": True,
            "is_hybrid": True,
            "variant": name,
        }
    elif is_pqc:
        is_candidate = any(
            kw in normalized_name
            for kw in [
                "FALCON",
                "FN-DSA",
                "HQC",
                "BIKE",
                "MCELIECE",
                "FRODO",
                "NTRU",
                "SNTRUP761",
            ]
        )
        return {
            "pqc_status": "pqc_candidate" if is_candidate else "pqc_ready",
            "is_quantum_vulnerable": False,
            "is_pqc": True,
            "is_hybrid": False,
            "variant": name,
        }

    if any(
        kw in normalized_name
        for kw in ["3DES", "TRIPLEDES", "TRIPLE-DES", "DES-EDE", "DES_EDE"]
    ):
        return {
            "pqc_status": "disallowed_now",
            "is_quantum_vulnerable": True,
            "is_pqc": False,
            "is_hybrid": False,
            "variant": "3DES",
        }

    if "AES" in normalized_name:
        if key_size:
            if key_size < 128:
                return {
                    "pqc_status": "vulnerable",
                    "is_quantum_vulnerable": True,
                    "is_pqc": False,
                    "is_hybrid": False,
                    "variant": f"AES-{key_size}",
                }
            elif key_size == 128:
                return {
                    "pqc_status": "safe_until_2030",
                    "is_quantum_vulnerable": True,
                    "is_pqc": False,
                    "is_hybrid": False,
                    "variant": "AES-128",
                }
            elif key_size == 192:
                return {
                    "pqc_status": "safe_until_2030",
                    "is_quantum_vulnerable": True,
                    "is_pqc": False,
                    "is_hybrid": False,
                    "variant": "AES-192",
                }
            elif key_size == 256:
                return {
                    "pqc_status": "safe",
                    "is_quantum_vulnerable": False,
                    "is_pqc": False,
                    "is_hybrid": False,
                    "variant": "AES-256",
                }

    if any(kw in normalized_name for kw in ["ED25519", "ED448"]):
        return {
            "pqc_status": "vulnerable",
            "is_quantum_vulnerable": True,
            "is_pqc": False,
            "is_hybrid": False,
            "variant": name if "ED25519" in normalized_name else "Ed448",
        }

    if any(
        kw in normalized_name for kw in ["X25519", "X448", "CURVE25519", "CURVE448"]
    ):
        variant = (
            "X25519"
            if ("X25519" in normalized_name or "CURVE25519" in normalized_name)
            else "X448"
        )
        return {
            "pqc_status": "vulnerable",
            "is_quantum_vulnerable": True,
            "is_pqc": False,
            "is_hybrid": False,
            "variant": variant,
        }

    is_vulnerable = False
    status_val = "vulnerable"
    if any(
        kw in normalized_name
        for kw in ["RSA", "ECDSA", "ECDH", "DSA", "DH", "ELGAMAL", "GOST", "SM2", "SRP"]
    ):
        is_vulnerable = True
        has_disallowed = (
            "MD5" in normalized_name
            or "SHA1" in normalized_name
            or "SHA-1" in normalized_name
            or ("DSA" in normalized_name and "ECDSA" not in normalized_name)
            or (
                "RSA" in normalized_name
                and any(sz in normalized_name for sz in ["1024", "512"])
            )
        )
        if has_disallowed:
            status_val = "disallowed_now"

    if is_vulnerable:
        variant = name
        m = re.search(r"RSA[_\-]?(\d{3,5})", normalized_name)
        if m:
            variant = f"RSA-{m.group(1)}"
        else:
            m = re.search(r"(?:SECP|P)(?:-|_)?(\d{3})", normalized_name)
            if m:
                variant = f"EC-P{m.group(1)}"
        return {
            "pqc_status": status_val,
            "is_quantum_vulnerable": True,
            "is_pqc": False,
            "is_hybrid": False,
            "variant": variant,
        }

    return {
        "pqc_status": "unknown",
        "is_quantum_vulnerable": False,
        "is_pqc": False,
        "is_hybrid": False,
    }


def get_deprecation_deadline_year(name: str, key_size: Optional[int] = None) -> int:
    """Get the deprecation deadline year for a cryptographic algorithm.
    Uses the registry classification if possible.
    """
    # 1. Classify algorithm first
    classification = classify_algorithm(name, key_size=key_size)
    status = classification.get("pqc_status", "unknown")

    # 2. Look up specific OID or name details in registry for a direct deadline_year
    normalized_name = name.upper().strip() if name else ""

    if REGISTRY_DATA:
        all_categories = REGISTRY_DATA.get("algorithms", {})
        for cat_name, cat_data in all_categories.items():
            for algo in cat_data.get("algorithms", []):
                algo_name = algo.get("name", "")
                aliases = [a.upper() for a in algo.get("also_known_as", [])]

                match_found = False
                if normalized_name == algo_name.upper():
                    match_found = True
                elif normalized_name.replace("-", "") == algo_name.upper().replace(
                    "-", ""
                ):
                    match_found = True
                elif normalized_name in aliases:
                    match_found = True
                elif algo_name.upper() in normalized_name:
                    if algo_name.upper() in (
                        "RSA",
                        "ECDSA",
                        "ECDH",
                        "DSA",
                        "DH",
                        "AES",
                        "SHA",
                        "CAMELLIA",
                        "ARIA",
                        "HMAC",
                    ):
                        # Avoid mis-matching DSA for ECDSA or DH for ECDH
                        if algo_name.upper() == "DSA" and any(
                            kw in normalized_name
                            for kw in (
                                "ECDSA",
                                "ML-DSA",
                                "SLH-DSA",
                                "MLDSA",
                                "SLHDSA",
                                "FN-DSA",
                                "FNDSA",
                            )
                        ):
                            pass
                        elif algo_name.upper() == "DH" and "ECDH" in normalized_name:
                            pass
                        else:
                            match_found = True

                if match_found:
                    status_details = None
                    if "key_sizes" in algo and key_size is not None:
                        status_details = resolve_key_size_status(
                            algo["key_sizes"], key_size
                        )
                    elif "curves" in algo:
                        # Parse curve
                        curve_val_temp = None
                        m = re.search(r"(?:SECP|P)(?:-|_)?(\d{3})", normalized_name)
                        if m:
                            curve_val_temp = f"P-{m.group(1)}"
                        elif (
                            "X25519" in normalized_name
                            or "CURVE25519" in normalized_name
                        ):
                            curve_val_temp = "X25519"
                        elif "X448" in normalized_name or "CURVE448" in normalized_name:
                            curve_val_temp = "X448"
                        elif key_size is not None and any(
                            kw in normalized_name for kw in ("ECDSA", "ECDH", "EC")
                        ):
                            if key_size == 192:
                                curve_val_temp = "P-192"
                            elif key_size == 224:
                                curve_val_temp = "P-224"
                            elif key_size == 256:
                                curve_val_temp = "P-256"
                            elif key_size == 384:
                                curve_val_temp = "P-384"
                            elif key_size == 521:
                                curve_val_temp = "P-521"

                        if curve_val_temp:
                            status_details = resolve_curve_status(
                                algo["curves"], curve_val_temp
                            )

                    if status_details and "deadline_year" in status_details:
                        return status_details["deadline_year"]
                    if "deadline_year" in algo:
                        return algo["deadline_year"]

    # 3. Fallback to status definitions deadline_year in registry
    if REGISTRY_DATA:
        status_defs = REGISTRY_DATA.get("status_definitions", {})
        if status in status_defs:
            dl = status_defs[status].get("deadline_year")
            if dl is not None:
                return dl

    # 4. Fallback to original hardcoded timeline
    name_upper = name.upper() if name else ""
    pqc_keywords = [
        "ML-KEM",
        "KYBER",
        "ML-DSA",
        "DILITHIUM",
        "FALCON",
        "SLH-DSA",
        "SPHINCS",
    ]
    if any(kw in name_upper for kw in pqc_keywords):
        return 2099

    if any(kw in name_upper for kw in ["ED25519", "ED448", "X25519", "X448"]):
        return 2035

    if "AES" in name_upper:
        size = key_size or 128
        if size >= 256:
            return 2099
        return 2030

    if "SHA-512" in name_upper or "SHA-384" in name_upper:
        return 2099
    if "SHA-256" in name_upper or "SHA-224" in name_upper:
        return 2030
    if "SHA-1" in name_upper or "SHA1" in name_upper:
        return 2026

    if "RSA" in name_upper:
        size = key_size or 2048
        if size < 2048:
            return 2026
        elif size < 3072:
            return 2030
        else:
            return 2035

    if "ECDSA" in name_upper or "ECDH" in name_upper or "EC" in name_upper:
        size = key_size or 256
        if size < 256:
            return 2026
        elif size < 384:
            return 2030
        else:
            return 2035

    if "DH" in name_upper or "FFDH" in name_upper or "DIFFIE" in name_upper:
        size = key_size or 2048
        if size < 2048:
            return 2026
        elif size < 3072:
            return 2030
        else:
            return 2035

    return 2030
