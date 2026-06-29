"""
Cryptographic Asset Risk Service.

Implements a weighted multi-factor risk scoring model that combines:
    * Data Sensitivity (Mosca's HNDL theorem)    (30%)
    * System exposure                            (20%)
    * Algorithm vulnerability                    (20%)
    * Replaceability                             (15%)  [NEW in 5-dim model]
    * Regulatory deadline proximity              (15%)

The legacy "Business Criticality" dimension has been folded into Exposure
(fold: tier_0/tier_1 raise the system exposure to "internet"/"dmz"). The
Replaceability dimension captures the operational cost of swapping the
primitive (e.g. HSM firmware uplift vs. software library rekey).

The model also classifies algorithms into a "disallowed-now" bucket for
primitives that are already cryptographically broken or have been disallowed
by NIST / CA/Browser Forum (e.g. MD5, SHA-1, DES, 3DES, RSA < 2048, RC4).
"""

from datetime import datetime
from typing import Any, List, Optional

from app.analysis.algo_classifier import get_deprecation_deadline_year
from app.analysis.mosca_model import calculate_hndl_exposure


# Algorithms that are disallowed NOW (forbidden by NIST SP 800-131A Rev.2,
# CA/Browser Forum, or otherwise cryptographically broken).
DISALLOWED_NOW_PATTERNS = {
    # Hash
    "md5", "md-5", "md4", "md-4", "md2", "md-2",
    "sha-1", "sha1", "ripemd", "whirlpool",
    # Symmetric
    "des", "3des", "triple-des", "tripledes", "rc2", "rc4", "rc5",
    # Key exchange / asymmetric
    "rsa-512", "rsa-768", "rsa-1024",
    "dsa-512", "dsa-768", "dsa-1024",
    "dh-768", "dh-1024",
    # Signature
    "ecdsa-sha1", "ecdsa-with-sha1",
    # Protocol
    "ssl 2.0", "ssl 3.0", "tls 1.0", "tls 1.1",
    "ssl 2-0", "ssl 3-0", "tls 1-0", "tls 1-1",
    "sslv2", "sslv3", "tlsv1.0", "tlsv1.1", "tlsv1",
}


def is_disallowed_now(algorithm: str) -> bool:
    """
    Return True if the given algorithm name is cryptographically disallowed
    for use today (NIST SP 800-131A Rev.2, etc.).
    """
    if not algorithm:
        return False
    normalized = algorithm.lower().strip()
    # Build alternate normalised forms (with dots, dashes, and stripped).
    forms = {
        normalized,
        normalized.replace("_", "-").replace(".", "-"),
        normalized.replace(" ", "").replace("_", "").replace(".", "").replace("-", ""),
    }
    for form in forms:
        for pat in DISALLOWED_NOW_PATTERNS:
            # Match both with and without spaces.
            if pat in form or pat.replace(" ", "") in form:
                return True
    # Catch RSA/ECC with sub-acceptable key sizes
    upper = algorithm.upper()
    if "RSA" in upper:
        import re
        m = re.search(r"RSA[_\-\.]?(\d{3,5})", upper)
        if m and int(m.group(1)) < 2048:
            return True
    return False


def derive_data_longevity_years(
    asset: Optional[Any] = None,
    cert_data: Optional[Any] = None,
    finding_type: Optional[str] = None,
    kex_algos: Optional[List[str]] = None,
) -> int:
    """
    Derive the data longevity (sensitivity window) for an asset or finding
    in years. This is the X value in Mosca's inequality (X + Y > Z):
    how long must the data remain confidential beyond the migration window.

    Default: 5 years (typical regulated data retention).
    Heuristics:
      * Certificate/Key with `keyEncipherment` or `dataEncipherment` -> 25y
      * PKI Root CA / HSM / KMS -> 30y (long-lived trust anchors)
      * Production environment -> 10y
      * Staging / dev -> 3y
      * SSH / VPN KEX (transient session secrets) -> 25y (SNDL still relevant
        for long-lived credentials that traverse the connection)
    """
    base = 5

    # Long-lived key usage implies long confidentiality requirement.
    if cert_data is not None:
        key_usage: list[str] = []
        if isinstance(cert_data, dict):
            key_usage = cert_data.get("key_usage") or []
        else:
            key_usage = getattr(cert_data, "key_usage", None) or []
        if "keyEncipherment" in key_usage or "dataEncipherment" in key_usage:
            base = max(base, 25)

    if finding_type in {"ssh_weak_kex", "vpn_weak_ike"} or kex_algos:
        base = max(base, 25)

    # HSM / KMS / CA assets have long-lived secrets.
    if asset is not None:
        asset_type = getattr(asset, "asset_type", "")
        if asset_type in {"hsm", "kms", "certificate_authority"}:
            base = max(base, 30)
        env = (getattr(asset, "environment", "") or "").lower()
        if env == "production":
            base = max(base, 10)
        elif env in {"staging", "preprod", "development"}:
            base = min(base, 3)
    return base


def derive_hndl_exposure(
    asset: Optional[Any] = None,
    cert_data: Optional[Any] = None,
    finding_type: Optional[str] = None,
    kex_algos: Optional[List[str]] = None,
    quantum_timeline_year: Optional[int] = None,
) -> str:
    """
    Derive HNDL (Harvest Now, Decrypt Later) exposure for an asset/finding
    using Mosca's theorem applied to its metadata.
    """
    longevity = derive_data_longevity_years(
        asset=asset,
        cert_data=cert_data,
        finding_type=finding_type,
        kex_algos=kex_algos,
    )
    return calculate_hndl_exposure(longevity, quantum_timeline_year)


def derive_replaceability(
    asset: Optional[Any] = None,
    finding_type: Optional[str] = None,
    algorithm: Optional[str] = None,
    key_size: Optional[int] = None,
) -> str:
    """
    Derive the operational replaceability of a primitive on a 5-point scale.

    Higher replaceability_score means it is HARDER to replace (i.e. higher
    risk if the primitive is broken). 5 = HSM firmware uplift or 30-year
    trust anchor rotation; 1 = drop-in library swap.

    Heuristics:
      * HSM / KMS / CA: hard (5)
      * Production TLS termination: medium-hard (4)
      * Production SSH KEX / VPN IKE: medium (3) (rekey + bounce)
      * Software library: low (1)
      * dev / test environments: low (1)
      * SSH KEX, IKE: medium (3) — requires service restart / rekey
    """
    if asset is not None:
        asset_type = getattr(asset, "asset_type", "")
        if asset_type in {"hsm", "kms", "certificate_authority"}:
            return "hard"
        env = (getattr(asset, "environment", "") or "").lower()
        if env in {"development", "testing", "staging", "preprod"}:
            return "low"

    if finding_type in {"ssh_weak_kex", "vpn_weak_ike", "ike_weak_dh", "tls_weak_kex"}:
        return "medium"
    if finding_type in {"sast_weak_crypto"}:
        return "low"
    return "medium"


def calculate_risk_score(
    asset: Optional[Any] = None,
    cert: Optional[Any] = None,
    algorithms: Optional[List[Any]] = None,
    hndl_exposure: Optional[str] = None,
    system_exposure: Optional[str] = None,
    pqc_status: Optional[str] = None,
    replaceability: Optional[str] = None,
    years_to_deadline: Optional[int] = None,
    algorithm: Optional[str] = None,
    key_size: Optional[int] = None,
    finding_type: Optional[str] = None,
    kex_algos: Optional[List[str]] = None,
    # Legacy / fold-in parameters (kept for back-compat)
    business_criticality: Optional[str] = None,
) -> int:
    """
    Calculate a cryptographic asset risk score (5-25 raw, displayed 0-100).

    5-dim model (locked 2026-06-05):
        1. Data Sensitivity (HNDL / Mosca)         30%
        2. System Exposure                         20%
        3. Algorithm Vulnerability                 20%
        4. Replaceability (operational cost)       15%
        5. Regulatory Deadline Proximity           15%
    """
    # Resolve system_exposure from asset if not provided.
    if system_exposure is None and asset is not None:
        asset_type = getattr(asset, "asset_type", "")
        if asset_type in ["web_app", "api", "load_balancer"]:
            system_exposure = "internet"
        else:
            system_exposure = "internal"
    if system_exposure is None:
        system_exposure = "internal"

    # Fold legacy business_criticality into exposure (tier_0 -> internet, tier_1 -> dmz).
    if business_criticality is not None and asset is None:
        bcl = business_criticality.lower()
        if bcl == "tier_0":
            system_exposure = "internet"
        elif bcl == "tier_1":
            system_exposure = "dmz"
    if asset is not None and business_criticality is not None:
        env = getattr(asset, "environment", "").lower()
        if env == "production" or business_criticality.lower() == "tier_0":
            system_exposure = "internet"
        elif env in ["staging", "preprod"] or business_criticality.lower() == "tier_1":
            system_exposure = "dmz"

    # Resolve pqc_status
    if pqc_status is None:
        pqc_status = "vulnerable"
        if cert is not None:
            pqc_capable = getattr(cert, "pqc_capable", False)
            sig_algo = getattr(cert, "sig_algorithm", "") or ""
            if pqc_capable:
                pqc_status = "pqc_ready"
            elif is_disallowed_now(sig_algo):
                pqc_status = "disallowed_now"
            else:
                pqc_status = "vulnerable"
        elif algorithms:
            statuses = [getattr(a, "pqc_status", "vulnerable") for a in algorithms]
            if "disallowed_now" in statuses:
                pqc_status = "disallowed_now"
            elif "vulnerable" in statuses:
                pqc_status = "vulnerable"
            elif "hybrid" in statuses:
                pqc_status = "hybrid"
            elif "pqc_ready" in statuses:
                pqc_status = "pqc_ready"
            elif "safe" in statuses:
                pqc_status = "safe"

    # Resolve HNDL exposure via Mosca if not provided
    if hndl_exposure is None:
        hndl_exposure = derive_hndl_exposure(
            asset=asset,
            cert_data=cert,
            finding_type=finding_type,
            kex_algos=kex_algos,
        )

    # Resolve replaceability
    if replaceability is None:
        replaceability = derive_replaceability(
            asset=asset,
            finding_type=finding_type,
            algorithm=algorithm,
            key_size=key_size,
        )

    # Resolve years_to_deadline
    if years_to_deadline is None:
        algo_name = algorithm
        if not algo_name and cert:
            algo_name = getattr(cert, "sig_algorithm", "")
        if not algo_name and algorithms:
            algo_name = getattr(algorithms[0], "algorithm_name", "")

        size = key_size
        if not size and cert:
            size = getattr(cert, "pub_key_size", None)
        if not size and algorithms:
            size = getattr(algorithms[0], "key_size", None)

        deadline_year = get_deprecation_deadline_year(algo_name or "", size)
        years_to_deadline = max(0, deadline_year - datetime.now().year)

    # 1. Data Sensitivity / HNDL (1-5) - 30%
    hndl_scores = {"none": 1, "low": 2, "medium": 3, "high": 5}
    hndl_score = hndl_scores.get(hndl_exposure.lower(), 1)

    # 2. System Exposure (1-5) - 20%
    exposure_scores = {"internal": 1, "dmz": 3, "internet": 5}
    exposure_score = exposure_scores.get(system_exposure.lower(), 1)

    # 3. Algorithm Vulnerability (1-5) - 20%
    algo_scores = {
        "pqc_ready": 1,
        "safe": 1,
        "hybrid": 2,
        "transitioning": 3,
        "vulnerable": 5,
        "disallowed_now": 5,
        "unknown": 4,
    }
    algo_score = algo_scores.get(pqc_status.lower(), 4)

    # 4. Replaceability (1-5) - 15% (NEW)
    replaceability_scores = {
        "low": 1,        # drop-in library swap
        "medium": 3,     # service restart / rekey
        "hard": 5,       # HSM firmware uplift, CA re-issuance
    }
    replaceability_score = replaceability_scores.get(replaceability.lower(), 3)

    # 5. Regulatory Deadline Proximity (1-5) - 15%
    if years_to_deadline < 2:
        deadline_score = 5
    elif years_to_deadline < 4:
        deadline_score = 4
    elif years_to_deadline < 6:
        deadline_score = 3
    elif years_to_deadline < 10:
        deadline_score = 2
    else:
        deadline_score = 1

    # Sum of subscores 5-25; expose the raw value.
    total_score = (
        hndl_score
        + exposure_score
        + algo_score
        + replaceability_score
        + deadline_score
    )
    return int(total_score)


def risk_score_to_percent(raw: int) -> int:
    """Convert raw 5-25 score to a 0-100 percentage (linear mapping)."""
    pct = (raw - 5) / 20.0 * 100.0
    return max(0, min(100, int(round(pct))))


# 5-dim weight breakdown (kept as a public record for tests / dashboards).
RISK_WEIGHTS_5DIM = {
    "data_sensitivity": 0.30,
    "exposure": 0.20,
    "algorithm": 0.20,
    "replaceability": 0.15,
    "regulatory": 0.15,
}
