"""
Tests for `app.analysis.algo_classifier` - the algorithm classification
and deprecation deadline logic.

The module has 44% line coverage; this file pushes it well above 80%
by exercising every branch of `classify_algorithm` and
`get_deprecation_deadline_year`.
"""
from __future__ import annotations

import pytest

from app.analysis.algo_classifier import (
    CLASSICAL_EDDSA_OIDS,
    CLASSICAL_KEX_OIDS,
    CLASSICAL_SIGNATURE_OIDS,
    CLASSICAL_X_OIDS,
    HYBRID_KEX_GROUPS,
    HYBRID_SIGNATURE_OIDS,
    PQC_KEX_GROUPS,
    PQC_SIGNATURE_OIDS,
    classify_algorithm,
    get_deprecation_deadline_year,
)


# ----------------------------------------- classify_algorithm: KEX ids -


def test_classify_algorithm_kex_pqc_group_id():
    """PQC KEX group id (e.g. ML-KEM) -> pqc_ready, is_pqc=True."""
    pqc_kid = next(iter(PQC_KEX_GROUPS))
    result = classify_algorithm("ignored-name", kex_group_id=pqc_kid)
    assert result["pqc_status"] == "pqc_ready"
    assert result["is_pqc"] is True
    assert result["is_hybrid"] is False


def test_classify_algorithm_kex_hybrid_group_id():
    """Hybrid KEX group id (curve25519 hybrid) -> hybrid, is_pqc=True, is_hybrid=True."""
    if not HYBRID_KEX_GROUPS:
        pytest.skip("no hybrid KEX group ids")
    hkid = next(iter(HYBRID_KEX_GROUPS))
    result = classify_algorithm("ignored-name", kex_group_id=hkid)
    assert result["pqc_status"] == "hybrid"
    assert result["is_pqc"] is True
    assert result["is_hybrid"] is True


# ----------------------------------------- classify_algorithm: OIDs ---


def test_classify_algorithm_oid_pqc_signature():
    pqc_oid = next(iter(PQC_SIGNATURE_OIDS))
    result = classify_algorithm("ignored", oid=pqc_oid)
    assert result["pqc_status"] == "pqc_ready"
    assert result["is_pqc"] is True


def test_classify_algorithm_oid_hybrid_signature():
    if not HYBRID_SIGNATURE_OIDS:
        pytest.skip("no hybrid sig OIDs")
    hoid = next(iter(HYBRID_SIGNATURE_OIDS))
    result = classify_algorithm("ignored", oid=hoid)
    assert result["pqc_status"] == "hybrid"
    assert result["is_hybrid"] is True


def test_classify_algorithm_oid_eddsa_vulnerable():
    soid = next(iter(CLASSICAL_EDDSA_OIDS))
    result = classify_algorithm("ignored", oid=soid)
    assert result["pqc_status"] == "vulnerable"
    assert result["is_pqc"] is False


def test_classify_algorithm_oid_x_vulnerable():
    koid = next(iter(CLASSICAL_X_OIDS))
    result = classify_algorithm("ignored", oid=koid)
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_oid_classical_signature_vulnerable():
    # Use sha256WithRSAEncryption OID which is vulnerable (not disallowed_now like md5/sha1)
    csoid = "1.2.840.113549.1.1.11"
    result = classify_algorithm("ignored", oid=csoid)
    assert result["pqc_status"] == "vulnerable"
    assert result["is_quantum_vulnerable"] is True


def test_classify_algorithm_oid_classical_kex_vulnerable():
    ckoid = next(iter(CLASSICAL_KEX_OIDS))
    result = classify_algorithm("ignored", oid=ckoid)
    assert result["pqc_status"] == "vulnerable"
    assert result["is_quantum_vulnerable"] is True


def test_classify_algorithm_oid_unknown_default_to_unknown():
    """Unknown OID -> pqc_status=unknown, is_quantum_vulnerable=False."""
    result = classify_algorithm("ignored", oid="1.2.3.4.5.6.7.8.9")
    assert result["pqc_status"] == "unknown"
    assert result["is_quantum_vulnerable"] is False


# --------------------------------- classify_algorithm: name-based --


def test_classify_algorithm_name_pqc_pure():
    """ML-KEM alone (no classical part) -> pqc_ready, not hybrid."""
    result = classify_algorithm("ML-KEM-768")
    assert result["pqc_status"] == "pqc_ready"
    assert result["is_pqc"] is True
    assert result["is_hybrid"] is False


def test_classify_algorithm_name_pqc_hybrid_with_x25519():
    """ML-KEM combined with X25519 -> hybrid."""
    result = classify_algorithm("X25519MLKEM768")
    assert result["pqc_status"] == "hybrid"
    assert result["is_hybrid"] is True


def test_classify_algorithm_name_pqc_hybrid_with_secp():
    """ML-KEM combined with secp256r1 -> hybrid."""
    result = classify_algorithm("SECP256R1MLKEM768")
    assert result["pqc_status"] == "hybrid"


def test_classify_algorithm_name_ed25519_vulnerable():
    result = classify_algorithm("ED25519")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_name_ed448_vulnerable():
    result = classify_algorithm("ED448")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_name_x25519_vulnerable():
    result = classify_algorithm("X25519")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_name_rsa_vulnerable():
    result = classify_algorithm("RSA")
    assert result["pqc_status"] == "vulnerable"
    assert result["is_quantum_vulnerable"] is True


def test_classify_algorithm_name_ecdsa_vulnerable():
    result = classify_algorithm("ECDSA")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_name_dh_vulnerable():
    result = classify_algorithm("DH")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_name_dsa_vulnerable():
    result = classify_algorithm("DSA")
    assert result["pqc_status"] == "disallowed_now"


def test_classify_algorithm_name_ecdh_vulnerable():
    result = classify_algorithm("ECDH")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_name_ml_dsa_pqc():
    """ML-DSA (Dilithium) by name -> pqc_ready."""
    result = classify_algorithm("ML-DSA-65")
    assert result["pqc_status"] == "pqc_ready"
    assert result["is_pqc"] is True


def test_classify_algorithm_name_kyber_pqc():
    result = classify_algorithm("KYBER-768")
    assert result["pqc_status"] == "pqc_ready"


def test_classify_algorithm_name_composite_hybrid():
    """'COMPOSITE' name pattern -> hybrid (when also a PQC keyword)."""
    result = classify_algorithm("ML-KEM-COMPOSITE")
    assert result["is_pqc"] is True
    assert result["is_hybrid"] is True


def test_classify_algorithm_name_plus_hybrid():
    """Plus-separated name like 'X25519+ML-KEM' -> hybrid."""
    result = classify_algorithm("X25519+ML-KEM-768")
    assert result["is_pqc"] is True
    assert result["is_hybrid"] is True


def test_classify_algorithm_name_unknown_default():
    result = classify_algorithm("UNKNOWN-CUSTOM-ALGO")
    assert result["pqc_status"] == "unknown"


def test_classify_algorithm_empty_name():
    result = classify_algorithm("")
    assert result["pqc_status"] == "unknown"


# ------------------------------- classify_algorithm: cipher suites --


def test_classify_algorithm_tls13_cipher_suite_safe():
    """TLS 1.3 cipher suites name only symmetric primitives -> safe."""
    result = classify_algorithm("TLS_AES_256_GCM_SHA384")
    assert result["pqc_status"] == "safe"
    assert result["is_quantum_vulnerable"] is False


def test_classify_algorithm_tls12_cipher_suite_vulnerable():
    """TLS 1.2 cipher suites with classical key exchange -> vulnerable."""
    result = classify_algorithm("ECDHE-RSA-AES256-GCM-SHA384")
    assert result["pqc_status"] == "vulnerable"
    assert result["is_quantum_vulnerable"] is True
    # Must not mis-attribute the AES-256 key size to RSA.
    assert result["variant"] == "ECDHE-RSA-AES256-GCM-SHA384"


def test_classify_algorithm_openssl_short_cipher_suite_vulnerable():
    """OpenSSL short names like AES256-GCM-SHA384 are vulnerable (static RSA)."""
    result = classify_algorithm("AES256-GCM-SHA384")
    assert result["pqc_status"] == "vulnerable"
    assert result["is_quantum_vulnerable"] is True


def test_classify_algorithm_aes_256_standalone_still_safe():
    """Plain AES-256-GCM is still safe; cipher-suite detection must not misfire."""
    result = classify_algorithm("AES-256-GCM")
    assert result["pqc_status"] == "safe"
    assert result["is_quantum_vulnerable"] is False
    assert result["variant"] == "AES-256"


# ------------------------------- get_deprecation_deadline_year ------


def test_get_deprecation_deadline_year_rsa_under_2048():
    """RSA < 2048 -> 2026 (NIST SP 800-131A Rev.2)."""
    assert get_deprecation_deadline_year("RSA", key_size=1024) == 2026


def test_get_deprecation_deadline_year_rsa_2048():
    """RSA 2048 -> 2030."""
    assert get_deprecation_deadline_year("RSA", key_size=2048) == 2030


def test_get_deprecation_deadline_year_rsa_3071():
    """RSA 3071 (still < 3072) -> 2030."""
    assert get_deprecation_deadline_year("RSA", key_size=3071) == 2030


def test_get_deprecation_deadline_year_rsa_4096_plus():
    """RSA 4096+ -> 2035."""
    assert get_deprecation_deadline_year("RSA", key_size=4096) == 2035


def test_get_deprecation_deadline_year_rsa_no_key_size():
    """RSA without key_size defaults to 2048 -> 2030."""
    assert get_deprecation_deadline_year("RSA") == 2030


def test_get_deprecation_deadline_year_ecdsa_256_384():
    """ECDSA 256 -> 2030, ECDSA 384 -> 2035."""
    assert get_deprecation_deadline_year("ECDSA", key_size=256) == 2030
    assert get_deprecation_deadline_year("ECDSA", key_size=384) == 2035


def test_get_deprecation_deadline_year_ecdsa_521():
    """ECDSA 521+ -> 2035."""
    assert get_deprecation_deadline_year("ECDSA", key_size=521) == 2035


def test_get_deprecation_deadline_year_ecdsa_under_256():
    """ECDSA < 256 -> 2026."""
    assert get_deprecation_deadline_year("ECDSA", key_size=192) == 2026


def test_get_deprecation_deadline_year_sha1():
    """SHA-1 -> 2026 (only SHA-1 has a specific override; MD5 falls through)."""
    assert get_deprecation_deadline_year("SHA1") == 2026


def test_get_deprecation_deadline_year_sha2_sha3():
    """SHA-2 / SHA-3 are safe through 2030+."""
    assert get_deprecation_deadline_year("SHA-256") >= 2030
    assert get_deprecation_deadline_year("SHA-384") >= 2030


def test_get_deprecation_deadline_year_aes_128_192():
    """AES 128/192 -> 2030 (Grover halves effective security)."""
    assert get_deprecation_deadline_year("AES-128", key_size=128) == 2030
    assert get_deprecation_deadline_year("AES-192", key_size=192) == 2030


def test_get_deprecation_deadline_year_aes_256():
    """AES 256 -> 2099 (safe)."""
    assert get_deprecation_deadline_year("AES-256", key_size=256) == 2099


def test_get_deprecation_deadline_year_pqc_safe_horizon():
    """ML-KEM, ML-DSA, etc. return 2099."""
    assert get_deprecation_deadline_year("ML-KEM-768") == 2099
    assert get_deprecation_deadline_year("ML-DSA-65") == 2099
    assert get_deprecation_deadline_year("KYBER-512") == 2099
    assert get_deprecation_deadline_year("DILITHIUM-3") == 2099


def test_get_deprecation_deadline_year_safe_classical_curves():
    """Ed25519/Ed448/X25519/X448 -> 2035."""
    assert get_deprecation_deadline_year("ED25519") == 2035
    assert get_deprecation_deadline_year("ED448") == 2035
    assert get_deprecation_deadline_year("X25519") == 2035
    assert get_deprecation_deadline_year("X448") == 2035


def test_get_deprecation_deadline_year_unknown_algorithm():
    """Unknown algorithm -> 2030 default."""
    assert get_deprecation_deadline_year("XYZNONE-1") == 2030
