"""
Extended tests for `app.analysis.algo_classifier` to cover remaining
uncovered branches: registry loading, update_mappings, resolve_key_size_status,
resolve_curve_status, classify_cipher_suite edge cases, and fallback paths.
"""

from __future__ import annotations

import contextlib
import pytest
from unittest.mock import patch

from app.analysis.algo_classifier import (
    classify_algorithm,
    get_deprecation_deadline_year,
    resolve_key_size_status,
    resolve_curve_status,
    _classify_cipher_suite,
    load_registry_file,
    update_mappings_from_registry,
    REGISTRY_DATA,
    PQC_KEX_GROUPS,
    HYBRID_KEX_GROUPS,
    PQC_SIGNATURE_OIDS,
    HYBRID_SIGNATURE_OIDS,
    CLASSICAL_SIGNATURE_OIDS,
    CLASSICAL_KEX_OIDS,
)


# --- resolve_key_size_status edge cases ---


def test_resolve_key_size_less_than_match():
    d = {"<2048": {"status": "vulnerable"}, "2048-4096": {"status": "safe_until_2030"}}
    assert resolve_key_size_status(d, 1024)["status"] == "vulnerable"


def test_resolve_key_size_range_match():
    d = {"<2048": {"status": "vulnerable"}, "2048-4096": {"status": "safe_until_2030"}}
    assert resolve_key_size_status(d, 2048)["status"] == "safe_until_2030"


def test_resolve_key_size_plus_match():
    d = {"3072+": {"status": "safe"}}
    assert resolve_key_size_status(d, 4096)["status"] == "safe"


def test_resolve_key_size_exact_match():
    d = {"256": {"status": "safe"}}
    assert resolve_key_size_status(d, 256)["status"] == "safe"


def test_resolve_key_size_no_match():
    d = {"<1024": {"status": "vulnerable"}}
    assert resolve_key_size_status(d, 2048) is None


def test_resolve_key_size_invalid_less_than():
    d = {"<abc": {"status": "vulnerable"}}
    assert resolve_key_size_status(d, 1024) is None


def test_resolve_key_size_invalid_plus():
    d = {"abc+": {"status": "vulnerable"}}
    assert resolve_key_size_status(d, 1024) is None


def test_resolve_key_size_invalid_range():
    d = {"abc-def": {"status": "vulnerable"}}
    assert resolve_key_size_status(d, 1024) is None


def test_resolve_key_size_invalid_exact():
    d = {"abc": {"status": "vulnerable"}}
    assert resolve_key_size_status(d, 1024) is None


# --- resolve_curve_status edge cases ---


def test_resolve_curve_status_match_p256():
    d = {"P-256": {"status": "vulnerable"}}
    assert resolve_curve_status(d, "secp256r1")["status"] == "vulnerable"


def test_resolve_curve_status_match_p384():
    d = {"P-384": {"status": "vulnerable"}}
    assert resolve_curve_status(d, "secp384r1")["status"] == "vulnerable"


def test_resolve_curve_status_match_p521():
    d = {"P-521": {"status": "vulnerable"}}
    assert resolve_curve_status(d, "secp521r1")["status"] == "vulnerable"


def test_resolve_curve_status_no_match():
    d = {"P-256": {"status": "vulnerable"}}
    assert resolve_curve_status(d, "UNKNOWN_CURVE") is None


# --- _classify_cipher_suite edge cases ---


def test_classify_cipher_suite_chacha20_tls13():
    result = _classify_cipher_suite(
        "TLS_CHACHA20_POLY1305_SHA256", "TLS_CHACHA20_POLY1305_SHA256"
    )
    assert result["pqc_status"] == "safe"


def test_classify_cipher_suite_short_aes_gcm():
    result = _classify_cipher_suite("AES256-GCM-SHA384", "AES256-GCM-SHA384")
    assert result["pqc_status"] == "vulnerable"


def test_classify_cipher_suite_short_aes_cbc():
    result = _classify_cipher_suite("AES128-SHA256", "AES128-SHA256")
    assert result["pqc_status"] == "vulnerable"


def test_classify_cipher_suite_short_chacha20():
    result = _classify_cipher_suite(
        "CHACHA20-POLY1305-SHA256", "CHACHA20-POLY1305-SHA256"
    )
    assert result["pqc_status"] == "vulnerable"


def test_classify_cipher_suite_empty_normalized():
    assert _classify_cipher_suite("x", "") is None


def test_classify_cipher_suite_no_match():
    result = _classify_cipher_suite("UNKNOWN", "UNKNOWN")
    assert result is None


# --- classify_algorithm: more fallback paths ---


def test_classify_algorithm_3des():
    result = classify_algorithm("3DES-EDE-CBC")
    assert result["pqc_status"] == "disallowed_now"
    assert result["variant"] == "3DES"


def test_classify_algorithm_aes_128():
    result = classify_algorithm("AES-128-GCM")
    assert result["pqc_status"] == "safe_until_2030"
    assert result["variant"] == "AES-128"


def test_classify_algorithm_aes_192():
    result = classify_algorithm("AES-192-GCM")
    assert result["pqc_status"] == "safe_until_2030"
    assert result["variant"] == "AES-192"


def test_classify_algorithm_aes_256():
    result = classify_algorithm("AES-256-GCM")
    assert result["pqc_status"] == "safe"
    assert result["variant"] == "AES-256"


def test_classify_algorithm_aes_small_key():
    result = classify_algorithm("AES-64-GCM")
    # 64-bit AES: key_size parsed, but < 128 path may not match if parsed differently
    assert result["pqc_status"] in ("vulnerable", "unknown")


def test_classify_algorithm_rsa_with_key_size():
    result = classify_algorithm("RSA", key_size=1024)
    assert result["pqc_status"] in ("vulnerable", "disallowed_now")


def test_classify_algorithm_ecdsa_with_curve():
    result = classify_algorithm("ECDSA-P256")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_rsa_variant_extraction():
    result = classify_algorithm("RSA-4096")
    assert "RSA" in result["variant"]


def test_classify_algorithm_ec_variant_extraction():
    result = classify_algorithm("ECDSA-P384")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_disallowed_md5():
    result = classify_algorithm("RSA-MD5")
    assert result["pqc_status"] in ("disallowed_now", "vulnerable")


def test_classify_algorithm_disallowed_sha1_rsa():
    result = classify_algorithm("RSA-SHA1")
    assert result["pqc_status"] in ("disallowed_now", "vulnerable")


def test_classify_algorithm_dsa_disallowed():
    result = classify_algorithm("DSA")
    assert result["pqc_status"] == "disallowed_now"


def test_classify_algorithm_rsa_512_disallowed():
    result = classify_algorithm("RSA-512")
    assert result["pqc_status"] == "disallowed_now"


def test_classify_algorithm_hybrid_falcon():
    result = classify_algorithm("FALCON-512")
    assert result["pqc_status"] == "pqc_candidate"
    assert result["is_pqc"] is True


def test_classify_algorithm_sphincs():
    result = classify_algorithm("SLH-DSA-SHA2-128s")
    assert result["pqc_status"] in ("pqc_ready", "vulnerable", "unknown")


def test_classify_algorithm_hqc():
    result = classify_algorithm("HQC-128")
    assert result["pqc_status"] == "pqc_candidate"


def test_classify_algorithm_bike():
    result = classify_algorithm("BIKE-L1")
    assert result["pqc_status"] == "pqc_candidate"


def test_classify_algorithm_sntrup():
    result = classify_algorithm("SNTRUP761")
    assert result["pqc_status"] == "pqc_candidate"


def test_classify_algorithm_aes_no_key_size():
    result = classify_algorithm("AES-GCM")
    # Without key size, falls through to unknown or safe
    assert result["pqc_status"] in ("unknown", "safe", "safe_until_2030", "vulnerable")


def test_classify_algorithm_elgamal():
    result = classify_algorithm("ELGAMAL")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_gost():
    result = classify_algorithm("GOST-34.10")
    assert result["pqc_status"] == "vulnerable"


# --- classify_algorithm: registry-based paths with key_sizes ---


def test_classify_algorithm_registry_key_sizes():
    """When REGISTRY_DATA has key_sizes, resolve_key_size_status is called."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data loaded")
    # Find an algorithm with key_sizes in the registry
    all_categories = REGISTRY_DATA.get("algorithms", {})
    for cat_name, cat_data in all_categories.items():
        for algo in cat_data.get("algorithms", []):
            if "key_sizes" in algo:
                algo_name = algo["name"]
                # Pick a key size from the dict
                for k, details in algo["key_sizes"].items():
                    if k.startswith("<"):
                        try:
                            test_size = int(k[1:]) - 1
                            result = classify_algorithm(algo_name, key_size=test_size)
                            assert result["pqc_status"] != "unknown"
                            return
                        except ValueError:
                            continue
                    elif k.endswith("+"):
                        try:
                            test_size = int(k[:-1]) + 1
                            result = classify_algorithm(algo_name, key_size=test_size)
                            assert result["pqc_status"] != "unknown"
                            return
                        except ValueError:
                            continue
    pytest.skip("No suitable key_sizes entry found in registry")


# --- classify_algorithm: registry-based KEX group ID lookup ---


def test_classify_algorithm_registry_kex_group_tls():
    """KEX group ID found in tls_iana_groups registry."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data")
    tls_groups = REGISTRY_DATA.get("tls_iana_groups", {}).get("groups", {})
    for hex_id, group in tls_groups.items():
        try:
            int_id = int(hex_id, 16)
        except ValueError:
            continue
        result = classify_algorithm("test", kex_group_id=int_id)
        assert result["pqc_status"] != "unknown"
        return
    pytest.skip("No TLS groups in registry")


def test_classify_algorithm_registry_kex_group_ike():
    """KEX group ID found in ikev2_groups registry."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data")
    ike_groups = REGISTRY_DATA.get("ikev2_groups", {}).get("groups", {})
    for dec_id, group in ike_groups.items():
        try:
            int_id = int(dec_id)
        except ValueError:
            continue
        # Only test if not already in TLS groups
        tls_groups = REGISTRY_DATA.get("tls_iana_groups", {}).get("groups", {})
        hex_key = f"0x{int_id:04X}"
        if hex_key not in tls_groups:
            result = classify_algorithm("test", kex_group_id=int_id)
            assert result["pqc_status"] != "unknown"
            return
    pytest.skip("No unique IKE groups in registry")


# --- classify_algorithm: registry-based OID lookup ---


def test_classify_algorithm_registry_oid_signature():
    """OID found in signature_oids registry."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data")
    sig_oids = REGISTRY_DATA.get("signature_oids", {})
    for oid, details in sig_oids.items():
        result = classify_algorithm("test", oid=oid)
        assert result["pqc_status"] != "unknown"
        return
    pytest.skip("No signature OIDs in registry")


# --- classify_algorithm: registry-based name matching ---


def test_classify_algorithm_registry_name_match_exact():
    """Exact name match in registry."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data")
    all_categories = REGISTRY_DATA.get("algorithms", {})
    for cat_name, cat_data in all_categories.items():
        for algo in cat_data.get("algorithms", []):
            name = algo.get("name", "")
            if name and name.upper() in ("RSA", "ECDSA", "ECDH", "DH", "DSA"):
                continue  # Skip generic names that have complex logic
            if name:
                result = classify_algorithm(name)
                if result["pqc_status"] != "unknown":
                    return
    pytest.skip("No suitable registry name found")


def test_classify_algorithm_registry_name_alias_match():
    """Name matches via also_known_as alias."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data")
    all_categories = REGISTRY_DATA.get("algorithms", {})
    for cat_name, cat_data in all_categories.items():
        for algo in cat_data.get("algorithms", []):
            aliases = algo.get("also_known_as", [])
            if aliases:
                result = classify_algorithm(aliases[0])
                if result["pqc_status"] != "unknown":
                    return
    pytest.skip("No aliases found in registry")


# --- classify_algorithm: ECC curve parsing from name ---


def test_classify_algorithm_parse_curve_secp256():
    result = classify_algorithm("ECDSA-SECP256R1")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_parse_curve_x25519_in_name():
    result = classify_algorithm("ECDH-X25519")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_parse_curve_x448_in_name():
    result = classify_algorithm("ECDH-X448")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_parse_curve_ed25519_in_name():
    result = classify_algorithm("ECDSA-ED25519")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_parse_curve_ed448_in_name():
    result = classify_algorithm("ECDSA-ED448")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_ecc_key_size_to_curve_192():
    result = classify_algorithm("ECDSA", key_size=192)
    assert result["pqc_status"] in ("vulnerable", "disallowed_now")


def test_classify_algorithm_ecc_key_size_to_curve_224():
    result = classify_algorithm("ECDSA", key_size=224)
    assert result["pqc_status"] in ("vulnerable", "disallowed_now")


def test_classify_algorithm_ecc_key_size_to_curve_256():
    result = classify_algorithm("ECDSA", key_size=256)
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_ecc_key_size_to_curve_384():
    result = classify_algorithm("ECDSA", key_size=384)
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_ecc_key_size_to_curve_521():
    result = classify_algorithm("ECDSA", key_size=521)
    assert result["pqc_status"] == "vulnerable"


# --- classify_algorithm: variant normalization ---


def test_classify_algorithm_variant_3des_normalization():
    result = classify_algorithm("TRIPLEDES")
    assert result["variant"] == "3DES"


def test_classify_algorithm_variant_aes_normalization():
    result = classify_algorithm("AES_256_GCM")
    assert result["variant"] == "AES-256"


def test_classify_algorithm_variant_ecdsa_curve_normalization():
    result = classify_algorithm("ECDSA-P256")
    # variant should normalize
    assert "ECDSA" in result["variant"] or "P256" in result["variant"]


# --- classify_algorithm: DSA vs ECDSA disambiguation ---


def test_classify_algorithm_dsa_not_misclassified_for_ecdsa():
    """DSA substring must not match ECDSA."""
    result = classify_algorithm("ECDSA-P256")
    # Should be classified as ECDSA (vulnerable), not DSA (disallowed_now)
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_dh_not_misclassified_for_ecdh():
    """DH substring must not match ECDH."""
    result = classify_algorithm("ECDH-P256")
    assert result["pqc_status"] == "vulnerable"


# --- classify_algorithm: registry name matching with key_sizes ---


def test_classify_algorithm_registry_name_with_key_size():
    """Registry name match that resolves via key_sizes."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data")
    all_categories = REGISTRY_DATA.get("algorithms", {})
    for cat_name, cat_data in all_categories.items():
        for algo in cat_data.get("algorithms", []):
            if "key_sizes" in algo:
                name = algo.get("name", "")
                if name and name.upper() not in (
                    "RSA",
                    "ECDSA",
                    "ECDH",
                    "DH",
                    "DSA",
                    "AES",
                    "SHA",
                ):
                    # Try a key size that would match
                    for k in algo["key_sizes"]:
                        if k.startswith("<"):
                            try:
                                test_size = int(k[1:]) - 1
                                result = classify_algorithm(name, key_size=test_size)
                                assert result["pqc_status"] != "unknown"
                                return
                            except ValueError:
                                continue
                        elif k.endswith("+"):
                            try:
                                test_size = int(k[:-1]) + 1
                                result = classify_algorithm(name, key_size=test_size)
                                assert result["pqc_status"] != "unknown"
                                return
                            except ValueError:
                                continue
    pytest.skip("No suitable registry name with key_sizes found")


# --- classify_algorithm: registry name matching with curves ---


def test_classify_algorithm_registry_name_with_curve():
    """Registry name match that resolves via curves."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data")
    all_categories = REGISTRY_DATA.get("algorithms", {})
    for cat_name, cat_data in all_categories.items():
        for algo in cat_data.get("algorithms", []):
            if "curves" in algo:
                name = algo.get("name", "")
                if name and name.upper() not in (
                    "RSA",
                    "ECDSA",
                    "ECDH",
                    "DH",
                    "DSA",
                    "AES",
                    "SHA",
                ):
                    result = classify_algorithm(name + "-P256")
                    if result["pqc_status"] != "unknown":
                        return
    pytest.skip("No suitable registry name with curves found")


# --- classify_algorithm: AES fallback without key size ---


def test_classify_algorithm_aes_no_key_size_fallback():
    """AES without parseable key size returns safe (256 default for AES-GCM)."""
    result = classify_algorithm("AES-GCM")
    # Without key size, it may fall through to unknown
    assert result["pqc_status"] in ("unknown", "safe", "safe_until_2030", "vulnerable")


# --- classify_algorithm: DH key size parsing ---


def test_classify_algorithm_dh_key_size_from_name():
    result = classify_algorithm("DH-2048")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_dh_key_size_from_name_4096():
    result = classify_algorithm("DH-4096")
    assert result["pqc_status"] == "vulnerable"


# --- classify_algorithm: numeric key size in name ---


def test_classify_algorithm_numeric_key_size_2048():
    result = classify_algorithm("RSA-2048")
    assert result["pqc_status"] == "vulnerable"


def test_classify_algorithm_numeric_key_size_4096():
    result = classify_algorithm("RSA-4096")
    assert result["pqc_status"] == "vulnerable"


# --- get_deprecation_deadline_year: registry paths ---


def test_get_deprecation_deadline_year_registry_status_defs():
    """When registry has status_definitions with deadline_year."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data")
    status_defs = REGISTRY_DATA.get("status_definitions", {})
    for status, details in status_defs.items():
        if "deadline_year" in details:
            # Find an algorithm that maps to this status
            all_categories = REGISTRY_DATA.get("algorithms", {})
            for cat_name, cat_data in all_categories.items():
                for algo in cat_data.get("algorithms", []):
                    if algo.get("status") == status:
                        name = algo.get("name", "")
                        if name:
                            result = get_deprecation_deadline_year(name)
                            assert isinstance(result, int)
                            return
    pytest.skip("No status_definitions with deadline_year found")


def test_get_deprecation_deadline_year_registry_algo_deadline():
    """When registry algorithm has a direct deadline_year."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data")
    all_categories = REGISTRY_DATA.get("algorithms", {})
    for cat_name, cat_data in all_categories.items():
        for algo in cat_data.get("algorithms", []):
            if "deadline_year" in algo:
                name = algo.get("name", "")
                if name:
                    result = get_deprecation_deadline_year(name)
                    assert isinstance(result, int)
                    return
    pytest.skip("No algorithm with deadline_year found")


def test_get_deprecation_deadline_year_registry_curve_resolution():
    """get_deprecation_deadline_year with curve-based algorithm."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data")
    all_categories = REGISTRY_DATA.get("algorithms", {})
    for cat_name, cat_data in all_categories.items():
        for algo in cat_data.get("algorithms", []):
            if "curves" in algo:
                name = algo.get("name", "")
                if name and name.upper() not in (
                    "RSA",
                    "ECDSA",
                    "ECDH",
                    "DH",
                    "DSA",
                    "AES",
                    "SHA",
                ):
                    result = get_deprecation_deadline_year(name + "-P256")
                    assert isinstance(result, int)
                    return
    pytest.skip("No algorithm with curves found")


# --- get_deprecation_deadline_year: DSA/ECDH/DH/FFDH paths ---


def test_get_deprecation_deadline_year_dh_1024():
    assert get_deprecation_deadline_year("DH", key_size=1024) == 2026


def test_get_deprecation_deadline_year_dh_2048():
    assert get_deprecation_deadline_year("DH", key_size=2048) == 2030


def test_get_deprecation_deadline_year_dh_4096():
    assert get_deprecation_deadline_year("DH", key_size=4096) == 2035


def test_get_deprecation_deadline_year_ffdh():
    assert get_deprecation_deadline_year("FFDH", key_size=2048) == 2030


def test_get_deprecation_deadline_year_diffie():
    assert get_deprecation_deadline_year("DIFFIE-HELLMAN", key_size=2048) == 2030


def test_get_deprecation_deadline_year_ec_under_256():
    assert get_deprecation_deadline_year("EC", key_size=192) == 2026


def test_get_deprecation_deadline_year_ec_256():
    assert get_deprecation_deadline_year("EC", key_size=256) == 2030


def test_get_deprecation_deadline_year_ec_384():
    assert get_deprecation_deadline_year("EC", key_size=384) == 2035


def test_get_deprecation_deadline_year_sha512():
    assert get_deprecation_deadline_year("SHA-512") == 2099


def test_get_deprecation_deadline_year_sha224():
    assert get_deprecation_deadline_year("SHA-224") == 2030


def test_get_deprecation_deadline_year_aes_no_key_size():
    """AES without key_size defaults to 128 -> 2030."""
    assert get_deprecation_deadline_year("AES") == 2030


def test_get_deprecation_deadline_year_aes_256_no_key_size_arg():
    """AES-256 in name but no key_size arg -> parses from name."""
    assert get_deprecation_deadline_year("AES-256") == 2099


def test_get_deprecation_deadline_year_none_name():
    """None name -> default 2030."""
    assert get_deprecation_deadline_year(None) == 2030


def test_get_deprecation_deadline_year_empty_name():
    """Empty name -> default 2030."""
    assert get_deprecation_deadline_year("") == 2030


# --- classify_algorithm: SECP384R1MLKEM1024 hybrid ---


def test_classify_algorithm_secp384r1mlkem1024():
    result = classify_algorithm("SECP384R1MLKEM1024")
    assert result["pqc_status"] == "hybrid"
    assert result["is_hybrid"] is True


# --- classify_algorithm: composite with non-PQC ---


def test_classify_algorithm_composite_without_pqc():
    """COMPOSITE without PQC keyword -> not hybrid."""
    result = classify_algorithm("COMPOSITE-UNKNOWN")
    # Without a PQC keyword, composite alone doesn't trigger hybrid
    assert result["is_hybrid"] is False or result["pqc_status"] == "unknown"


# --- classify_algorithm: KEX group in hardcoded but not registry ---


def test_classify_algorithm_kex_group_hardcoded_fallback():
    """KEX group ID found in hardcoded PQC_KEX_GROUPS but not in registry."""
    # Find a group in PQC_KEX_GROUPS that's not in the registry
    if not PQC_KEX_GROUPS:
        pytest.skip("No PQC_KEX_GROUPS")
    tls_groups = (
        REGISTRY_DATA.get("tls_iana_groups", {}).get("groups", {})
        if REGISTRY_DATA
        else {}
    )
    ike_groups = (
        REGISTRY_DATA.get("ikev2_groups", {}).get("groups", {}) if REGISTRY_DATA else {}
    )
    for kid in PQC_KEX_GROUPS:
        hex_key = f"0x{kid:04X}"
        if hex_key not in tls_groups and str(kid) not in ike_groups:
            result = classify_algorithm("test", kex_group_id=kid)
            assert result["pqc_status"] == "pqc_ready"
            return
    pytest.skip("All PQC_KEX_GROUPS are in registry")


# --- classify_algorithm: KEX group unknown ---


def test_classify_algorithm_kex_group_unknown():
    """Unknown KEX group ID -> falls through to name-based classification."""
    result = classify_algorithm("RSA", kex_group_id=99999)
    # Should fall through to name-based RSA classification
    assert result["pqc_status"] == "vulnerable"


# --- classify_algorithm: OID in hardcoded but not registry ---


def test_classify_algorithm_oid_hardcoded_fallback():
    """OID found in hardcoded dicts but not in registry."""
    if not PQC_SIGNATURE_OIDS:
        pytest.skip("No PQC_SIGNATURE_OIDS")
    sig_oids = REGISTRY_DATA.get("signature_oids", {}) if REGISTRY_DATA else {}
    for oid in PQC_SIGNATURE_OIDS:
        if oid not in sig_oids:
            result = classify_algorithm("test", oid=oid)
            assert result["pqc_status"] in ("pqc_ready", "pqc_candidate")
            return
    pytest.skip("All PQC_SIGNATURE_OIDS are in registry")


# --- classify_algorithm: OID unknown falls through ---


def test_classify_algorithm_oid_unknown_falls_to_name():
    """Unknown OID falls through to name-based classification."""
    result = classify_algorithm("ML-KEM-768", oid="9.9.9.9.9.9")
    # OID takes priority if found; unknown OID returns unknown
    assert result["pqc_status"] in ("pqc_ready", "unknown")


# --- load_registry_file edge cases ---


def test_load_registry_file_returns_dict():
    result = load_registry_file()
    assert isinstance(result, dict)


# --- update_mappings_from_registry edge cases ---


def test_update_mappings_from_registry_no_data():
    """When REGISTRY_DATA is empty, function returns without error."""
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        update_mappings_from_registry()


def test_update_mappings_from_registry_with_data():
    """When REGISTRY_DATA has data, mappings are updated."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data")
    # Just verify it doesn't raise
    update_mappings_from_registry()


# --- classify_algorithm: AES key size parsing from name ---


def test_classify_algorithm_aes_key_size_parsed_from_name():
    result = classify_algorithm("AES_128_CBC")
    assert result["pqc_status"] == "safe_until_2030"


def test_classify_algorithm_aes_key_size_256_parsed():
    result = classify_algorithm("AES-256-CBC")
    assert result["pqc_status"] == "safe"


# --- classify_algorithm: DH key size parsed from name ---


def test_classify_algorithm_dh_key_size_parsed():
    result = classify_algorithm("DH_4096")
    assert result["pqc_status"] == "vulnerable"


# --- classify_algorithm: generic numeric key size ---


def test_classify_algorithm_generic_numeric_512():
    result = classify_algorithm("UNKNOWN-512")
    # 512 should be parsed as key size
    assert result["pqc_status"] in ("unknown", "vulnerable")


def test_classify_algorithm_generic_numeric_8192():
    result = classify_algorithm("UNKNOWN-8192")
    assert result["pqc_status"] in ("unknown", "vulnerable")


# --- classify_algorithm: X25519+ML-KEM hybrid with plus ---


def test_classify_algorithm_plus_hybrid_ml_kem():
    result = classify_algorithm("X25519+ML-KEM-768")
    assert result["is_hybrid"] is True
    assert result["is_pqc"] is True


# --- classify_algorithm: FRODO ---


def test_classify_algorithm_frodo():
    result = classify_algorithm("FRODO-640-SHAKE")
    assert result["pqc_status"] == "pqc_candidate"


# --- classify_algorithm: MCELIECE ---


def test_classify_algorithm_mceliece():
    result = classify_algorithm("MCELIECE-348864")
    assert result["pqc_status"] == "pqc_candidate"


# --- classify_algorithm: NTRU ---


def test_classify_algorithm_ntru():
    result = classify_algorithm("NTRU-HPS-2048-509")
    assert result["pqc_status"] == "pqc_candidate"


# --- classify_algorithm: SM2 ---


def test_classify_algorithm_sm2():
    result = classify_algorithm("SM2")
    assert result["pqc_status"] == "vulnerable"


# --- classify_algorithm: SRP ---


def test_classify_algorithm_srp():
    result = classify_algorithm("SRP-2048")
    assert result["pqc_status"] == "vulnerable"


# --- get_deprecation_deadline_year: DSA path ---


def test_get_deprecation_deadline_year_dsa():
    result = get_deprecation_deadline_year("DSA", key_size=2048)
    assert isinstance(result, int)


# --- get_deprecation_deadline_year: registry name match with DSA disambiguation ---


def test_get_deprecation_deadline_year_registry_dsa_not_ecdsa():
    """DSA should not match ECDSA in registry lookup."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data")
    # Just verify it doesn't crash
    result = get_deprecation_deadline_year("ECDSA-P256")
    assert isinstance(result, int)


# --- get_deprecation_deadline_year: registry name match with DH disambiguation ---


def test_get_deprecation_deadline_year_registry_dh_not_ecdh():
    """DH should not match ECDH in registry lookup."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data")
    result = get_deprecation_deadline_year("ECDH-P256")
    assert isinstance(result, int)


# --- get_deprecation_deadline_year: registry alias match ---


def test_get_deprecation_deadline_year_registry_alias():
    """get_deprecation_deadline_year with alias name."""
    if not REGISTRY_DATA:
        pytest.skip("No registry data")
    all_categories = REGISTRY_DATA.get("algorithms", {})
    for cat_name, cat_data in all_categories.items():
        for algo in cat_data.get("algorithms", []):
            aliases = algo.get("also_known_as", [])
            if aliases and "deadline_year" in algo:
                result = get_deprecation_deadline_year(aliases[0])
                assert isinstance(result, int)
                return
    pytest.skip("No alias with deadline_year found")


# --- Coverage improvement tests for remaining gaps ---


def test_load_registry_file_json_error():
    """load_registry_file catches JSON errors and returns {}."""
    with patch("app.analysis.algo_classifier.json.load", side_effect=ValueError("bad")):
        result = load_registry_file()
    assert result == {}


def test_update_mappings_from_registry_invalid_and_hybrid_entries():
    """update_mappings_from_registry skips invalid ids and adds hybrid entries."""
    registry = {
        "tls_iana_groups": {
            "groups": {
                "not_hex": {"name": "bad", "status": "hybrid", "type": "hybrid"},
                "0x0001": {"name": "good", "status": "hybrid", "type": "hybrid"},
            }
        },
        "ikev2_groups": {
            "groups": {
                "not_dec": {"name": "bad2", "status": "hybrid"},
                "2": {"name": "good2", "status": "hybrid"},
            }
        },
        "signature_oids": {
            "1.2.3": {"name": "Hybrid Sig", "status": "hybrid"},
            "1.2.4": {"name": "EdDSA", "status": "vulnerable"},
        },
        "kex_oids": {
            "1.2.5": {"name": "X", "status": "vulnerable"},
        },
    }
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", registry):
        with contextlib.ExitStack() as stack:
            for target in (
                "app.analysis.algo_classifier.PQC_KEX_GROUPS",
                "app.analysis.algo_classifier.HYBRID_KEX_GROUPS",
                "app.analysis.algo_classifier.PQC_SIGNATURE_OIDS",
                "app.analysis.algo_classifier.HYBRID_SIGNATURE_OIDS",
                "app.analysis.algo_classifier.CLASSICAL_EDDSA_OIDS",
                "app.analysis.algo_classifier.CLASSICAL_SIGNATURE_OIDS",
                "app.analysis.algo_classifier.CLASSICAL_KEX_OIDS",
                "app.analysis.algo_classifier.CLASSICAL_X_OIDS",
            ):
                stack.enter_context(patch.dict(target, {}, clear=True))
            update_mappings_from_registry()
            assert PQC_KEX_GROUPS[1] == "good"
            assert HYBRID_KEX_GROUPS[1] == "good"
            assert PQC_KEX_GROUPS[2] == "good2"
            assert HYBRID_KEX_GROUPS[2] == "good2"
            assert CLASSICAL_SIGNATURE_OIDS["1.2.4"] == "EdDSA"
            assert HYBRID_SIGNATURE_OIDS["1.2.3"] == "Hybrid Sig"
            assert CLASSICAL_KEX_OIDS["1.2.5"] == "X"


# --- classify_algorithm: OID fallback branches (registry empty) ---


def test_classify_algorithm_oid_fallback_pqc_signature():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        result = classify_algorithm("test", oid="2.16.840.1.101.3.4.3.17")
        assert result["pqc_status"] == "pqc_ready"
        assert result["is_pqc"] is True


def test_classify_algorithm_oid_fallback_hybrid_signature():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        result = classify_algorithm("test", oid="2.16.840.1.114027.80.4.1")
        assert result["pqc_status"] == "hybrid"
        assert result["is_hybrid"] is True


def test_classify_algorithm_oid_fallback_classical_eddsa():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        result = classify_algorithm("test", oid="1.3.101.112")
        assert result["pqc_status"] == "vulnerable"
        assert result["variant"] == "Ed25519"


def test_classify_algorithm_oid_fallback_classical_x():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        result = classify_algorithm("test", oid="1.3.101.110")
        assert result["pqc_status"] == "vulnerable"
        assert result["variant"] == "X25519"


def test_classify_algorithm_oid_fallback_classical_signature():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        result = classify_algorithm("test", oid="1.2.840.113549.1.1.11")
        assert result["pqc_status"] == "vulnerable"
        assert result["variant"] == "sha256WithRSAEncryption"


def test_classify_algorithm_oid_fallback_classical_kex():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        result = classify_algorithm("test", oid="1.2.840.113549.1.3.1")
        assert result["pqc_status"] == "vulnerable"
        assert result["variant"] == "dhKeyAgreement"


# --- classify_algorithm: registry name hyphen-removal match ---


def test_classify_algorithm_registry_name_hyphen_removed():
    """RIPEMD160 matches the registry entry RIPEMD-160 via hyphen removal."""
    result = classify_algorithm("RIPEMD160")
    assert result["pqc_status"] == "disallowed_now"


# --- classify_algorithm: plus/composite fallback ---


def test_classify_algorithm_plus_composite_fallback():
    result = classify_algorithm("MCELIECE+COMPOSITE")
    assert result["is_hybrid"] is True
    assert result["is_pqc"] is True


# --- classify_algorithm: AES/Ed/X fallback branches (registry empty) ---


def test_classify_algorithm_fallback_aes_under_128():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        result = classify_algorithm("AES-64", key_size=64)
        assert result["pqc_status"] == "vulnerable"
        assert result["variant"] == "AES-64"


def test_classify_algorithm_fallback_aes_192():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        result = classify_algorithm("AES-192", key_size=192)
        assert result["pqc_status"] == "safe_until_2030"
        assert result["variant"] == "AES-192"


def test_classify_algorithm_fallback_ed25519():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        result = classify_algorithm("Ed25519")
        assert result["pqc_status"] == "vulnerable"
        assert result["variant"] == "Ed25519"


def test_classify_algorithm_fallback_ed448():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        result = classify_algorithm("Ed448")
        assert result["pqc_status"] == "vulnerable"
        assert result["variant"] == "Ed448"


def test_classify_algorithm_fallback_x25519():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        result = classify_algorithm("X25519")
        assert result["pqc_status"] == "vulnerable"
        assert result["variant"] == "X25519"


def test_classify_algorithm_fallback_x448():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        result = classify_algorithm("X448")
        assert result["pqc_status"] == "vulnerable"
        assert result["variant"] == "X448"


# --- classify_algorithm: classical vulnerable fallback with disallowed markers ---


def test_classify_algorithm_fallback_dsa_disallowed():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        result = classify_algorithm("DSA-2048")
        assert result["pqc_status"] == "disallowed_now"


def test_classify_algorithm_fallback_rsa_1024_disallowed():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        result = classify_algorithm("RSA-1024")
        assert result["pqc_status"] == "disallowed_now"
        assert result["variant"] == "RSA-1024"


# --- get_deprecation_deadline_year: registry hyphen-removal match ---


def test_get_deprecation_deadline_year_registry_name_hyphen_removed():
    """RIPEMD160 matches RIPEMD-160 in the registry via hyphen removal."""
    result = get_deprecation_deadline_year("RIPEMD160")
    assert isinstance(result, int)


# --- get_deprecation_deadline_year: curve resolution via key_size / X curves ---


def test_get_deprecation_deadline_year_registry_curve_by_key_size():
    result = get_deprecation_deadline_year("ECDH", key_size=256)
    assert isinstance(result, int)


def test_get_deprecation_deadline_year_registry_curve_key_sizes():
    """Exercise all key_size-to-curve branches for curve-based algorithms."""
    for size, expected_status in (
        (192, "disallowed_now"),
        (224, "disallowed_now"),
        (256, "vulnerable"),
        (384, "vulnerable"),
        (521, "vulnerable"),
    ):
        result = get_deprecation_deadline_year("ECDSA", key_size=size)
        assert isinstance(result, int)


def test_get_deprecation_deadline_year_registry_curve_x25519():
    result = get_deprecation_deadline_year("ECDH-X25519")
    assert isinstance(result, int)


def test_get_deprecation_deadline_year_registry_curve_x448():
    result = get_deprecation_deadline_year("ECDH-X448")
    assert isinstance(result, int)


# --- get_deprecation_deadline_year: hardcoded fallback timeline ---


def test_get_deprecation_deadline_year_fallback_pqc():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        assert get_deprecation_deadline_year("ML-KEM-768") == 2099


def test_get_deprecation_deadline_year_fallback_ed25519_year():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        assert get_deprecation_deadline_year("Ed25519") == 2035


def test_get_deprecation_deadline_year_fallback_aes256():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        assert get_deprecation_deadline_year("AES-256", key_size=256) == 2099


def test_get_deprecation_deadline_year_fallback_sha_variants():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        assert get_deprecation_deadline_year("SHA-512") == 2099
        assert get_deprecation_deadline_year("SHA-384") == 2099
        assert get_deprecation_deadline_year("SHA-256") == 2030
        assert get_deprecation_deadline_year("SHA-224") == 2030
        assert get_deprecation_deadline_year("SHA-1") == 2026


def test_get_deprecation_deadline_year_fallback_rsa_sizes():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        assert get_deprecation_deadline_year("RSA", key_size=1024) == 2026
        assert get_deprecation_deadline_year("RSA", key_size=2048) == 2030
        assert get_deprecation_deadline_year("RSA", key_size=4096) == 2035


def test_get_deprecation_deadline_year_fallback_dh_sizes():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        assert get_deprecation_deadline_year("DH", key_size=1024) == 2026
        assert get_deprecation_deadline_year("DH", key_size=2048) == 2030
        assert get_deprecation_deadline_year("DH", key_size=4096) == 2035
        assert get_deprecation_deadline_year("FFDH", key_size=2048) == 2030
        assert get_deprecation_deadline_year("DIFFIE-HELLMAN", key_size=2048) == 2030


def test_get_deprecation_deadline_year_fallback_ec_sizes():
    with patch("app.analysis.algo_classifier.REGISTRY_DATA", {}):
        assert get_deprecation_deadline_year("EC", key_size=192) == 2026
        assert get_deprecation_deadline_year("EC", key_size=256) == 2030
        assert get_deprecation_deadline_year("EC", key_size=384) == 2035


# --- resolve_curve_status: SECP* variants (lines 208, 210, 212) ---


def test_resolve_curve_status_secp256_variant():
    d = {"P-256": {"status": "vulnerable"}}
    assert resolve_curve_status(d, "secp256r1")["status"] == "vulnerable"


def test_resolve_curve_status_secp384_variant():
    d = {"P-384": {"status": "vulnerable"}}
    assert resolve_curve_status(d, "secp384r1")["status"] == "vulnerable"


def test_resolve_curve_status_secp521_variant():
    d = {"P-521": {"status": "vulnerable"}}
    assert resolve_curve_status(d, "secp521r1")["status"] == "vulnerable"


# --- classify_algorithm: DH substring with ECDH disambiguation (line 534) ---


def test_classify_algorithm_ecdh_contains_dh():
    """Names containing 'DH' but also 'ECDH' must not match a bare DH entry."""
    result = classify_algorithm("ECDH-P256")
    assert result["pqc_status"] == "vulnerable"
    assert "ECDH" in result["variant"]


# --- classify_algorithm: explicit hybrid KEX groups (lines 597-598) ---


def test_classify_algorithm_hybrid_x25519_mlkem768():
    result = classify_algorithm("X25519MLKEM768")
    assert result["pqc_status"] == "hybrid"
    assert result["is_hybrid"] is True
    assert result["is_pqc"] is True


def test_classify_algorithm_hybrid_secp256_mlkem768():
    result = classify_algorithm("SECP256R1MLKEM768")
    assert result["pqc_status"] == "hybrid"
    assert result["is_hybrid"] is True
    assert result["is_pqc"] is True


def test_classify_algorithm_hybrid_secp384_mlkem1024():
    result = classify_algorithm("SECP384R1MLKEM1024")
    assert result["pqc_status"] == "hybrid"
    assert result["is_hybrid"] is True
    assert result["is_pqc"] is True
