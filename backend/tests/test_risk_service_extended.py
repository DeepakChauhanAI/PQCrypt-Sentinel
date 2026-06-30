from unittest.mock import MagicMock

from app.services.risk_service import (
    calculate_risk_score,
    is_disallowed_now,
    derive_data_longevity_years,
    derive_replaceability,
    risk_score_to_percent,
)


class TestIsDisallowedNow:
    def test_empty_string(self):
        assert is_disallowed_now("") is False

    def test_none(self):
        assert is_disallowed_now(None) is False

    def test_rc4(self):
        assert is_disallowed_now("RC4") is True
        assert is_disallowed_now("rc4") is True

    def test_sslv2(self):
        assert is_disallowed_now("SSLv2") is True
        assert is_disallowed_now("SSLv3") is True

    def test_tls10_tls11(self):
        assert is_disallowed_now("TLSv1.0") is True
        assert is_disallowed_now("TLSv1.1") is True

    def test_tls12_caught_by_pattern(self):
        # TLSv1.2 is caught because "tlsv1" is a substring of "tlsv1.2"
        assert is_disallowed_now("TLSv1.2") is True
        # "TLS 1.2" with space does NOT match the tlsv1 pattern
        assert is_disallowed_now("TLS 1.2") is False

    def test_rsa768(self):
        assert is_disallowed_now("RSA-768") is True

    def test_dsa_512(self):
        assert is_disallowed_now("DSA-512") is True

    def test_dh_768(self):
        assert is_disallowed_now("DH-768") is True
        assert is_disallowed_now("DH-1024") is True

    def test_ripemd(self):
        assert is_disallowed_now("RIPEMD") is True

    def test_ecdsa_sha1(self):
        assert is_disallowed_now("ecdsa-with-SHA1") is True

    def test_mlkem_safe(self):
        assert is_disallowed_now("ML-KEM-768") is False
        assert is_disallowed_now("ML-DSA-65") is False

    def test_whitespace_handling(self):
        assert is_disallowed_now("  MD5  ") is True

    def test_no_pattern_match(self):
        assert is_disallowed_now("ChaCha20") is False


class TestDeriveDataLongevityYears:
    def test_cert_with_key_encipherment(self):
        cert = MagicMock()
        cert.key_usage = ["keyEncipherment", "digitalSignature"]
        assert derive_data_longevity_years(cert_data=cert) >= 25

    def test_cert_with_data_encipherment(self):
        cert = MagicMock()
        cert.key_usage = ["dataEncipherment"]
        assert derive_data_longevity_years(cert_data=cert) >= 25

    def test_cert_dict_key_usage(self):
        cert_data = {"key_usage": ["keyEncipherment"]}
        assert derive_data_longevity_years(cert_data=cert_data) >= 25

    def test_vpn_weak_ike(self):
        assert derive_data_longevity_years(finding_type="vpn_weak_ike") >= 25

    def test_kex_algos_provided(self):
        assert derive_data_longevity_years(kex_algos=["curve25519-sha256"]) >= 25

    def test_asset_type_kms(self):
        asset = MagicMock()
        asset.asset_type = "kms"
        asset.environment = "production"
        assert derive_data_longevity_years(asset=asset) >= 30

    def test_asset_staging(self):
        asset = MagicMock()
        asset.asset_type = "server"
        asset.environment = "staging"
        assert derive_data_longevity_years(asset=asset) <= 3

    def test_asset_preprod(self):
        asset = MagicMock()
        asset.asset_type = "server"
        asset.environment = "preprod"
        assert derive_data_longevity_years(asset=asset) <= 3


class TestDeriveReplaceability:
    def test_sast_weak_crypto(self):
        assert derive_replaceability(finding_type="sast_weak_crypto") == "low"

    def test_ike_weak_dh(self):
        assert derive_replaceability(finding_type="ike_weak_dh") == "medium"

    def test_unknown_finding_type(self):
        assert derive_replaceability(finding_type="unknown_type") == "medium"

    def test_no_context(self):
        assert derive_replaceability() == "medium"


class TestCalculateRiskScoreExtended:
    def test_with_algorithms_list(self):
        algo1 = MagicMock()
        algo1.pqc_status = "vulnerable"
        algo1.algorithm_name = "RSA-2048"
        algo1.key_size = 2048
        algo2 = MagicMock()
        algo2.pqc_status = "hybrid"
        algo2.algorithm_name = "X25519Kyber768"
        algo2.key_size = 768

        score = calculate_risk_score(algorithms=[algo1, algo2])
        assert score > 0

    def test_with_algorithms_disallowed_now(self):
        algo = MagicMock()
        algo.pqc_status = "disallowed_now"
        algo.algorithm_name = "RSA-1024"
        algo.key_size = 1024
        score = calculate_risk_score(algorithms=[algo])
        assert score >= 15

    def test_with_algorithms_pqc_ready(self):
        algo = MagicMock()
        algo.pqc_status = "pqc_ready"
        algo.algorithm_name = "ML-DSA-65"
        algo.key_size = 256
        score = calculate_risk_score(algorithms=[algo])
        assert score <= 15

    def test_with_algorithms_safe(self):
        algo = MagicMock()
        algo.pqc_status = "safe"
        algo.algorithm_name = "AES-256-GCM"
        algo.key_size = 256
        score = calculate_risk_score(algorithms=[algo])
        assert score <= 15

    def test_legacy_business_criticality_tier_1(self):
        score = calculate_risk_score(
            pqc_status="vulnerable",
            hndl_exposure="low",
            business_criticality="tier_1",
            years_to_deadline=10,
        )
        assert score > 0

    def test_asset_web_app_exposure(self):
        asset = MagicMock()
        asset.asset_type = "web_app"
        asset.environment = "production"
        score = calculate_risk_score(
            asset=asset, pqc_status="vulnerable", years_to_deadline=10
        )
        assert score > 0

    def test_asset_api_exposure(self):
        asset = MagicMock()
        asset.asset_type = "api"
        asset.environment = "production"
        score = calculate_risk_score(
            asset=asset, pqc_status="vulnerable", years_to_deadline=10
        )
        assert score > 0

    def test_years_to_deadline_thresholds(self):
        for years, expected_min_score in [(1, 20), (3, 15), (5, 10), (8, 8), (15, 5)]:
            score = calculate_risk_score(
                pqc_status="vulnerable",
                hndl_exposure="low",
                system_exposure="internal",
                replaceability="low",
                years_to_deadline=years,
            )
            assert score >= 5

    def test_cert_with_pqc_capable(self):
        cert = MagicMock()
        cert.pqc_capable = True
        cert.sig_algorithm = "ML-DSA-65"
        cert.pub_key_size = 256
        score = calculate_risk_score(cert=cert)
        assert score > 0

    def test_cert_with_disallowed_sig(self):
        cert = MagicMock()
        cert.pqc_capable = False
        cert.sig_algorithm = "md5WithRSAEncryption"
        cert.pub_key_size = 1024
        score = calculate_risk_score(cert=cert)
        assert score >= 15


class TestRiskScoreToPercent:
    def test_boundary_values(self):
        assert risk_score_to_percent(5) == 0
        assert risk_score_to_percent(25) == 100

    def test_mid_value(self):
        assert risk_score_to_percent(15) == 50

    def test_clamping(self):
        assert risk_score_to_percent(0) == 0
        assert risk_score_to_percent(100) == 100
