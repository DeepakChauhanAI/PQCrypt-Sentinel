import pytest
from unittest.mock import MagicMock
from app.services.risk_service import (
    calculate_risk_score,
    is_disallowed_now,
    derive_data_longevity_years,
    derive_hndl_exposure,
    risk_score_to_percent,
)


def test_is_disallowed_now_md5():
    assert is_disallowed_now("MD5") is True
    assert is_disallowed_now("md5WithRSAEncryption") is True
    assert is_disallowed_now("md5") is True


def test_is_disallowed_now_sha1():
    assert is_disallowed_now("SHA-1") is True
    assert is_disallowed_now("sha1WithRSAEncryption") is True
    assert is_disallowed_now("ecdsa-with-SHA1") is True


def test_is_disallowed_now_des():
    assert is_disallowed_now("DES") is True
    assert is_disallowed_now("3DES") is True
    assert is_disallowed_now("Triple-DES") is True


def test_is_disallowed_now_weak_rsa():
    assert is_disallowed_now("RSA-1024") is True
    assert is_disallowed_now("RSA-512") is True
    assert is_disallowed_now("RSA-2048") is False
    assert is_disallowed_now("RSA-4096") is False


def test_is_disallowed_now_safe_algos():
    assert is_disallowed_now("AES-256-GCM") is False
    assert is_disallowed_now("ChaCha20-Poly1305") is False
    assert is_disallowed_now("Ed25519") is False
    assert is_disallowed_now("ML-KEM-768") is False


def test_is_disallowed_now_protocols():
    assert is_disallowed_now("TLS 1.0") is True
    assert is_disallowed_now("SSL 3.0") is True
    assert is_disallowed_now("TLS 1.2") is False
    assert is_disallowed_now("TLS 1.3") is False


def test_derive_data_longevity_years_default():
    """Without any asset context, default longevity is 5y."""
    assert derive_data_longevity_years() == 5


def test_derive_data_longevity_years_production():
    """Production assets have >= 10y longevity."""
    asset = MagicMock()
    asset.asset_type = "server"
    asset.environment = "production"
    assert derive_data_longevity_years(asset=asset) >= 10


def test_derive_data_longevity_years_hsm_kms_ca():
    """PKI trust anchors imply 30y+ longevity."""
    asset = MagicMock()
    asset.asset_type = "hsm"
    asset.environment = "production"
    assert derive_data_longevity_years(asset=asset) >= 30

    asset.asset_type = "certificate_authority"
    assert derive_data_longevity_years(asset=asset) >= 30


def test_derive_data_longevity_years_development():
    """Dev environment has lower longevity."""
    asset = MagicMock()
    asset.asset_type = "server"
    asset.environment = "development"
    assert derive_data_longevity_years(asset=asset) <= 5


def test_derive_data_longevity_years_ssh_kex():
    """SSH KEX findings (transient session) imply 25y SNDL risk."""
    assert derive_data_longevity_years(finding_type="ssh_weak_kex") >= 25


def test_derive_hndl_exposure_production_hsm():
    """Production HSM -> 25-30y data + 2035 quantum = HIGH HNDL."""
    asset = MagicMock()
    asset.asset_type = "hsm"
    asset.environment = "production"
    exposure = derive_hndl_exposure(asset=asset, quantum_timeline_year=2035)
    assert exposure == "high"


def test_derive_hndl_exposure_dev_no_longevity():
    """Dev asset with no asset = 3y + 2035 quantum = MEDIUM HNDL.

    With quantum_timeline=2035, migration_window=11y, longevity=3y
    (capped for dev), the formula returns medium (11 < 3+10=13).
    """
    asset = MagicMock()
    asset.asset_type = "container"
    asset.environment = "development"
    exposure = derive_hndl_exposure(asset=asset, quantum_timeline_year=2035)
    assert exposure == "medium"


def test_risk_score_disallowed_now_high():
    """A disallowed-now algorithm triggers maximum vulnerability score (5)."""
    asset = MagicMock()
    asset.asset_type = "server"
    asset.environment = "production"
    asset.asset_metadata = {}
    cert = MagicMock()
    cert.pqc_capable = False
    cert.sig_algorithm = "md5WithRSAEncryption"
    cert.pub_key_size = 1024
    score = calculate_risk_score(asset=asset, cert=cert)
    # hndl=5, exposure=1(internal), algo=5, replaceability=3(medium), deadline=5 => 19
    assert score >= 19


def test_risk_score_uses_mosca_for_hndl():
    """When asset is None, HNDL defaults from explicit parameter.

    With years_to_deadline=1 we hit deadline_score=5 (<2 threshold).
    """
    score = calculate_risk_score(
        hndl_exposure="high",
        system_exposure="internet",
        pqc_status="vulnerable",
        replaceability="hard",
        years_to_deadline=1,
    )
    # 5+5+5+5+5 = 25 (max)
    assert score == 25


def test_risk_score_to_percent():
    assert risk_score_to_percent(5) == 0
    assert risk_score_to_percent(25) == 100
    assert risk_score_to_percent(15) == 50
    assert 0 <= risk_score_to_percent(10) <= 100


def test_weights_5dim_sum_to_one():
    from app.services.risk_service import RISK_WEIGHTS_5DIM
    assert abs(sum(RISK_WEIGHTS_5DIM.values()) - 1.0) < 1e-9
    assert "replaceability" in RISK_WEIGHTS_5DIM
    assert "business_criticality" not in RISK_WEIGHTS_5DIM


def test_replaceability_hsm_is_hard():
    from app.services.risk_service import derive_replaceability
    a = MagicMock()
    a.asset_type = "hsm"
    a.environment = "production"
    assert derive_replaceability(asset=a) == "hard"

    a.asset_type = "kms"
    assert derive_replaceability(asset=a) == "hard"

    a.asset_type = "certificate_authority"
    assert derive_replaceability(asset=a) == "hard"


def test_replaceability_dev_is_low():
    from app.services.risk_service import derive_replaceability
    a = MagicMock()
    a.asset_type = "server"
    a.environment = "development"
    assert derive_replaceability(asset=a) == "low"

    a.environment = "testing"
    assert derive_replaceability(asset=a) == "low"


def test_replaceability_ssh_kex_is_medium():
    from app.services.risk_service import derive_replaceability
    assert derive_replaceability(finding_type="ssh_weak_kex") == "medium"
    assert derive_replaceability(finding_type="vpn_weak_ike") == "medium"
    assert derive_replaceability(finding_type="tls_weak_kex") == "medium"


def test_5dim_risk_includes_replaceability():
    """Same inputs, different replaceability -> different raw score."""
    soft = calculate_risk_score(
        pqc_status="vulnerable",
        system_exposure="internal",
        hndl_exposure="low",
        replaceability="low",
        years_to_deadline=10,
    )
    hard = calculate_risk_score(
        pqc_status="vulnerable",
        system_exposure="internal",
        hndl_exposure="low",
        replaceability="hard",
        years_to_deadline=10,
    )
    assert hard > soft
    assert hard - soft == 4  # replaceability: low(1) -> hard(5) = +4


def test_5dim_risk_business_criticality_folds_into_exposure():
    """Legacy tier_0/tier_1 must still produce internet/dmz exposure."""
    from app.services.risk_service import calculate_risk_score
    a = calculate_risk_score(
        pqc_status="safe", hndl_exposure="low",
        business_criticality="tier_0", years_to_deadline=10,
    )
    b = calculate_risk_score(
        pqc_status="safe", hndl_exposure="low",
        business_criticality="tier_3", years_to_deadline=10,
    )
    assert a > b
    # tier_0 -> internet (5) vs tier_3 -> internal (1), so delta = 4
    assert a - b == 4
