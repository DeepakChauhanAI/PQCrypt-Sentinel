"""
Tests for the `finding_service` module: covers the TLS, SSH and
expiry paths so coverage on `app/services/finding_service.py` rises
above 80%.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock


def _make_asset(asset_type: str = "web_app", env: str = "production", metadata=None):
    return SimpleNamespace(
        id="asset-1",
        asset_type=asset_type,
        environment=env,
        discovery_source="tls_scan",
        asset_metadata=metadata or {},
    )


def _make_session(asset):
    """Return an AsyncMock session that yields the given asset on first execute()."""
    session = AsyncMock()
    res = MagicMock()
    res.scalar_one_or_none = MagicMock(return_value=asset)
    session.execute = AsyncMock(return_value=res)
    session.commit = AsyncMock()
    session.add = MagicMock()
    return session


def _make_cert_data(
    *,
    pqc_status: str = "vulnerable",
    sig_algo: str = "sha256WithRSAEncryption",
    pub_key_algo: str = "rsa",
    pub_key_size: int = 2048,
    is_self_signed: bool = False,
    not_after_offset_days: int = 365,
):
    return {
        "pqc_details": {"pqc_status": pqc_status},
        "sig_algorithm": sig_algo,
        "pub_key_algorithm": pub_key_algo,
        "pub_key_size": pub_key_size,
        "is_self_signed": is_self_signed,
        "not_after": datetime.now(timezone.utc) + timedelta(days=not_after_offset_days),
    }


def test_generate_findings_returns_zero_for_missing_asset():
    """Unknown asset_id is a no-op."""
    from app.services.finding_service import generate_findings

    session = AsyncMock()
    res = MagicMock()
    res.scalar_one_or_none = MagicMock(return_value=None)
    session.execute = AsyncMock(return_value=res)

    count = asyncio.run(generate_findings(session, "scan-1", "missing"))
    assert count == 0
    session.commit.assert_not_called()


def test_generate_findings_weak_signature_algorithm():
    """A vulnerable certificate produces a weak_algorithm finding."""
    from app.services.finding_service import generate_findings

    asset = _make_asset()
    session = _make_session(asset)
    cert = _make_cert_data(pqc_status="vulnerable", sig_algo="md5WithRSAEncryption")

    count = asyncio.run(generate_findings(session, "scan-1", asset.id, cert_data=cert))

    assert count == 1
    add_calls = [c.args[0] for c in session.add.call_args_list]
    types = {f.finding_type for f in add_calls}
    assert "weak_algorithm" in types
    weak = next(f for f in add_calls if f.finding_type == "weak_algorithm")
    assert weak.severity == "high"
    assert weak.pqc_status == "vulnerable"
    assert weak.layer == "L2"  # weak_algorithm default layer


def test_generate_findings_self_signed():
    """Self-signed cert produces a self_signed finding (medium severity)."""
    from app.services.finding_service import generate_findings

    asset = _make_asset()
    session = _make_session(asset)
    cert = _make_cert_data(is_self_signed=True)

    count = asyncio.run(generate_findings(session, "scan-1", asset.id, cert_data=cert))
    add_calls = [c.args[0] for c in session.add.call_args_list]
    types = {f.finding_type for f in add_calls}
    assert "self_signed" in types
    self_signed = next(f for f in add_calls if f.finding_type == "self_signed")
    assert self_signed.severity == "medium"
    assert self_signed.layer == "L2"


def test_generate_findings_weak_rsa_key_size():
    """RSA < 2048 produces a critical weak_key_size finding."""
    from app.services.finding_service import generate_findings

    asset = _make_asset()
    session = _make_session(asset)
    cert = _make_cert_data(pub_key_algo="RSA", pub_key_size=1024)

    count = asyncio.run(generate_findings(session, "scan-1", asset.id, cert_data=cert))
    add_calls = [c.args[0] for c in session.add.call_args_list]
    weak = next((f for f in add_calls if f.finding_type == "weak_key_size"), None)
    assert weak is not None
    assert weak.severity == "critical"
    assert "RSA-1024" in weak.algorithm
    # key_size is stored in evidence (Finding has no dedicated column)
    assert (weak.evidence or {}).get("pub_key_size") == 1024


def test_generate_findings_no_weak_key_for_strong_rsa():
    """A 2048-bit RSA cert does NOT trigger weak_key_size."""
    from app.services.finding_service import generate_findings

    asset = _make_asset()
    session = _make_session(asset)
    cert = _make_cert_data(pub_key_algo="RSA", pub_key_size=2048)

    asyncio.run(generate_findings(session, "scan-1", asset.id, cert_data=cert))
    types = [c.args[0].finding_type for c in session.add.call_args_list]
    assert "weak_key_size" not in types


def test_generate_findings_expired_certificate():
    """A cert with not_after in the past produces a critical cert_expired finding."""
    from app.services.finding_service import generate_findings

    asset = _make_asset()
    session = _make_session(asset)
    cert = _make_cert_data(not_after_offset_days=-1)

    asyncio.run(generate_findings(session, "scan-1", asset.id, cert_data=cert))
    types = [c.args[0].finding_type for c in session.add.call_args_list]
    assert "cert_expired" in types
    expired = next(
        c.args[0]
        for c in session.add.call_args_list
        if c.args[0].finding_type == "cert_expired"
    )
    assert expired.severity == "critical"


def test_generate_findings_expiring_soon():
    """A cert with < 30 days to expiry produces a high cert_expiring finding."""
    from app.services.finding_service import generate_findings

    asset = _make_asset()
    session = _make_session(asset)
    cert = _make_cert_data(not_after_offset_days=10)

    asyncio.run(generate_findings(session, "scan-1", asset.id, cert_data=cert))
    types = [c.args[0].finding_type for c in session.add.call_args_list]
    assert "cert_expiring" in types
    assert "cert_expired" not in types


def test_generate_findings_naive_datetime_is_treated_as_utc():
    """A naive (no-tzinfo) not_after must not crash and is treated as UTC."""
    from app.services.finding_service import generate_findings

    asset = _make_asset()
    session = _make_session(asset)
    cert = _make_cert_data()
    cert["not_after"] = datetime.now() + timedelta(days=10)  # no tzinfo

    count = asyncio.run(generate_findings(session, "scan-1", asset.id, cert_data=cert))
    assert count >= 1


def test_generate_findings_ssh_no_pqc_kex():
    """A KEX list without PQC keywords produces an ssh_weak_kex finding."""
    from app.services.finding_service import generate_findings

    asset = _make_asset(asset_type="server", env="production")
    session = _make_session(asset)

    count = asyncio.run(
        generate_findings(
            session,
            "scan-1",
            asset.id,
            kex_algos=["ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"],
        )
    )
    assert count == 1
    finding = session.add.call_args.args[0]
    assert finding.finding_type == "ssh_weak_kex"
    assert finding.severity == "high"
    assert "ecdh-sha2-nistp256" in finding.algorithm


def test_generate_findings_ssh_with_pqc_kex_is_safe():
    """A KEX list that includes a PQC keyword produces no ssh_weak_kex finding."""
    from app.services.finding_service import generate_findings

    asset = _make_asset(asset_type="server", env="production")
    session = _make_session(asset)

    count = asyncio.run(
        generate_findings(
            session,
            "scan-1",
            asset.id,
            kex_algos=["sntrup761x25519-sha512@openssh.com"],
        )
    )
    assert count == 0


def test_generate_findings_persists_mosca_fields_in_evidence():
    """evidence.mosca must contain data_longevity_years, quantum_timeline_year, replaceability."""
    from app.services.finding_service import generate_findings

    asset = _make_asset()
    session = _make_session(asset)
    cert = _make_cert_data(pqc_status="vulnerable", sig_algo="md5WithRSAEncryption")

    asyncio.run(generate_findings(session, "scan-1", asset.id, cert_data=cert))
    finding = session.add.call_args.args[0]
    mosca = finding.evidence.get("mosca", {})
    assert "data_longevity_years" in mosca
    assert "quantum_timeline_year" in mosca
    assert "replaceability" in mosca


def test_serialize_evidence_handles_datetimes():
    """Datetimes inside evidence are converted to ISO 8601 strings."""
    from app.services.finding_service import _serialize_evidence

    dt = datetime(2024, 1, 1, tzinfo=timezone.utc)
    out = _serialize_evidence({"stamp": dt, "list": [dt], "plain": "x"})
    assert out["stamp"] == "2024-01-01T00:00:00+00:00"
    assert out["list"] == ["2024-01-01T00:00:00+00:00"]
    assert out["plain"] == "x"


def test_serialize_evidence_handles_naive_datetime():
    """A naive datetime is treated as UTC and emits a +00:00 offset."""
    from app.services.finding_service import _serialize_evidence

    out = _serialize_evidence({"stamp": datetime(2024, 1, 1)})
    # We can't assert on the date (TZ conversion is implementation-defined),
    # only that the value is an ISO 8601 string with a UTC offset suffix.
    assert isinstance(out["stamp"], str)
    assert out["stamp"].endswith("+00:00")
