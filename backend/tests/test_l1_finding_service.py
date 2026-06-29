"""
Tests for `app.services.l1_finding_service` — the bridge between the
L1 (OCSP + DNSSEC) probe scanner and the `Finding` table.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import List
from unittest.mock import AsyncMock, MagicMock

import pytest


# --------------------------------------------------------------------- helpers


def _make_asset(
    asset_id: str = "asset-1",
    asset_type: str = "web_app",
    env: str = "production",
):
    return SimpleNamespace(
        id=asset_id,
        asset_type=asset_type,
        environment=env,
        discovery_source="tls_scan",
        asset_metadata={},
    )


def _session_with_asset(asset):
    """AsyncMock session that yields `asset` on .execute().scalar_one_or_none()."""
    session = AsyncMock()
    res = MagicMock()
    res.scalar_one_or_none = MagicMock(return_value=asset)
    session.execute = AsyncMock(return_value=res)
    session.commit = AsyncMock()
    session.add = MagicMock()
    return session


def _make_ocsp_result(**overrides):
    defaults = dict(
        host="example.com",
        cert_thumbprint="deadbeef",
        success=True,
        status="good",
        responder_url="http://ocsp.example.com",
        responder_name="CN=OCSP",
        signature_algorithm="sha256WithRSAEncryption",
        error_message=None,
        pqc_status="vulnerable",
        raw={"response_status": "SUCCESSFUL"},
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_dnssec_result(**overrides):
    defaults = dict(
        domain="example.com",
        success=True,
        has_dnskey=True,
        has_rrsig=True,
        has_ds=True,
        algorithms=["ECDSAP256SHA256"],
        chain_of_trust=True,
        error_message=None,
        pqc_status="safe",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _added_findings(session) -> List:
    return [c.args[0] for c in session.add.call_args_list]


# ----------------------------------------------------------------- OCSP tests


def test_persist_ocsp_revoked_creates_critical_cert_expired():
    from app.services.l1_finding_service import L1FindingService

    asset = _make_asset()
    session = _session_with_asset(asset)
    probe = _make_ocsp_result(status="revoked", pqc_status="vulnerable")

    count = asyncio.run(
        L1FindingService(session).persist_ocsp_results(
            scan_id="scan-1",
            probe_results=[(asset.id, probe)],
        )
    )
    assert count == 1

    findings = _added_findings(session)
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == "cert_expired"
    assert f.severity == "critical"
    assert f.layer == "L1"
    assert f.algorithm_type == "ocsp"
    assert f.scan_id == "scan-1"
    assert "Revoked" in f.title
    session.commit.assert_awaited()


def test_persist_ocsp_disallowed_now_creates_high_severity():
    from app.services.l1_finding_service import L1FindingService

    asset = _make_asset()
    session = _session_with_asset(asset)
    probe = _make_ocsp_result(signature_algorithm="sha1WithRSAEncryption", pqc_status="disallowed_now")

    count = asyncio.run(
        L1FindingService(session).persist_ocsp_results(
            scan_id="scan-1",
            probe_results=[(asset.id, probe)],
        )
    )
    assert count == 1

    findings = _added_findings(session)
    assert findings[0].severity == "high"
    assert findings[0].finding_type == "weak_algorithm"
    assert findings[0].layer == "L1"


def test_persist_ocsp_safe_creates_no_finding():
    from app.services.l1_finding_service import L1FindingService

    asset = _make_asset()
    session = _session_with_asset(asset)
    probe = _make_ocsp_result(pqc_status="safe")

    count = asyncio.run(
        L1FindingService(session).persist_ocsp_results(
            scan_id="scan-1",
            probe_results=[(asset.id, probe)],
        )
    )
    assert count == 0
    assert session.add.call_count == 0
    # No commit when nothing was created.
    session.commit.assert_not_awaited()


def test_persist_ocsp_probe_failure_skipped():
    from app.services.l1_finding_service import L1FindingService

    asset = _make_asset()
    session = _session_with_asset(asset)
    probe = _make_ocsp_result(success=False)

    count = asyncio.run(
        L1FindingService(session).persist_ocsp_results(
            scan_id="scan-1",
            probe_results=[(asset.id, probe)],
        )
    )
    assert count == 0
    assert session.add.call_count == 0


def test_persist_ocsp_safe_until_2030_creates_medium():
    from app.services.l1_finding_service import L1FindingService

    asset = _make_asset()
    session = _session_with_asset(asset)
    probe = _make_ocsp_result(signature_algorithm="ecdsa-with-SHA256", pqc_status="safe_until_2030")

    count = asyncio.run(
        L1FindingService(session).persist_ocsp_results(
            scan_id="scan-1",
            probe_results=[(asset.id, probe)],
        )
    )
    assert count == 1
    f = _added_findings(session)[0]
    assert f.severity == "medium"


# ---------------------------------------------------------------- DNSSEC tests


def test_persist_dnssec_vulnerable_creates_high():
    from app.services.l1_finding_service import L1FindingService

    asset = _make_asset()
    session = _session_with_asset(asset)
    probe = _make_dnssec_result(
        algorithms=["RSASHA1", "RSASHA256"],
        pqc_status="vulnerable",
    )

    count = asyncio.run(
        L1FindingService(session).persist_dnssec_results(
            scan_id="scan-1",
            probe_results=[(asset.id, probe)],
        )
    )
    assert count == 1

    f = _added_findings(session)[0]
    assert f.finding_type == "weak_algorithm"
    assert f.severity == "high"
    assert f.layer == "L1"
    assert f.algorithm_type == "dnssec"
    assert "RSASHA1" in (f.algorithm or "")


def test_persist_dnssec_safe_no_finding():
    from app.services.l1_finding_service import L1FindingService

    asset = _make_asset()
    session = _session_with_asset(asset)
    probe = _make_dnssec_result(algorithms=["ECDSAP256SHA256"], pqc_status="safe", chain_of_trust=True)

    count = asyncio.run(
        L1FindingService(session).persist_dnssec_results(
            scan_id="scan-1",
            probe_results=[(asset.id, probe)],
        )
    )
    assert count == 0


def test_persist_dnssec_incomplete_chain_creates_medium():
    from app.services.l1_finding_service import L1FindingService

    asset = _make_asset()
    session = _session_with_asset(asset)
    # No DS in parent; everything else signed. Chain is broken.
    probe = _make_dnssec_result(
        has_ds=False,
        chain_of_trust=False,
        algorithms=["ECDSAP256SHA256"],
        pqc_status="safe",
    )

    count = asyncio.run(
        L1FindingService(session).persist_dnssec_results(
            scan_id="scan-1",
            probe_results=[(asset.id, probe)],
        )
    )
    assert count == 1

    f = _added_findings(session)[0]
    assert f.finding_type == "pqc_not_supported"
    assert f.severity == "medium"
    assert f.layer == "L1"


def test_persist_dnssec_unknown_zone_creates_medium():
    from app.services.l1_finding_service import L1FindingService

    asset = _make_asset()
    session = _session_with_asset(asset)
    probe = _make_dnssec_result(
        has_dnskey=False,
        has_rrsig=False,
        has_ds=False,
        algorithms=[],
        pqc_status="unknown",
        chain_of_trust=False,
    )

    count = asyncio.run(
        L1FindingService(session).persist_dnssec_results(
            scan_id="scan-1",
            probe_results=[(asset.id, probe)],
        )
    )
    assert count == 1
    f = _added_findings(session)[0]
    assert f.finding_type == "pqc_not_supported"
    assert f.severity == "medium"


def test_persist_dnssec_failure_skipped():
    from app.services.l1_finding_service import L1FindingService

    asset = _make_asset()
    session = _session_with_asset(asset)
    probe = _make_dnssec_result(success=False, pqc_status="vulnerable")

    count = asyncio.run(
        L1FindingService(session).persist_dnssec_results(
            scan_id="scan-1",
            probe_results=[(asset.id, probe)],
        )
    )
    assert count == 0


# ------------------------------------------------------------------- evidence


def test_evidence_contains_mosca_fields():
    from app.services.l1_finding_service import L1FindingService

    asset = _make_asset()
    session = _session_with_asset(asset)
    probe = _make_dnssec_result(algorithms=["RSASHA1"], pqc_status="vulnerable")

    asyncio.run(
        L1FindingService(session).persist_dnssec_results(
            scan_id="scan-1",
            probe_results=[(asset.id, probe)],
        )
    )

    f = _added_findings(session)[0]
    assert f.evidence is not None
    assert "mosca" in f.evidence
    mosca = f.evidence["mosca"]
    assert "data_longevity_years" in mosca
    assert "quantum_timeline_year" in mosca
    assert "replaceability" in mosca
    assert mosca["quantum_timeline_year"] > 2025


def test_finding_has_risk_score_in_range():
    from app.services.l1_finding_service import L1FindingService

    asset = _make_asset()
    session = _session_with_asset(asset)
    probe = _make_ocsp_result(pqc_status="disallowed_now")

    asyncio.run(
        L1FindingService(session).persist_ocsp_results(
            scan_id="scan-1",
            probe_results=[(asset.id, probe)],
        )
    )

    f = _added_findings(session)[0]
    # Risk score is the raw 5-25; we only assert it's been computed and bounded.
    assert isinstance(f.risk_score, int)
    assert 5 <= f.risk_score <= 25


# ----------------------------------------------------- generate_l1_findings --


def test_generate_l1_findings_returns_counts():
    from app.services.l1_finding_service import generate_l1_findings

    asset = _make_asset()
    session = _session_with_asset(asset)

    ocsp = [("asset-1", _make_ocsp_result(pqc_status="vulnerable"))]
    dnssec = [("asset-1", _make_dnssec_result(algorithms=["RSASHA1"], pqc_status="vulnerable"))]

    counts = asyncio.run(
        generate_l1_findings(
            session,
            scan_id="scan-1",
            ocsp_results=ocsp,
            dnssec_results=dnssec,
        )
    )
    assert counts == {"ocsp_findings": 1, "dnssec_findings": 1}
    # Two commits (one per persist call inside the wrapper).
    assert session.commit.await_count == 2


def test_generate_l1_findings_empty_inputs_no_commits():
    from app.services.l1_finding_service import generate_l1_findings

    asset = _make_asset()
    session = _session_with_asset(asset)

    counts = asyncio.run(
        generate_l1_findings(
            session,
            scan_id="scan-1",
            ocsp_results=[],
            dnssec_results=[],
        )
    )
    assert counts == {"ocsp_findings": 0, "dnssec_findings": 0}
    session.commit.assert_not_awaited()
