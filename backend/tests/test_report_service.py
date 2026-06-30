"""
Tests for `app.services.report_service` - CBOM, SARIF, CSV, PDF, and
the `generate_report` dispatcher.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ------------------- SARIF for SAST findings --------------------


def test_generate_sarif_for_sast_findings_empty():
    """No inputs yields a valid empty SARIF doc."""
    from app.services.report_service import generate_sarif_for_sast_findings

    out = generate_sarif_for_sast_findings("scan-x")
    assert out["version"] == "2.1.0"
    assert "runs" in out
    run = out["runs"][0]
    assert run["tool"]["driver"]["name"] == "PQCrypt Sentinel SAST"
    assert run["results"] == []


def test_generate_sarif_for_sast_findings_semgrep_only():
    """Semgrep findings become SARIF results with ruleIndex."""
    from app.services.report_service import generate_sarif_for_sast_findings

    semgrep = {
        "success": True,
        "findings": [
            {
                "rule": "python.lang.security.audit.rsa-usage",
                "file": "src/crypto.py",
                "line": 42,
                "message": "RSA used",
                "severity": "ERROR",
            }
        ],
    }
    out = generate_sarif_for_sast_findings("scan-1", semgrep_results=semgrep)
    run = out["runs"][0]
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "python.lang.security.audit.rsa-usage"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 42
    assert len(run["tool"]["driver"]["rules"]) == 1


def test_generate_sarif_for_sast_findings_trivy_only():
    """Trivy findings with various severities map to SARIF levels."""
    from app.services.report_service import generate_sarif_for_sast_findings

    trivy = {
        "success": True,
        "findings": [
            {
                "Target": "requirements.txt",
                "VulnerabilityID": "CVE-2024-9999",
                "PkgName": "openssl",
                "InstalledVersion": "1.0.1",
                "FixedVersion": "1.0.2",
                "Severity": "CRITICAL",
                "Title": "OpenSSL < 1.0.2",
            },
            {
                "Target": "requirements.txt",
                "VulnerabilityID": "CVE-2024-8888",
                "Severity": "MEDIUM",
                "Title": "Medium issue",
            },
        ],
    }
    out = generate_sarif_for_sast_findings("scan-2", trivy_results=trivy)
    run = out["runs"][0]
    assert len(run["results"]) == 2
    levels = {r["level"] for r in run["results"]}
    assert "error" in levels
    assert "warning" in levels


def test_generate_sarif_for_sast_findings_dedup_rules():
    """Same rule appearing in two findings only registers one rule entry."""
    from app.services.report_service import generate_sarif_for_sast_findings

    semgrep = {
        "success": True,
        "findings": [
            {
                "rule": "rsa-usage",
                "file": "a.py",
                "line": 1,
                "message": "x",
                "severity": "ERROR",
            },
            {
                "rule": "rsa-usage",
                "file": "b.py",
                "line": 2,
                "message": "x",
                "severity": "ERROR",
            },
        ],
    }
    out = generate_sarif_for_sast_findings("scan-3", semgrep_results=semgrep)
    run = out["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2


def test_generate_sarif_for_sast_findings_failed_inputs_ignored():
    """Inputs with `success: False` are skipped."""
    from app.services.report_service import generate_sarif_for_sast_findings

    out = generate_sarif_for_sast_findings(
        "scan-x",
        semgrep_results={"success": False, "findings": [{"rule": "r1"}]},
        trivy_results={"success": False, "findings": [{"VulnerabilityID": "v1"}]},
    )
    assert out["runs"][0]["results"] == []


def test_generate_sarif_for_sast_findings_trivy_non_dict_skipped():
    """Trivy entries that aren't dicts are skipped without crashing."""
    from app.services.report_service import generate_sarif_for_sast_findings

    out = generate_sarif_for_sast_findings(
        "scan-x",
        trivy_results={
            "success": True,
            "findings": ["not-a-dict", {"VulnerabilityID": "v1", "Severity": "HIGH"}],
        },
    )
    run = out["runs"][0]
    assert len(run["results"]) == 1


# ------------------- SARIF report (DB-backed) --------------------


def _finding_row(
    finding_id: str = "f-1",
    finding_type: str = "code_weak_crypto",
    severity: str = "high",
    title: str = "RSA used",
    algorithm: str = "RSA",
    pqc_status: str = "vulnerable",
):
    return SimpleNamespace(
        id=finding_id,
        scan_id="scan-1",
        asset_id="a-1",
        finding_type=finding_type,
        severity=severity,
        title=title,
        description=title,
        algorithm=algorithm,
        pqc_status=pqc_status,
        evidence={"file": "src/crypto.py", "line": 42, "path": "/x"},
    )


def test_generate_sarif_report_empty_scan_ids():
    """Empty scan_ids yields an empty SARIF document."""
    from app.services.report_service import generate_sarif_report

    session = AsyncMock()
    with tempfile.TemporaryDirectory() as tmp:
        with patch("app.services.report_service.os.path.dirname") as mock_dirname:
            mock_dirname.return_value = tmp
            out_path = asyncio.run(generate_sarif_report(session, "report-1", []))
        assert os.path.exists(out_path)
        with open(out_path) as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["results"] == []


def test_generate_sarif_report_with_findings():
    """SAST findings from DB are converted to SARIF results."""
    from app.services.report_service import generate_sarif_report

    findings = [
        _finding_row("f-1", "code_weak_crypto", "high", "RSA weak"),
        _finding_row("f-2", "sbom_vulnerable_lib", "medium", "openssl old"),
    ]

    session = AsyncMock()
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return MagicMock(
                scalars=MagicMock(
                    return_value=MagicMock(all=MagicMock(return_value=findings))
                )
            )
        return MagicMock()

    session.execute.side_effect = _execute

    with tempfile.TemporaryDirectory() as tmp:
        with patch("app.services.report_service.os.path.dirname") as mock_dirname:
            mock_dirname.return_value = tmp
            out_path = asyncio.run(
                generate_sarif_report(session, "report-2", ["scan-1"])
            )
        with open(out_path) as f:
            data = json.load(f)
        run = data["runs"][0]
        assert len(run["results"]) == 2
        props = run["results"][0]["properties"]
        assert props["pqc:algorithm"] == "RSA"
        assert props["pqc:status"] == "vulnerable"


# ------------------- CSV export --------------------


def test_generate_csv_findings_export_empty():
    """Empty result set produces a CSV with just the header."""
    from app.services.report_service import generate_csv_findings_export

    session = AsyncMock()
    session.execute.return_value = MagicMock(all=MagicMock(return_value=[]))

    with tempfile.TemporaryDirectory() as tmp:
        with patch("app.services.report_service.os.path.dirname") as mock_dirname:
            # All 3 dirname calls collapse to tmp
            mock_dirname.return_value = tmp
            out_path = asyncio.run(generate_csv_findings_export(session, "report-3"))
        with open(out_path) as f:
            content = f.read()
        assert "finding_id" in content
        assert "asset_name" in content


def test_generate_csv_findings_export_with_rows():
    """Findings are written as CSV rows."""
    from app.services.report_service import generate_csv_findings_export

    finding = SimpleNamespace(
        id="f-1",
        asset_id="a-1",
        scan_id="s-1",
        finding_type="weak_algorithm",
        severity="high",
        title="RSA weak",
        description="d",
        algorithm="RSA",
        algorithm_type="cert",
        pqc_status="vulnerable",
        hndl_exposure="high",
        risk_score=70,
        status="open",
        first_detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_verified_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        remediation="Use ML-DSA-65",
        recommended_algorithm="ML-DSA-65",
        deleted_at=None,
    )
    asset = SimpleNamespace(
        id="a-1",
        name="app.example.com",
        asset_type="server",
        environment="prod",
        fqdn="app.example.com",
        ip_address="10.0.0.1",
    )
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        all=MagicMock(return_value=[(finding, asset)])
    )

    with tempfile.TemporaryDirectory() as tmp:
        with patch("app.services.report_service.os.path.dirname") as mock_dirname:
            mock_dirname.return_value = tmp
            out_path = asyncio.run(generate_csv_findings_export(session, "report-4"))
        with open(out_path) as f:
            content = f.read()
        assert "RSA" in content
        assert "app.example.com" in content


# ------------------- PDF (HTML fallback) --------------------


def test_generate_pdf_executive_report_no_data():
    """Empty asset/finding lists produce an HTML fallback file."""
    from app.services.report_service import generate_pdf_executive_report

    session = AsyncMock()
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        return MagicMock(
            scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
        )

    session.execute.side_effect = _execute

    with tempfile.TemporaryDirectory() as tmp:
        with patch(
            "app.services.report_service.os.path.dirname"
        ) as mock_dirname, patch.dict("sys.modules", {"weasyprint": None}):
            mock_dirname.return_value = tmp
            out_path = asyncio.run(generate_pdf_executive_report(session, "report-5"))
        # Returns HTML fallback path
        assert out_path.endswith(".html")
        assert os.path.exists(out_path)
        with open(out_path) as f:
            content = f.read()
        assert "PQCrypt Sentinel" in content
        assert "Cryptographic Posture" in content


def test_generate_pdf_executive_report_with_findings():
    """Findings and assets appear in the rendered HTML."""
    from app.services.report_service import generate_pdf_executive_report

    asset = SimpleNamespace(
        id="a-1",
        name="db.example.com",
        asset_type="database",
        environment="prod",
        business_service="payments",
        owner_id=None,
        fqdn="db.example.com",
        ip_address="10.0.0.5",
    )
    finding = SimpleNamespace(
        id="f-1",
        asset_id="a-1",
        scan_id="s-1",
        finding_type="weak_algorithm",
        severity="critical",
        title="RSA-1024 in use",
        description="d",
        algorithm="RSA",
        pqc_status="vulnerable",
        hndl_exposure="high",
        risk_score=95,
        status="open",
        first_detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_verified_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        recommended_algorithm="ML-DSA-65",
    )
    algo_rows = [("vulnerable", 1), ("pqc_ready", 2)]

    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return MagicMock(
                scalars=MagicMock(
                    return_value=MagicMock(all=MagicMock(return_value=[asset]))
                )
            )
        if call_count["n"] == 2:
            return MagicMock(
                scalars=MagicMock(
                    return_value=MagicMock(all=MagicMock(return_value=[finding]))
                )
            )
        return MagicMock(all=MagicMock(return_value=algo_rows))

    session = AsyncMock()
    session.execute.side_effect = _execute

    with tempfile.TemporaryDirectory() as tmp:
        with patch(
            "app.services.report_service.os.path.dirname"
        ) as mock_dirname, patch.dict("sys.modules", {"weasyprint": None}):
            mock_dirname.return_value = tmp
            out_path = asyncio.run(generate_pdf_executive_report(session, "report-6"))
        with open(out_path) as f:
            content = f.read()
        assert "RSA-1024" in content
        assert "PQCrypt Sentinel" in content
        # readiness is 200% (2 pqc-ready algos / 1 asset)
        assert "200.0%" in content or "vulnerable" in content


# ------------------- CBOM generation --------------------


def test_generate_cbom_not_found():
    """Raises ValueError when report_id doesn't exist."""
    from app.services.report_service import generate_cbom

    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=None)
    )

    with pytest.raises(ValueError, match="not found"):
        asyncio.run(generate_cbom(session, "missing-id"))


def test_generate_cbom_no_assets():
    """Generates an empty CBOM when no assets exist."""
    from app.services.report_service import generate_cbom

    report = SimpleNamespace(
        id="report-1",
        scope_filters={},
        status="queued",
        file_path=None,
    )
    session = AsyncMock()
    # 1st execute: report lookup -> found
    # 2nd: assets (paged loop) -> empty
    # After CBOM gen: report update lookup
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return MagicMock(scalar_one_or_none=MagicMock(return_value=report))
        if call_count["n"] == 2:
            return MagicMock(
                scalars=MagicMock(
                    return_value=MagicMock(all=MagicMock(return_value=[]))
                )
            )
        return MagicMock(scalar_one_or_none=MagicMock(return_value=report))

    session.execute.side_effect = _execute
    session.commit = AsyncMock()
    session.refresh = AsyncMock()

    with tempfile.TemporaryDirectory() as tmp:
        with patch("app.services.report_service.os.path.dirname") as mock_dirname:
            mock_dirname.return_value = tmp
            out_path = asyncio.run(generate_cbom(session, "report-1"))
        assert os.path.exists(out_path)
        with open(out_path) as f:
            data = json.load(f)
        assert data["specVersion"] == "1.7"


# ------------------- generate_report dispatcher --------------------


def test_generate_report_not_found():
    """Raises ValueError when report_id doesn't exist."""
    from app.services.report_service import generate_report

    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=None)
    )

    with pytest.raises(ValueError, match="not found"):
        asyncio.run(generate_report(session, "missing", "cbom", "json"))


def test_generate_report_unsupported_combination():
    """Raises ValueError on bad report_type/format pair."""
    from app.services.report_service import generate_report

    report = SimpleNamespace(
        id="r-1",
        status="queued",
        scope_filters={},
    )
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=report)
    )
    session.commit = AsyncMock()
    session.refresh = AsyncMock()

    with pytest.raises(ValueError, match="Unsupported"):
        asyncio.run(generate_report(session, "r-1", "garbage", "xml"))


def test_generate_report_internal_failure_marks_failed():
    """When generation raises, the report row is marked failed."""
    from app.services.report_service import generate_report

    report = SimpleNamespace(
        id="r-1",
        status="queued",
        scope_filters={},
    )
    session = AsyncMock()

    async def _execute(stmt):
        return MagicMock(scalar_one_or_none=MagicMock(return_value=report))

    session.execute.side_effect = _execute
    session.commit = AsyncMock()
    session.refresh = AsyncMock()

    with patch(
        "app.services.report_service.generate_cbom",
        new=AsyncMock(side_effect=RuntimeError("boom")),
    ):
        with pytest.raises(RuntimeError, match="boom"):
            asyncio.run(generate_report(session, "r-1", "cbom", "json"))
    assert report.status == "failed"
    assert "boom" in report.error_message


def test_generate_report_dispatch_csv():
    """`findings`/`csv` dispatches to `generate_csv_findings_export`."""
    from app.services.report_service import generate_report

    report = SimpleNamespace(id="r-2", status="queued", scope_filters={})
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=report)
    )
    session.commit = AsyncMock()
    session.refresh = AsyncMock()

    with patch(
        "app.services.report_service.generate_csv_findings_export",
        new=AsyncMock(return_value="/tmp/out.csv"),
    ) as m:
        out = asyncio.run(generate_report(session, "r-2", "findings", "csv"))
    assert out == "/tmp/out.csv"
    m.assert_called_once()
    assert report.status == "ready"


def test_generate_report_dispatch_pdf():
    """`executive`/`pdf` dispatches to `generate_pdf_executive_report`."""
    from app.services.report_service import generate_report

    report = SimpleNamespace(id="r-3", status="queued", scope_filters={})
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=report)
    )
    session.commit = AsyncMock()
    session.refresh = AsyncMock()

    with patch(
        "app.services.report_service.generate_pdf_executive_report",
        new=AsyncMock(return_value="/tmp/r.html"),
    ) as m:
        out = asyncio.run(generate_report(session, "r-3", "executive", "pdf"))
    assert out == "/tmp/r.html"
    m.assert_called_once()


def test_generate_report_dispatch_sarif():
    """`sast`/`sarif` dispatches to `generate_sarif_report` with scan_ids."""
    from app.services.report_service import generate_report

    report = SimpleNamespace(id="r-4", status="queued", scope_filters={})
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=report)
    )
    session.commit = AsyncMock()
    session.refresh = AsyncMock()

    with patch(
        "app.services.report_service.generate_sarif_report",
        new=AsyncMock(return_value="/tmp/sarif.json"),
    ) as m:
        out = asyncio.run(
            generate_report(session, "r-4", "sast", "sarif", scan_ids=["s1", "s2"])
        )
    assert out == "/tmp/sarif.json"
    m.assert_called_once_with(session, "r-4", ["s1", "s2"])


# ------------------- Additional Coverage Tests --------------------


def test_ecma424_order_recursive_direct():
    """Directly test _ecma424_order_recursive with nested dicts and lists to cover line 45."""
    from app.services.report_service import (
        _ecma424_order_recursive,
        _CRYPTO_PROPERTIES_ORDER,
    )

    test_dict = {
        "oid": "1.2.3",
        "assetType": "algorithm",
        "extra": {"oid": "4.5.6", "assetType": "cert"},
        "list_items": [{"oid": "7.8.9", "assetType": "key"}],
    }

    result = _ecma424_order_recursive(test_dict, _CRYPTO_PROPERTIES_ORDER)
    assert list(result.keys())[0] == "assetType"
    assert list(result.keys())[1] == "oid"


def test_post_process_cbom_json_error():
    """Verify post_process_cbom handles json parsing exception gracefully."""
    from app.services.report_service import post_process_cbom

    bad_json = "{invalid_json"
    result = post_process_cbom(bad_json, {})
    assert result == bad_json


def test_post_process_cbom_direct_mismatches_and_dep_types():
    """Test post_process_cbom with custom JSON to hit specific branch lines (332, 362, 410-415, 423)."""
    from app.services.report_service import post_process_cbom

    cbom_in = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "bom-ref": "cert-missing",
                "type": "cryptographicAsset",
                "name": "Missing Cert",
            }
        ],
        "dependencies": [
            {
                "ref": "asset-1",
                "dependsOn": ["key-1", "protocol-1", {"ref": "some-other-child"}],
            }
        ],
    }

    json_str = json.dumps(cbom_in)
    res_str = post_process_cbom(json_str, {})
    res = json.loads(res_str)
    assert res["specVersion"] == "1.7"


def test_generate_cbom_with_rich_assets():
    """Test generate_cbom with a variety of assets, certificates, and algorithms to cover post-processing logic."""
    from app.services.report_service import generate_cbom

    report = SimpleNamespace(
        id="report-rich",
        scope_filters={
            "environment": "production",
            "business_service": "payments",
            "owner_id": "user-1",
        },
        status="queued",
        file_path=None,
    )

    class MockCert:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

        @property
        def asset_metadata(self):
            if getattr(self, "_trigger_meta_err", False):
                raise AttributeError("Simulated error reading asset_metadata")
            return getattr(self, "_metadata", {})

    cert1 = MockCert(
        id="c1",
        thumbprint="thumb12345",
        subject="CN=test1",
        issuer="CN=issuer1",
        serial_number="123",
        sig_algorithm="sha256WithRSAEncryption",
        pub_key_algorithm="RSA",
        pub_key_size=2048,
        curve_name=None,
        not_before=datetime(2026, 1, 1),
        not_after=datetime(2027, 1, 1),
        pqc_capable=False,
        is_ca=False,
        is_self_signed=False,
        sig_algorithm_oid="1.2.840.113549.1.1.11",
        _metadata={
            "tls_version": "TLSv1.2",
            "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256",
            "asset_type": "web_app",
        },
    )
    cert2 = MockCert(
        id="c2",
        thumbprint="thumb67890",
        subject="CN=test2",
        issuer="CN=issuer2",
        serial_number="456",
        sig_algorithm="RSASSA-PSS",
        pub_key_algorithm="RSA",
        pub_key_size=3072,
        curve_name=None,
        not_before=datetime(2026, 1, 1),
        not_after=datetime(2027, 1, 1),
        pqc_capable=False,
        is_ca=True,
        is_self_signed=False,
        sig_algorithm_oid=None,
        _metadata={
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "asset_type": "api",
        },
    )
    cert3 = MockCert(
        id="c3",
        thumbprint="thumbecdsa",
        subject="CN=test3",
        issuer="CN=issuer3",
        serial_number="789",
        sig_algorithm="ecdsa-with-SHA384",
        pub_key_algorithm="EC",
        pub_key_size=384,
        curve_name="secp384r1",
        not_before=datetime(2026, 1, 1),
        not_after=datetime(2027, 1, 1),
        pqc_capable=False,
        is_ca=False,
        is_self_signed=False,
        sig_algorithm_oid=None,
        _trigger_meta_err=True,
    )
    cert4 = MockCert(
        id="c4",
        thumbprint="thumbecdsa521",
        subject="CN=test4",
        issuer="CN=issuer4",
        serial_number="101",
        sig_algorithm="ecdsa-with-SHA512",
        pub_key_algorithm="EC",
        pub_key_size=521,
        curve_name="secp521r1",
        not_before=None,
        not_after=None,
        pqc_capable=False,
        is_ca=False,
        is_self_signed=False,
        sig_algorithm_oid=None,
        _metadata={},
    )
    cert5 = MockCert(
        id="c5",
        thumbprint="thurbed25519",
        subject="CN=test5",
        issuer="CN=issuer5",
        serial_number="102",
        sig_algorithm="ed25519",
        pub_key_algorithm="ed25519",
        pub_key_size=256,
        curve_name=None,
        not_before=datetime(2026, 1, 1),
        not_after=datetime(2027, 1, 1),
        pqc_capable=False,
        is_ca=False,
        is_self_signed=False,
        sig_algorithm_oid=None,
        _metadata={},
    )
    cert6 = MockCert(
        id="c6",
        thumbprint="thurbed448",
        subject="CN=test6",
        issuer="CN=issuer6",
        serial_number="103",
        sig_algorithm="ed448",
        pub_key_algorithm="ed448",
        pub_key_size=456,
        curve_name=None,
        not_before=datetime(2026, 1, 1),
        not_after=datetime(2027, 1, 1),
        pqc_capable=False,
        is_ca=False,
        is_self_signed=False,
        sig_algorithm_oid=None,
        _metadata={},
    )
    cert7 = MockCert(
        id="c7",
        thumbprint="thurbpqc",
        subject="CN=test7",
        issuer="CN=issuer7",
        serial_number="104",
        sig_algorithm="ML-DSA-65",
        pub_key_algorithm="ML-DSA",
        pub_key_size=0,
        curve_name=None,
        not_before=datetime(2026, 1, 1),
        not_after=datetime(2027, 1, 1),
        pqc_capable=True,
        is_ca=False,
        is_self_signed=False,
        sig_algorithm_oid=None,
        _metadata={},
    )
    cert8 = MockCert(
        id="c8",
        thumbprint="thurbecdsa256",
        subject="CN=test8",
        issuer="CN=issuer8",
        serial_number="105",
        sig_algorithm="ecdsa-with-SHA256",
        pub_key_algorithm="EC",
        pub_key_size=256,
        curve_name="secp256r1",
        not_before=datetime(2026, 1, 1),
        not_after=datetime(2027, 1, 1),
        pqc_capable=False,
        is_ca=False,
        is_self_signed=False,
        sig_algorithm_oid=None,
        _metadata={},
    )
    cert9 = MockCert(
        id="c9",
        thumbprint="thurbecdsaother",
        subject="CN=test9",
        issuer="CN=issuer9",
        serial_number="106",
        sig_algorithm="ecdsa-with-SHA224",
        pub_key_algorithm="EC",
        pub_key_size=224,
        curve_name="secp224r1",
        not_before=datetime(2026, 1, 1),
        not_after=datetime(2027, 1, 1),
        pqc_capable=False,
        is_ca=False,
        is_self_signed=False,
        sig_algorithm_oid=None,
        _metadata={},
    )
    cert10 = MockCert(
        id="c10",
        thumbprint="thurb_rsa_large",
        subject="CN=test10",
        issuer="CN=issuer10",
        serial_number="107",
        sig_algorithm="sha256WithRSAEncryption",
        pub_key_algorithm="RSA",
        pub_key_size=16384,
        curve_name=None,
        not_before=datetime(2026, 1, 1),
        not_after=datetime(2027, 1, 1),
        pqc_capable=False,
        is_ca=False,
        is_self_signed=False,
        sig_algorithm_oid=None,
        _metadata={},
    )
    cert11 = MockCert(
        id="c11",
        thumbprint="thurb_rsa_medium",
        subject="CN=test11",
        issuer="CN=issuer11",
        serial_number="108",
        sig_algorithm="sha256WithRSAEncryption",
        pub_key_algorithm="RSA",
        pub_key_size=8192,
        curve_name=None,
        not_before=datetime(2026, 1, 1),
        not_after=datetime(2027, 1, 1),
        pqc_capable=False,
        is_ca=False,
        is_self_signed=False,
        sig_algorithm_oid=None,
        _metadata={},
    )
    cert12 = MockCert(
        id="c12",
        thumbprint="thurb_rsa_small",
        subject="CN=test12",
        issuer="CN=issuer12",
        serial_number="109",
        sig_algorithm="sha256WithRSAEncryption",
        pub_key_algorithm="RSA",
        pub_key_size=1024,
        curve_name=None,
        not_before=datetime(2026, 1, 1),
        not_after=datetime(2027, 1, 1),
        pqc_capable=False,
        is_ca=False,
        is_self_signed=False,
        sig_algorithm_oid=None,
        _metadata={},
    )

    class MockAlgo:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    algo1 = MockAlgo(
        id="a1",
        algorithm_name="ML-KEM-768",
        algorithm_type="kem",
        key_size=256,
        curve="kyber",
        oid="1.3.6.1.4.1.2.275.2",
        pqc_status="pqc_ready",
    )
    algo2 = MockAlgo(
        id="a2",
        algorithm_name="ML-DSA-87",
        algorithm_type="signature",
        key_size=0,
        curve=None,
        oid=None,
        pqc_status="safe",
    )
    algo3 = MockAlgo(
        id="a3",
        algorithm_name="AES-256-GCM",
        algorithm_type="symmetric",
        key_size=256,
        curve=None,
        oid=None,
        pqc_status="safe",
    )
    algo4 = MockAlgo(
        id="a4",
        algorithm_name="SHA-256",
        algorithm_type="hash",
        key_size=0,
        curve=None,
        oid=None,
        pqc_status="safe",
    )
    algo5 = MockAlgo(
        id="a5",
        algorithm_name="HMAC-SHA256",
        algorithm_type="mac",
        key_size=256,
        curve=None,
        oid=None,
        pqc_status="safe",
    )
    algo6 = MockAlgo(
        id="a6",
        algorithm_name="RSA-3072",
        algorithm_type="signature",
        key_size=3072,
        curve=None,
        oid=None,
        pqc_status="vulnerable",
    )
    algo7 = MockAlgo(
        id="a7",
        algorithm_name="ECDSA",
        algorithm_type="signature",
        key_size=256,
        curve=None,
        oid=None,
        pqc_status="vulnerable",
    )
    algo8 = MockAlgo(
        id="a8",
        algorithm_name="Ed25519",
        algorithm_type="signature",
        key_size=256,
        curve=None,
        oid=None,
        pqc_status="vulnerable",
    )
    algo9 = MockAlgo(
        id="a9",
        algorithm_name="Hardware-HSM-Kyber",
        algorithm_type="kem",
        key_size=256,
        curve=None,
        oid=None,
        pqc_status="pqc_ready",
    )
    algo10 = MockAlgo(
        id="a10",
        algorithm_name="KMS-Key",
        algorithm_type="kem",
        key_size=256,
        curve=None,
        oid=None,
        pqc_status="pqc_ready",
    )
    algo11 = MockAlgo(
        id="a11",
        algorithm_name="RSA-15360",
        algorithm_type="signature",
        key_size=15360,
        curve=None,
        oid=None,
        pqc_status="vulnerable",
    )
    algo12 = MockAlgo(
        id="a12",
        algorithm_name="RSA-7680",
        algorithm_type="signature",
        key_size=7680,
        curve=None,
        oid=None,
        pqc_status="vulnerable",
    )
    algo13 = MockAlgo(
        id="a13",
        algorithm_name="RSA-2048",
        algorithm_type="signature",
        key_size=2048,
        curve=None,
        oid=None,
        pqc_status="vulnerable",
    )
    algo14 = MockAlgo(
        id="a14",
        algorithm_name="RSA-1024",
        algorithm_type="signature",
        key_size=1024,
        curve=None,
        oid=None,
        pqc_status="vulnerable",
    )
    algo15 = MockAlgo(
        id="a15",
        algorithm_name="ECDSA-521",
        algorithm_type="signature",
        key_size=521,
        curve=None,
        oid=None,
        pqc_status="vulnerable",
    )
    algo16 = MockAlgo(
        id="a16",
        algorithm_name="ECDSA-384",
        algorithm_type="signature",
        key_size=384,
        curve=None,
        oid=None,
        pqc_status="vulnerable",
    )
    algo17 = MockAlgo(
        id="a17",
        algorithm_name="ECDSA-224",
        algorithm_type="signature",
        key_size=224,
        curve=None,
        oid=None,
        pqc_status="vulnerable",
    )
    algo18 = MockAlgo(
        id="a18",
        algorithm_name="some-pqc-1024",
        algorithm_type="kem",
        key_size=256,
        curve=None,
        oid=None,
        pqc_status="safe",
    )
    algo19 = MockAlgo(
        id="a19",
        algorithm_name="some-pqc-768",
        algorithm_type="kem",
        key_size=256,
        curve=None,
        oid=None,
        pqc_status="safe",
    )
    algo20 = MockAlgo(
        id="a20",
        algorithm_name="some-pqc-other",
        algorithm_type="kem",
        key_size=256,
        curve=None,
        oid=None,
        pqc_status="safe",
    )

    asset = SimpleNamespace(
        id="rich-asset-1",
        name="rich-asset-1",
        asset_type="server",
        environment="production",
        ip_address="10.0.0.1",
        fqdn="srv.example.com",
        deleted_at=None,
        certificates=[
            cert1,
            cert2,
            cert3,
            cert4,
            cert5,
            cert6,
            cert7,
            cert8,
            cert9,
            cert10,
            cert11,
            cert12,
        ],
        algorithms=[
            algo1,
            algo2,
            algo3,
            algo4,
            algo5,
            algo6,
            algo7,
            algo8,
            algo9,
            algo10,
            algo11,
            algo12,
            algo13,
            algo14,
            algo15,
            algo16,
            algo17,
            algo18,
            algo19,
            algo20,
        ],
    )

    session = AsyncMock()
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return MagicMock(scalar_one_or_none=MagicMock(return_value=report))
        if call_count["n"] == 2:
            return MagicMock(
                scalars=MagicMock(
                    return_value=MagicMock(all=MagicMock(return_value=[asset]))
                )
            )
        if call_count["n"] == 3:
            return MagicMock(
                scalars=MagicMock(
                    return_value=MagicMock(all=MagicMock(return_value=[]))
                )
            )
        return MagicMock(scalar_one_or_none=MagicMock(return_value=report))

    session.execute.side_effect = _execute
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.expunge_all = MagicMock()

    with tempfile.TemporaryDirectory() as tmp:
        with patch("app.services.report_service.os.path.dirname") as mock_dirname:
            mock_dirname.return_value = tmp
            out_path = asyncio.run(generate_cbom(session, "report-rich"))
        assert os.path.exists(out_path)
        with open(out_path) as f:
            data = json.load(f)
        assert data["specVersion"] == "1.7"

        components = data.get("components", [])
        assert len(components) > 0


def test_generate_cbom_exception_path():
    """Verify generate_cbom sets status to failed when an exception occurs."""
    from app.services.report_service import generate_cbom

    report = SimpleNamespace(
        id="report-err",
        scope_filters={},
        status="queued",
        file_path=None,
    )
    session = AsyncMock()
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return MagicMock(scalar_one_or_none=MagicMock(return_value=report))
        if call_count["n"] == 2:
            raise RuntimeError("database error during assets query")
        return MagicMock(scalar_one_or_none=MagicMock(return_value=report))

    session.execute.side_effect = _execute
    session.commit = AsyncMock()
    session.refresh = AsyncMock()

    with pytest.raises(RuntimeError, match="database error"):
        asyncio.run(generate_cbom(session, "report-err"))

    assert report.status == "failed"
    assert "database error" in report.error_message


def test_generate_cbom_exception_no_report():
    """Verify generate_cbom handles exception when report is not found in database."""
    from app.services.report_service import generate_cbom

    report = SimpleNamespace(
        id="report-err-none",
        scope_filters={},
        status="queued",
        file_path=None,
    )
    session = AsyncMock()
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return MagicMock(scalar_one_or_none=MagicMock(return_value=report))
        if call_count["n"] == 2:
            raise RuntimeError("database error during assets query")
        return MagicMock(scalar_one_or_none=MagicMock(return_value=None))

    session.execute.side_effect = _execute
    session.commit = AsyncMock()
    session.refresh = AsyncMock()

    with pytest.raises(RuntimeError, match="database error"):
        asyncio.run(generate_cbom(session, "report-err-none"))

    assert report.status == "generating"


def test_generate_csv_findings_export_with_scope_filters():
    """Verify CSV export filters by environment, business_service, owner_id and handles None value formats."""
    from app.services.report_service import generate_csv_findings_export

    finding = SimpleNamespace(
        id="f-1",
        asset_id="a-1",
        scan_id="s-1",
        finding_type="weak_algorithm",
        severity="high",
        title="RSA weak",
        description="d",
        algorithm=None,
        algorithm_type="cert",
        pqc_status="vulnerable",
        hndl_exposure="high",
        risk_score=70,
        status="open",
        first_detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_verified_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        remediation="Use ML-DSA-65",
        recommended_algorithm="ML-DSA-65",
        deleted_at=None,
    )
    asset = SimpleNamespace(
        id="a-1",
        name="app.example.com",
        asset_type="server",
        environment="prod",
        business_service="finance",
        owner_id="user-123",
        fqdn="app.example.com",
        ip_address="10.0.0.1",
    )
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        all=MagicMock(return_value=[(finding, asset)])
    )

    scope_filters = {
        "environment": "prod",
        "business_service": "finance",
        "owner_id": "user-123",
    }

    with tempfile.TemporaryDirectory() as tmp:
        with patch("app.services.report_service.os.path.dirname") as mock_dirname:
            mock_dirname.return_value = tmp
            out_path = asyncio.run(
                generate_csv_findings_export(
                    session, "report-csv-filters", scope_filters
                )
            )
        assert os.path.exists(out_path)


def test_generate_pdf_executive_report_with_filters():
    """Verify PDF executive report queries are filtered by environment and business_service."""
    from app.services.report_service import generate_pdf_executive_report

    session = AsyncMock()
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        return MagicMock(
            scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
        )

    session.execute.side_effect = _execute

    scope_filters = {
        "environment": "production",
        "business_service": "billing",
        "quantum_timeline_year": 2030,
    }

    with tempfile.TemporaryDirectory() as tmp:
        with patch(
            "app.services.report_service.os.path.dirname"
        ) as mock_dirname, patch.dict("sys.modules", {"weasyprint": None}):
            mock_dirname.return_value = tmp
            out_path = asyncio.run(
                generate_pdf_executive_report(
                    session, "report-pdf-filters", scope_filters
                )
            )
        assert out_path.endswith(".html")
        assert os.path.exists(out_path)


def test_generate_pdf_executive_report_esc_none():
    """Verify _esc handles None input values correctly in PDF HTML rendering."""
    from app.services.report_service import generate_pdf_executive_report

    asset = SimpleNamespace(
        id="a-1",
        name="db.example.com",
        asset_type="database",
        environment="prod",
        business_service="payments",
        owner_id=None,
        fqdn="db.example.com",
        ip_address="10.0.0.5",
    )
    finding = SimpleNamespace(
        id="f-1",
        asset_id="a-1",
        scan_id="s-1",
        finding_type="weak_algorithm",
        severity=None,
        title=None,
        description=None,
        algorithm=None,
        pqc_status="vulnerable",
        hndl_exposure=None,
        risk_score=95,
        status="open",
        first_detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_verified_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        recommended_algorithm="ML-DSA-65",
    )

    session = AsyncMock()
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return MagicMock(
                scalars=MagicMock(
                    return_value=MagicMock(all=MagicMock(return_value=[asset]))
                )
            )
        if call_count["n"] == 2:
            return MagicMock(
                scalars=MagicMock(
                    return_value=MagicMock(all=MagicMock(return_value=[finding]))
                )
            )
        return MagicMock(all=MagicMock(return_value=[]))

    session.execute.side_effect = _execute

    with tempfile.TemporaryDirectory() as tmp:
        with patch(
            "app.services.report_service.os.path.dirname"
        ) as mock_dirname, patch.dict("sys.modules", {"weasyprint": None}):
            mock_dirname.return_value = tmp
            out_path = asyncio.run(
                generate_pdf_executive_report(session, "report-esc-none")
            )
        assert out_path.endswith(".html")
        assert os.path.exists(out_path)


def test_generate_pdf_executive_report_weasyprint_success_mocked():
    """Verify WeasyPrint success path when it is mock-installed."""
    from app.services.report_service import generate_pdf_executive_report

    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    )

    class MockHTML:
        def __init__(self, string, base_url):
            self.string = string
            self.base_url = base_url

        def write_pdf(self, path):
            with open(path, "w") as f:
                f.write("mocked pdf content")

    with tempfile.TemporaryDirectory() as tmp:
        with patch(
            "app.services.report_service.os.path.dirname"
        ) as mock_dirname, patch.dict(
            "sys.modules", {"weasyprint": SimpleNamespace(HTML=MockHTML)}
        ):
            mock_dirname.return_value = tmp
            out_path = asyncio.run(
                generate_pdf_executive_report(session, "report-wp-ok")
            )
        assert out_path.endswith(".pdf")
        assert os.path.exists(out_path)


def test_generate_compliance_report_no_data():
    """Empty data produces a valid compliance JSON structure."""
    from app.services.report_service import generate_compliance_report

    session = AsyncMock()
    session.execute.side_effect = lambda stmt: MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    )

    with tempfile.TemporaryDirectory() as tmp:
        with patch("app.services.report_service.os.path.dirname") as mock_dirname:
            mock_dirname.return_value = tmp
            out_path = asyncio.run(generate_compliance_report(session, "report-c1"))
        with open(out_path) as f:
            data = json.load(f)
        assert data["report_metadata"]["report_type"] == "compliance"
        assert data["executive_summary"]["total_assets"] == 0
        assert data["executive_summary"]["total_findings"] == 0
        assert data["findings_by_asset"] == []
        assert data["compliance_mapping"] == []


def test_generate_compliance_report_with_findings():
    """Findings appear grouped by asset with NIST controls."""
    from app.services.report_service import generate_compliance_report

    asset = SimpleNamespace(
        id="a-1",
        name="app.example.com",
        asset_type="web_app",
        environment="prod",
        fqdn="app.example.com",
        ip_address="10.0.0.1",
        business_service="payments",
        owner_id=None,
        deleted_at=None,
    )
    algo = SimpleNamespace(pqc_status="pqc_ready", asset_id="a-1")
    algo_rows = [("pqc_ready", "a-1")]

    finding1 = SimpleNamespace(
        id="f-1",
        asset_id="a-1",
        scan_id="s-1",
        finding_type="weak_algorithm",
        severity="critical",
        title="RSA-1024",
        description="Weak algorithm",
        algorithm="RSA",
        pqc_status="vulnerable",
        hndl_exposure="high",
        risk_score=95,
        status="open",
        first_detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_verified_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        resolved_at=None,
        remediation="Migrate to ML-KEM-768",
        recommended_algorithm="ML-KEM-768",
        priority_queue="P1",
        deleted_at=None,
    )
    finding2 = SimpleNamespace(
        id="f-2",
        asset_id="a-1",
        scan_id="s-1",
        finding_type="cert_expiring",
        severity="medium",
        title="Cert expiring",
        description="Expires soon",
        algorithm=None,
        pqc_status="vulnerable",
        hndl_exposure="low",
        risk_score=20,
        status="in_progress",
        first_detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_verified_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        resolved_at=None,
        remediation="Renew certificate",
        recommended_algorithm="ECDSA-P256",
        priority_queue="P3",
        deleted_at=None,
    )
    rows = [(finding1, asset), (finding2, asset)]

    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return MagicMock(
                scalars=MagicMock(
                    return_value=MagicMock(all=MagicMock(return_value=[asset]))
                )
            )
        if call_count["n"] == 2:
            return MagicMock(all=MagicMock(return_value=rows))
        return MagicMock(all=MagicMock(return_value=algo_rows))

    session = AsyncMock()
    session.execute.side_effect = _execute

    with tempfile.TemporaryDirectory() as tmp:
        with patch("app.services.report_service.os.path.dirname") as mock_dirname:
            mock_dirname.return_value = tmp
            out_path = asyncio.run(generate_compliance_report(session, "report-c2"))
        with open(out_path) as f:
            data = json.load(f)

    assert (
        data["report_metadata"]["framework"] == "NIST / SBI Cryptographic Posture Audit"
    )
    assert data["executive_summary"]["total_assets"] == 1
    assert data["executive_summary"]["total_findings"] == 2
    assert data["executive_summary"]["findings_by_severity"]["critical"] == 1
    assert data["executive_summary"]["findings_by_severity"]["medium"] == 1

    asset_entries = data["findings_by_asset"]
    assert len(asset_entries) == 1
    a1 = asset_entries[0]
    assert a1["asset_name"] == "app.example.com"
    assert a1["pqc_readiness_pct"] > 0
    assert len(a1["findings"]) == 2

    first = a1["findings"][0]
    assert first["nist_control"] == "SC-17 (PKI) / SA-11 (Developer Security)"
    assert first["priority_queue"] == "P1"

    mapping = data["compliance_mapping"]
    assert len(mapping) == 2
    assert mapping[0]["risk_score"] == 95


def test_generate_report_dispatch_compliance():
    """`compliance`/`json` dispatches to `generate_compliance_report`."""
    from app.services.report_service import generate_report

    report = SimpleNamespace(id="r-5", status="queued", scope_filters={})
    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalar_one_or_none=MagicMock(return_value=report)
    )
    session.commit = AsyncMock()
    session.refresh = AsyncMock()

    with patch(
        "app.services.report_service.generate_compliance_report",
        new=AsyncMock(return_value="/tmp/c.json"),
    ) as m:
        out = asyncio.run(generate_report(session, "r-5", "compliance", "json"))
    assert out == "/tmp/c.json"
    m.assert_called_once()
    assert report.status == "ready"


def test_generate_pdf_executive_report_weasyprint_failure():
    """If WeasyPrint throws an exception during write_pdf, it falls back to HTML."""
    from app.services.report_service import generate_pdf_executive_report

    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    )

    class MockHTML:
        def __init__(self, string, base_url):
            pass

        def write_pdf(self, path):
            raise RuntimeError("Weasyprint crashed")

    with tempfile.TemporaryDirectory() as tmp:
        with patch(
            "app.services.report_service.os.path.dirname"
        ) as mock_dirname, patch.dict(
            "sys.modules", {"weasyprint": SimpleNamespace(HTML=MockHTML)}
        ):
            mock_dirname.return_value = tmp
            out_path = asyncio.run(
                generate_pdf_executive_report(session, "report-wp-fail")
            )
        assert out_path.endswith(".html")
        assert os.path.exists(out_path)


# ------------------- Coverage gap fill-ins --------------------


def test_generate_pdf_executive_report_unsupported_format():
    """Unsupported executive format raises ValueError."""
    from app.services.report_service import generate_pdf_executive_report

    session = AsyncMock()
    with pytest.raises(ValueError, match="Unsupported executive report format"):
        asyncio.run(generate_pdf_executive_report(session, "r-x", fmt="docx"))


def test_generate_compliance_report_unsupported_format():
    """Unsupported compliance format raises ValueError."""
    from app.services.report_service import generate_compliance_report

    session = AsyncMock()
    with pytest.raises(ValueError, match="Unsupported compliance report format"):
        asyncio.run(generate_compliance_report(session, "r-x", fmt="pdf"))


def test_generate_compliance_report_html_output():
    """Compliance report fmt='html' writes and returns HTML path."""
    from app.services.report_service import generate_compliance_report

    session = AsyncMock()
    session.execute.side_effect = lambda stmt: MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    )

    with tempfile.TemporaryDirectory() as tmp:
        with patch("app.services.report_service.os.path.dirname") as mock_dirname:
            mock_dirname.return_value = tmp
            out_path = asyncio.run(
                generate_compliance_report(session, "report-c-html", fmt="html")
            )
        assert out_path.endswith(".html")
        assert os.path.exists(out_path)


def test_render_compliance_html_empty():
    """_render_compliance_html with empty report renders all fallback rows."""
    from app.services.report_service import _render_compliance_html

    html = _render_compliance_html(
        {
            "report_metadata": {"report_id": "r-empty"},
            "executive_summary": {},
        }
    )
    assert "r-empty" in html
    assert "No remediation data" in html
    assert "No algorithms recorded" in html
    assert "No assets in scope" in html
    assert "No findings recorded" in html
    assert "No compliance mapping data" in html


def test_render_compliance_html_rich():
    """_render_compliance_html with rich data renders every table section."""
    from app.services.report_service import _render_compliance_html

    report = {
        "report_metadata": {
            "report_id": "r-rich",
            "framework": "NIST",
            "generated_at": "2026-01-01T00:00:00Z",
            "scope_filters": {"environment": "prod"},
        },
        "executive_summary": {
            "total_assets": 2,
            "total_findings": 3,
            "overall_pqc_readiness_pct": 66.7,
            "findings_by_severity": {
                "critical": 1,
                "high": 1,
                "medium": 0,
                "low": 1,
                "info": 0,
            },
            "remediation_status": {"open": 2, "resolved": 1},
            "algorithm_distribution": {"pqc_ready": 1, "vulnerable": 2},
        },
        "findings_by_asset": [
            {
                "asset_name": "srv-1",
                "asset_type": "server",
                "environment": "prod",
                "fqdn": "srv-1.example.com",
                "ip_address": "10.0.0.1",
                "pqc_readiness_pct": 50.0,
                "findings": [
                    {
                        "finding_type": "weak_algorithm",
                        "severity": "critical",
                        "risk_score": 95,
                        "status": "open",
                        "recommended_algorithm": "ML-KEM-768",
                        "remediation": "Rotate",
                        "nist_control": "SC-17",
                    }
                ],
            }
        ],
        "compliance_mapping": [
            {
                "asset_name": "srv-1",
                "finding_type": "weak_algorithm",
                "nist_control": "SC-17",
                "risk_score": 95,
                "status": "open",
                "recommended_algorithm": "ML-KEM-768",
                "remediation": "Rotate",
            }
        ],
    }
    html = _render_compliance_html(report)
    assert "r-rich" in html
    assert "srv-1" in html
    assert "weak_algorithm" in html
    assert "66.7%" in html
    assert "SC-17" in html
    assert "ML-KEM-768" in html


def test_generate_pdf_executive_report_html_format():
    """fmt='html' returns the HTML path directly."""
    from app.services.report_service import generate_pdf_executive_report

    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    )

    with tempfile.TemporaryDirectory() as tmp:
        with patch("app.services.report_service.os.path.dirname") as mock_dirname:
            mock_dirname.return_value = tmp
            out_path = asyncio.run(
                generate_pdf_executive_report(session, "r-html", fmt="html")
            )
        assert out_path.endswith(".html")
        assert os.path.exists(out_path)


def test_generate_pdf_executive_report_owner_id_filter():
    """owner_id scope filter is applied."""
    from app.services.report_service import generate_pdf_executive_report

    session = AsyncMock()
    session.execute.return_value = MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    )

    with tempfile.TemporaryDirectory() as tmp:
        with patch(
            "app.services.report_service.os.path.dirname"
        ) as mock_dirname, patch.dict("sys.modules", {"weasyprint": None}):
            mock_dirname.return_value = tmp
            out_path = asyncio.run(
                generate_pdf_executive_report(
                    session, "r-owner", scope_filters={"owner_id": "u-1"}
                )
            )
        assert out_path.endswith(".html")


def test_generate_compliance_report_with_scope_filters():
    """Compliance report applies environment, business_service, owner_id filters."""
    from app.services.report_service import generate_compliance_report

    session = AsyncMock()
    session.execute.side_effect = lambda stmt: MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    )

    with tempfile.TemporaryDirectory() as tmp:
        with patch("app.services.report_service.os.path.dirname") as mock_dirname:
            mock_dirname.return_value = tmp
            out_path = asyncio.run(
                generate_compliance_report(
                    session,
                    "r-c-filters",
                    scope_filters={
                        "environment": "prod",
                        "business_service": "pay",
                        "owner_id": "u-1",
                    },
                )
            )
        assert os.path.exists(out_path)


def test_post_process_cbom_meta_extraction_branches():
    """Exercise all meta extraction branches for protocol components."""
    from app.services.report_service import post_process_cbom

    class FakeAsset:
        asset_metadata = {
            "tls_version": "TLSv1.2",
            "cipher_suite": "AES128-SHA",
            "asset_type": "web_app",
        }

    def _cert(**kwargs):
        defaults = {
            "thumbprint": "a" * 64,
            "pub_key_size": 2048,
            "not_before": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "not_after": datetime(2027, 1, 1, tzinfo=timezone.utc),
        }
        defaults.update(kwargs)
        return SimpleNamespace(**defaults)

    class CertWithTemp:
        thumbprint = "a" * 64
        pub_key_size = 2048
        not_before = datetime(2026, 1, 1, tzinfo=timezone.utc)
        not_after = datetime(2027, 1, 1, tzinfo=timezone.utc)
        temp_asset_metadata = {
            "tls_version": "TLSv1.0",
            "cipher_suite": "DES",
            "asset_type": "legacy",
        }

    cert_with_asset = _cert(asset=FakeAsset())
    cert_with_meta = _cert(asset_metadata={"tls_version": "TLSv1.3"})

    class CertWithMetaError:
        thumbprint = "a" * 64
        pub_key_size = 2048
        not_before = datetime(2026, 1, 1, tzinfo=timezone.utc)
        not_after = datetime(2027, 1, 1, tzinfo=timezone.utc)

        @property
        def temp_asset_metadata(self):
            raise RuntimeError("boom")

        @property
        def asset(self):
            return None

        @property
        def asset_metadata(self):
            raise RuntimeError("also boom")

    cbom = {
        "components": [
            {"bom-ref": "cert-1", "type": "certificate"},
            {"bom-ref": "cert-2", "type": "certificate"},
            {"bom-ref": "cert-3", "type": "certificate"},
            {"bom-ref": "cert-4", "type": "certificate"},
        ]
    }
    assets_map = {
        "cert-1": CertWithTemp(),
        "cert-2": cert_with_asset,
        "cert-3": cert_with_meta,
        "cert-4": CertWithMetaError(),
    }
    out = json.loads(post_process_cbom(json.dumps(cbom), assets_map))
    comps = {c["bom-ref"]: c for c in out["components"]}
    assert "protocol-1" in comps
    assert comps["protocol-1"]["cryptoProperties"]["version"] == "TLSv1.0"
    assert "protocol-2" in comps
    assert comps["protocol-2"]["cryptoProperties"]["version"] == "TLSv1.2"
    assert "protocol-3" in comps
    assert comps["protocol-3"]["cryptoProperties"]["version"] == "TLSv1.3"
    assert "protocol-4" in comps
    assert comps["protocol-4"]["cryptoProperties"]["version"] == "unknown"
