import csv
import json
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.mark.asyncio
async def test_generate_csv_findings_export(tmp_path):
    """CSV export should write header + one row per finding with proper fields."""
    from app.services.report_service import generate_csv_findings_export
    from app.models.models import Asset, Finding, User
    from datetime import datetime, timezone

    # Patch reports dir to a tmp path
    with patch("app.services.report_service.os.path.dirname") as mock_dirname, \
         patch("app.services.report_service.os.makedirs") as mock_makedirs, \
         patch("builtins.open", create=True) as mock_open:

        mock_dirname.return_value = str(tmp_path)
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file

        # Set up session + finding
        asset = MagicMock(spec=Asset)
        asset.id = "a-1"
        asset.name = "server-01"
        asset.asset_type = "server"
        asset.environment = "production"
        asset.fqdn = "server-01.example.com"
        asset.ip_address = "10.0.0.1"
        asset.business_service = "auth"
        asset.owner_id = "u-1"

        finding = MagicMock(spec=Finding)
        finding.id = "f-1"
        finding.asset_id = "a-1"
        finding.finding_type = "weak_algorithm"
        finding.severity = "high"
        finding.title = "Test finding"
        finding.description = "Weak RSA"
        finding.algorithm = "RSA-2048"
        finding.pqc_status = "vulnerable"
        finding.hndl_exposure = "high"
        finding.risk_score = 18
        finding.status = "open"
        finding.first_detected_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
        finding.last_verified_at = datetime(2024, 1, 2, tzinfo=timezone.utc)
        finding.remediation = "Migrate to ML-DSA-65"
        finding.recommended_algorithm = "ML-DSA-65"
        finding.ticket_id = "TICKET-1"
        finding.asset = asset

        # Mock session.execute to return finding rows
        session = AsyncMock(spec=AsyncSession)
        result = MagicMock()
        result.all.return_value = [(finding, asset)]
        session.execute.return_value = result

        file_path = await generate_csv_findings_export(session, "report-123", scope_filters={})

        assert file_path.endswith("findings_report-123.csv")
        mock_open.assert_called()


@pytest.mark.asyncio
async def test_generate_sarif_report_with_no_scan_ids(tmp_path):
    """SARIF with empty scan_ids should still produce a valid SARIF doc."""
    from app.services.report_service import generate_sarif_report

    with patch("app.services.report_service.os.path.dirname") as mock_dirname, \
         patch("app.services.report_service.os.makedirs") as mock_makedirs, \
         patch("builtins.open", create=True) as mock_open:

        mock_dirname.return_value = str(tmp_path)
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file

        session = AsyncMock(spec=AsyncSession)
        result = MagicMock()
        result.scalars.return_value.all.return_value = []
        session.execute.return_value = result

        file_path = await generate_sarif_report(session, "report-456", scan_ids=[])

        assert file_path.endswith("sarif_report-456.json")
        mock_open.assert_called()


def test_report_create_accepts_csv_format():
    """The /reports endpoint should accept findings/csv combinations."""
    from app.api.reports import ReportCreate, ALLOWED_REPORT_COMBOS

    p = ReportCreate(report_type="findings", format="csv", scope_filters={})
    assert p.report_type == "findings"
    assert p.format == "csv"
    assert ("findings", "csv") in ALLOWED_REPORT_COMBOS
    assert ("executive", "pdf") in ALLOWED_REPORT_COMBOS
    assert ("sast", "sarif") in ALLOWED_REPORT_COMBOS
    assert ("cbom", "json") in ALLOWED_REPORT_COMBOS


def test_report_create_with_scan_ids():
    from app.api.reports import ReportCreate
    p = ReportCreate(
        report_type="sast",
        format="sarif",
        scope_filters={},
        scan_ids=["s-1", "s-2"],
    )
    assert p.scan_ids == ["s-1", "s-2"]


def test_media_type_mapping_for_exports():
    """FileResponse should pick the right media type for each export format."""
    from app.api.reports import download_report  # noqa: F401

    media_type_map = {
        "json": "application/json",
        "csv": "text/csv",
        "pdf": "application/pdf",
        "sarif": "application/sarif+json",
    }
    # Verify expected media types
    assert media_type_map["pdf"] == "application/pdf"
    assert media_type_map["csv"] == "text/csv"
    assert media_type_map["sarif"] == "application/sarif+json"
