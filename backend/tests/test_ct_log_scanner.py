import pytest
from unittest.mock import patch, MagicMock
from app.scanners.ct_log_scanner import (
    CTLogResult,
    _fetch_ct_json,
    scan_ct_logs_for_domain,
)
import asyncio


class TestCTLogResult:
    def test_init_defaults(self):
        result = CTLogResult(domain="example.com", success=True)
        assert result.domain == "example.com"
        assert result.success is True
        assert result.certificates == []
        assert result.error_message is None

    def test_init_with_certificates(self):
        certs = [{"id": 1, "name": "cert.pem"}]
        result = CTLogResult(domain="example.com", success=True, certificates=certs)
        assert result.certificates == certs

    def test_init_with_error(self):
        result = CTLogResult(
            domain="example.com", success=False, error_message="timeout"
        )
        assert result.success is False
        assert result.error_message == "timeout"


class TestFetchCtJson:
    def test_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"id": 1, "name_value": "example.com"}]
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("httpx.Client", return_value=mock_client):
            result = _fetch_ct_json("https://crt.sh/?q=example.com&output=json", 10)
            assert len(result) == 1

    def test_http_error(self):
        import httpx

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found", request=MagicMock(), response=mock_resp
        )

        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        with patch("httpx.Client", return_value=mock_client):
            with pytest.raises(httpx.HTTPStatusError):
                _fetch_ct_json("https://crt.sh/?q=example.com&output=json", 10)


class TestScanCTLogsForDomain:
    def test_success(self):
        mock_data = [{"id": 1, "name_value": "example.com"}]
        with patch(
            "app.scanners.ct_log_scanner._fetch_ct_json",
            return_value=mock_data,
        ):
            result = asyncio.run(scan_ct_logs_for_domain("example.com", timeout=5))
        assert result.success is True
        assert result.domain == "example.com"
        assert len(result.certificates) == 1

    def test_non_list_response(self):
        with patch(
            "app.scanners.ct_log_scanner._fetch_ct_json",
            return_value={"error": "bad request"},
        ):
            result = asyncio.run(scan_ct_logs_for_domain("example.com", timeout=5))
        assert result.success is False
        assert "Unexpected" in result.error_message

    def test_network_exception(self):
        with patch(
            "app.scanners.ct_log_scanner._fetch_ct_json",
            side_effect=Exception("Connection refused"),
        ):
            result = asyncio.run(scan_ct_logs_for_domain("example.com", timeout=5))
        assert result.success is False
        assert "Connection refused" in result.error_message

    def test_empty_certificates(self):
        with patch(
            "app.scanners.ct_log_scanner._fetch_ct_json",
            return_value=[],
        ):
            result = asyncio.run(scan_ct_logs_for_domain("nodomain.example", timeout=5))
        assert result.success is True
        assert result.certificates == []
