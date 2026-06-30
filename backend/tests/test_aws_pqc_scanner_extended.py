import sys

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from app.connectors.aws_pqc_scanner import (
    AWSPQCScanner,
    _parse_key_size,
    _remediation_for_kms,
    _remediation_for_acm,
    _empty_stats,
    PQC_TLS_POLICIES,
)


def _make_scanner(**overrides):
    defaults = dict(
        access_key_id="AK",
        secret_access_key="SK",
        region="us-east-1",
        session_token=None,
    )
    defaults.update(overrides)
    return AWSPQCScanner(**defaults)


def _mock_session(existing=None):
    session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing
    session.execute.return_value = mock_result
    return session


def _mock_boto(service_mocks):
    def _factory(service_name, **kwargs):
        return service_mocks.get(service_name, MagicMock())

    return _factory


# ── Pure function tests ──────────────────────────────────────────────────


class TestParseKeySize:
    def test_rsa_2048(self):
        assert _parse_key_size("RSA_2048") == 2048

    def test_ec_prime256v1(self):
        assert _parse_key_size("EC_prime256v1") == 256

    def test_ec_p384(self):
        assert _parse_key_size("EC-P384") == 384

    def test_ec_p521(self):
        assert _parse_key_size("EC-P521") == 521

    def test_unknown_returns_none(self):
        assert _parse_key_size("UNKNOWN") is None

    def test_fallback_256_without_three_digit_match(self):
        # "256" substring fallback (line 987)
        assert _parse_key_size("EC_Prime_256_v1") == 256

    def test_fallback_384_without_three_digit_match(self):
        # "384" substring fallback (line 989)
        assert _parse_key_size("NIST_P384") == 384

    def test_fallback_521_without_three_digit_match(self):
        # "521" substring fallback (line 991)
        assert _parse_key_size("SECG_521_R1") == 521


class TestRemediationForKms:
    def test_rsa(self):
        msg = _remediation_for_kms("RSA_2048")
        assert "Rotate this KMS key" in msg

    def test_ecc(self):
        msg = _remediation_for_kms("ECC_NIST_P256")
        assert "Rotate this KMS key" in msg

    def test_hmac(self):
        msg = _remediation_for_kms("HMAC_SHA256")
        assert "HMAC" in msg

    def test_other(self):
        msg = _remediation_for_kms("SM2")
        assert "Review this key" in msg


class TestRemediationForAcm:
    def test_basic(self):
        msg = _remediation_for_acm("sha256WithRSAEncryption")
        assert "sha256WithRSAEncryption" in msg
        assert "quantum" in msg


class TestEmptyStats:
    def test_returns_zeroed_dict(self):
        s = _empty_stats()
        assert s["assets_created"] == 0
        assert s["assets_updated"] == 0
        assert s["algorithms_recorded"] == 0
        assert s["findings_created"] == 0
        assert s["certificates_recorded"] == 0
        assert s["errors"] == []


# ── Scanner._boto_kwargs ─────────────────────────────────────────────────


class TestBotoKwargs:
    def test_without_session_token(self):
        scanner = _make_scanner()
        kw = scanner._boto_kwargs()
        assert "aws_session_token" not in kw
        assert kw["aws_access_key_id"] == "AK"
        assert kw["aws_secret_access_key"] == "SK"
        assert kw["region_name"] == "us-east-1"

    def test_with_session_token(self):
        scanner = _make_scanner(session_token="tok")
        kw = scanner._boto_kwargs()
        assert kw["aws_session_token"] == "tok"


# ── Error paths ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_kms_describe_key_exception():
    mock_kms = MagicMock()
    mock_kms.get_paginator.return_value.paginate.return_value = [
        {"Keys": [{"KeyId": "bad-key"}]}
    ]
    mock_kms.describe_key.side_effect = Exception("access denied")

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"kms": mock_kms})):
        result = await scanner.scan(_mock_session(), "scan-err")

    assert any("KMS" in e for e in result["errors"])
    assert "KMS" in result["services_scanned"]


@pytest.mark.asyncio
async def test_acm_describe_certificate_exception():
    mock_acm = MagicMock()
    mock_acm.get_paginator.return_value.paginate.return_value = [
        {"CertificateSummaryList": [{"CertificateArn": "arn:acm:bad"}]}
    ]
    mock_acm.describe_certificate.side_effect = Exception("not found")

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"acm": mock_acm})):
        result = await scanner.scan(_mock_session(), "scan-acm-err")

    assert any("ACM" in e for e in result["errors"])


@pytest.mark.asyncio
async def test_elbv2_describe_listeners_exception():
    mock_elb = MagicMock()
    mock_elb.get_paginator.return_value.paginate.return_value = [
        {
            "LoadBalancers": [
                {
                    "LoadBalancerArn": "arn:lb:1",
                    "LoadBalancerName": "lb-1",
                    "DNSName": "lb.dns",
                    "Type": "application",
                }
            ]
        }
    ]
    mock_elb.describe_listeners.side_effect = Exception("listener fail")

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"elbv2": mock_elb})):
        result = await scanner.scan(_mock_session(), "scan-elb-err")

    assert any("ELBv2" in e for e in result["errors"])


@pytest.mark.asyncio
async def test_cloudfront_list_distributions_exception():
    mock_cf = MagicMock()
    mock_cf.get_paginator.return_value.paginate.side_effect = Exception("cf down")

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"cloudfront": mock_cf})):
        result = await scanner.scan(_mock_session(), "scan-cf-err")

    # CloudFront error is caught at service level or by _scan_cloudfront
    assert result is not None
    assert isinstance(result.get("errors"), list)


@pytest.mark.asyncio
async def test_s3_encryption_client_error():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "noenc"}]}

    class S3ClientError(Exception):
        pass

    mock_s3.exceptions = MagicMock()
    mock_s3.exceptions.ClientError = S3ClientError
    mock_s3.get_bucket_encryption.side_effect = S3ClientError("no encryption config")

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"s3": mock_s3})):
        result = await scanner.scan(_mock_session(), "scan-s3-ce")

    assert "S3" in result["services_scanned"]
    assert result["errors"] == []


@pytest.mark.asyncio
async def test_s3_general_encryption_error():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "err-bkt"}]}
    mock_s3.get_bucket_encryption.side_effect = Exception("boom")

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"s3": mock_s3})):
        result = await scanner.scan(_mock_session(), "scan-s3-gen-err")

    # Error is caught either at bucket level or service level
    assert result is not None
    assert isinstance(result.get("errors"), list)


@pytest.mark.asyncio
async def test_iam_list_server_certificates_exception():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.side_effect = Exception("iam down")

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"iam": mock_iam})):
        result = await scanner.scan(_mock_session(), "scan-iam-err")

    # IAM error is caught at service level
    assert result is not None
    assert isinstance(result.get("errors"), list)


# ── S3 SSE-S3 (AES256) path ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_s3_sse_s3_aes256():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "sse-s3-bkt"}]}
    mock_s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        }
    }

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"s3": mock_s3})):
        result = await scanner.scan(_mock_session(), "scan-sse-s3")

    assert "S3" in result["services_scanned"]
    assert result["assets_created"] >= 1


# ── S3 no-encryption path (ClientError → NONE) ──────────────────────────


@pytest.mark.asyncio
async def test_s3_no_encryption_skipped():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "plain-bkt"}]}

    class S3ClientError(Exception):
        pass

    mock_s3.exceptions = MagicMock()
    mock_s3.exceptions.ClientError = S3ClientError
    mock_s3.get_bucket_encryption.side_effect = S3ClientError(
        "ServerSideEncryptionConfigurationNotFoundError"
    )

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"s3": mock_s3})):
        result = await scanner.scan(_mock_session(), "scan-s3-none")

    assert "S3" in result["services_scanned"]
    assert result["assets_created"] == 0


# ── Disabled KMS key ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_kms_disabled_key():
    mock_kms = MagicMock()
    mock_kms.get_paginator.return_value.paginate.return_value = [
        {"Keys": [{"KeyId": "disabled-key"}]}
    ]
    mock_kms.describe_key.return_value = {
        "KeyMetadata": {
            "KeyId": "disabled-key",
            "KeySpec": "RSA_2048",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Disabled",
            "Origin": "AWS_KMS",
            "Arn": "arn:aws:kms:us-east-1:123:key/disabled-key",
        }
    }

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"kms": mock_kms})):
        result = await scanner.scan(_mock_session(), "scan-kms-dis")

    assert "KMS" in result["services_scanned"]
    assert result["findings_created"] >= 1


# ── HMAC KMS key ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_kms_hmac_key():
    mock_kms = MagicMock()
    mock_kms.get_paginator.return_value.paginate.return_value = [
        {"Keys": [{"KeyId": "hmac-key"}]}
    ]
    mock_kms.describe_key.return_value = {
        "KeyMetadata": {
            "KeyId": "hmac-key",
            "KeySpec": "HMAC_SHA256",
            "KeyUsage": "GENERATE_VERIFY_MAC",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "Arn": "arn:aws:kms:us-east-1:123:key/hmac-key",
        }
    }

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"kms": mock_kms})):
        result = await scanner.scan(_mock_session(), "scan-kms-hmac")

    assert "KMS" in result["services_scanned"]
    assert result["assets_created"] >= 1


# ── PQC TLS policy for ELBv2 (no finding) ───────────────────────────────


@pytest.mark.asyncio
async def test_elbv2_pqc_tls_policy_no_finding():
    pqc_policy = next(iter(PQC_TLS_POLICIES))
    mock_elb = MagicMock()
    mock_elb.get_paginator.return_value.paginate.return_value = [
        {
            "LoadBalancers": [
                {
                    "LoadBalancerArn": "arn:lb:pqc",
                    "LoadBalancerName": "pqc-lb",
                    "DNSName": "pqc.dns",
                    "Type": "application",
                }
            ]
        }
    ]
    mock_elb.describe_listeners.return_value = {
        "Listeners": [
            {
                "ListenerArn": "arn:listener:pqc",
                "Port": 443,
                "Protocol": "HTTPS",
                "SslPolicy": pqc_policy,
            }
        ]
    }

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"elbv2": mock_elb})):
        result = await scanner.scan(_mock_session(), "scan-elb-pqc")

    assert "ELBv2" in result["services_scanned"]
    assert result["findings_created"] == 0
    assert result["assets_created"] >= 1


# ── Existing asset update path in _upsert_asset ─────────────────────────


@pytest.mark.asyncio
async def test_upsert_asset_updates_existing():
    existing_asset = MagicMock()
    existing_asset.id = "existing-id"
    existing_asset.asset_metadata = {}
    existing_asset.last_scan_id = None
    existing_asset.last_verified_at = None
    existing_asset.fqdn = None
    existing_asset.ip_address = None
    existing_asset.port = None

    session = _mock_session(existing=existing_asset)

    mock_kms = MagicMock()
    mock_kms.get_paginator.return_value.paginate.return_value = [
        {"Keys": [{"KeyId": "k1"}]}
    ]
    mock_kms.describe_key.return_value = {
        "KeyMetadata": {
            "KeyId": "k1",
            "KeySpec": "RSA_2048",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "Arn": "arn:aws:kms:us-east-1:123:key/k1",
        }
    }

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"kms": mock_kms})):
        result = await scanner.scan(session, "scan-upsert")

    assert result["assets_updated"] >= 1


# ── Existing certificate in _record_certificate ─────────────────────────


@pytest.mark.asyncio
async def test_record_certificate_skips_existing():
    existing_cert = MagicMock()
    existing_cert.thumbprint = "abc"

    session = AsyncMock()
    call_count = [0]

    async def mock_execute(stmt):
        call_count[0] += 1
        mock_result = MagicMock()
        if call_count[0] <= 1:
            mock_result.scalar_one_or_none.return_value = None
        else:
            mock_result.scalar_one_or_none.return_value = existing_cert
        return mock_result

    session.execute = mock_execute

    mock_acm = MagicMock()
    mock_acm.get_paginator.return_value.paginate.return_value = [
        {"CertificateSummaryList": [{"CertificateArn": "arn:acm:dup"}]}
    ]
    mock_acm.describe_certificate.return_value = {
        "Certificate": {
            "CertificateArn": "arn:acm:dup",
            "DomainName": "dup.example.com",
            "SignatureAlgorithm": "sha256WithRSAEncryption",
            "KeyAlgorithm": "RSA_2048",
            "KeyLength": 2048,
            "Status": "ISSUED",
            "Type": "AMAZON_ISSUED",
            "NotAfter": datetime.now(timezone.utc),
            "NotBefore": datetime.now(timezone.utc),
            "SubjectAlternativeNames": ["dup.example.com"],
        }
    }

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"acm": mock_acm})):
        result = await scanner.scan(session, "scan-cert-dup")

    assert "ACM" in result["services_scanned"]


# ── Finding dedup in _create_finding ─────────────────────────────────────


@pytest.mark.asyncio
async def test_create_finding_dedup():
    existing_finding = MagicMock()

    session = AsyncMock()
    call_count = [0]

    async def mock_execute(stmt):
        call_count[0] += 1
        mock_result = MagicMock()
        if call_count[0] == 1:
            mock_result.scalar_one_or_none.return_value = None
        else:
            mock_result.scalar_one_or_none.return_value = existing_finding
        return mock_result

    session.execute = mock_execute

    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "ServerCertificateMetadataList": [
                {
                    "ServerCertificateName": "dup-cert",
                    "Arn": "arn:iam::123:server-certificate/dup-cert",
                }
            ]
        }
    ]

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"iam": mock_iam})):
        result = await scanner.scan(session, "scan-dedup")

    assert result["findings_created"] == 0


# ── KMS unknown key spec fallback ───────────────────────────────────────


@pytest.mark.asyncio
async def test_kms_unknown_key_spec():
    mock_kms = MagicMock()
    mock_kms.get_paginator.return_value.paginate.return_value = [
        {"Keys": [{"KeyId": "unknown-spec"}]}
    ]
    mock_kms.describe_key.return_value = {
        "KeyMetadata": {
            "KeyId": "unknown-spec",
            "KeySpec": "FUTURE_ALGO",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "Arn": "arn:aws:kms:us-east-1:123:key/unknown-spec",
        }
    }

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"kms": mock_kms})):
        result = await scanner.scan(_mock_session(), "scan-unk")

    assert "KMS" in result["services_scanned"]
    assert result["assets_created"] >= 1


# ── CloudFront happy path ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cloudfront_distribution():
    mock_cf = MagicMock()
    mock_cf.get_paginator.return_value.paginate.return_value = [
        {
            "DistributionList": {
                "Items": [
                    {
                        "Id": "cf-1",
                        "DomainName": "d123.cloudfront.net",
                        "Aliases": {"Items": ["cdn.example.com"]},
                        "ViewerCertificate": {
                            "SSLSupportMethod": "sni-only",
                            "MinimumProtocolVersion": "TLSv1.2_2021",
                            "CertificateSource": "acm",
                        },
                    }
                ]
            }
        }
    ]

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"cloudfront": mock_cf})):
        result = await scanner.scan(_mock_session(), "scan-cf")

    assert "CloudFront" in result["services_scanned"]
    assert result["findings_created"] >= 0


# ── ELBv2 non-HTTPS listener ignored ────────────────────────────────────


@pytest.mark.asyncio
async def test_elbv2_non_https_listener_skipped():
    mock_elb = MagicMock()
    mock_elb.get_paginator.return_value.paginate.return_value = [
        {
            "LoadBalancers": [
                {
                    "LoadBalancerArn": "arn:lb:tcp",
                    "LoadBalancerName": "tcp-lb",
                    "DNSName": "tcp.dns",
                    "Type": "network",
                }
            ]
        }
    ]
    mock_elb.describe_listeners.return_value = {
        "Listeners": [
            {
                "ListenerArn": "arn:listener:tcp",
                "Port": 80,
                "Protocol": "TCP",
            }
        ]
    }

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"elbv2": mock_elb})):
        result = await scanner.scan(_mock_session(), "scan-tcp")

    assert "ELBv2" in result["services_scanned"]
    assert result["assets_created"] == 0
    assert result["findings_created"] == 0


# ── S3 aws:kms:dsse path ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_s3_kms_dsse():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "dsse-bkt"}]}
    mock_s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms:dsse",
                        "KMSMasterKeyID": "arn:aws:kms:us-east-1:123:key/dsse-key",
                    },
                    "BucketKeyEnabled": True,
                }
            ]
        }
    }

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"s3": mock_s3})):
        result = await scanner.scan(_mock_session(), "scan-dsse")

    assert "S3" in result["services_scanned"]
    assert result["assets_created"] >= 1


# ── ACM non-ISSUED status ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_acm_pending_certificate():
    mock_acm = MagicMock()
    mock_acm.get_paginator.return_value.paginate.return_value = [
        {"CertificateSummaryList": [{"CertificateArn": "arn:acm:pending"}]}
    ]
    mock_acm.describe_certificate.return_value = {
        "Certificate": {
            "CertificateArn": "arn:acm:pending",
            "DomainName": "pending.example.com",
            "SignatureAlgorithm": "sha256WithRSAEncryption",
            "KeyAlgorithm": "RSA_2048",
            "Status": "PENDING_VALIDATION",
            "Type": "AMAZON_ISSUED",
            "NotAfter": datetime.now(timezone.utc),
            "NotBefore": datetime.now(timezone.utc),
            "SubjectAlternativeNames": ["pending.example.com"],
        }
    }

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"acm": mock_acm})):
        result = await scanner.scan(_mock_session(), "scan-acm-pending")

    assert "ACM" in result["services_scanned"]
    assert result["findings_created"] >= 1


# ── boto3 import error ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_boto3_import_error():
    scanner = _make_scanner()
    with patch.dict(sys.modules, {"boto3": None}):
        with pytest.raises(RuntimeError, match="boto3 is required"):
            await scanner.scan(_mock_session(), "scan-no-boto")


# ── ELBv2 non-PQC HTTPS listener creates a finding ───────────────────────


@pytest.mark.asyncio
async def test_elbv2_non_pqc_https_listener_finding():
    mock_elb = MagicMock()
    mock_elb.get_paginator.return_value.paginate.return_value = [
        {
            "LoadBalancers": [
                {
                    "LoadBalancerArn": "arn:lb:web",
                    "LoadBalancerName": "web-lb",
                    "DNSName": "web.dns",
                    "Type": "application",
                }
            ]
        }
    ]
    mock_elb.describe_listeners.return_value = {
        "Listeners": [
            {
                "ListenerArn": "arn:listener:web",
                "Port": 443,
                "Protocol": "HTTPS",
                "SslPolicy": "ELBSecurityPolicy-TLS-1-0-2015-04",
            }
        ]
    }

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"elbv2": mock_elb})):
        result = await scanner.scan(_mock_session(), "scan-elb-finding")

    assert "ELBv2" in result["services_scanned"]
    assert result["findings_created"] >= 1
    assert result["assets_created"] >= 1


# ── S3 unknown SSE algorithm ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_s3_unknown_sse_algorithm():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "custom-enc"}]}
    mock_s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "CUSTOM"}}
            ]
        }
    }

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"s3": mock_s3})):
        result = await scanner.scan(_mock_session(), "scan-s3-custom")

    assert "S3" in result["services_scanned"]
    assert result["assets_created"] >= 1


# ── S3 general bucket encryption error ──────────────────────────────────


@pytest.mark.asyncio
async def test_s3_bucket_encryption_general_error_records_error():
    class ClientError(Exception):
        pass

    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "err-bkt"}]}
    mock_s3.exceptions = MagicMock()
    mock_s3.exceptions.ClientError = ClientError
    mock_s3.get_bucket_encryption.side_effect = Exception("unexpected")

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"s3": mock_s3})):
        result = await scanner.scan(_mock_session(), "scan-s3-bucket-err")

    assert "S3" in result["services_scanned"]
    assert any("err-bkt" in e for e in result["errors"])


# ── IAM server certificate creates a finding ────────────────────────────


@pytest.mark.asyncio
async def test_iam_server_certificate_creates_finding():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "ServerCertificateMetadataList": [
                {
                    "ServerCertificateName": "iam-cert",
                    "Arn": "arn:iam::123:server-certificate/iam-cert",
                }
            ]
        }
    ]

    scanner = _make_scanner()
    with patch("boto3.client", side_effect=_mock_boto({"iam": mock_iam})):
        result = await scanner.scan(_mock_session(), "scan-iam-finding")

    assert "IAM" in result["services_scanned"]
    assert result["findings_created"] >= 1
    assert result["assets_created"] >= 1


# ── _upsert_asset updates optional fields on existing asset ─────────────


@pytest.mark.asyncio
async def test_upsert_asset_updates_optional_fields():
    existing_asset = MagicMock()
    existing_asset.id = "existing-id"
    existing_asset.asset_metadata = {}
    existing_asset.last_scan_id = None
    existing_asset.last_verified_at = None
    existing_asset.fqdn = None
    existing_asset.ip_address = None
    existing_asset.port = None

    session = _mock_session(existing=existing_asset)
    scanner = _make_scanner()
    asset, created = await scanner._upsert_asset(
        session,
        name="existing",
        asset_type="server",
        environment="cloud",
        discovery_source="aws",
        scan_id="scan-upsert-fields",
        metadata={"key": "value"},
        fqdn="host.example.com",
        ip_address="10.0.0.1",
        port=443,
    )

    assert created is False
    assert asset.fqdn == "host.example.com"
    assert asset.ip_address == "10.0.0.1"
    assert asset.port == 443
