import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone
from app.connectors.aws_pqc_scanner import AWSPQCScanner

@pytest.mark.asyncio
async def test_aws_pqc_scanner_full_run():
    session = AsyncMock()

    # Mock DB query results (no existing asset, etc.)
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    session.execute.return_value = mock_result

    # Instantiate scanner
    scanner = AWSPQCScanner(
        access_key_id="test-key",
        secret_access_key="test-secret",
        region="us-east-1",
        session_token="test-session"
    )

    # Mock boto3 client calls
    mock_kms = MagicMock()
    mock_kms.get_paginator.return_value.paginate.return_value = [
        {"Keys": [{"KeyId": "kms-key-1"}]}
    ]
    mock_kms.describe_key.return_value = {
        "KeyMetadata": {
            "KeyId": "kms-key-1",
            "KeySpec": "RSA_2048",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "Arn": "arn:aws:kms:us-east-1:123456789012:key/kms-key-1"
        }
    }

    mock_acm = MagicMock()
    mock_acm.get_paginator.return_value.paginate.return_value = [
        {"CertificateSummaryList": [{"CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/acm-cert-1"}]}
    ]
    mock_acm.describe_certificate.return_value = {
        "Certificate": {
            "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/acm-cert-1",
            "DomainName": "example.com",
            "SignatureAlgorithm": "sha256WithRSAEncryption",
            "KeyLength": 2048,
            "NotAfter": datetime.now(timezone.utc)
        }
    }

    mock_elb = MagicMock()
    mock_elb.get_paginator.return_value.paginate.return_value = [
        {"LoadBalancers": [{"LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/elb-1/123", "DNSName": "elb-1.amazonaws.com"}]}
    ]
    mock_elb.describe_listeners.return_value = {
        "Listeners": [
            {
                "ListenerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/elb-1/123/456",
                "Port": 443,
                "Protocol": "HTTPS",
                "SslPolicy": "ELBSecurityPolicy-2016-08"
            }
        ]
    }

    mock_cf = MagicMock()
    mock_cf.list_distributions.return_value = {
        "DistributionList": {
            "Items": [
                {
                    "Id": "dist-1",
                    "DomainName": "dist-1.cloudfront.net",
                    "ViewerCertificate": {
                        "SSLSupportMethod": "sni-only",
                        "MinimumProtocolVersion": "TLSv1.2_2021",
                        "CertificateSource": "acm",
                        "Certificate": "arn:aws:acm:us-east-1:123456789012:certificate/acm-cert-1"
                    }
                }
            ]
        }
    }

    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {
        "Buckets": [{"Name": "my-s3-bucket"}]
    }
    mock_s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyId": "kms-key-1"
                    }
                }
            ]
        }
    }

    mock_iam = MagicMock()
    mock_iam.list_server_certificates.return_value = {
        "ServerCertificateMetadataList": [
            {
                "ServerCertificateName": "iam-cert-1",
                "Arn": "arn:aws:iam::123456789012:server-certificate/iam-cert-1"
            }
        ]
    }
    # certificate parser might fail parsing the empty body so let's mock certificate parser if needed
    # but let's provide a mock body
    mock_iam.get_server_certificate.return_value = {
        "ServerCertificate": {
            "CertificateBody": "-----BEGIN CERTIFICATE-----\nMIIB...",
            "ServerCertificateMetadata": {
                "ServerCertificateName": "iam-cert-1",
                "Arn": "arn:aws:iam::123456789012:server-certificate/iam-cert-1"
            }
        }
    }

    def get_mock_client(service_name, **kwargs):
        if service_name == "kms":
            return mock_kms
        elif service_name == "acm":
            return mock_acm
        elif service_name == "elbv2":
            return mock_elb
        elif service_name == "cloudfront":
            return mock_cf
        elif service_name == "s3":
            return mock_s3
        elif service_name == "iam":
            return mock_iam
        return MagicMock()

    with patch("boto3.client", side_effect=get_mock_client):
        result = await scanner.scan(session, "test-scan-id")
        
        assert result["assets_created"] > 0 or result["assets_updated"] > 0
        assert len(result["services_scanned"]) == 6
        assert len(result["errors"]) == 0
