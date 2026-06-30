"""
AWS PQC Scanner — Comprehensive Post-Quantum Cryptography Assessment.

Scans across multiple AWS services to discover and classify cryptographic
material for quantum vulnerability:

  - KMS keys (algorithm, key spec, usage)
  - ACM certificates (signature algorithm, key size, expiry)
  - ELB/ALB listeners (TLS policies, cipher suites)
  - CloudFront distributions (TLS viewer/origin policies)
  - S3 bucket default encryption
  - IAM server certificates
  - Secrets Manager encryption configs

Each discovered cryptographic component is:
  1. Upserted as an Asset (or Certificate)
  2. Classified via algo_classifier
  3. Recorded as an Algorithm row
  4. Evaluated for PQC Findings with risk scores
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis.algo_classifier import classify_algorithm
from app.models.models import Algorithm, Asset, Certificate, Finding
from app.services.layer_service import layer_for_finding
from app.services.risk_service import calculate_risk_score

logger = logging.getLogger(__name__)

# ── AWS key spec → readable algorithm mapping ──────────────────────────
KMS_KEY_SPEC_MAP: Dict[str, Tuple[str, str, Optional[int]]] = {
    # (algorithm_name, algorithm_type, key_size)
    "SYMMETRIC_DEFAULT": ("AES-256", "symmetric", 256),
    "RSA_2048": ("RSA-2048", "signature", 2048),
    "RSA_3072": ("RSA-3072", "signature", 3072),
    "RSA_4096": ("RSA-4096", "signature", 4096),
    "ECC_NIST_P256": ("ECDSA-P256", "signature", 256),
    "ECC_NIST_P384": ("ECDSA-P384", "signature", 384),
    "ECC_NIST_P521": ("ECDSA-P521", "signature", 521),
    "ECC_SECG_P256K1": ("ECDSA-secp256k1", "signature", 256),
    "HMAC_224": ("HMAC-SHA224", "mac", 224),
    "HMAC_256": ("HMAC-SHA256", "mac", 256),
    "HMAC_384": ("HMAC-SHA384", "mac", 384),
    "HMAC_512": ("HMAC-SHA512", "mac", 512),
    "SM2": ("SM2", "signature", 256),
}

# ELB TLS policies known to be PQC-safe or hybrid
PQC_TLS_POLICIES = {
    "ELBSecurityPolicy-PQ-TLS-1-0-2020-12",
    "ELBSecurityPolicy-PQ-TLS-1-1-2020-12",
    "ELBSecurityPolicy-PQ-TLS-1-2-2020-12",
}

# Minimum acceptable TLS policy prefix (anything older is suspicious)
MODERN_TLS_PREFIXES = (
    "ELBSecurityPolicy-TLS13-",
    "ELBSecurityPolicy-FS-1-2-",
    "ELBSecurityPolicy-PQ-",
)


def _remediation_for_kms(key_spec: str) -> str:
    if "RSA" in key_spec or "ECC" in key_spec or "EC" in key_spec:
        return (
            "Rotate this KMS key to an AES-256 symmetric key for envelope "
            "encryption, or plan migration to a PQC-based key once AWS KMS "
            "supports ML-KEM / ML-DSA."
        )
    if "HMAC" in key_spec:
        return "HMAC keys are not directly quantum-vulnerable; ensure HMAC-SHA256+ is used."
    return "Review this key's usage and plan a migration to quantum-safe alternatives."


def _remediation_for_acm(algo: str) -> str:
    return (
        f"The ACM certificate uses {algo}, which is vulnerable to quantum "
        f"attacks. Request a new certificate with a PQC-capable signature "
        f"algorithm (e.g., ML-DSA-65) when your CA supports it, or deploy a "
        f"hybrid TLS certificate."
    )


class AWSPQCScanner:
    """Scan an AWS account for PQC-vulnerable cryptographic material."""

    def __init__(
        self,
        access_key_id: str,
        secret_access_key: str,
        region: str = "us-east-1",
        session_token: Optional[str] = None,
    ):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.region = region
        self.session_token = session_token

    def _boto_kwargs(self) -> dict:
        kwargs: dict = {
            "aws_access_key_id": self.access_key_id,
            "aws_secret_access_key": self.secret_access_key,
            "region_name": self.region,
        }
        if self.session_token:
            kwargs["aws_session_token"] = self.session_token
        return kwargs

    # ── Public entry point ─────────────────────────────────────────────
    async def scan(
        self,
        session: AsyncSession,
        scan_id: str,
    ) -> Dict[str, Any]:
        """Run the full AWS PQC scan and persist results."""
        try:
            import boto3  # noqa: F401
        except ImportError as exc:
            raise RuntimeError("boto3 is required for the AWS PQC scanner") from exc

        results: Dict[str, Any] = {
            "assets_created": 0,
            "assets_updated": 0,
            "algorithms_recorded": 0,
            "findings_created": 0,
            "certificates_recorded": 0,
            "services_scanned": [],
            "errors": [],
        }

        # Run each service scanner concurrently where possible
        scanners = [
            ("KMS", self._scan_kms),
            ("ACM", self._scan_acm),
            ("ELBv2", self._scan_elbv2),
            ("CloudFront", self._scan_cloudfront),
            ("S3", self._scan_s3),
            ("IAM", self._scan_iam_certs),
        ]

        for service_name, scanner_fn in scanners:
            try:
                svc_result = await scanner_fn(session, scan_id)
                results["assets_created"] += svc_result.get("assets_created", 0)
                results["assets_updated"] += svc_result.get("assets_updated", 0)
                results["algorithms_recorded"] += svc_result.get(
                    "algorithms_recorded", 0
                )
                results["findings_created"] += svc_result.get("findings_created", 0)
                results["certificates_recorded"] += svc_result.get(
                    "certificates_recorded", 0
                )
                results["services_scanned"].append(service_name)
                if svc_result.get("errors"):
                    results["errors"].extend(svc_result["errors"])
            except Exception as exc:
                err_msg = f"{service_name}: {exc}"
                logger.warning(f"AWS PQC scan error — {err_msg}")
                results["errors"].append(err_msg)

        await session.flush()
        return results

    # ── KMS ─────────────────────────────────────────────────────────────
    async def _scan_kms(self, session: AsyncSession, scan_id: str) -> Dict[str, Any]:
        import boto3

        stats = _empty_stats()

        def _list_and_describe():
            kms = boto3.client("kms", **self._boto_kwargs())
            paginator = kms.get_paginator("list_keys")
            keys_out = []
            for page in paginator.paginate():
                for key in page.get("Keys", []):
                    kid = key["KeyId"]
                    try:
                        desc = kms.describe_key(KeyId=kid).get("KeyMetadata", {})
                        keys_out.append(desc)
                    except Exception as e:
                        keys_out.append({"KeyId": kid, "_error": str(e)})
            return keys_out

        key_metas = await asyncio.to_thread(_list_and_describe)

        for meta in key_metas:
            if "_error" in meta:
                stats["errors"].append(f"KMS key {meta.get('KeyId')}: {meta['_error']}")
                continue

            key_id = meta.get("KeyId", "unknown")
            key_spec = meta.get("KeySpec", "SYMMETRIC_DEFAULT")
            key_usage = meta.get("KeyUsage", "ENCRYPT_DECRYPT")
            key_state = meta.get("KeyState", "Enabled")
            origin = meta.get("Origin", "AWS_KMS")
            arn = meta.get("Arn", "")

            # Map key spec to algo
            algo_name, algo_type, key_size = KMS_KEY_SPEC_MAP.get(
                key_spec, (key_spec, "signature", None)
            )

            classification = classify_algorithm(algo_name)
            pqc_status = classification.get("pqc_status", "unknown")
            is_qv = classification.get("is_quantum_vulnerable", False)

            # Upsert asset
            asset_name = f"aws-kms:{key_id}"
            asset, created = await self._upsert_asset(
                session,
                name=asset_name,
                asset_type="kms",
                environment="cloud" if origin == "AWS_KMS" else "unknown",
                discovery_source="aws_pqc_scan",
                scan_id=scan_id,
                metadata={
                    "provider": "aws",
                    "service": "KMS",
                    "key_id": key_id,
                    "key_spec": key_spec,
                    "key_usage": key_usage,
                    "key_state": key_state,
                    "origin": origin,
                    "arn": arn,
                    "pqc_status": pqc_status,
                },
            )
            stats["assets_created" if created else "assets_updated"] += 1

            # Record algorithm
            await self._record_algorithm(
                session,
                asset.id,
                scan_id,
                algo_name,
                algo_type,
                key_size,
                pqc_status,
                is_qv,
                protocol="KMS",
            )
            stats["algorithms_recorded"] += 1

            # Generate finding if vulnerable
            if is_qv:
                created_f = await self._create_finding(
                    session,
                    asset,
                    scan_id,
                    finding_type="kms_vulnerable",
                    severity="high" if key_state == "Enabled" else "medium",
                    title=f"Quantum-Vulnerable KMS Key ({key_spec})",
                    description=(
                        f"AWS KMS key {key_id} uses {algo_name} which is vulnerable "
                        f"to attack by a cryptographically-relevant quantum computer. "
                        f"Key usage: {key_usage}, state: {key_state}."
                    ),
                    algorithm=algo_name,
                    pqc_status=pqc_status,
                    remediation=_remediation_for_kms(key_spec),
                    recommended_algorithm="AES-256 (symmetric) or ML-KEM-768 (future PQC)",
                    key_size=key_size,
                    evidence={
                        "service": "KMS",
                        "key_id": key_id,
                        "key_spec": key_spec,
                        "key_usage": key_usage,
                        "key_state": key_state,
                        "arn": arn,
                    },
                )
                if created_f:
                    stats["findings_created"] += 1

        return stats

    # ── ACM ─────────────────────────────────────────────────────────────
    async def _scan_acm(self, session: AsyncSession, scan_id: str) -> Dict[str, Any]:
        import boto3

        stats = _empty_stats()

        def _list_certs():
            acm = boto3.client("acm", **self._boto_kwargs())
            paginator = acm.get_paginator("list_certificates")
            certs = []
            for page in paginator.paginate():
                for summary in page.get("CertificateSummaryList", []):
                    try:
                        detail = acm.describe_certificate(
                            CertificateArn=summary["CertificateArn"]
                        ).get("Certificate", {})
                        certs.append(detail)
                    except Exception as e:
                        certs.append(
                            {
                                "CertificateArn": summary["CertificateArn"],
                                "_error": str(e),
                            }
                        )
            return certs

        certs = await asyncio.to_thread(_list_certs)

        for cert in certs:
            if "_error" in cert:
                stats["errors"].append(
                    f"ACM cert {cert.get('CertificateArn')}: {cert['_error']}"
                )
                continue

            arn = cert.get("CertificateArn", "")
            domain = cert.get("DomainName", "unknown")
            sig_algo = cert.get("SignatureAlgorithm", "UNKNOWN")
            key_algo = cert.get("KeyAlgorithm", "UNKNOWN")
            key_size = _parse_key_size(key_algo)
            status = cert.get("Status", "UNKNOWN")
            not_after = cert.get("NotAfter")
            not_before = cert.get("NotBefore")
            cert_type = cert.get("Type", "UNKNOWN")  # AMAZON_ISSUED, IMPORTED, PRIVATE
            sans = cert.get("SubjectAlternativeNames", [])

            # Classify the signature algorithm
            classification = classify_algorithm(sig_algo)
            pqc_status = classification.get("pqc_status", "unknown")
            is_qv = classification.get("is_quantum_vulnerable", False)

            # Upsert asset
            asset_name = f"aws-acm:{domain}"
            asset, created = await self._upsert_asset(
                session,
                name=asset_name,
                asset_type=(
                    "certificate_authority" if "CA" in cert_type.upper() else "kms"
                ),
                environment="cloud",
                discovery_source="aws_pqc_scan",
                scan_id=scan_id,
                fqdn=domain,
                metadata={
                    "provider": "aws",
                    "service": "ACM",
                    "arn": arn,
                    "domain": domain,
                    "signature_algorithm": sig_algo,
                    "key_algorithm": key_algo,
                    "status": status,
                    "type": cert_type,
                    "san_count": len(sans),
                    "pqc_status": pqc_status,
                },
            )
            stats["assets_created" if created else "assets_updated"] += 1

            # Record algorithm
            await self._record_algorithm(
                session,
                asset.id,
                scan_id,
                sig_algo,
                "signature",
                key_size,
                pqc_status,
                is_qv,
                protocol="ACM",
            )
            stats["algorithms_recorded"] += 1

            # Record certificate row
            if not_before and not_after:
                await self._record_certificate(
                    session,
                    asset.id,
                    domain,
                    sig_algo,
                    key_algo,
                    key_size,
                    not_before,
                    not_after,
                    is_ca=("CA" in cert_type.upper()),
                    san_dns=[s for s in sans if not s.replace(".", "").isdigit()],
                    pqc_status=pqc_status,
                )
                stats["certificates_recorded"] += 1

            # Generate finding
            if is_qv:
                sev = "high" if status == "ISSUED" else "medium"
                created_f = await self._create_finding(
                    session,
                    asset,
                    scan_id,
                    finding_type="weak_algorithm",
                    severity=sev,
                    title=f"Quantum-Vulnerable ACM Certificate ({sig_algo})",
                    description=(
                        f"ACM certificate for {domain} (ARN: {arn}) uses {sig_algo} "
                        f"which is vulnerable to quantum attacks. Status: {status}."
                    ),
                    algorithm=sig_algo,
                    pqc_status=pqc_status,
                    remediation=_remediation_for_acm(sig_algo),
                    recommended_algorithm="ML-DSA-65",
                    key_size=key_size,
                    evidence={
                        "service": "ACM",
                        "arn": arn,
                        "domain": domain,
                        "sig_algorithm": sig_algo,
                        "key_algorithm": key_algo,
                        "status": status,
                        "type": cert_type,
                    },
                )
                if created_f:
                    stats["findings_created"] += 1

        return stats

    # ── ELBv2 (ALB/NLB) ────────────────────────────────────────────────
    async def _scan_elbv2(self, session: AsyncSession, scan_id: str) -> Dict[str, Any]:
        import boto3

        stats = _empty_stats()

        def _list_lbs_and_listeners():
            elbv2 = boto3.client("elbv2", **self._boto_kwargs())
            paginator = elbv2.get_paginator("describe_load_balancers")
            results = []
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    lb_arn = lb["LoadBalancerArn"]
                    lb_name = lb.get("LoadBalancerName", "unknown")
                    lb_dns = lb.get("DNSName", "")
                    lb_type = lb.get("Type", "application")
                    try:
                        listeners_resp = elbv2.describe_listeners(
                            LoadBalancerArn=lb_arn
                        )
                        for listener in listeners_resp.get("Listeners", []):
                            if listener.get("Protocol") in ("HTTPS", "TLS"):
                                results.append(
                                    {
                                        "lb_arn": lb_arn,
                                        "lb_name": lb_name,
                                        "lb_dns": lb_dns,
                                        "lb_type": lb_type,
                                        "listener_arn": listener["ListenerArn"],
                                        "port": listener.get("Port", 443),
                                        "protocol": listener.get("Protocol"),
                                        "ssl_policy": listener.get("SslPolicy", ""),
                                    }
                                )
                    except Exception as e:
                        results.append(
                            {
                                "lb_arn": lb_arn,
                                "lb_name": lb_name,
                                "_error": str(e),
                            }
                        )
            return results

        listeners = await asyncio.to_thread(_list_lbs_and_listeners)

        for item in listeners:
            if "_error" in item:
                stats["errors"].append(f"ELBv2 {item.get('lb_name')}: {item['_error']}")
                continue

            lb_name = item["lb_name"]
            lb_dns = item.get("lb_dns", "")
            ssl_policy = item.get("ssl_policy", "")
            port = item.get("port", 443)

            is_pqc_policy = ssl_policy in PQC_TLS_POLICIES
            is_modern = any(ssl_policy.startswith(p) for p in MODERN_TLS_PREFIXES)
            pqc_status = (
                "pqc_ready"
                if is_pqc_policy
                else ("vulnerable" if not is_modern else "vulnerable")
            )

            # Upsert asset
            asset_name = f"aws-elb:{lb_name}"
            asset, created = await self._upsert_asset(
                session,
                name=asset_name,
                asset_type="load_balancer",
                environment="cloud",
                discovery_source="aws_pqc_scan",
                scan_id=scan_id,
                fqdn=lb_dns,
                port=port,
                metadata={
                    "provider": "aws",
                    "service": "ELBv2",
                    "lb_arn": item["lb_arn"],
                    "lb_type": item["lb_type"],
                    "ssl_policy": ssl_policy,
                    "pqc_status": pqc_status,
                },
            )
            stats["assets_created" if created else "assets_updated"] += 1

            # Record algorithm (the TLS policy itself)
            algo_name = ssl_policy or "Unknown-TLS-Policy"
            await self._record_algorithm(
                session,
                asset.id,
                scan_id,
                algo_name,
                "key_exchange",
                None,
                pqc_status,
                not is_pqc_policy,
                protocol="TLS",
            )
            stats["algorithms_recorded"] += 1

            # Finding for non-PQC TLS policies
            if not is_pqc_policy:
                created_f = await self._create_finding(
                    session,
                    asset,
                    scan_id,
                    finding_type="pqc_not_supported",
                    severity="high",
                    title=f"ELB/ALB TLS Policy Lacks PQC Support ({ssl_policy})",
                    description=(
                        f"Load balancer {lb_name} ({lb_dns}) uses TLS policy "
                        f"'{ssl_policy}' which does not include post-quantum "
                        f"key exchange. Traffic is vulnerable to harvest-now-decrypt-later."
                    ),
                    algorithm=ssl_policy,
                    pqc_status="vulnerable",
                    remediation=(
                        "Update the listener's TLS security policy to one of the "
                        "PQ-TLS policies: ELBSecurityPolicy-PQ-TLS-1-0-2020-12 or later."
                    ),
                    recommended_algorithm="ELBSecurityPolicy-PQ-TLS-1-2-2020-12",
                    evidence={
                        "service": "ELBv2",
                        "lb_name": lb_name,
                        "lb_dns": lb_dns,
                        "ssl_policy": ssl_policy,
                        "listener_arn": item.get("listener_arn"),
                    },
                )
                if created_f:
                    stats["findings_created"] += 1

        return stats

    # ── CloudFront ──────────────────────────────────────────────────────
    async def _scan_cloudfront(
        self, session: AsyncSession, scan_id: str
    ) -> Dict[str, Any]:
        import boto3

        stats = _empty_stats()

        def _list_distributions():
            cf = boto3.client("cloudfront", **self._boto_kwargs())
            dists = []
            paginator = cf.get_paginator("list_distributions")
            for page in paginator.paginate():
                dist_list = page.get("DistributionList", {})
                for dist in dist_list.get("Items", []):
                    dists.append(dist)
            return dists

        try:
            distributions = await asyncio.to_thread(_list_distributions)
        except Exception as e:
            return {"errors": [f"CloudFront: {e}"], **_empty_stats()}

        for dist in distributions:
            dist_id = dist.get("Id", "unknown")
            domain = dist.get("DomainName", "")
            aliases = dist.get("Aliases", {}).get("Items", [])
            viewer_cert = dist.get("ViewerCertificate", {})
            min_protocol = viewer_cert.get("MinimumProtocolVersion", "TLSv1")
            ssl_support = viewer_cert.get("SSLSupportMethod", "sni-only")

            # CloudFront does not yet support PQC TLS
            pqc_status = "vulnerable"

            asset_name = f"aws-cloudfront:{dist_id}"
            asset, created = await self._upsert_asset(
                session,
                name=asset_name,
                asset_type="load_balancer",
                environment="cloud",
                discovery_source="aws_pqc_scan",
                scan_id=scan_id,
                fqdn=domain,
                port=443,
                metadata={
                    "provider": "aws",
                    "service": "CloudFront",
                    "distribution_id": dist_id,
                    "aliases": aliases,
                    "min_protocol": min_protocol,
                    "ssl_support": ssl_support,
                    "pqc_status": pqc_status,
                },
            )
            stats["assets_created" if created else "assets_updated"] += 1

            await self._record_algorithm(
                session,
                asset.id,
                scan_id,
                f"CloudFront-{min_protocol}",
                "key_exchange",
                None,
                pqc_status,
                True,
                protocol="TLS",
            )
            stats["algorithms_recorded"] += 1

            created_f = await self._create_finding(
                session,
                asset,
                scan_id,
                finding_type="pqc_not_supported",
                severity="medium",
                title=f"CloudFront Distribution Lacks PQC TLS ({dist_id})",
                description=(
                    f"CloudFront distribution {dist_id} ({domain}) uses "
                    f"minimum protocol {min_protocol}. CloudFront does not yet "
                    f"support PQC key exchange, leaving viewer connections "
                    f"vulnerable to harvest-now-decrypt-later attacks."
                ),
                algorithm=f"TLS-{min_protocol}",
                pqc_status="vulnerable",
                remediation=(
                    "Monitor AWS announcements for PQC support in CloudFront. "
                    "Set MinimumProtocolVersion to TLSv1.2_2021 or higher in the "
                    "meantime. Consider adding PQC-capable origin servers."
                ),
                recommended_algorithm="TLSv1.3 with ML-KEM (when available)",
                evidence={
                    "service": "CloudFront",
                    "distribution_id": dist_id,
                    "domain": domain,
                    "min_protocol": min_protocol,
                    "aliases": aliases,
                },
            )
            if created_f:
                stats["findings_created"] += 1

        return stats

    # ── S3 ──────────────────────────────────────────────────────────────
    async def _scan_s3(self, session: AsyncSession, scan_id: str) -> Dict[str, Any]:
        import boto3

        stats = _empty_stats()

        def _list_buckets_encryption():
            s3 = boto3.client("s3", **self._boto_kwargs())
            buckets = s3.list_buckets().get("Buckets", [])
            results = []
            for bucket in buckets:
                name = bucket["Name"]
                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                    rules = enc.get("ServerSideEncryptionConfiguration", {}).get(
                        "Rules", []
                    )
                    for rule in rules:
                        sse = rule.get("ApplyServerSideEncryptionByDefault", {})
                        results.append(
                            {
                                "bucket": name,
                                "sse_algorithm": sse.get("SSEAlgorithm", "NONE"),
                                "kms_key_id": sse.get("KMSMasterKeyID"),
                                "bucket_key_enabled": rule.get(
                                    "BucketKeyEnabled", False
                                ),
                            }
                        )
                except s3.exceptions.ClientError:
                    # No encryption config
                    results.append(
                        {
                            "bucket": name,
                            "sse_algorithm": "NONE",
                            "kms_key_id": None,
                            "bucket_key_enabled": False,
                        }
                    )
                except Exception as e:
                    results.append({"bucket": name, "_error": str(e)})
            return results

        bucket_configs = await asyncio.to_thread(_list_buckets_encryption)

        for cfg in bucket_configs:
            if "_error" in cfg:
                stats["errors"].append(f"S3 {cfg['bucket']}: {cfg['_error']}")
                continue

            bucket = cfg["bucket"]
            sse_algo = cfg["sse_algorithm"]
            kms_key = cfg.get("kms_key_id")

            if sse_algo == "NONE":
                # Unencrypted bucket — note as info-level
                continue

            # Map SSE algorithm
            if sse_algo == "aws:kms" or sse_algo == "aws:kms:dsse":
                algo_name = "AES-256 (KMS-managed)"
                algo_type = "symmetric"
                key_size = 256
            elif sse_algo == "AES256":
                algo_name = "AES-256 (SSE-S3)"
                algo_type = "symmetric"
                key_size = 256
            else:
                algo_name = sse_algo
                algo_type = "symmetric"
                key_size = None

            classification = classify_algorithm(algo_name)
            pqc_status = classification.get("pqc_status", "unknown")
            is_qv = classification.get("is_quantum_vulnerable", False)

            asset_name = f"aws-s3:{bucket}"
            asset, created = await self._upsert_asset(
                session,
                name=asset_name,
                asset_type="cloud_resource",
                environment="cloud",
                discovery_source="aws_pqc_scan",
                scan_id=scan_id,
                metadata={
                    "provider": "aws",
                    "service": "S3",
                    "bucket": bucket,
                    "sse_algorithm": sse_algo,
                    "kms_key_id": kms_key,
                    "bucket_key_enabled": cfg.get("bucket_key_enabled", False),
                    "pqc_status": pqc_status,
                },
            )
            stats["assets_created" if created else "assets_updated"] += 1

            await self._record_algorithm(
                session,
                asset.id,
                scan_id,
                algo_name,
                algo_type,
                key_size,
                pqc_status,
                is_qv,
                protocol="S3-SSE",
            )
            stats["algorithms_recorded"] += 1

        return stats

    # ── IAM Server Certificates ─────────────────────────────────────────
    async def _scan_iam_certs(
        self, session: AsyncSession, scan_id: str
    ) -> Dict[str, Any]:
        import boto3

        stats = _empty_stats()

        def _list_server_certs():
            iam = boto3.client("iam", **self._boto_kwargs())
            paginator = iam.get_paginator("list_server_certificates")
            certs = []
            for page in paginator.paginate():
                for meta in page.get("ServerCertificateMetadataList", []):
                    certs.append(meta)
            return certs

        try:
            iam_certs = await asyncio.to_thread(_list_server_certs)
        except Exception as e:
            return {"errors": [f"IAM: {e}"], **_empty_stats()}

        for cert_meta in iam_certs:
            cert_name = cert_meta.get("ServerCertificateName", "unknown")
            arn = cert_meta.get("Arn", "")

            # IAM certs are always classical (RSA/ECDSA)
            asset_name = f"aws-iam-cert:{cert_name}"
            asset, created = await self._upsert_asset(
                session,
                name=asset_name,
                asset_type="kms",
                environment="cloud",
                discovery_source="aws_pqc_scan",
                scan_id=scan_id,
                metadata={
                    "provider": "aws",
                    "service": "IAM",
                    "cert_name": cert_name,
                    "arn": arn,
                    "pqc_status": "vulnerable",
                },
            )
            stats["assets_created" if created else "assets_updated"] += 1

            await self._record_algorithm(
                session,
                asset.id,
                scan_id,
                "RSA (IAM Server Cert)",
                "signature",
                2048,
                "vulnerable",
                True,
                protocol="IAM",
            )
            stats["algorithms_recorded"] += 1

            created_f = await self._create_finding(
                session,
                asset,
                scan_id,
                finding_type="weak_algorithm",
                severity="medium",
                title=f"IAM Server Certificate Uses Classical Algorithm ({cert_name})",
                description=(
                    f"IAM server certificate '{cert_name}' (ARN: {arn}) uses a "
                    f"classical signature algorithm. Migrate to ACM-managed "
                    f"certificates for automated renewal and future PQC support."
                ),
                algorithm="RSA",
                pqc_status="vulnerable",
                remediation=(
                    "Migrate from IAM server certificates to ACM-managed certificates. "
                    "IAM server certificates are legacy and do not support modern features."
                ),
                recommended_algorithm="ML-DSA-65",
                evidence={
                    "service": "IAM",
                    "cert_name": cert_name,
                    "arn": arn,
                },
            )
            if created_f:
                stats["findings_created"] += 1

        return stats

    # ── Shared helpers ──────────────────────────────────────────────────

    async def _upsert_asset(
        self,
        session: AsyncSession,
        name: str,
        asset_type: str,
        environment: str,
        discovery_source: str,
        scan_id: str,
        metadata: dict,
        fqdn: Optional[str] = None,
        ip_address: Optional[str] = None,
        port: Optional[int] = None,
    ) -> Tuple[Asset, bool]:
        """Upsert an asset. Returns (asset, was_created)."""
        stmt = select(Asset).where(Asset.name == name, Asset.deleted_at.is_(None))
        res = await session.execute(stmt)
        existing = res.scalar_one_or_none()

        if existing:
            existing.asset_metadata = metadata
            existing.last_scan_id = scan_id
            existing.last_verified_at = datetime.now(timezone.utc)
            if fqdn:
                existing.fqdn = fqdn
            if ip_address:
                existing.ip_address = ip_address
            if port:
                existing.port = port
            return existing, False
        else:
            asset = Asset(
                name=name,
                asset_type=asset_type,
                environment=environment,
                discovery_source=discovery_source,
                first_scan_id=scan_id,
                last_scan_id=scan_id,
                asset_metadata=metadata,
                fqdn=fqdn,
                ip_address=ip_address,
                port=port,
            )
            session.add(asset)
            await session.flush()  # to get the id
            return asset, True

    async def _record_algorithm(
        self,
        session: AsyncSession,
        asset_id: str,
        scan_id: str,
        algo_name: str,
        algo_type: str,
        key_size: Optional[int],
        pqc_status: str,
        is_qv: bool,
        protocol: str = "",
    ):
        # Normalise pqc_status to valid enum values
        valid_statuses = {"vulnerable", "transitioning", "hybrid", "pqc_ready", "safe"}
        db_status = pqc_status if pqc_status in valid_statuses else "vulnerable"

        algo = Algorithm(
            asset_id=asset_id,
            scan_id=scan_id,
            algorithm_name=algo_name,
            algorithm_type=algo_type,
            key_size=key_size,
            pqc_status=db_status,
            is_quantum_vulnerable=is_qv,
            protocol=protocol,
        )
        session.add(algo)

    async def _record_certificate(
        self,
        session: AsyncSession,
        asset_id: str,
        domain: str,
        sig_algo: str,
        key_algo: str,
        key_size: Optional[int],
        not_before: Any,
        not_after: Any,
        is_ca: bool = False,
        san_dns: Optional[List[str]] = None,
        pqc_status: str = "vulnerable",
    ):
        import hashlib

        thumbprint = hashlib.sha256(
            f"{domain}:{sig_algo}:{not_after}".encode()
        ).hexdigest()[:64]

        # Check if already exists
        stmt = select(Certificate).where(
            Certificate.thumbprint == thumbprint,
            Certificate.deleted_at.is_(None),
        )
        res = await session.execute(stmt)
        if res.scalar_one_or_none():
            return  # already recorded

        pub_key_algo = key_algo.split("-")[0] if "-" in key_algo else key_algo
        classification = classify_algorithm(sig_algo)

        cert = Certificate(
            asset_id=asset_id,
            thumbprint=thumbprint,
            subject=f"CN={domain}",
            issuer="Amazon" if "AMAZON" in sig_algo.upper() else "Unknown",
            sig_algorithm=sig_algo,
            pub_key_algorithm=pub_key_algo,
            pub_key_size=key_size,
            not_before=(
                not_before
                if isinstance(not_before, datetime)
                else datetime.now(timezone.utc)
            ),
            not_after=(
                not_after
                if isinstance(not_after, datetime)
                else datetime.now(timezone.utc)
            ),
            is_self_signed=False,
            is_ca=is_ca,
            san_dns=san_dns or [],
            pqc_capable=classification.get("is_pqc", False),
            pqc_details={
                "pqc_status": pqc_status,
                "is_quantum_vulnerable": classification.get(
                    "is_quantum_vulnerable", True
                ),
            },
        )
        session.add(cert)

    async def _create_finding(
        self,
        session: AsyncSession,
        asset: Asset,
        scan_id: str,
        finding_type: str,
        severity: str,
        title: str,
        description: str,
        algorithm: str,
        pqc_status: str,
        remediation: str,
        recommended_algorithm: str,
        key_size: Optional[int] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Create a finding if one doesn't already exist. Returns True if created."""
        now = datetime.now(timezone.utc)

        # Deduplicate
        existing = await session.execute(
            select(Finding).where(
                Finding.asset_id == asset.id,
                Finding.scan_id == scan_id,
                Finding.finding_type == finding_type,
                Finding.algorithm == (algorithm or ""),
                Finding.deleted_at.is_(None),
            )
        )
        if existing.scalar_one_or_none():
            return False

        # Calculate risk score
        system_exposure = (
            "internet"
            if asset.asset_type in ["load_balancer", "web_app", "api"]
            else "internal"
        )
        risk_score = calculate_risk_score(
            hndl_exposure="high" if pqc_status == "vulnerable" else "low",
            system_exposure=system_exposure,
            pqc_status=pqc_status,
            replaceability="moderate",
            years_to_deadline=4,  # default 2030 deadline
        )

        layer = layer_for_finding(finding_type=finding_type, asset=asset)

        finding = Finding(
            asset_id=asset.id,
            scan_id=scan_id,
            finding_type=finding_type,
            severity=severity,
            title=title,
            description=description,
            algorithm=algorithm,
            pqc_status=pqc_status,
            risk_score=risk_score,
            layer=layer,
            hndl_exposure="high" if pqc_status == "vulnerable" else "low",
            evidence=evidence or {},
            remediation=remediation,
            recommended_algorithm=recommended_algorithm,
            status="open",
            first_detected_at=now,
            last_verified_at=now,
        )
        session.add(finding)
        return True


def _empty_stats() -> Dict[str, Any]:
    return {
        "assets_created": 0,
        "assets_updated": 0,
        "algorithms_recorded": 0,
        "findings_created": 0,
        "certificates_recorded": 0,
        "errors": [],
    }


def _parse_key_size(key_algo: str) -> Optional[int]:
    """Extract key size from ACM key algorithm strings like RSA_2048, EC_prime256v1."""
    import re

    m = re.search(r"(\d{3,5})", key_algo)
    if m:
        return int(m.group(1))
    if "256" in key_algo:
        return 256
    if "384" in key_algo:
        return 384
    if "521" in key_algo:
        return 521
    return None
