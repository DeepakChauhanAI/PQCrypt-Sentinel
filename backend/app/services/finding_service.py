from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.models import Finding, Asset
from app.analysis.algo_classifier import classify_algorithm
from app.services.risk_service import calculate_risk_score


def _serialize_evidence(value: Any) -> Any:
    """Recursively convert datetime objects to ISO 8601 strings so JSONB columns serialize cleanly."""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat() if value.tzinfo is None else value.isoformat()
    if isinstance(value, dict):
        return {key: _serialize_evidence(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_serialize_evidence(item) for item in value]
    return value

async def generate_findings(
    session: AsyncSession,
    scan_id: str,
    asset_id: str,
    cert_data: Optional[Dict[str, Any]] = None,
    kex_algos: Optional[List[str]] = None,
) -> int:
    """
    Analyze scan outcomes and generate finding records.
    Returns the count of findings created.
    """
    # Load the asset to get environment/metadata for risk score calculation
    asset_result = await session.execute(select(Asset).where(Asset.id == asset_id))
    asset = asset_result.scalar_one_or_none()
    if not asset:
        return 0

    findings_created = 0
    now = datetime.now(timezone.utc)

    # Helper function to create finding with risk score and insert
    async def add_finding(
        finding_type: str,
        severity: str,
        title: str,
        description: str,
        algorithm: Optional[str],
        pqc_status: str,
        remediation: str,
        recommended_algorithm: str,
        key_size: Optional[int] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ):
        nonlocal findings_created

        # Deduplicate: skip if a finding with the same asset+scan+type+algorithm
        # already exists for this scan to avoid redundant rows.
        existing = await session.execute(
            select(Finding).where(
                Finding.asset_id == asset.id,
                Finding.scan_id == scan_id,
                Finding.finding_type == finding_type,
                Finding.algorithm == (algorithm or ""),
                Finding.deleted_at.is_(None),
            )
        )
        existing_row = existing.scalar_one_or_none()
        if existing_row is not None and isinstance(existing_row, Finding):
            return

        from app.analysis.mosca_model import calculate_hndl_exposure
        from app.config import settings
        from app.services.risk_service import (
            derive_data_longevity_years,
            derive_replaceability,
        )
        from app.services.layer_service import layer_for_finding

        # Derive Mosca X (data longevity) and replaceability
        data_longevity_years = derive_data_longevity_years(
            asset=asset,
            cert_data=cert_data,
            finding_type=finding_type,
            kex_algos=kex_algos,
        )
        quantum_timeline_year = settings.QUANTUM_TIMELINE_YEAR
        hndl_exposure = calculate_hndl_exposure(data_longevity_years, quantum_timeline_year)
        replaceability = derive_replaceability(
            asset=asset,
            finding_type=finding_type,
            algorithm=algorithm,
            key_size=key_size,
        )

        # Determine system exposure
        system_exposure = "internet" if asset.asset_type in ["web_app", "api", "load_balancer"] else "internal"

        # Determine years_to_deadline
        from app.analysis.algo_classifier import get_deprecation_deadline_year
        deadline_year = get_deprecation_deadline_year(algorithm or "", key_size)
        years_to_deadline = max(0, deadline_year - now.year)

        risk_score = calculate_risk_score(
            hndl_exposure=hndl_exposure,
            system_exposure=system_exposure,
            pqc_status=pqc_status,
            replaceability=replaceability,
            years_to_deadline=years_to_deadline,
        )

        # Persist Mosca fields into evidence JSONB so they survive into the CBOM
        # and are queryable for dashboards. Schema is additive and backward
        # compatible — older findings simply have None for these.
        ev = dict(_serialize_evidence(evidence) or {})
        ev.setdefault("mosca", {})
        ev["mosca"]["data_longevity_years"] = data_longevity_years
        ev["mosca"]["quantum_timeline_year"] = quantum_timeline_year
        ev["mosca"]["replaceability"] = replaceability

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
            layer=layer_for_finding(finding_type=finding_type, asset=asset),
            hndl_exposure=hndl_exposure,
            evidence=ev,
            remediation=remediation,
            recommended_algorithm=recommended_algorithm,
            status="open",
            first_detected_at=now,
            last_verified_at=now,
        )
        session.add(finding)
        findings_created += 1

    # Scenario 1: TLS Certificate findings
    if cert_data:
        pqc_status = cert_data["pqc_details"]["pqc_status"]
        algo_name = cert_data["sig_algorithm"]

        # 1.1 Weak algorithm / quantum vulnerable
        if pqc_status == "vulnerable":
            await add_finding(
                finding_type="weak_algorithm",
                severity="high",
                title=f"Quantum Vulnerable Signature Algorithm ({algo_name})",
                description=f"The certificate uses the classical signature algorithm {algo_name}, which is vulnerable to decryption by future cryptanalytically-relevant quantum computers.",
                algorithm=algo_name,
                pqc_status="vulnerable",
                remediation="Configure the server to use a hybrid certificate or a post-quantum certificate using ML-DSA or Falcon.",
                recommended_algorithm="ML-DSA-65",
                evidence=cert_data,
            )

        # 1.2 Self signed
        if cert_data["is_self_signed"]:
            await add_finding(
                finding_type="self_signed",
                severity="medium",
                title="Self-Signed Certificate in Use",
                description="The SSL/TLS service presents a self-signed certificate, which does not provide authentic trust anchor verification.",
                algorithm=algo_name,
                pqc_status=pqc_status,
                remediation="Replace the self-signed certificate with one issued by a trusted corporate PKI or public CA.",
                recommended_algorithm="ML-DSA-65",
                evidence=cert_data,
            )

        # 1.3 Key size checks
        pub_key_algo = cert_data["pub_key_algorithm"]
        pub_key_size = cert_data["pub_key_size"]
        if pub_key_algo == "RSA" and pub_key_size < 2048:
            await add_finding(
                finding_type="weak_key_size",
                severity="critical",
                title="Weak RSA Key Size (< 2048 bits)",
                description=f"The certificate uses a weak RSA key size of {pub_key_size} bits, which is insecure against both classical and quantum attacks.",
                algorithm=f"RSA-{pub_key_size}",
                pqc_status="vulnerable",
                remediation="Generate a new key pair with at least 2048-bit RSA, or migrate to ECDSA (P-256/P-384) / PQC.",
                recommended_algorithm="ML-DSA-65",
                key_size=pub_key_size,
                evidence=cert_data,
            )

        # 1.4 Expiration checks
        not_after = cert_data["not_after"]
        # Convert not_after to timezone-aware datetime if it is not
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)

        days_to_expiry = (not_after - now).days
        if days_to_expiry < 0:
            await add_finding(
                finding_type="cert_expired",
                severity="critical",
                title="Expired SSL/TLS Certificate",
                description=f"The certificate expired on {not_after.isoformat()}.",
                algorithm=algo_name,
                pqc_status=pqc_status,
                remediation="Renew the certificate immediately.",
                recommended_algorithm="ML-DSA-65",
                evidence=cert_data,
            )
        elif days_to_expiry < 30:
            await add_finding(
                finding_type="cert_expiring",
                severity="high",
                title=f"SSL/TLS Certificate Expiring Soon ({days_to_expiry} days)",
                description=f"The certificate is set to expire on {not_after.isoformat()}.",
                algorithm=algo_name,
                pqc_status=pqc_status,
                remediation="Renew the certificate before it expires.",
                recommended_algorithm="ML-DSA-65",
                evidence=cert_data,
            )

    # Scenario 2: SSH algorithms
    if kex_algos:
        # Check if SSH supports any PQC key exchange
        pqc_kex_keywords = ["mlkem", "sntrup", "kyber", "ntrup", "pqc"]
        has_pqc_kex = any(any(kw in algo.lower() for kw in pqc_kex_keywords) for algo in kex_algos)

        if not has_pqc_kex:
            await add_finding(
                finding_type="ssh_weak_kex",
                severity="high",
                title="SSH Server Lacks Post-Quantum Key Exchange",
                description="The SSH server only supports classical key exchange algorithms (e.g. diffie-hellman-group14-sha256, ecdh-sha2-nistp256) which are vulnerable to store-now-decipher-later attacks.",
                algorithm=kex_algos[0] if kex_algos else "classical-kex",
                pqc_status="vulnerable",
                remediation="Configure the SSH server to support hybrid post-quantum key exchange groups, such as sntrup761x25519-sha512@openssh.com.",
                recommended_algorithm="sntrup761x25519-sha512@openssh.com",
                evidence={"supported_kex": kex_algos},
            )

    if findings_created > 0:
        await session.flush()

    return findings_created
