"""
Persist L1 (OCSP + DNSSEC) probe results into the Finding table.

The probe layer (`app.scanners.ocsp_dnssec_scanner`) produces:
  * `OCSPProbeResult`   — per (host, cert) tuple
  * `DNSSECProbeResult` — per domain

This service translates each non-trivial probe outcome into a `Finding`
row. It mirrors the structure of `app.services.finding_service` (the
TLS/SSH path) so the dashboard, CBOM, and SARIF consumers can treat
L1 findings uniformly.

Mapping summary (locked 2026-06-05):

  OCSP revoked status          -> critical  cert_expired     pqc_status=unknown
  OCSP weak signature (md5/sha1) -> high   weak_algorithm   pqc_status=disallowed_now
  OCSP weak signature (rsa)     -> high   weak_algorithm   pqc_status=vulnerable
  OCSP weak signature (ecdsa)       -> medium weak_algorithm pqc_status=safe_until_2030
  OCSP weak signature (ed25519/ed448) -> high   weak_algorithm pqc_status=vulnerable
  OCSP responder unreachable    -> low    pqc_not_supported (no finding; just an info row)

  DNSSEC vulnerable alg (RSA-SHA1/MD5/DSA/NSEC3DSA) -> high weak_algorithm pqc_status=vulnerable
  DNSSEC mixed algs            -> medium weak_algorithm pqc_status=safe_until_2030
  DNSSEC all-safe algs         -> (no finding)
  DNSSEC unsigned zone / no chain -> medium pqc_not_supported pqc_status=vulnerable

The service never raises. Probe outcomes that cannot be classified are
skipped (returning a 0-count) so a single bad host never blocks the
rest of the scan.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Sequence, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.analysis.mosca_model import calculate_hndl_exposure
from app.config import settings
from app.models.models import Asset, Certificate, Finding
from app.scanners.ocsp_dnssec_scanner import (
    DNSSECProbeResult,
    OCSPProbeResult,
)
from app.services.risk_service import (
    calculate_risk_score,
    derive_data_longevity_years,
    derive_replaceability,
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ helpers --


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _ocsp_severity(pqc_status: str) -> Optional[str]:
    """Map OCSP pqc_status -> severity. Returns None when no finding should be raised."""
    if pqc_status == "disallowed_now":
        return "high"
    if pqc_status == "vulnerable":
        return "high"
    if pqc_status == "safe_until_2030":
        return "medium"
    if pqc_status == "safe":
        return None  # no finding
    return None  # unknown / pqc_ready / hybrid


def _dnssec_severity(pqc_status: str, chain_of_trust: bool) -> Optional[str]:
    if pqc_status == "vulnerable":
        return "high"
    if pqc_status == "safe_until_2030":
        return "medium"
    if pqc_status == "safe" and not chain_of_trust:
        # Signed but no DS in parent — partial chain. Still worth flagging
        # because the operator may be unaware of the gap.
        return "medium"
    if pqc_status == "unknown":
        return "medium"
    return None  # safe and chained -> no finding


# ------------------------------------------------------------- main service --


class L1FindingService:
    """Translate L1 probe results into Finding rows.

    Use the module-level functions below for the common case; the class
    exists so tests can construct a service with custom sessions and so
    future DI (e.g. swapping in a CBOM reporter) can pass a custom
    instance.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def persist_ocsp_results(
        self,
        scan_id: str,
        probe_results: Sequence[Tuple[str, OCSPProbeResult]],
    ) -> int:
        """`probe_results` is a sequence of (asset_id, OCSPProbeResult) pairs.

        Returns the count of new findings created.
        """
        count = 0
        for asset_id, probe in probe_results:
            if probe.success is False:
                # Unreachable / parse failure — skip; we never raise.
                continue
            if probe.status == "revoked":
                count += await self._add_revoked_finding(scan_id, asset_id, probe)
                continue
            severity = _ocsp_severity(probe.pqc_status)
            if severity is None:
                continue
            count += await self._add_ocsp_weak_sig_finding(
                scan_id, asset_id, probe, severity
            )
        if count > 0:
            await self.session.commit()
        return count

    async def persist_dnssec_results(
        self,
        scan_id: str,
        probe_results: Sequence[Tuple[str, DNSSECProbeResult]],
    ) -> int:
        """`probe_results` is a sequence of (asset_id, DNSSECProbeResult) pairs.

        Returns the count of new findings created.
        """
        count = 0
        for asset_id, probe in probe_results:
            if not probe.success:
                continue
            severity = _dnssec_severity(probe.pqc_status, probe.chain_of_trust)
            if severity is None:
                continue
            if probe.pqc_status == "vulnerable" or any(
                a in {"RSASHA1", "RSAMD5", "DSA", "NSEC3DSA"} for a in probe.algorithms
            ):
                count += await self._add_dnssec_weak_algo_finding(
                    scan_id, asset_id, probe, severity
                )
            elif not probe.chain_of_trust or probe.pqc_status == "unknown":
                count += await self._add_dnssec_missing_chain_finding(
                    scan_id, asset_id, probe, severity
                )
            else:
                count += await self._add_dnssec_weak_algo_finding(
                    scan_id, asset_id, probe, severity
                )
        if count > 0:
            await self.session.commit()
        return count

    # --------------------------------------------------------- finding builders

    async def _load_asset(self, asset_id: str) -> Optional[Asset]:
        result = await self.session.execute(select(Asset).where(Asset.id == asset_id))
        return result.scalar_one_or_none()

    async def _resolve_l1_cert(
        self, asset_id: str
    ) -> Optional[Certificate]:  # noqa: D401
        """Return the most recently issued leaf certificate for an asset, if any.

        Used to surface key_usage and cert metadata in the evidence JSONB
        when the probe result itself doesn't carry the full cert.
        Currently unused but kept for the upcoming OCSP wiring pass.
        """
        result = await self.session.execute(
            select(Certificate)
            .where(Certificate.asset_id == asset_id)
            .where(Certificate.deleted_at.is_(None))
            .order_by(Certificate.not_before.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    def _build_evidence(
        self,
        asset: Asset,
        finding_type: str,
        algorithm: Optional[str],
        key_size: Optional[int],
        probe_payload: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], Optional[str], int, Optional[str]]:
        """Run risk score + Mosca enrichments and return (evidence, pqc_status, risk_score, hndl).

        Mirrors the inner helper in `finding_service.generate_findings`
        but is decoupled so L1 findings can be created without
        cert_data / kex_algos inputs.
        """
        data_longevity_years = derive_data_longevity_years(
            asset=asset,
            cert_data=None,
            finding_type=finding_type,
            kex_algos=None,
        )
        quantum_timeline_year = settings.QUANTUM_TIMELINE_YEAR
        hndl_exposure = calculate_hndl_exposure(
            data_longevity_years, quantum_timeline_year
        )
        replaceability = derive_replaceability(
            asset=asset,
            finding_type=finding_type,
            algorithm=algorithm,
            key_size=key_size,
        )
        from app.analysis.algo_classifier import get_deprecation_deadline_year

        deadline_year = get_deprecation_deadline_year(algorithm or "", key_size)
        years_to_deadline = max(0, deadline_year - _now_utc().year)

        risk_score = calculate_risk_score(
            hndl_exposure=hndl_exposure,
            pqc_status=probe_payload.get("pqc_status"),
            replaceability=replaceability,
            years_to_deadline=years_to_deadline,
        )

        ev: Dict[str, Any] = dict(probe_payload or {})
        ev.setdefault("mosca", {})
        ev["mosca"]["data_longevity_years"] = data_longevity_years
        ev["mosca"]["quantum_timeline_year"] = quantum_timeline_year
        ev["mosca"]["replaceability"] = replaceability
        return (
            ev,
            str(probe_payload.get("pqc_status", "unknown")),
            risk_score,
            hndl_exposure,
        )

    async def _add_revoked_finding(
        self,
        scan_id: str,
        asset_id: str,
        probe: OCSPProbeResult,
    ) -> int:
        asset = await self._load_asset(asset_id)
        if asset is None:
            return 0

        evidence, pqc_status, risk_score, hndl_exposure = self._build_evidence(
            asset,
            finding_type="cert_expired",
            algorithm=probe.signature_algorithm,
            key_size=None,
            probe_payload={
                "probe": "ocsp",
                "host": probe.host,
                "cert_thumbprint": probe.cert_thumbprint,
                "ocsp_status": probe.status,
                "responder_url": probe.responder_url,
                "responder_name": probe.responder_name,
                "signature_algorithm": probe.signature_algorithm,
                "pqc_status": probe.pqc_status,
                "raw": probe.raw,
            },
        )

        finding = Finding(
            asset_id=asset.id,
            scan_id=scan_id,
            finding_type="cert_expired",
            severity="critical",
            title=f"Certificate Revoked by OCSP Responder ({probe.host})",
            description=(
                f"OCSP responder {probe.responder_url} reports status=revoked for "
                f"cert {probe.cert_thumbprint}. The certificate MUST be replaced "
                f"immediately and any service presenting it must be rotated."
            ),
            algorithm=probe.signature_algorithm,
            algorithm_type="ocsp",
            pqc_status=pqc_status,
            risk_score=risk_score,
            layer="L1",
            hndl_exposure=hndl_exposure,
            evidence=evidence,
            remediation=(
                "Replace the certificate and rotate the underlying key pair. "
                "Verify the issuer is operating a valid PKI."
            ),
            recommended_algorithm="ML-DSA-65",
            status="open",
            first_detected_at=_now_utc(),
            last_verified_at=_now_utc(),
        )
        self.session.add(finding)
        return 1

    async def _add_ocsp_weak_sig_finding(
        self,
        scan_id: str,
        asset_id: str,
        probe: OCSPProbeResult,
        severity: str,
    ) -> int:
        asset = await self._load_asset(asset_id)
        if asset is None:
            return 0

        evidence, pqc_status, risk_score, hndl_exposure = self._build_evidence(
            asset,
            finding_type="weak_algorithm",
            algorithm=probe.signature_algorithm,
            key_size=None,
            probe_payload={
                "probe": "ocsp",
                "host": probe.host,
                "cert_thumbprint": probe.cert_thumbprint,
                "ocsp_status": probe.status,
                "responder_url": probe.responder_url,
                "responder_name": probe.responder_name,
                "signature_algorithm": probe.signature_algorithm,
                "pqc_status": probe.pqc_status,
                "raw": probe.raw,
            },
        )

        finding = Finding(
            asset_id=asset.id,
            scan_id=scan_id,
            finding_type="weak_algorithm",
            severity=severity,
            title=(
                f"OCSP Responder Signs with Quantum-Vulnerable Algorithm "
                f"({probe.signature_algorithm})"
            ),
            description=(
                f"OCSP responder {probe.responder_url} signs responses with "
                f"{probe.signature_algorithm}, which is classified as "
                f"`{probe.pqc_status}` against the 5-dim risk model. "
                f"A cryptanalytically-relevant quantum computer could forge "
                f"revocation responses, undermining the chain of trust."
            ),
            algorithm=probe.signature_algorithm,
            algorithm_type="ocsp",
            pqc_status=pqc_status,
            risk_score=risk_score,
            layer="L1",
            hndl_exposure=hndl_exposure,
            evidence=evidence,
            remediation=(
                "Migrate the OCSP responder to a post-quantum-capable signature "
                "(ML-DSA-65) or a hybrid PQC scheme."
            ),
            recommended_algorithm="ML-DSA-65",
            status="open",
            first_detected_at=_now_utc(),
            last_verified_at=_now_utc(),
        )
        self.session.add(finding)
        return 1

    async def _add_dnssec_weak_algo_finding(
        self,
        scan_id: str,
        asset_id: str,
        probe: DNSSECProbeResult,
        severity: str,
    ) -> int:
        asset = await self._load_asset(asset_id)
        if asset is None:
            return 0

        alg_label = ",".join(probe.algorithms) or "unknown"
        evidence, pqc_status, risk_score, hndl_exposure = self._build_evidence(
            asset,
            finding_type="weak_algorithm",
            algorithm=alg_label,
            key_size=None,
            probe_payload={
                "probe": "dnssec",
                "domain": probe.domain,
                "algorithms": probe.algorithms,
                "has_dnskey": probe.has_dnskey,
                "has_rrsig": probe.has_rrsig,
                "has_ds": probe.has_ds,
                "chain_of_trust": probe.chain_of_trust,
                "pqc_status": probe.pqc_status,
                "error_message": probe.error_message,
            },
        )

        finding = Finding(
            asset_id=asset.id,
            scan_id=scan_id,
            finding_type="weak_algorithm",
            severity=severity,
            title=f"DNSSEC Uses Quantum-Vulnerable Algorithm(s) for {probe.domain}",
            description=(
                f"DNSSEC records for {probe.domain} are signed with "
                f"`{alg_label}`. These algorithms are quantum-vulnerable; "
                f"a CRQC could forge RRSIGs and hijack the delegation."
            ),
            algorithm=alg_label,
            algorithm_type="dnssec",
            pqc_status=pqc_status,
            risk_score=risk_score,
            layer="L1",
            hndl_exposure=hndl_exposure,
            evidence=evidence,
            remediation=(
                "Re-sign the zone using a post-quantum-aware DNSSEC algorithm "
                "(e.g. ECDSAP256SHA256 / Ed25519 today; ML-DSA-65 in 2027+). "
                "Coordinate DS record updates with the parent zone."
            ),
            recommended_algorithm="ECDSAP256SHA256",
            status="open",
            first_detected_at=_now_utc(),
            last_verified_at=_now_utc(),
        )
        self.session.add(finding)
        return 1

    async def _add_dnssec_missing_chain_finding(
        self,
        scan_id: str,
        asset_id: str,
        probe: DNSSECProbeResult,
        severity: str,
    ) -> int:
        asset = await self._load_asset(asset_id)
        if asset is None:
            return 0

        evidence, pqc_status, risk_score, hndl_exposure = self._build_evidence(
            asset,
            finding_type="pqc_not_supported",
            algorithm=",".join(probe.algorithms) or "none",
            key_size=None,
            probe_payload={
                "probe": "dnssec",
                "domain": probe.domain,
                "algorithms": probe.algorithms,
                "has_dnskey": probe.has_dnskey,
                "has_rrsig": probe.has_rrsig,
                "has_ds": probe.has_ds,
                "chain_of_trust": probe.chain_of_trust,
                "pqc_status": probe.pqc_status,
                "error_message": probe.error_message,
            },
        )

        finding = Finding(
            asset_id=asset.id,
            scan_id=scan_id,
            finding_type="pqc_not_supported",
            severity=severity,
            title=f"DNSSEC Chain of Trust Incomplete for {probe.domain}",
            description=(
                f"Domain {probe.domain} has DNSKEY={probe.has_dnskey}, "
                f"RRSIG={probe.has_rrsig}, DS={probe.has_ds}. "
                f"The chain of trust is not intact, leaving the delegation "
                f"vulnerable to cache poisoning by a quantum-capable attacker."
            ),
            algorithm=None,
            algorithm_type="dnssec",
            pqc_status=pqc_status,
            risk_score=risk_score,
            layer="L1",
            hndl_exposure=hndl_exposure,
            evidence=evidence,
            remediation=(
                "Publish a DS record in the parent zone and ensure RRSIGs "
                "cover the full zone. If the zone is intentionally unsigned, "
                "mark this as an accepted risk."
            ),
            recommended_algorithm="ECDSAP256SHA256",
            status="open",
            first_detected_at=_now_utc(),
            last_verified_at=_now_utc(),
        )
        self.session.add(finding)
        return 1


# ----------------------------------------------------------------- module API


async def generate_l1_findings(
    session: AsyncSession,
    scan_id: str,
    ocsp_results: Sequence[Tuple[str, OCSPProbeResult]],
    dnssec_results: Sequence[Tuple[str, DNSSECProbeResult]],
) -> Dict[str, int]:
    """Convenience wrapper: persist all L1 findings and return per-bucket counts.

    Returns a dict with keys `ocsp_findings` and `dnssec_findings` for the
    dashboard to display.
    """
    svc = L1FindingService(session)
    ocsp_count = await svc.persist_ocsp_results(scan_id, ocsp_results)
    dnssec_count = await svc.persist_dnssec_results(scan_id, dnssec_results)
    return {"ocsp_findings": ocsp_count, "dnssec_findings": dnssec_count}


__all__ = [
    "L1FindingService",
    "generate_l1_findings",
]
