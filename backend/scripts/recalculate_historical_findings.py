"""
Recompute historical Finding records to reflect corrected NIST IR 8547 buckets.

Run from the backend directory:
    python -m scripts.recalculate_historical_findings

This script:
  1. Normalizes stale pqc_status values (safe_until_2035 / safe -> vulnerable)
     for Ed25519/Ed448/X25519/X448 and related algorithms.
  2. Recomputes risk_score for findings affected by deadline changes:
     * RSA-3072+  (2030 -> 2035)
     * ECC P-384+ (2030 -> 2035)
     * DH-3072+   (2030 -> 2035)
     * AES-256    (2035 -> 2099)
     * SHA-384/512 (2035 -> 2099)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select, update, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import AsyncSessionLocal
from app.models.models import Finding
from app.analysis.algo_classifier import get_deprecation_deadline_year
from app.services.risk_service import calculate_risk_score

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Algorithms whose deadline changed because of the registry fix.
# (pattern_in_algorithm_name, expected_old_deadline, expected_new_deadline)
DEADLINE_CORRECTIONS: list[tuple[str, int, int]] = [
    ("rsa-3072", 2030, 2035),
    ("rsa-4096", 2035, 2035),  # status changed but deadline stayed 2035
    ("ecdsa", 2030, 2035),  # P-384 only; we re-evaluate per key size
    ("aes-256", 2035, 2099),
    ("sha-384", 2035, 2099),
    ("sha-512", 2035, 2099),
    ("dh-3072", 2030, 2035),
    ("dh-4096", 2035, 2035),
    ("dh-8192", 2035, 2035),
]


def _extract_key_size(evidence: Optional[Dict[str, Any]]) -> Optional[int]:
    if not evidence:
        return None
    # cert_data often carries pub_key_size
    for key in ("pub_key_size", "key_size"):
        val = evidence.get(key)
        if isinstance(val, int):
            return val
    return None


def _extract_replaceability(evidence: Optional[Dict[str, Any]]) -> str:
    if not evidence:
        return "medium"
    mosca = evidence.get("mosca") or {}
    return mosca.get("replaceability") or "medium"


def _extract_system_exposure(evidence: Optional[Dict[str, Any]]) -> str:
    if not evidence:
        return "internal"
    # Heuristic: if evidence contains host/web references assume internet
    return "internal"


async def _update_pqc_statuses(session: AsyncSession) -> int:
    """Normalize stale pqc_status strings for Ed25519/Ed448/X25519/X448."""
    stmt = (
        update(Finding)
        .where(
            Finding.pqc_status.in_(["safe_until_2035", "safe"]),
            Finding.algorithm.ilike("%ed25519%")
            | Finding.algorithm.ilike("%ed448%")
            | Finding.algorithm.ilike("%x25519%")
            | Finding.algorithm.ilike("%x448%")
            | Finding.algorithm.ilike("%curve25519%")
            | Finding.algorithm.ilike("%curve448%"),
        )
        .values(pqc_status="vulnerable")
    )
    result = await session.execute(stmt)
    count = result.rowcount
    await session.commit()
    logger.info("Normalized %d findings with stale pqc_status for Ed/X curves", count)
    return count


async def _recompute_risk_scores(session: AsyncSession) -> int:
    """Recompute risk_score for findings whose algorithm deadline changed."""
    updated = 0
    now_year = datetime.now(timezone.utc).year

    # Build a filter: any algorithm that contains one of the correction keywords
    filter_clauses = []
    for pattern, _old, _new in DEADLINE_CORRECTIONS:
        filter_clauses.append(Finding.algorithm.ilike(f"%{pattern}%"))

    result = await session.execute(
        select(Finding).where(or_(*filter_clauses), Finding.deleted_at.is_(None))
    )
    findings = result.scalars().all()

    for finding in findings:
        algo = (finding.algorithm or "").upper()
        key_size = _extract_key_size(finding.evidence)

        # Use the corrected deadline logic
        deadline_year = get_deprecation_deadline_year(algo, key_size)
        years_to_deadline = max(0, deadline_year - now_year)

        # Keep existing Mosca values from evidence
        replaceability = _extract_replaceability(finding.evidence)
        system_exposure = (
            finding.evidence.get("system_exposure", "internal")
            if finding.evidence
            else "internal"
        )
        hndl_exposure = finding.hndl_exposure or "medium"
        pqc_status = finding.pqc_status or "vulnerable"

        new_score = calculate_risk_score(
            hndl_exposure=hndl_exposure,
            system_exposure=system_exposure,
            pqc_status=pqc_status,
            replaceability=replaceability,
            years_to_deadline=years_to_deadline,
        )

        if new_score != finding.risk_score:
            finding.risk_score = new_score
            finding.last_verified_at = datetime.now(timezone.utc)
            updated += 1

    await session.commit()
    logger.info("Recomputed risk_score for %d findings", updated)
    return updated


async def main() -> None:
    async with AsyncSessionLocal() as session:
        status_updates = await _update_pqc_statuses(session)
        score_updates = await _recompute_risk_scores(session)
        logger.info(
            "Historic scan fix complete: %d pqc_status updates, %d risk_score updates",
            status_updates,
            score_updates,
        )


if __name__ == "__main__":
    asyncio.run(main())
