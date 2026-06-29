"""Backfill script — wrap any existing groupable Scan in a ScanGroup.

Run from the backend directory:

    python -m scripts.backfill_scan_groups

Why this exists
---------------
Before the auto-wrap fix in ``app/api/scans.py``, a CIDR range scan
(``192.168.1.0/24``) was created as a single ``Scan`` row with
``scan_group_id = NULL`` and ``target_kind = NULL``. That meant:

  1. The scan never appeared in the Scan Groups tab.
  2. Every Finding it produced had ``scan_group_name = NULL`` in the
     "Scan / Group" column of the Findings page.
  3. Every Asset it produced had no scan-group context on the Assets
     page.

This script walks the existing ``scans`` table once, finds any scan that
would be groupable under the new target_classifier rules and currently
has ``scan_group_id IS NULL``, and creates a ScanGroup for it. It is
idempotent: a second run produces no new groups.

It also patches ``target_kind`` / ``target_label`` on every scan that
still has them as NULL, so the rest of the UI (sidebar badges, scan
detail) gets the right metadata for free.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select, or_, update, and_

from app.db import AsyncSessionLocal
from app.models.models import Scan, ScanGroup
from app.utils.target_classifier import classify_target, suggest_group_name

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


async def backfill() -> None:
    """Run the one-shot backfill.

    Steps:
      1. Patch ``target_kind`` / ``target_label`` for every scan that
         still has them as NULL.
      2. For every groupable scan with ``scan_group_id IS NULL``, create
         a ScanGroup and link it. The group inherits the scan's started
         / completed timestamps so the Scan Groups tab shows the right
         rollups.
    """
    async with AsyncSessionLocal() as session:
        # 1. Patch target_kind / target_label on all scans
        all_scans = (
            await session.execute(
                select(Scan).where(
                    or_(Scan.target_kind.is_(None), Scan.target_label.is_(None))
                )
            )
        ).scalars().all()

        patched_metadata = 0
        for scan in all_scans:
            changed = False
            if not scan.target_kind or not scan.target_label:
                classification = classify_target(scan.target)
                if not scan.target_kind:
                    scan.target_kind = classification.kind
                    changed = True
                if not scan.target_label:
                    scan.target_label = classification.label
                    changed = True
            if changed:
                patched_metadata += 1
        if patched_metadata:
            logger.info("Patched target_kind/target_label on %d scan(s).", patched_metadata)
            await session.commit()

        # 2. Wrap groupable scans with NULL scan_group_id in a new group
        groupable_scans = (
            await session.execute(
                select(Scan).where(
                    Scan.scan_group_id.is_(None),
                    Scan.deleted_at.is_(None),
                )
            )
        ).scalars().all()

        groups_created = 0
        for scan in groupable_scans:
            classification = classify_target(scan.target)
            if not classification.is_groupable:
                continue

            group = ScanGroup(
                name=suggest_group_name(scan.target, scan.scan_type),
                description=(
                    f"Backfilled group for {classification.kind} scan of "
                    f"`{scan.target}` (scan #{str(scan.id)[:8]}, "
                    f"originally created at {scan.created_at.isoformat() if scan.created_at else 'unknown'})."
                ),
                status=scan.status if scan.status in {"running", "completed", "failed", "cancelled", "queued"} else "completed",
                started_at=scan.started_at,
                completed_at=scan.completed_at,
                created_by=scan.created_by,
                created_at=scan.created_at or datetime.now(timezone.utc),
            )
            session.add(group)
            await session.flush()  # populate group.id
            scan.scan_group_id = group.id
            groups_created += 1
            logger.info(
                "Wrapped scan %s (target=%s) in new group %s (%s).",
                scan.id, scan.target, group.id, group.name,
            )

        if groups_created:
            await session.commit()
            logger.info("Backfill complete: created %d ScanGroup row(s).", groups_created)
        else:
            logger.info("Backfill complete: no scans needed a new group.")


if __name__ == "__main__":
    asyncio.run(backfill())
