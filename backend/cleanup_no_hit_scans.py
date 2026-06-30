"""Hard-delete scans that produced no assets and no findings.

Targets scans in terminal states (completed / failed / cancelled) where
`assets_found = 0` AND `findings_created = 0` — the classic "ghost scan"
state where the orchestrator reported a result but no real rows exist.

Note: the `Scan` model has no `deleted_at` column, so this script
hard-deletes scan rows (following the pattern in `cleanup_scans.py`).
Asset/Finding `deleted_at` columns exist but are irrelevant here since
no-hit scans own no assets and no findings.

Usage (from backend/ dir with venv active):
    python cleanup_no_hit_scans.py [--dry-run]
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import delete, select, update

from app.db import AsyncSessionLocal
from app.models.models import Scan, ScanLog, Finding, Asset
from app.utils.cache import get_redis_cache


async def cleanup(dry_run: bool = False) -> None:
    async with AsyncSessionLocal() as session:
        # 1. Find candidate scans: terminal status, no assets, no findings
        result = await session.execute(
            select(Scan)
            .where(
                Scan.status.in_(["completed", "failed", "cancelled"]),
                Scan.assets_found == 0,
                Scan.findings_created == 0,
            )
            .order_by(Scan.created_at.asc())
        )
        candidates = result.scalars().all()

        if not candidates:
            print("No no-hit scans found. Nothing to clean up.")
            return

        print(
            f"{'[DRY RUN] ' if dry_run else ''}Found {len(candidates)} no-hit scan(s):"
        )
        for s in candidates:
            print(
                f"  - {s.id}  type={s.scan_type:10s}  target={s.target!s:30s}  "
                f"status={s.status:10s}  created={s.created_at.isoformat()}"
            )

        if dry_run:
            print("Dry run — no changes made.")
            return

        scan_ids = [s.id for s in candidates]

        # 2. Null out FK references on assets (defensive — these scans
        # shouldn't own any assets, but clean up just in case).
        await session.execute(
            update(Asset)
            .where(Asset.first_scan_id.in_(scan_ids))
            .values(first_scan_id=None)
        )
        await session.execute(
            update(Asset)
            .where(Asset.last_scan_id.in_(scan_ids))
            .values(last_scan_id=None)
        )
        await session.flush()

        # 3. Delete findings tied to these scans (should be zero, but
        # defensive in case a finding was created after the scan row's
        # findings_created counter was last updated).
        deleted_findings = await session.execute(
            delete(Finding).where(Finding.scan_id.in_(scan_ids))
        )
        print(f"Deleted {deleted_findings.rowcount or 0} finding(s).")

        # 4. Delete scan logs.
        deleted_logs = await session.execute(
            delete(ScanLog).where(ScanLog.scan_id.in_(scan_ids))
        )
        print(f"Deleted {deleted_logs.rowcount or 0} scan log(s).")

        # 5. Hard-delete the scan rows.
        deleted_scans = await session.execute(delete(Scan).where(Scan.id.in_(scan_ids)))
        print(f"Deleted {deleted_scans.rowcount or 0} scan row(s).")

        await session.commit()

        # 6. Clear dashboard cache so the layer coverage / summary
        # endpoints recompute against the new state.
        try:
            cache = await get_redis_cache()
            client = await cache._get_client()
            if client is not None:
                cursor = 0
                cleared = 0
                while True:
                    cursor, keys = await client.scan(
                        cursor=cursor, match="pqc:dashboard:*", count=100
                    )
                    if keys:
                        await client.delete(*keys)
                        cleared += len(keys)
                    if cursor == 0:
                        break
                print(f"Cleared {cleared} dashboard cache key(s).")
        except Exception as exc:
            print(f"WARNING: failed to clear dashboard cache: {exc}")

        print(f"Cleanup complete. {len(candidates)} no-hit scan(s) removed.")


if __name__ == "__main__":
    dry_run = "--dry-run" in sys.argv
    asyncio.run(cleanup(dry_run=dry_run))
