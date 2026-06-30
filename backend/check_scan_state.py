import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import select, func

from app.db import AsyncSessionLocal
from app.models.models import Scan, Asset, Finding, ScanLog


async def check():
    scan_id = "cc260879-4a33-4698-a9d9-2ffba0079e86"
    async with AsyncSessionLocal() as session:
        s = (
            await session.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one_or_none()
        if not s:
            print("Scan not found")
            return
        print("=== SCAN ROW ===")
        print(
            f"  status={s.status}  started_at={s.started_at}  completed_at={s.completed_at}"
        )
        print(
            f"  duration={s.duration_seconds}s  assets_found={s.assets_found}  findings_created={s.findings_created}"
        )
        print(f"  target={s.target}  type={s.scan_type}")
        print(f"  error_message={s.error_message}")

        a = (
            await session.execute(
                select(func.count(Asset.id)).where(
                    Asset.last_scan_id == scan_id, Asset.deleted_at.is_(None)
                )
            )
        ).scalar_one()
        f = (
            await session.execute(
                select(func.count(Finding.id)).where(
                    Finding.scan_id == scan_id, Finding.deleted_at.is_(None)
                )
            )
        ).scalar_one()
        print("\n=== ACTUAL DB COUNTS ===")
        print(f"  assets: {a}   findings: {f}")

        logs = (
            (
                await session.execute(
                    select(ScanLog)
                    .where(ScanLog.scan_id == scan_id)
                    .order_by(ScanLog.timestamp)
                )
            )
            .scalars()
            .all()
        )
        print(f"\n=== LOGS ({len(logs)} rows) ===")
        for log in logs:
            print(f"  [{log.level:5s}/{log.phase:10s}] {log.message}")


asyncio.run(check())
