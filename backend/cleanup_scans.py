import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from app.db import AsyncSessionLocal
from app.models.models import Scan, ScanLog, Finding, Asset
from sqlalchemy import delete, select, update

async def keep_only_latest_scan():
    async with AsyncSessionLocal() as session:
        # 1. Find the most recent scan
        result = await session.execute(
            select(Scan.id).order_by(Scan.created_at.desc()).limit(1)
        )
        latest_scan_id = result.scalar_one_or_none()

        if not latest_scan_id:
            print("No scans found. Nothing to clean up.")
            return

        print(f"Keeping scan {latest_scan_id}, removing all older scans...")

        # 2. Remove FK references from assets pointing to older scans
        await session.execute(
            update(Asset)
            .where(Asset.first_scan_id != latest_scan_id)
            .where(Asset.first_scan_id.is_not(None))
            .values(first_scan_id=None)
        )
        await session.execute(
            update(Asset)
            .where(Asset.last_scan_id != latest_scan_id)
            .where(Asset.last_scan_id.is_not(None))
            .values(last_scan_id=None)
        )
        await session.flush()

        # 3. Delete scan logs for all scans except the latest
        await session.execute(
            delete(ScanLog).where(ScanLog.scan_id != latest_scan_id)
        )
        print("Deleted scan logs for old scans.")

        # 4. Delete findings tied to old scans
        await session.execute(
            delete(Finding).where(Finding.scan_id != latest_scan_id)
        )
        print("Deleted findings for old scans.")

        # 5. Delete old scans
        await session.execute(
            delete(Scan).where(Scan.id != latest_scan_id)
        )
        print("Deleted old scans.")

        await session.commit()
        print(f"Cleanup complete. Only scan {latest_scan_id} remains.")

asyncio.run(keep_only_latest_scan())
