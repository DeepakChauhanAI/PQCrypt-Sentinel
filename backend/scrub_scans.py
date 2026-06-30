import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from app.db import AsyncSessionLocal
from app.models.models import Scan, ScanLog, Finding, Asset
from sqlalchemy import delete, update


async def scrub():
    async with AsyncSessionLocal() as session:
        print("Nullifying scan FK references on assets...")
        await session.execute(
            update(Asset)
            .where(Asset.first_scan_id.is_not(None))
            .values(first_scan_id=None)
        )
        await session.execute(
            update(Asset)
            .where(Asset.last_scan_id.is_not(None))
            .values(last_scan_id=None)
        )
        await session.flush()

        print("Deleting scan logs...")
        await session.execute(delete(ScanLog))
        print("Deleting findings...")
        await session.execute(delete(Finding))
        print("Deleting scans...")
        await session.execute(delete(Scan))
        await session.commit()
        print("Committed. All scans, logs, and findings removed.")
        print("Assets remain intact with scan FK columns cleared.")


asyncio.run(scrub())
