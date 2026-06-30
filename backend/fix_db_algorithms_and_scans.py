import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import delete, select, update
from sqlalchemy.orm import selectinload
from app.db import AsyncSessionLocal
from app.models.models import Scan, ScanLog, Finding, Asset, Algorithm
from app.analysis.algo_classifier import classify_algorithm
from app.services.risk_service import calculate_risk_score
from app.utils.cache import get_redis_cache


async def run_fix():
    print("Connecting to the database...")
    async with AsyncSessionLocal() as session:
        # --- PART 1: Delete empty/failed/cancelled scan records ---
        # Empty scans are completed scans with 0 assets and 0 findings.
        # Failed/cancelled scans are scans with status "failed" or "cancelled".
        print("Finding empty, failed, or cancelled scans...")
        result = await session.execute(
            select(Scan).where(
                (Scan.status.in_(["failed", "cancelled"]))
                | (
                    (Scan.status == "completed")
                    & (Scan.assets_found == 0)
                    & (Scan.findings_created == 0)
                )
            )
        )
        scans_to_delete = result.scalars().all()

        if scans_to_delete:
            scan_ids = [s.id for s in scans_to_delete]
            print(f"Found {len(scans_to_delete)} scan(s) to delete:")
            for s in scans_to_delete:
                print(
                    f"  - ID: {s.id}, Type: {s.scan_type}, Status: {s.status}, Target: {s.target}"
                )

            # Nullify references in Asset table
            print("Nullifying scan references on assets...")
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

            # Delete findings tied to these scans
            print("Deleting findings for selected scans...")
            deleted_findings = await session.execute(
                delete(Finding).where(Finding.scan_id.in_(scan_ids))
            )
            print(f"Deleted {deleted_findings.rowcount or 0} finding(s).")

            # Delete algorithms tied to these scans
            print("Deleting algorithms for selected scans...")
            deleted_algos = await session.execute(
                delete(Algorithm).where(Algorithm.scan_id.in_(scan_ids))
            )
            print(f"Deleted {deleted_algos.rowcount or 0} algorithm(s).")

            # Delete logs
            print("Deleting scan logs...")
            deleted_logs = await session.execute(
                delete(ScanLog).where(ScanLog.scan_id.in_(scan_ids))
            )
            print(f"Deleted {deleted_logs.rowcount or 0} log(s).")

            # Delete the scans
            print("Deleting scans...")
            deleted_scans = await session.execute(
                delete(Scan).where(Scan.id.in_(scan_ids))
            )
            print(f"Deleted {deleted_scans.rowcount or 0} scan row(s).")
        else:
            print("No empty, failed, or cancelled scans found.")

        # --- PART 2: Fix correct status/classification for algorithms ---
        print("\nRetrieving all remaining algorithms for re-classification...")
        result = await session.execute(select(Algorithm))
        algorithms = result.scalars().all()
        print(f"Found {len(algorithms)} algorithm(s) in the database.")

        updated_count = 0
        for algo in algorithms:
            # Reclassify using our updated classify_algorithm logic
            classification = classify_algorithm(
                name=algo.algorithm_name,
                oid=algo.oid,
                algorithm_type=algo.algorithm_type,
            )

            detailed_status = classification.get("pqc_status", "unknown")
            is_qv = classification.get("is_quantum_vulnerable", False)

            old_status = algo.pqc_status
            old_qv = algo.is_quantum_vulnerable

            # This triggers validates decorator in models.py
            algo.pqc_status = detailed_status
            algo.is_quantum_vulnerable = is_qv

            if algo.pqc_status != old_status or algo.is_quantum_vulnerable != old_qv:
                print(f"  Updating algo {algo.algorithm_name} (OID: {algo.oid}):")
                print(
                    f"    pqc_status: {old_status} -> {algo.pqc_status} (detailed: {detailed_status})"
                )
                print(
                    f"    is_quantum_vulnerable: {old_qv} -> {algo.is_quantum_vulnerable}"
                )
                updated_count += 1

                # Also find and update corresponding findings for this asset & algorithm name
                findings_result = await session.execute(
                    select(Finding)
                    .options(selectinload(Finding.asset))
                    .where(
                        Finding.asset_id == algo.asset_id,
                        Finding.algorithm == algo.algorithm_name,
                    )
                )
                findings = findings_result.scalars().all()
                for finding in findings:
                    old_f_status = finding.pqc_status
                    finding.pqc_status = detailed_status

                    # Recalculate risk score
                    old_score = finding.risk_score
                    finding.risk_score = calculate_risk_score(
                        asset=finding.asset,
                        pqc_status=detailed_status,
                        algorithm=finding.algorithm,
                        key_size=(
                            finding.evidence.get("key_size")
                            if finding.evidence
                            else None
                        ),
                        finding_type=finding.finding_type,
                    )
                    print(f"      Finding '{finding.title}':")
                    print(f"        pqc_status: {old_f_status} -> {finding.pqc_status}")
                    print(f"        risk_score: {old_score} -> {finding.risk_score}")

        print(
            f"Re-classification completed. Updated {updated_count} algorithm record(s)."
        )

        print("Committing changes...")
        await session.commit()
        print("Database commit successful.")

        # Clear dashboard cache
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


if __name__ == "__main__":
    asyncio.run(run_fix())
