import csv
import io
import logging
from typing import Dict, Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError, DBAPIError
from app.connectors.base import BaseConnector
from app.models.models import Asset

logger = logging.getLogger(__name__)


class CSVCMDBConnector(BaseConnector):
    def __init__(self):
        super().__init__("CSV CMDB Connector")

    async def sync(self, csv_content: str, session: AsyncSession) -> Dict[str, Any]:
        """
        Parses a CSV string, updates/inserts assets into the DB, and commits.
        Returns a dict summary of imported, updated, and skipped rows.
        """
        reader = csv.DictReader(io.StringIO(csv_content))
        if not reader.fieldnames:
            return {"status": "error", "error": "CSV is empty or missing headers"}

        # Normalize fieldnames to lowercase/stripped
        reader.fieldnames = [f.strip().lower() for f in reader.fieldnames]

        valid_asset_types = {
            "server",
            "endpoint",
            "network_device",
            "load_balancer",
            "vpn_gateway",
            "database",
            "web_app",
            "api",
            "container",
            "kubernetes_cluster",
            "cloud_resource",
            "hsm",
            "kms",
            "certificate_authority",
            "smart_card",
            "firmware",
            "saas",
            "other",
        }
        valid_envs = {"production", "staging", "development", "testing", "unknown"}

        imported_count = 0
        updated_count = 0
        skipped_count = 0
        errors: list[str] = []
        seen_names_this_batch: set[str] = set()

        for index, row in enumerate(reader, start=1):
            raw_name = row.get("name")
            name = (raw_name or "").strip()
            if not name:
                skipped_count += 1
                errors.append(f"Row {index}: Missing 'name' field")
                continue

            name_lower = name.lower()
            if name_lower in seen_names_this_batch:
                skipped_count += 1
                errors.append(f"Row {index}: Duplicate name '{name}' in same file")
                continue
            seen_names_this_batch.add(name_lower)

            asset_type = (row.get("asset_type") or "other").strip().lower()
            if asset_type not in valid_asset_types:
                asset_type = "other"

            environment = (row.get("environment") or "unknown").strip().lower()
            if environment not in valid_envs:
                environment = "unknown"

            ip_address = row.get("ip_address")
            ip_address = ip_address.strip() if ip_address else None
            fqdn = row.get("fqdn")
            fqdn = fqdn.strip() if fqdn else None

            port_val = row.get("port")
            port = None
            if port_val:
                try:
                    port = int(port_val.strip())
                except ValueError:
                    pass

            protocol = row.get("protocol")
            protocol = protocol.strip() if protocol else None
            os_val = row.get("os")
            os_val = os_val.strip() if os_val else None
            business_service = row.get("business_service")
            business_service = business_service.strip() if business_service else None
            cmdb_ci_id = row.get("cmdb_ci_id")
            cmdb_ci_id = cmdb_ci_id.strip() if cmdb_ci_id else None

            try:
                stmt = select(Asset).where(
                    Asset.name == name, Asset.deleted_at.is_(None)
                )
                res = await session.execute(stmt)
                existing_asset = res.scalar_one_or_none()

                if existing_asset:
                    existing_asset.asset_type = asset_type
                    existing_asset.ip_address = ip_address
                    existing_asset.fqdn = fqdn
                    existing_asset.port = port
                    existing_asset.protocol = protocol
                    existing_asset.os = os_val
                    existing_asset.environment = environment
                    existing_asset.business_service = business_service
                    existing_asset.cmdb_ci_id = cmdb_ci_id
                    existing_asset.discovery_source = "csv_cmdb"
                    updated_count += 1
                else:
                    new_asset = Asset(
                        name=name,
                        asset_type=asset_type,
                        ip_address=ip_address,
                        fqdn=fqdn,
                        port=port,
                        protocol=protocol,
                        os=os_val,
                        environment=environment,
                        business_service=business_service,
                        cmdb_ci_id=cmdb_ci_id,
                        discovery_source="csv_cmdb",
                        asset_metadata={},
                    )
                    session.add(new_asset)
                    imported_count += 1
            except (IntegrityError, DBAPIError) as row_err:
                logger.warning(f"Row {index} DB error for '{name}': {row_err}")
                skipped_count += 1
                errors.append(f"Row {index}: Database error for '{name}' — {row_err}")
                # Roll back just this row's partial state; continue with next row
                await session.rollback()

        try:
            await session.commit()
        except (IntegrityError, DBAPIError) as commit_err:
            logger.exception("Final commit failed for CSV import")
            await session.rollback()
            return {
                "status": "error",
                "error": f"Database commit failed: {commit_err}",
                "imported": imported_count,
                "updated": updated_count,
                "skipped": skipped_count,
                "errors": errors,
            }

        return {
            "status": "success",
            "imported": imported_count,
            "updated": updated_count,
            "skipped": skipped_count,
            "errors": errors,
        }
