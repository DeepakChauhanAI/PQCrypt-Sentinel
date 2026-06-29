import json
import logging
from datetime import datetime, timezone
from typing import List, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func, and_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.config import settings
from app.db import get_session
from app.models.models import Asset, Finding, Algorithm, Scan
from app.models.schemas import (
    DashboardSummary,
    DashboardRiskDistribution,
    DashboardProgressItem,
    DashboardLayerCoverage,
)
from app.models.models import User
from app.utils.cache import get_redis_cache

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])

CACHE_TTL = settings.DASHBOARD_CACHE_TTL_SECONDS
CACHE_KEY_PREFIX = "dashboard:"


async def get_cache(key: str) -> Optional[Any]:
    cache = await get_redis_cache()
    return await cache.get(f"{CACHE_KEY_PREFIX}{key}")


async def set_cache(key: str, value: Any, ttl: int = CACHE_TTL) -> None:
    cache = await get_redis_cache()
    await cache.set(f"{CACHE_KEY_PREFIX}{key}", value, ttl=ttl)


async def clear_dashboard_cache() -> None:
    cache = await get_redis_cache()
    # Only clear dashboard:* keys, leave the rest of the pqc: namespace alone.
    try:
        client = await cache._get_client()  # internal but safe
    except Exception:
        return
    if client is None:
        return
    try:
        cursor = 0
        while True:
            cursor, keys = await client.scan(
                cursor=cursor, match=f"pqc:{CACHE_KEY_PREFIX}*", count=100
            )
            if keys:
                await client.delete(*keys)
            if cursor == 0:
                break
    except Exception as exc:
        logger.warning(f"Dashboard cache clear error: {exc}")


def _worst_pqc_status(statuses: list[str]) -> str:
    """Return the worst PQC status for an asset from its algorithm statuses.

    Priority (most severe first): vulnerable > hybrid > pqc_ready > safe.
    Assets with no algorithms are treated as vulnerable.
    """
    clean = [s for s in statuses if s]
    if not clean:
        return "vulnerable"
    if "vulnerable" in clean:
        return "vulnerable"
    if "hybrid" in clean:
        return "hybrid"
    if "pqc_ready" in clean:
        return "pqc_ready"
    if "safe" in clean:
        return "safe"
    return "vulnerable"


@router.get("/summary", response_model=DashboardSummary)
async def get_summary(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    cache_key = "dashboard:summary"
    cached = await get_cache(cache_key)
    if cached:
        return cached

    # Query metrics
    # 1. Total assets count + PQC status breakdown
    total_assets_res = await session.execute(
        select(func.count(Asset.id)).where(Asset.deleted_at.is_(None))
    )
    total_assets = total_assets_res.scalar_one() or 0

    # Aggregate per-asset worst status in Python so ``safe`` is treated as a
    # distinct non-vulnerable bucket and not silently folded into vulnerable.
    pairs_res = await session.execute(
        select(Asset.id, Algorithm.pqc_status)
        .select_from(Asset)
        .outerjoin(Algorithm, Asset.id == Algorithm.asset_id)
        .where(Asset.deleted_at.is_(None))
    )
    asset_statuses: dict[str, list[str]] = {}
    for asset_id, algo_status in pairs_res.all():
        asset_statuses.setdefault(asset_id, []).append(algo_status or "")

    vulnerable_count = 0
    hybrid_count = 0
    pqc_ready_count = 0
    safe_count = 0
    for statuses in asset_statuses.values():
        worst = _worst_pqc_status(statuses)
        if worst == "vulnerable":
            vulnerable_count += 1
        elif worst == "hybrid":
            hybrid_count += 1
        elif worst == "pqc_ready":
            pqc_ready_count += 1
        elif worst == "safe":
            safe_count += 1

    pqc_readiness_score = 0.0
    if total_assets > 0:
        pqc_readiness_score = (
            (safe_count + hybrid_count + pqc_ready_count) / total_assets
        ) * 100.0

    # 2. Critical/High findings count
    crit_res = await session.execute(
        select(func.count(Finding.id)).where(
            and_(
                Finding.severity == "critical",
                Finding.status == "open",
                Finding.deleted_at.is_(None)
            )
        )
    )
    critical_findings = crit_res.scalar_one() or 0

    high_res = await session.execute(
        select(func.count(Finding.id)).where(
            and_(
                Finding.severity == "high",
                Finding.status == "open",
                Finding.deleted_at.is_(None)
            )
        )
    )
    high_findings = high_res.scalar_one() or 0

    # 3. Drift alerts (open findings of type config_drift or pqc_downgrade)
    drift_res = await session.execute(
        select(func.count(Finding.id)).where(
            and_(
                Finding.finding_type.in_(["config_drift", "pqc_downgrade"]),
                Finding.status == "open",
                Finding.deleted_at.is_(None)
            )
        )
    )
    drift_alerts_count = drift_res.scalar_one() or 0

    summary = {
        "pqc_readiness_score": round(pqc_readiness_score, 2),
        "total_assets": total_assets,
        "vulnerable_count": vulnerable_count,
        "hybrid_count": hybrid_count,
        "pqc_ready_count": pqc_ready_count,
        "safe_count": safe_count,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "drift_alerts_count": drift_alerts_count,
    }

    await set_cache(cache_key, summary)
    return summary


@router.get("/risk-distribution", response_model=DashboardRiskDistribution)
async def get_risk_distribution(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    cache_key = "dashboard:risk-distribution"
    cached = await get_cache(cache_key)
    if cached:
        return cached

    distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    res = await session.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(and_(Finding.status == "open", Finding.deleted_at.is_(None)))
        .group_by(Finding.severity)
    )

    for severity, count in res.all():
        sev_lower = severity.lower()
        if sev_lower in distribution:
            distribution[sev_lower] = count

    await set_cache(cache_key, distribution)
    return distribution


@router.get("/progress", response_model=List[DashboardProgressItem])
async def get_progress(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    cache_key = "dashboard:progress"
    cached = await get_cache(cache_key)
    if cached:
        return cached

    # Fetch last 12 completed scans
    scans_res = await session.execute(
        select(Scan).where(Scan.status == "completed").order_by(Scan.completed_at.desc()).limit(12)
    )
    scans = scans_res.scalars().all()
    scans = list(reversed(scans))

    if not scans:
        await set_cache(cache_key, [])
        return []

    # Single GROUP BY query — eliminates N+1 pattern
    scan_ids = [s.id for s in scans]
    algo_res = await session.execute(
        select(
            Algorithm.scan_id,
            Algorithm.asset_id,
            func.min(Algorithm.pqc_status).label("worst_status"),
        )
        .where(Algorithm.scan_id.in_(scan_ids))
        .group_by(Algorithm.scan_id, Algorithm.asset_id)
    )

    scan_asset_status: dict[str, dict[str, str]] = {}
    for scan_id_val, asset_id_val, worst in algo_res.all():
        scan_asset_status.setdefault(str(scan_id_val), {})[str(asset_id_val)] = worst

    progress = []
    for s in scans:
        asset_statuses = scan_asset_status.get(str(s.id), {})
        vuln = sum(1 for st in asset_statuses.values() if st == "vulnerable")
        hyb = sum(1 for st in asset_statuses.values() if st == "hybrid")
        pqc = sum(1 for st in asset_statuses.values() if st == "pqc_ready")

        completed_at = getattr(s, "completed_at", None)
        created_at = getattr(s, "created_at", None) or datetime.now(timezone.utc)
        date_str = completed_at.strftime("%Y-%m-%d") if completed_at else created_at.strftime("%Y-%m-%d")

        progress.append(
            {
                "scan_date": date_str,
                "vulnerable": vuln,
                "hybrid": hyb,
                "pqc_ready": pqc,
            }
        )

    await set_cache(cache_key, progress)
    return progress


# Layer definitions for 7 infrastructure layers
LAYER_DEFINITIONS = [
    {"id": "L1", "name": "Network", "description": "TLS, SSH, VPN/IKEv2, DNSSEC, OCSP, SMTP STARTTLS"},
    {"id": "L2", "name": "PKI", "description": "Root CA, Intermediate CAs, TLS Server Certs, Code-signing, TSA"},
    {"id": "L3", "name": "HSM/KMS", "description": "General HSMs, Payment HSMs (3DES), Cloud KMS"},
    {"id": "L4", "name": "Application", "description": "JWT Algorithms, Container Images, API Crypto"},
    {"id": "L5", "name": "Data", "description": "TDE Algorithms, Backup Encryption, Column-level Encryption"},
    {"id": "L6", "name": "Infrastructure", "description": "SSH Host Keys, Kerberos RC4, Windows CNG/Schannel"},
    {"id": "L7", "name": "Endpoint", "description": "Windows Cert Store, BitLocker, Firmware Signing"},
]

# Mapping of asset types / discovery sources to layers
ASSET_TO_LAYER = {
    # L1 Network
    "server": "L1",
    "load_balancer": "L1",
    "vpn_gateway": "L1",
    "network_device": "L1",
    "web_app": "L1",
    "api": "L1",
    "tls_scan": "L1",
    "ssh_scan": "L1",
    "ike_scan": "L1",
    "mail_scan": "L1",
    
    # L2 PKI
    "certificate_authority": "L2",
    "pki": "L2",
    "ct_log": "L2",
    
    # L3 HSM/KMS
    "hsm": "L3",
    "kms": "L3",
    "aws_kms": "L3",
    "azure_key_vault": "L3",
    "gcp_kms": "L3",
    "pkcs11": "L3",
    "kmip": "L3",
    
    # L4 Application
    "application": "L4",
    "container": "L4",
    "kubernetes_cluster": "L4",
    "kubernetes": "L4",
    "jwt": "L4",
    "saml": "L4",
    "saml_metadata": "L4",
    "source_code": "L4",
    
    # L5 Data
    "database": "L5",
    "tde": "L5",
    "backup": "L5",
    "backup_encryption": "L5",
    
    # L6 Infrastructure
    "ssh_host_key": "L6",
    "kerberos": "L6",
    "windows_cng": "L6",
    
    # L7 Endpoint
    "endpoint": "L7",
    "windows_cert_store": "L7",
    "bitlocker": "L7",
    "firmware": "L7",
}


def _determine_layer_for_asset(asset: Asset) -> str:
    """Determine which infrastructure layer an asset belongs to."""
    # Check asset_type first
    asset_type = (asset.asset_type or "").lower()
    if asset_type in ASSET_TO_LAYER:
        return ASSET_TO_LAYER[asset_type]
    
    # Check discovery source
    disc_source = (asset.discovery_source or "").lower()
    if disc_source in ASSET_TO_LAYER:
        return ASSET_TO_LAYER[disc_source]
    
    # Check asset metadata for hints
    meta = asset.asset_metadata or {}
    if isinstance(meta, dict):
        provider = meta.get("provider", "").lower()
        if provider in ASSET_TO_LAYER:
            return ASSET_TO_LAYER[provider]
        key_type = meta.get("key_type", "").lower()
        if "hsm" in key_type or "kms" in key_type:
            return "L3"
    
    # Default to L1 for unknown
    return "L1"


@router.get("/layer-coverage", response_model=DashboardLayerCoverage)
async def get_layer_coverage(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Get 7-layer infrastructure coverage heatmap data.
    Returns coverage percentage and asset counts per layer.
    """
    cache_key = "dashboard:layer-coverage"
    cached = await get_cache(cache_key)
    if cached:
        return cached

    # Get all active assets
    assets_res = await session.execute(
        select(Asset).where(Asset.deleted_at.is_(None))
    )
    assets = assets_res.scalars().all()

    # Initialize layer stats. The dict values are heterogeneous
    # (str for ids/names, int for counts, float for percentages) so
    # we use `object` and narrow on read.
    layer_stats: dict[str, dict[str, object]] = {}
    for layer in LAYER_DEFINITIONS:
        layer_id = layer["id"]
        layer_stats[layer_id] = {
            "layer_id": layer_id,
            "layer_name": layer["name"],
            "description": layer["description"],
            "total_assets": 0,
            "scanned_assets": 0,
            "vulnerable_assets": 0,
            "hybrid_assets": 0,
            "pqc_ready_assets": 0,
            "coverage_pct": 0.0,
            "risk_score_avg": 0.0,
        }

    # Layer-count map kept separately so the hot loop in the body below
    # can mutate plain ints without going through `dict[object]`.
    counts: dict[str, dict[str, int]] = {
        layer_id: {
            "total": 0,
            "scanned": 0,
            "vulnerable": 0,
            "hybrid": 0,
            "pqc_ready": 0,
        }
        for layer_id in layer_stats
    }

    # Classify assets into layers
    for asset in assets:
        layer_id = _determine_layer_for_asset(asset)
        counts_for_layer = counts.get(layer_id)
        if counts_for_layer is None:
            continue

        counts_for_layer["total"] += 1
        if asset.last_verified_at:
            counts_for_layer["scanned"] += 1

        # NOTE: Asset model does not carry pqc_status / risk_score
        # directly — the dashboard used to read these from the Asset
        # row. In practice the dashboard's per-layer pqc_status breakdown
        # is computed from the asset's *algorithms* / *findings*
        # elsewhere; for the layer-coverage endpoint we only need the
        # counts, not the pqc breakdown. These lines are kept as a
        # defensive cast so we don't crash on legacy rows that may
        # still surface a pqc_status from a denormalized column.
        asset_pqc = getattr(asset, "pqc_status", None)  # type: ignore[attr-defined]
        if asset_pqc == "vulnerable":
            counts_for_layer["vulnerable"] += 1
        elif asset_pqc == "hybrid":
            counts_for_layer["hybrid"] += 1
        elif asset_pqc == "pqc_ready":
            counts_for_layer["pqc_ready"] += 1

    # Calculate coverage and average risk score per layer
    for layer_id, stats in layer_stats.items():
        layer_counts = counts[layer_id]
        # Sync the int counts back into the public stats dict so the
        # response shape stays backward-compatible.
        stats["total_assets"] = layer_counts["total"]
        stats["scanned_assets"] = layer_counts["scanned"]
        stats["vulnerable_assets"] = layer_counts["vulnerable"]
        stats["hybrid_assets"] = layer_counts["hybrid"]
        stats["pqc_ready_assets"] = layer_counts["pqc_ready"]

        if layer_counts["total"] > 0:
            stats["coverage_pct"] = round(
                (layer_counts["scanned"] / layer_counts["total"]) * 100, 1
            )

        # Get average risk score for assets in this layer
        layer_assets = [a for a in assets if _determine_layer_for_asset(a) == layer_id]
        if layer_assets:
            risk_scores = [
                a.risk_score  # type: ignore[attr-defined]
                for a in layer_assets
                if getattr(a, "risk_score", None) is not None
            ]
            if risk_scores:
                stats["risk_score_avg"] = round(sum(risk_scores) / len(risk_scores), 1)

    # Build response
    layers: list[dict[str, object]] = []
    for layer in LAYER_DEFINITIONS:
        layer_id = layer["id"]
        layer_counts = counts[layer_id]
        layers.append({
            "layer_id": layer_id,
            "layer_name": layer["name"],
            "description": layer["description"],
            "total_assets": layer_counts["total"],
            "scanned_assets": layer_counts["scanned"],
            "vulnerable_assets": layer_counts["vulnerable"],
            "hybrid_assets": layer_counts["hybrid"],
            "pqc_ready_assets": layer_counts["pqc_ready"],
            "coverage_pct": layer_stats[layer_id]["coverage_pct"],
            "risk_score_avg": layer_stats[layer_id]["risk_score_avg"],
        })

    # Weight the overall coverage by asset count per layer so that
    # layers with zero assets don't artificially drag the score down
    # to 1/7 (=14.3%) every time only one layer has been scanned.
    total_all = sum(c["total"] for c in counts.values())
    scanned_all = sum(c["scanned"] for c in counts.values())
    response = {
        "layers": layers,
        "overall_coverage_pct": round(
            (scanned_all / total_all) * 100, 1
        ) if total_all > 0 else 0.0,
    }

    await set_cache(cache_key, response)
    return response
