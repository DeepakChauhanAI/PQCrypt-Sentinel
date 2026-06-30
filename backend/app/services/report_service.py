# mypy: ignore-errors
import csv
import io
import os
import logging
import json
import asyncio
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any, Optional
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from cyclonedx.model.bom import Bom, Tool, Property
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot7

from app.models.models import Asset, Algorithm, Finding, Report

logger = logging.getLogger(__name__)


# CycloneDX 1.7 ECMA-424 canonical field order for cryptoProperties.
# Properties not in this list (e.g. pqcSafe and pqc:* custom fields) are
# appended in alphabetical order after the standard fields.
_CRYPTO_PROPERTIES_ORDER = (
    "assetType",
    "algorithmProperties",
    "certificateProperties",
    "relatedCryptoMaterialProperties",
    "protocolProperties",
    "oid",
    "executionEnvironment",
    "implementationPlatform",
    "cryptoRefArray",
)


def _ecma424_order_recursive(obj: Any, key_order: tuple[str, ...]) -> Any:
    """Recursively reorder dict keys per ECMA-424 canonical ordering."""
    if isinstance(obj, dict):
        ordered = {}
        # Known keys first, in spec order
        for key in key_order:
            if key in obj:
                ordered[key] = _ecma424_order_recursive(obj[key], key_order)
        # Remaining keys in lexicographic order
        for key in sorted(obj.keys()):
            if key not in ordered:
                ordered[key] = _ecma424_order_recursive(obj[key], key_order)
        return ordered
    elif isinstance(obj, list):
        return [_ecma424_order_recursive(item, key_order) for item in obj]
    return obj


_CYCLONEDX_ASSET_TYPE_MAP = {
    "key_exchange": "protocol",
    "signature": "algorithm",
    "symmetric": "algorithm",
    "hash": "algorithm",
    "mac": "algorithm",
    "kem": "algorithm",
    "certificate": "certificate",
    "tls": "protocol",
    "ssh": "protocol",
    "ike": "protocol",
}


def _reorder_crypto_properties(data: dict) -> None:
    """
    Re-order the `cryptoProperties` dict on every component so that
    standard CycloneDX 1.7 fields appear in the ECMA-424 mandated order
    and custom (pqc:*) fields follow alphabetically.

    Mutates `data` in place; the function returns nothing.
    """

    def visit(obj: Any):
        if isinstance(obj, dict):
            if "cryptoProperties" in obj and isinstance(obj["cryptoProperties"], dict):
                cp = obj["cryptoProperties"]
                ordered_cp = {}
                for key in _CRYPTO_PROPERTIES_ORDER:
                    if key in cp:
                        ordered_cp[key] = cp[key]
                for key in sorted(cp.keys()):
                    if key not in ordered_cp:
                        ordered_cp[key] = cp[key]
                obj["cryptoProperties"] = ordered_cp
            for val in obj.values():
                visit(val)
        elif isinstance(obj, list):
            for item in obj:
                visit(item)

    visit(data)


def post_process_cbom(json_str: str, assets_map: dict) -> str:
    """
    Post-process the generated JSON string to:
    1. Set specVersion = "1.7".
    2. Add key records (relatedCryptoMaterialType, state, size, algorithmRef, creationDate, expirationDate, secured, format).
    3. Add certificate records with algorithmRef, subjectPublicKeyRef, certificateFormat.
    4. Add protocol records (name, version, cipherSuites, cryptoRefArray, relatedTo).
    5. Add dependency relationships: provides, uses, implements, ancestorOf, descendantOf.
    6. Inject pqcSafe, primitive, variant, nistQuantumSecurityLevel on cryptoProperties.
    """
    try:
        data = json.loads(json_str)
    except Exception as e:
        logger.error(f"Failed to parse CBOM JSON for post-processing: {e}")
        return json_str

    data["specVersion"] = "1.7"

    # Build maps for cross-references
    algo_by_name = {}
    cert_by_id = {}
    key_by_cert = {}

    for comp in data.get("components", []):
        ref = comp.get("bom-ref", "")
        if ref.startswith("algo-"):
            algo_by_name[ref] = comp
        elif ref.startswith("cert-"):
            cert_by_id[ref] = comp

    # Process each component
    for comp in data.get("components", []):
        ref = comp.get("bom-ref", "")

        # Certificate component
        if ref.startswith("cert-"):
            cert_id = ref.split("cert-", 1)[1]
            cert_obj = assets_map.get(f"cert-{cert_id}")
            if cert_obj:
                crypto_props = comp.setdefault("cryptoProperties", {})
                crypto_props["assetType"] = "certificate"

                pqc_capable = getattr(cert_obj, "pqc_capable", False)
                sig_algo = getattr(cert_obj, "sig_algorithm", "").lower()
                pub_algo = getattr(cert_obj, "pub_key_algorithm", "").lower()

                if pqc_capable:
                    pqc_status = "pqc_ready"
                else:
                    pqc_status = "vulnerable"

                pqc_safe = pqc_status in ["pqc_ready", "safe"]

                primitive = "signature"
                variant = "ess"
                key_size = getattr(cert_obj, "pub_key_size", 0) or 0
                curve = (getattr(cert_obj, "curve_name", "") or "").lower()
                if "rsa" in sig_algo:
                    if "pss" in sig_algo:
                        variant = f"RSA-PSS-{key_size}" if key_size else "RSA-PSS"
                    else:
                        variant = (
                            f"RSASSA-PKCS1-v1_5-{key_size}"
                            if key_size
                            else "RSASSA-PKCS1-v1_5"
                        )
                elif "ecdsa" in sig_algo or "ec" in pub_algo:
                    if curve.startswith("secp521") or key_size >= 521:
                        variant = "ECDSA-P521"
                    elif curve.startswith("secp384") or key_size >= 384:
                        variant = "ECDSA-P384"
                    elif (
                        curve.startswith("secp256")
                        or curve == "prime256v1"
                        or key_size >= 256
                    ):
                        variant = "ECDSA-P256"
                    else:
                        variant = f"ECDSA-{key_size}" if key_size else "ECDSA"
                elif "ed25519" in sig_algo:
                    variant = "Ed25519"
                elif "ed448" in sig_algo:
                    variant = "Ed448"

                nist_level = 0
                if pqc_capable:
                    nist_level = 3

                # Determine classical security level (bits)
                classical_sec_level = 0
                if "rsa" in sig_algo:
                    key_size = getattr(cert_obj, "pub_key_size", 0) or 0
                    if key_size >= 15360:
                        classical_sec_level = 256
                    elif key_size >= 7680:
                        classical_sec_level = 192
                    elif key_size >= 3072:
                        classical_sec_level = 128
                    elif key_size >= 2048:
                        classical_sec_level = 112
                    elif key_size >= 1024:
                        classical_sec_level = 80
                elif "ecdsa" in sig_algo or "ec" in pub_algo:
                    key_size = getattr(cert_obj, "pub_key_size", 0) or 0
                    if key_size >= 521:
                        classical_sec_level = 256
                    elif key_size >= 384:
                        classical_sec_level = 192
                    elif key_size >= 256:
                        classical_sec_level = 128
                    elif key_size >= 224:
                        classical_sec_level = 112
                elif "ed25519" in sig_algo or "ed448" in sig_algo:
                    classical_sec_level = 128

                # Determine certification level
                cert_level = "none"
                if pqc_capable:
                    cert_level = "FIPS 203/204/205"
                elif getattr(cert_obj, "is_ca", False):
                    cert_level = "CA/Browser Forum"

                algo_props = crypto_props.setdefault("algorithmProperties", {})
                algo_props["primitive"] = primitive
                algo_props["variant"] = variant
                algo_props["nistQuantumSecurityLevel"] = nist_level
                algo_props["classicalSecurityLevel"] = classical_sec_level
                algo_props["certificationLevel"] = cert_level
                algo_props["parameterSetIdentifier"] = variant

                # Add OID if available
                oid = getattr(cert_obj, "sig_algorithm_oid", None)
                if oid:
                    algo_props["oid"] = oid

                # Add execution environment and implementation platform
                crypto_props["executionEnvironment"] = "software"
                crypto_props["implementationPlatform"] = "x86_64/OS"

                # Add key reference for certificate
                key_ref = f"key-{cert_id}"
                algo_props["relatedCryptoMaterial"] = [
                    {"ref": key_ref, "relationship": "subjectPublicKeyRef"}
                ]

                cert_props = crypto_props.setdefault("certificateProperties", {})
                cert_props["subjectName"] = getattr(cert_obj, "subject", "")
                cert_props["issuerName"] = getattr(cert_obj, "issuer", "")
                cert_props["serialNumber"] = getattr(cert_obj, "serial_number", "")
                cert_props["certificateFormat"] = "PEM"
                if getattr(cert_obj, "not_before", None):
                    cert_props["notBefore"] = cert_obj.not_before.isoformat()
                if getattr(cert_obj, "not_after", None):
                    cert_props["notAfter"] = cert_obj.not_after.isoformat()

                crypto_props["pqcSafe"] = pqc_safe

        # Algorithm component
        elif ref.startswith("algo-"):
            algo_id = ref.split("algo-", 1)[1]
            algo_obj = assets_map.get(f"algo-{algo_id}")
            if algo_obj:
                crypto_props = comp.setdefault("cryptoProperties", {})
                algo_type = getattr(algo_obj, "algorithm_type", "").lower()
                crypto_props["assetType"] = _CYCLONEDX_ASSET_TYPE_MAP.get(
                    algo_type, "algorithm"
                )

                pqc_status = getattr(algo_obj, "pqc_status", "vulnerable")
                pqc_safe = pqc_status in ["pqc_ready", "safe"]

                algo_type = getattr(algo_obj, "algorithm_type", "").lower()
                primitive = "signature"
                if "exchange" in algo_type or "kem" in algo_type:
                    primitive = "kem"
                elif "symmetric" in algo_type:
                    primitive = "symmetric"
                elif "hash" in algo_type:
                    primitive = "hash"
                elif "mac" in algo_type:
                    primitive = "mac"

                name = getattr(algo_obj, "algorithm_name", "").lower()
                variant = name

                nist_level = 0
                if pqc_safe:
                    if "1024" in name or "87" in name or "5" in name:
                        nist_level = 5
                    elif "768" in name or "65" in name or "3" in name:
                        nist_level = 3
                    else:
                        nist_level = 1

                # Determine classical security level
                classical_sec_level = 0
                key_size = getattr(algo_obj, "key_size", 0) or 0
                if "rsa" in name:
                    if key_size >= 15360:
                        classical_sec_level = 256
                    elif key_size >= 7680:
                        classical_sec_level = 192
                    elif key_size >= 3072:
                        classical_sec_level = 128
                    elif key_size >= 2048:
                        classical_sec_level = 112
                    elif key_size >= 1024:
                        classical_sec_level = 80
                elif "ec" in name or "ecdsa" in name or "ecdh" in name:
                    if key_size >= 521:
                        classical_sec_level = 256
                    elif key_size >= 384:
                        classical_sec_level = 192
                    elif key_size >= 256:
                        classical_sec_level = 128
                    elif key_size >= 224:
                        classical_sec_level = 112
                elif "ed25519" in name or "ed448" in name:
                    classical_sec_level = 128

                # Determine certification level
                cert_level = "none"
                if pqc_safe:
                    cert_level = "FIPS 203/204/205"

                # Determine execution environment
                exec_env = "software"
                if "hsm" in name or "kms" in name:
                    exec_env = "hardware"

                algo_props = crypto_props.setdefault("algorithmProperties", {})
                algo_props["primitive"] = primitive
                algo_props["variant"] = variant
                algo_props["nistQuantumSecurityLevel"] = nist_level
                algo_props["classicalSecurityLevel"] = classical_sec_level
                algo_props["certificationLevel"] = cert_level
                algo_props["parameterSetIdentifier"] = variant

                if getattr(algo_obj, "curve", None):
                    algo_props["curve"] = algo_obj.curve
                if getattr(algo_obj, "key_size", None):
                    algo_props["keyLength"] = algo_obj.key_size
                if getattr(algo_obj, "oid", None):
                    algo_props["oid"] = algo_obj.oid

                # Add execution environment and implementation platform
                crypto_props["executionEnvironment"] = exec_env
                crypto_props["implementationPlatform"] = "x86_64/OS"

                # Add parameter set identifier
                algo_props["parameterSetIdentifier"] = variant

                crypto_props["pqcSafe"] = pqc_safe

    # Add key components for each certificate
    for ref, cert_comp in cert_by_id.items():
        cert_id = ref.split("cert-", 1)[1]
        cert_obj = assets_map.get(f"cert-{cert_id}")
        if not cert_obj:
            continue

        key_ref = f"key-{cert_id}"
        # Check if key already exists
        if not any(c.get("bom-ref") == key_ref for c in data.get("components", [])):
            key_comp = {
                "bom-ref": key_ref,
                "type": "cryptographicAsset",
                "name": f"Public Key {cert_obj.thumbprint[:8]}",
                "cryptoProperties": {
                    "assetType": "related-crypto-material",
                    "relatedCryptoMaterialType": "publicKey",
                    "state": "active",
                    "size": cert_obj.pub_key_size,
                    "algorithmRef": f"algo-{cert_id}",
                    "creationDate": (
                        cert_obj.not_before.isoformat()
                        if getattr(cert_obj, "not_before", None)
                        else datetime.now(timezone.utc).isoformat()
                    ),
                    "expirationDate": (
                        cert_obj.not_after.isoformat()
                        if getattr(cert_obj, "not_after", None)
                        else ""
                    ),
                    "secured": True,
                    "format": "raw",
                },
            }
            data.setdefault("components", []).append(key_comp)
            key_by_cert[cert_id] = key_ref

    # Add protocol components for TLS findings
    protocol_refs = []
    for ref, cert_comp in cert_by_id.items():
        cert_id = ref.split("cert-", 1)[1]
        cert_obj = assets_map.get(f"cert-{cert_id}")
        if not cert_obj:
            continue

        proto_ref = f"protocol-{cert_id}"
        if not any(c.get("bom-ref") == proto_ref for c in data.get("components", [])):
            try:
                if (
                    cert_obj
                    and getattr(cert_obj, "temp_asset_metadata", None) is not None
                ):
                    meta = cert_obj.temp_asset_metadata
                elif cert_obj and getattr(cert_obj, "asset", None):
                    meta = cert_obj.asset.asset_metadata or {}
                elif cert_obj and getattr(cert_obj, "asset_metadata", None):
                    meta = cert_obj.asset_metadata or {}
                else:
                    meta = {}
            except Exception:
                meta = {}
            tls_version = (meta.get("tls_version") or "").strip() or "unknown"
            cipher = (meta.get("cipher_suite") or "").strip()
            cipher_suites = [cipher] if cipher else []
            asset_kind = (meta.get("asset_type") or "").strip()
            variant = asset_kind or None
            crypto_props = {
                "assetType": "protocol",
                "name": "TLS",
                "version": tls_version,
                "cipherSuites": cipher_suites,
                "cryptoRefArray": [f"algo-{cert_id}", key_by_cert.get(cert_id, "")],
                "relatedTo": ref,
            }
            if variant:
                crypto_props["variant"] = variant
            proto_comp = {
                "bom-ref": proto_ref,
                "type": "cryptographicAsset",
                "name": "TLS Connection",
                "cryptoProperties": crypto_props,
            }
            data.setdefault("components", []).append(proto_comp)
            protocol_refs.append(proto_ref)

    # Update dependencies with proper types (CycloneDX 1.7 ECMA-424 vocabulary)
    # Valid dependencyType values: unknown, required, optional, provided
    new_dependencies = []
    for dep in data.get("dependencies", []):
        new_depends_on = []
        for child in dep.get("dependsOn", []):
            if isinstance(child, str):
                dep_type = "required"
                provides = ["cryptographic-asset"]
                if child.startswith("cert-"):
                    dep_type = "provided"
                    provides = ["certificate"]
                elif child.startswith("algo-"):
                    dep_type = "required"
                    provides = ["algorithm"]
                elif child.startswith("key-"):
                    dep_type = "provided"
                    provides = ["keyMaterial"]
                elif child.startswith("protocol-"):
                    dep_type = "required"
                    provides = ["protocol"]

                new_depends_on.append(
                    {"ref": child, "provides": provides, "dependencyType": dep_type}
                )
            else:
                new_depends_on.append(child)
        dep["dependsOn"] = new_depends_on
        new_dependencies.append(dep)

    data["dependencies"] = new_dependencies
    _reorder_crypto_properties(data)
    return json.dumps(data, indent=2)


async def generate_cbom(session: AsyncSession, report_id: str) -> str:
    """
    Generate CycloneDX 1.7 JSON CBOM report for the specified report ID.
    Uses a two-pass approach with post-processing for ECMA-424 compliance.
    """
    stmt = select(Report).where(Report.id == report_id)
    result = await session.execute(stmt)
    report = result.scalar_one_or_none()
    if not report:
        raise ValueError(f"Report {report_id} not found")

    report.status = "generating"
    await session.commit()
    await session.refresh(report)

    scope_filters = report.scope_filters or {}

    base_dir = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    reports_dir = os.path.join(base_dir, "static", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    file_path = os.path.join(reports_dir, f"cbom_{report_id}.json")

    try:
        bom = Bom()
        bom.metadata.tools.tools.add(Tool(name="PQCrypt Sentinel", version="1.0"))

        pending_dependencies: List[Tuple[Component, List[Component]]] = []
        assets_map: Dict[str, Any] = {}

        batch_size = 100
        offset = 0

        while True:
            asset_stmt = select(Asset).where(Asset.deleted_at.is_(None))

            if scope_filters.get("environment"):
                asset_stmt = asset_stmt.where(
                    Asset.environment == scope_filters["environment"]
                )
            if scope_filters.get("business_service"):
                asset_stmt = asset_stmt.where(
                    Asset.business_service == scope_filters["business_service"]
                )
            if scope_filters.get("owner_id"):
                asset_stmt = asset_stmt.where(
                    Asset.owner_id == scope_filters["owner_id"]
                )

            asset_stmt = (
                asset_stmt.options(
                    selectinload(Asset.certificates),
                    selectinload(Asset.algorithms),
                )
                .limit(batch_size)
                .offset(offset)
            )

            asset_res = await session.execute(asset_stmt)
            assets = asset_res.scalars().all()

            if not assets:
                break

            for asset in assets:
                asset_comp = Component(
                    name=asset.name,
                    type=ComponentType.APPLICATION,
                    bom_ref=f"asset-{asset.id}",
                )
                asset_comp.properties.add(
                    Property(name="pqc:asset_type", value=asset.asset_type)
                )
                asset_comp.properties.add(
                    Property(name="pqc:environment", value=asset.environment)
                )
                asset_comp.properties.add(
                    Property(name="pqc:ip_address", value=asset.ip_address or "")
                )
                asset_comp.properties.add(
                    Property(name="pqc:fqdn", value=asset.fqdn or "")
                )
                bom.components.add(asset_comp)

                cert_deps: List[Component] = []
                for cert in asset.certificates:
                    cert_comp = Component(
                        name=f"Certificate {cert.thumbprint[:8]}",
                        type=ComponentType.CRYPTOGRAPHIC_ASSET,
                        bom_ref=f"cert-{cert.id}",
                    )
                    cert_comp.properties.add(
                        Property(name="pqc:algorithm", value=cert.sig_algorithm)
                    )
                    cert_comp.properties.add(
                        Property(
                            name="pqc:key_size", value=str(cert.pub_key_size or "")
                        )
                    )
                    cert_comp.properties.add(
                        Property(
                            name="pqc:pqc_status",
                            value="pqc_ready" if cert.pqc_capable else "vulnerable",
                        )
                    )
                    cert_comp.properties.add(
                        Property(
                            name="pqc:not_after",
                            value=cert.not_after.isoformat() if cert.not_after else "",
                        )
                    )
                    bom.components.add(cert_comp)
                    cert_deps.append(cert_comp)
                    setattr(
                        cert,
                        "temp_asset_metadata",
                        getattr(asset, "asset_metadata", None),
                    )
                    assets_map[f"cert-{cert.id}"] = cert

                algo_deps: List[Component] = []
                for algo in asset.algorithms:
                    algo_comp = Component(
                        name=f"Algorithm {algo.algorithm_name}",
                        type=ComponentType.CRYPTOGRAPHIC_ASSET,
                        bom_ref=f"algo-{algo.id}",
                    )
                    algo_comp.properties.add(
                        Property(name="pqc:algorithm_name", value=algo.algorithm_name)
                    )
                    algo_comp.properties.add(
                        Property(name="pqc:algorithm_type", value=algo.algorithm_type)
                    )
                    algo_comp.properties.add(
                        Property(name="pqc:pqc_status", value=algo.pqc_status)
                    )
                    bom.components.add(algo_comp)
                    algo_deps.append(algo_comp)
                    assets_map[f"algo-{algo.id}"] = algo

                if cert_deps:
                    pending_dependencies.append((asset_comp, cert_deps))
                if algo_deps:
                    pending_dependencies.append((asset_comp, algo_deps))

            offset += batch_size
            session.expunge_all()

        for dependant, deps in pending_dependencies:
            bom.register_dependency(dependant, deps)

        output_json = JsonV1Dot7(bom).output_as_string()
        output_json = post_process_cbom(output_json, assets_map)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(output_json)

        report_stmt = select(Report).where(Report.id == report_id)
        report_res = await session.execute(report_stmt)
        report = report_res.scalar_one()

        report.status = "ready"
        report.file_path = file_path
        report.updated_at = datetime.now(timezone.utc)
        await session.commit()

        logger.info(f"CBOM report {report_id} generated successfully at {file_path}")
        return file_path

    except Exception as e:
        logger.exception(f"Failed to generate CBOM report {report_id}")

        report_stmt = select(Report).where(Report.id == report_id)
        report_res = await session.execute(report_stmt)
        report = report_res.scalar_one_or_none()
        if report:
            report.status = "failed"
            report.error_message = str(e)
            report.updated_at = datetime.now(timezone.utc)
            await session.commit()

        raise e


def generate_sarif_for_sast_findings(
    scan_id: str,
    semgrep_results: Optional[Dict[str, Any]] = None,
    trivy_results: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generate SARIF 2.1.0 output for SAST findings from Semgrep and Trivy.
    """
    sarif: Dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PQCrypt Sentinel SAST",
                        "version": "1.0",
                        "informationUri": "https://github.com/pqcrypt/sentinel",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    rule_map: Dict[str, int] = {}
    rule_index = 0

    def add_rule(rule_id: str, name: str, description: str, severity: str) -> int:
        nonlocal rule_index
        if rule_id not in rule_map:
            rule_map[rule_id] = rule_index
            sarif["runs"][0]["tool"]["driver"]["rules"].append(
                {
                    "id": rule_id,
                    "name": name,
                    "shortDescription": {"text": description},
                    "fullDescription": {"text": description},
                    "defaultConfiguration": {"level": severity.lower()},
                }
            )
            rule_index += 1
        return rule_map[rule_id]

    # Process Semgrep findings
    if semgrep_results and semgrep_results.get("success"):
        findings = semgrep_results.get("findings", [])
        for finding in findings:
            rule_id = finding.get("rule", "semgrep-unknown")
            file_path = finding.get("file", "")
            line = finding.get("line", 1)
            message = finding.get("message", "")
            severity = finding.get("severity", "warning")

            rule_idx = add_rule(
                rule_id=rule_id,
                name=f"Semgrep: {rule_id}",
                description=message or "Semgrep crypto finding",
                severity=severity,
            )

            sarif["runs"][0]["results"].append(
                {
                    "ruleId": rule_id,
                    "ruleIndex": rule_idx,
                    "level": severity.lower(),
                    "message": {"text": message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": file_path},
                                "region": {"startLine": line},
                            }
                        }
                    ],
                }
            )

    # Process Trivy findings
    if trivy_results and trivy_results.get("success"):
        findings = trivy_results.get("findings", [])
        for finding in findings:
            if not isinstance(finding, dict):
                continue

            # Extract relevant info from Trivy result
            target = finding.get("Target", "unknown")
            vuln_id = finding.get("VulnerabilityID", "trivy-unknown")
            pkg_name = finding.get("PkgName", "")
            installed_version = finding.get("InstalledVersion", "")
            fixed_version = finding.get("FixedVersion", "")
            severity = finding.get("Severity", "UNKNOWN")
            title = finding.get("Title", "")

            rule_id = f"trivy-{vuln_id}"
            file_path = target
            message = (
                f"{pkg_name} {installed_version} -> {fixed_version}: {title}"
                if pkg_name
                else vuln_id
            )

            severity_map = {
                "CRITICAL": "error",
                "HIGH": "error",
                "MEDIUM": "warning",
                "LOW": "note",
                "UNKNOWN": "note",
            }
            sarif_severity = severity_map.get(severity.upper(), "note")

            rule_idx = add_rule(
                rule_id=rule_id,
                name=f"Trivy: {vuln_id}",
                description=message,
                severity=sarif_severity,
            )

            sarif["runs"][0]["results"].append(
                {
                    "ruleId": rule_id,
                    "ruleIndex": rule_idx,
                    "level": sarif_severity,
                    "message": {"text": message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": file_path},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            )

    return sarif


async def generate_sarif_report(
    session: AsyncSession,
    report_id: str,
    scan_ids: List[str],
) -> str:
    """
    Generate SARIF report for SAST findings across multiple scans.
    Queries the database for findings with finding_type 'code_weak_crypto' or
    'sbom_vulnerable_lib' within the given scan_ids and converts them to SARIF.
    """
    base_dir = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    reports_dir = os.path.join(base_dir, "static", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    file_path = os.path.join(reports_dir, f"sarif_{report_id}.json")

    # Query SAST findings from the DB
    findings_res: List[Finding] = []
    if scan_ids:
        stmt = select(Finding).where(
            and_(
                Finding.scan_id.in_(scan_ids),
                Finding.finding_type.in_(["code_weak_crypto", "sbom_vulnerable_lib"]),
                Finding.deleted_at.is_(None),
            )
        )
        result = await session.execute(stmt)
        findings_res = list(result.scalars().all())

    sarif: Dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PQCrypt Sentinel SAST",
                        "version": "1.0",
                        "informationUri": "https://github.com/pqcrypt/sentinel",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    rule_map: Dict[str, int] = {}
    rule_index = 0

    def add_rule(rule_id: str, name: str, description: str, severity: str) -> int:
        nonlocal rule_index
        if rule_id not in rule_map:
            rule_map[rule_id] = rule_index
            sarif["runs"][0]["tool"]["driver"]["rules"].append(
                {
                    "id": rule_id,
                    "name": name,
                    "shortDescription": {"text": description},
                    "fullDescription": {"text": description},
                    "defaultConfiguration": {"level": severity.lower()},
                }
            )
            rule_index += 1
        return rule_map[rule_id]

    severity_to_sarif = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    for finding in findings_res:
        rule_id = f"pqc-sentinel-{finding.finding_type}"
        severity = severity_to_sarif.get(finding.severity, "warning")

        rule_idx = add_rule(
            rule_id=rule_id,
            name=f"PQCrypt: {finding.finding_type}",
            description=finding.title or finding.finding_type,
            severity=severity,
        )

        evidence = finding.evidence or {}
        file_uri = evidence.get("file", evidence.get("path", "")) or "unknown"
        line = evidence.get("line", evidence.get("start_line", 1)) or 1
        message = finding.description or finding.title or ""

        sarif["runs"][0]["results"].append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_idx,
                "level": severity,
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(file_uri)},
                            "region": {
                                "startLine": int(line) if str(line).isdigit() else 1
                            },
                        }
                    }
                ],
                "properties": {
                    "pqc:algorithm": finding.algorithm or "",
                    "pqc:status": finding.pqc_status or "",
                    "pqc:finding_id": str(finding.id),
                },
            }
        )

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

    logger.info(
        f"SARIF report {report_id} generated at {file_path} with {len(findings_res)} findings"
    )
    return file_path


async def generate_csv_findings_export(
    session: AsyncSession,
    report_id: str,
    scope_filters: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Export the current finding queue to a CSV file. Used for spreadsheet
    analysis, ticket import, and executive review.
    """
    base_dir = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    reports_dir = os.path.join(base_dir, "static", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    file_path = os.path.join(reports_dir, f"findings_{report_id}.csv")

    stmt = (
        select(Finding, Asset)
        .join(Asset, Finding.asset_id == Asset.id)
        .where(Finding.deleted_at.is_(None))
    )
    if scope_filters:
        if scope_filters.get("environment"):
            stmt = stmt.where(Asset.environment == scope_filters["environment"])
        if scope_filters.get("business_service"):
            stmt = stmt.where(
                Asset.business_service == scope_filters["business_service"]
            )
        if scope_filters.get("owner_id"):
            stmt = stmt.where(Asset.owner_id == scope_filters["owner_id"])

    stmt = stmt.options(selectinload(Finding.asset))
    stmt = stmt.order_by(
        Finding.risk_score.desc().nullslast(), Finding.first_detected_at.desc()
    )

    result = await session.execute(stmt)
    rows = result.all()

    columns = [
        "finding_id",
        "asset_id",
        "asset_name",
        "asset_type",
        "environment",
        "fqdn",
        "ip_address",
        "finding_type",
        "severity",
        "title",
        "description",
        "algorithm",
        "pqc_status",
        "hndl_exposure",
        "risk_score",
        "status",
        "first_detected_at",
        "last_verified_at",
        "remediation",
        "recommended_algorithm",
    ]

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, quoting=csv.QUOTE_MINIMAL)
    writer.writeheader()

    def _fmt(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)

    for finding, asset in rows:
        writer.writerow(
            {
                "finding_id": _fmt(finding.id),
                "asset_id": _fmt(finding.asset_id),
                "asset_name": _fmt(asset.name) if asset else "",
                "asset_type": _fmt(asset.asset_type) if asset else "",
                "environment": _fmt(asset.environment) if asset else "",
                "fqdn": _fmt(asset.fqdn) if asset else "",
                "ip_address": _fmt(asset.ip_address) if asset else "",
                "finding_type": _fmt(finding.finding_type),
                "severity": _fmt(finding.severity),
                "title": _fmt(finding.title),
                "description": _fmt(finding.description),
                "algorithm": _fmt(finding.algorithm),
                "pqc_status": _fmt(finding.pqc_status),
                "hndl_exposure": _fmt(finding.hndl_exposure),
                "risk_score": _fmt(finding.risk_score),
                "status": _fmt(finding.status),
                "first_detected_at": _fmt(finding.first_detected_at),
                "last_verified_at": _fmt(finding.last_verified_at),
                "remediation": _fmt(finding.remediation),
                "recommended_algorithm": _fmt(finding.recommended_algorithm),
            }
        )

    with open(file_path, "w", encoding="utf-8", newline="") as f:
        f.write(buffer.getvalue())

    logger.info(
        f"CSV findings export {report_id} generated at {file_path} with {len(rows)} rows"
    )
    return file_path


async def generate_pdf_executive_report(
    session: AsyncSession,
    report_id: str,
    scope_filters: Optional[Dict[str, Any]] = None,
    fmt: str = "pdf",
) -> str:
    """
    Render an executive-ready PDF/HTML report summarising the cryptographic
    posture of the inventory. Uses WeasyPrint for PDF; falls back to the HTML
    file if WeasyPrint is not installed or rendering fails. When ``fmt`` is
    ``html`` the HTML file is returned directly.

    Includes: total assets, findings by severity, PQC readiness percentage,
    top vulnerable assets, and average risk score.
    """
    base_dir = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    reports_dir = os.path.join(base_dir, "static", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    html_path = os.path.join(reports_dir, f"report_{report_id}.html")
    file_path = os.path.join(reports_dir, f"report_{report_id}.pdf")

    fmt = fmt.lower()
    if fmt not in ("pdf", "html"):
        raise ValueError(f"Unsupported executive report format: {fmt}")

    # Gather summary metrics
    asset_stmt = select(Asset).where(Asset.deleted_at.is_(None))
    finding_stmt = select(Finding).where(
        and_(Finding.status == "open", Finding.deleted_at.is_(None))
    )
    if scope_filters:
        if scope_filters.get("environment"):
            asset_stmt = asset_stmt.where(
                Asset.environment == scope_filters["environment"]
            )
            finding_stmt = finding_stmt.join(Asset).where(
                Asset.environment == scope_filters["environment"]
            )
        if scope_filters.get("business_service"):
            asset_stmt = asset_stmt.where(
                Asset.business_service == scope_filters["business_service"]
            )
            finding_stmt = finding_stmt.join(Asset).where(
                Asset.business_service == scope_filters["business_service"]
            )
        if scope_filters.get("owner_id"):
            asset_stmt = asset_stmt.where(Asset.owner_id == scope_filters["owner_id"])
            finding_stmt = finding_stmt.join(Asset).where(
                Asset.owner_id == scope_filters["owner_id"]
            )

    assets = (await session.execute(asset_stmt)).scalars().all()
    findings = (await session.execute(finding_stmt)).scalars().all()

    total_assets = len(assets)
    findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.severity or "info").lower()
        findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

    # Algorithm roll-up
    algo_res = await session.execute(
        select(Algorithm.pqc_status, Algorithm.id)
        .join(Asset, Asset.id == Algorithm.asset_id)
        .where(Asset.deleted_at.is_(None))
    )
    algo_status_counts: Dict[str, int] = {}
    for status, _ in algo_res.all():
        algo_status_counts[status] = algo_status_counts.get(status, 0) + 1

    pqc_ready_total = (
        algo_status_counts.get("pqc_ready", 0)
        + algo_status_counts.get("hybrid", 0)
        + algo_status_counts.get("safe", 0)
    )
    readiness_pct = (pqc_ready_total / total_assets * 100) if total_assets else 0

    # Average risk score across open findings
    risk_scores = [f.risk_score for f in findings if f.risk_score is not None]
    avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0

    # Top 10 highest-risk findings
    top_findings = sorted(
        [f for f in findings if f.risk_score is not None],
        key=lambda f: f.risk_score or 0,
        reverse=True,
    )[:10]

    # Top 10 vulnerable assets by open finding count and cumulative risk
    asset_map = {str(a.id): a for a in assets}
    asset_finding_stats: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        aid = str(f.asset_id)
        asset_name = asset_map[aid].name if aid in asset_map else "Unknown"
        entry = asset_finding_stats.setdefault(
            aid,
            {
                "asset_id": aid,
                "asset_name": asset_name,
                "open_findings": 0,
                "max_risk": 0,
                "total_risk": 0,
            },
        )
        entry["open_findings"] += 1
        score = f.risk_score or 0
        entry["total_risk"] += score
        entry["max_risk"] = max(entry["max_risk"], score)

    top_vulnerable_assets = sorted(
        asset_finding_stats.values(),
        key=lambda x: (x["open_findings"], x["total_risk"]),
        reverse=True,
    )[:10]

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _esc(text: Any) -> str:
        if text is None:
            return ""
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    rows_html = (
        "\n".join(
            f"<tr><td>{_esc(f.title)}</td><td>{_esc(f.severity)}</td><td>{_esc(f.algorithm or '-')}</td><td>{_esc(f.hndl_exposure or '-')}</td><td>{_esc(f.risk_score)}</td></tr>"
            for f in top_findings
        )
        or "<tr><td colspan='5'>No open findings</td></tr>"
    )

    vulnerable_asset_rows = (
        "\n".join(
            f"<tr><td>{_esc(a['asset_name'])}</td><td>{_esc(a['open_findings'])}</td><td>{_esc(a['max_risk'])}</td><td>{_esc(a['total_risk'])}</td></tr>"
            for a in top_vulnerable_assets
        )
        or "<tr><td colspan='4'>No vulnerable assets recorded</td></tr>"
    )

    algo_rows = (
        "\n".join(
            f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>"
            for k, v in sorted(algo_status_counts.items(), key=lambda x: -x[1])
        )
        or "<tr><td colspan='2'>No algorithms recorded</td></tr>"
    )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 32px; color: #1a1a1a; }}
  h1 {{ color: #0d1117; border-bottom: 2px solid #1f6feb; padding-bottom: 8px; }}
  h2 {{ color: #1f6feb; margin-top: 32px; }}
  .meta {{ color: #6e7681; font-size: 12px; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }}
  .kpi {{ padding: 12px; border: 1px solid #d0d7de; border-radius: 6px; background: #f6f8fa; }}
  .kpi-value {{ font-size: 28px; font-weight: bold; }}
  .kpi-label {{ color: #6e7681; font-size: 12px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
  th, td {{ border: 1px solid #d0d7de; padding: 6px 10px; text-align: left; font-size: 12px; }}
  th {{ background: #f6f8fa; }}
  .critical {{ color: #cf222e; font-weight: bold; }}
  .high {{ color: #d1242f; font-weight: bold; }}
  .medium {{ color: #9a6700; }}
  .low {{ color: #1a7f37; }}
</style>
</head><body>
<h1>PQCrypt Sentinel — Cryptographic Posture Executive Report</h1>
<p class="meta">Report ID: {_esc(report_id)} &middot; Generated: {_esc(generated_at)}</p>

<h2>Inventory &amp; Readiness</h2>
<div class="kpi-grid">
  <div class="kpi"><div class="kpi-label">Total Assets</div><div class="kpi-value">{total_assets}</div></div>
  <div class="kpi"><div class="kpi-label">PQC Readiness</div><div class="kpi-value">{readiness_pct:.1f}%</div></div>
  <div class="kpi"><div class="kpi-label">Open Findings</div><div class="kpi-value">{len(findings)}</div></div>
  <div class="kpi"><div class="kpi-label">Average Risk Score</div><div class="kpi-value">{avg_risk_score:.1f}</div></div>
  <div class="kpi critical"><div class="kpi-label">Critical</div><div class="kpi-value">{findings_by_severity.get('critical', 0)}</div></div>
  <div class="kpi high"><div class="kpi-label">High</div><div class="kpi-value">{findings_by_severity.get('high', 0)}</div></div>
  <div class="kpi medium"><div class="kpi-label">Medium</div><div class="kpi-value">{findings_by_severity.get('medium', 0)}</div></div>
  <div class="kpi low"><div class="kpi-label">Low / Info</div><div class="kpi-value">{findings_by_severity.get('low', 0) + findings_by_severity.get('info', 0)}</div></div>
</div>

<h2>Algorithm Distribution</h2>
<table><thead><tr><th>PQC Status</th><th>Asset Count</th></tr></thead><tbody>
{algo_rows}
</tbody></table>

<h2>Top 10 Vulnerable Assets</h2>
<table><thead><tr><th>Asset</th><th>Open Findings</th><th>Max Risk</th><th>Total Risk</th></tr></thead><tbody>
{vulnerable_asset_rows}
</tbody></table>

<h2>Top 10 Risk Findings</h2>
<table><thead><tr><th>Title</th><th>Severity</th><th>Algorithm</th><th>HNDL</th><th>Score</th></tr></thead><tbody>
{rows_html}
</tbody></table>

<p class="meta">Generated by PQCrypt Sentinel &middot; Quantum deadline year: {_esc(scope_filters.get('quantum_timeline_year', 2035) if scope_filters else 2035)}</p>
</body></html>"""

    with open(html_path, "w", encoding="utf-8") as out_f:
        out_f.write(html)

    if fmt == "html":
        logger.info(f"HTML executive report {report_id} generated at {html_path}")
        return html_path

    try:
        from weasyprint import HTML  # type: ignore

        await asyncio.to_thread(
            lambda: HTML(string=html, base_url=base_dir).write_pdf(file_path)
        )
        logger.info(f"PDF executive report {report_id} generated at {file_path}")
    except ImportError:
        logger.warning("WeasyPrint not installed; serving HTML report at %s", html_path)
        return html_path
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "WeasyPrint render failed (%s); falling back to HTML at %s", e, html_path
        )
        return html_path

    return file_path


async def generate_compliance_report(
    session: AsyncSession,
    report_id: str,
    scope_filters: Optional[Dict[str, Any]] = None,
    fmt: str = "json",
) -> str:
    """
    Produce a NIST / SBI-style compliance audit report. ``fmt`` controls the
    output representation:

    * ``json`` — structured audit document with asset inventory, findings,
      remediation status, and NIST control mapping.
    * ``html`` — human-readable HTML document containing the same data,
      suitable for download and review.

    Groups findings by asset, computes PQC readiness per asset, and renders
    remediation status broken down by lifecycle state.
    """
    base_dir = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    reports_dir = os.path.join(base_dir, "static", "reports")
    os.makedirs(reports_dir, exist_ok=True)

    fmt = fmt.lower()
    if fmt not in ("json", "html"):
        raise ValueError(f"Unsupported compliance report format: {fmt}")

    json_path = os.path.join(reports_dir, f"compliance_{report_id}.json")
    html_path = os.path.join(reports_dir, f"compliance_{report_id}.html")

    asset_stmt = select(Asset).where(Asset.deleted_at.is_(None))
    finding_stmt = (
        select(Finding, Asset)
        .join(Asset, Finding.asset_id == Asset.id)
        .where(Finding.deleted_at.is_(None))
    )
    algo_stmt = (
        select(Algorithm.pqc_status, Algorithm.asset_id)
        .join(Asset, Asset.id == Algorithm.asset_id)
        .where(Asset.deleted_at.is_(None))
    )

    if scope_filters:
        for key in ("environment", "business_service", "owner_id"):
            val = scope_filters.get(key)
            if val:
                asset_stmt = asset_stmt.where(getattr(Asset, key) == val)
                finding_stmt = finding_stmt.where(getattr(Asset, key) == val)
                algo_stmt = algo_stmt.where(getattr(Asset, key) == val)

    assets = (await session.execute(asset_stmt)).scalars().all()
    rows = (await session.execute(finding_stmt)).all()
    algo_rows = (await session.execute(algo_stmt)).all()

    algo_counts: Dict[str, int] = {}
    asset_algo_counts: Dict[str, Dict[str, int]] = {}
    for status, aid in algo_rows:
        algo_counts[status] = algo_counts.get(status, 0) + 1
        asset_algo_counts.setdefault(str(aid), {}).setdefault(status, 0)
        asset_algo_counts[str(aid)][status] += 1

    total_assets = len(assets)
    findings_by_severity: Dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    remediation_counts: Dict[str, int] = {
        "open": 0,
        "in_progress": 0,
        "resolved": 0,
        "accepted": 0,
        "false_positive": 0,
    }

    findings_by_asset: Dict[str, Dict[str, Any]] = {}
    for finding, asset in rows:
        sev = (finding.severity or "info").lower()
        findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1
        remediation_counts[finding.status] = (
            remediation_counts.get(finding.status, 0) + 1
        )

        aid = str(asset.id)
        entry = findings_by_asset.setdefault(
            aid,
            {
                "asset_id": aid,
                "asset_name": asset.name,
                "asset_type": asset.asset_type,
                "environment": asset.environment,
                "fqdn": asset.fqdn,
                "ip_address": asset.ip_address,
                "business_service": asset.business_service,
                "owner_id": str(asset.owner_id) if asset.owner_id else None,
                "algo_summary": asset_algo_counts.get(aid, {}),
                "pqc_readiness_pct": 0.0,
                "findings": [],
            },
        )
        entry["findings"].append(
            {
                "finding_id": str(finding.id),
                "finding_type": finding.finding_type,
                "severity": finding.severity,
                "title": finding.title,
                "description": finding.description,
                "algorithm": finding.algorithm,
                "pqc_status": finding.pqc_status,
                "hndl_exposure": finding.hndl_exposure,
                "risk_score": finding.risk_score,
                "status": finding.status,
                "priority_queue": finding.priority_queue,
                "remediation": finding.remediation,
                "recommended_algorithm": finding.recommended_algorithm,
                "first_detected_at": (
                    finding.first_detected_at.isoformat()
                    if finding.first_detected_at
                    else None
                ),
                "last_verified_at": (
                    finding.last_verified_at.isoformat()
                    if finding.last_verified_at
                    else None
                ),
                "resolved_at": (
                    finding.resolved_at.isoformat() if finding.resolved_at else None
                ),
                "nist_control": _finding_type_to_nist_control(finding.finding_type),
            }
        )

    pqc_ready_algos = (
        algo_counts.get("pqc_ready", 0)
        + algo_counts.get("hybrid", 0)
        + algo_counts.get("safe", 0)
    )
    overall_readiness = (pqc_ready_algos / total_assets * 100) if total_assets else 0.0

    for aid, entry in findings_by_asset.items():
        ac = entry["algo_summary"]
        ready = ac.get("pqc_ready", 0) + ac.get("hybrid", 0) + ac.get("safe", 0)
        denom = sum(ac.values()) if ac else 1
        entry["pqc_readiness_pct"] = round((ready / denom) * 100, 1)

    report = {
        "report_metadata": {
            "report_id": report_id,
            "report_type": "compliance",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scope_filters": scope_filters or {},
            "framework": "NIST / SBI Cryptographic Posture Audit",
        },
        "executive_summary": {
            "total_assets": total_assets,
            "total_findings": len(rows),
            "overall_pqc_readiness_pct": round(overall_readiness, 1),
            "findings_by_severity": findings_by_severity,
            "remediation_status": remediation_counts,
            "algorithm_distribution": dict(
                sorted(algo_counts.items(), key=lambda x: -x[1])
            ),
        },
        "findings_by_asset": list(findings_by_asset.values()),
        "compliance_mapping": _build_compliance_mapping(findings_by_asset),
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    if fmt == "html":
        html = _render_compliance_html(report)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(
            "Compliance HTML report %s generated at %s with %d assets",
            report_id,
            html_path,
            total_assets,
        )
        return html_path

    logger.info(
        "Compliance report %s generated at %s with %d assets",
        report_id,
        json_path,
        total_assets,
    )
    return json_path


_NIST_CONTROL_MAP: Dict[str, str] = {
    "weak_algorithm": "SC-17 (PKI) / SA-11 (Developer Security)",
    "weak_key_size": "SC-17 (PKI) / SA-11",
    "tls_version": "SC-8 (Transmission Confidentiality)",
    "pqc_not_supported": "SA-11 / PM-28 (PQC Migration)",
    "pqc_downgrade": "SC-8 / IA-5 (Authenticator Management)",
    "cert_expiring": "SC-17 (PKI) / SI-2 (Flaw Remediation)",
    "cert_expired": "SC-17 (PKI)",
    "self_signed": "SC-17 (PKI)",
    "unknown_ca": "SC-17 (PKI)",
    "ssh_weak_kex": "SC-8 / IA-5",
    "ssh_weak_host_key": "SC-8 / IA-5",
    "vpn_weak_ike": "SC-8 / IA-5",
    "hsm_vulnerable": "SC-12 (Cryptographic Key Establishment)",
    "kms_vulnerable": "SC-12 / SA-11",
    "code_weak_crypto": "SA-11 / SI-10 (Information Input Validation)",
    "sbom_vulnerable_lib": "SA-11 / CM-7 (Least Functionality)",
    "config_drift": "CM-2 (Baseline Configuration) / SI-2",
    "other": "SA-11 (Developer Security)",
}


def _finding_type_to_nist_control(finding_type: str) -> str:
    return _NIST_CONTROL_MAP.get(finding_type, "SA-11 (Developer Security)")


def _build_compliance_mapping(findings_by_asset: Dict[str, Dict[str, Any]]) -> list:
    mapping: list = []
    for aid, entry in findings_by_asset.items():
        for f in entry.get("findings", []):
            mapping.append(
                {
                    "asset_name": entry["asset_name"],
                    "environment": entry["environment"],
                    "finding_id": f["finding_id"],
                    "finding_type": f["finding_type"],
                    "nist_control": f["nist_control"],
                    "risk_score": f["risk_score"],
                    "remediation": f["remediation"],
                    "status": f["status"],
                    "recommended_algorithm": f["recommended_algorithm"],
                }
            )
    mapping.sort(key=lambda x: -(x.get("risk_score") or 0))
    return mapping


def _render_compliance_html(report: Dict[str, Any]) -> str:
    """Render the compliance report dictionary as an HTML document."""

    def _esc(text: Any) -> str:
        if text is None:
            return ""
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    meta = report.get("report_metadata", {})
    summary = report.get("executive_summary", {})
    generated_at = meta.get("generated_at", "")
    scope = meta.get("scope_filters", {})

    sev = summary.get("findings_by_severity", {})
    remediation = summary.get("remediation_status", {})
    algo_dist = summary.get("algorithm_distribution", {})

    # Executive summary cards
    summary_cards = f"""
    <div class="kpi-grid">
      <div class="kpi"><div class="kpi-label">Total Assets</div><div class="kpi-value">{summary.get('total_assets', 0)}</div></div>
      <div class="kpi"><div class="kpi-label">Total Findings</div><div class="kpi-value">{summary.get('total_findings', 0)}</div></div>
      <div class="kpi"><div class="kpi-label">PQC Readiness</div><div class="kpi-value">{summary.get('overall_pqc_readiness_pct', 0.0):.1f}%</div></div>
      <div class="kpi critical"><div class="kpi-label">Critical</div><div class="kpi-value">{sev.get('critical', 0)}</div></div>
      <div class="kpi high"><div class="kpi-label">High</div><div class="kpi-value">{sev.get('high', 0)}</div></div>
      <div class="kpi medium"><div class="kpi-label">Medium</div><div class="kpi-value">{sev.get('medium', 0)}</div></div>
      <div class="kpi low"><div class="kpi-label">Low / Info</div><div class="kpi-value">{sev.get('low', 0) + sev.get('info', 0)}</div></div>
    </div>
    """

    # Remediation status rows
    remediation_rows = (
        "\n".join(
            f"<tr><td>{_esc(status)}</td><td>{_esc(count)}</td></tr>"
            for status, count in sorted(remediation.items(), key=lambda x: -x[1])
        )
        or "<tr><td colspan='2'>No remediation data</td></tr>"
    )

    # Algorithm distribution rows
    algo_rows = (
        "\n".join(
            f"<tr><td>{_esc(status)}</td><td>{_esc(count)}</td></tr>"
            for status, count in sorted(algo_dist.items(), key=lambda x: -x[1])
        )
        or "<tr><td colspan='2'>No algorithms recorded</td></tr>"
    )

    # Asset inventory rows
    asset_entries = report.get("findings_by_asset", [])
    inventory_rows = (
        "\n".join(
            f"""<tr>
          <td>{_esc(a.get('asset_name'))}</td>
          <td>{_esc(a.get('asset_type'))}</td>
          <td>{_esc(a.get('environment'))}</td>
          <td>{_esc(a.get('fqdn'))}</td>
          <td>{_esc(a.get('ip_address'))}</td>
          <td>{_esc(a.get('pqc_readiness_pct'))}%</td>
          <td>{_esc(len(a.get('findings', [])))}</td>
        </tr>"""
            for a in asset_entries
        )
        or "<tr><td colspan='7'>No assets in scope</td></tr>"
    )

    # Findings rows across all assets
    all_findings: List[Dict[str, Any]] = []
    for a in asset_entries:
        for f in a.get("findings", []):
            f["_asset_name"] = a.get("asset_name")
            f["_asset_environment"] = a.get("environment")
            all_findings.append(f)
    all_findings.sort(key=lambda x: -(x.get("risk_score") or 0))

    findings_rows = (
        "\n".join(
            f"""<tr>
          <td>{_esc(f.get('_asset_name'))}</td>
          <td>{_esc(f.get('finding_type'))}</td>
          <td class="{_esc(f.get('severity'))}">{_esc(f.get('severity'))}</td>
          <td>{_esc(f.get('risk_score'))}</td>
          <td>{_esc(f.get('status'))}</td>
          <td>{_esc(f.get('recommended_algorithm') or '-')}</td>
          <td>{_esc(f.get('remediation') or '-')}</td>
          <td>{_esc(f.get('nist_control'))}</td>
        </tr>"""
            for f in all_findings
        )
        or "<tr><td colspan='8'>No findings recorded</td></tr>"
    )

    # Compliance mapping rows
    mapping_rows = (
        "\n".join(
            f"""<tr>
          <td>{_esc(m.get('asset_name'))}</td>
          <td>{_esc(m.get('finding_type'))}</td>
          <td>{_esc(m.get('nist_control'))}</td>
          <td>{_esc(m.get('risk_score'))}</td>
          <td>{_esc(m.get('status'))}</td>
          <td>{_esc(m.get('recommended_algorithm') or '-')}</td>
          <td>{_esc(m.get('remediation') or '-')}</td>
        </tr>"""
            for m in report.get("compliance_mapping", [])
        )
        or "<tr><td colspan='7'>No compliance mapping data</td></tr>"
    )

    scope_items = ", ".join(f"{_esc(k)}={_esc(v)}" for k, v in scope.items()) or "None"

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>NIST / SBI Compliance Audit — {_esc(meta.get('report_id'))}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 32px; color: #1a1a1a; }}
  h1 {{ color: #0d1117; border-bottom: 2px solid #1f6feb; padding-bottom: 8px; }}
  h2 {{ color: #1f6feb; margin-top: 32px; }}
  h3 {{ color: #24292f; margin-top: 24px; }}
  .meta {{ color: #6e7681; font-size: 12px; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }}
  .kpi {{ padding: 12px; border: 1px solid #d0d7de; border-radius: 6px; background: #f6f8fa; }}
  .kpi-value {{ font-size: 28px; font-weight: bold; }}
  .kpi-label {{ color: #6e7681; font-size: 12px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
  th, td {{ border: 1px solid #d0d7de; padding: 6px 10px; text-align: left; font-size: 12px; }}
  th {{ background: #f6f8fa; }}
  .critical {{ color: #cf222e; font-weight: bold; }}
  .high {{ color: #d1242f; font-weight: bold; }}
  .medium {{ color: #9a6700; }}
  .low {{ color: #1a7f37; }}
  .info {{ color: #6e7681; }}
</style>
</head><body>
<h1>PQCrypt Sentinel — NIST / SBI Compliance Audit</h1>
<p class="meta">Report ID: {_esc(meta.get('report_id'))} &middot; Framework: {_esc(meta.get('framework'))}</p>
<p class="meta">Generated: {_esc(generated_at)} &middot; Scope filters: {scope_items}</p>

<h2>Executive Summary</h2>
{summary_cards}

<h2>Remediation Status</h2>
<table><thead><tr><th>Status</th><th>Count</th></tr></thead><tbody>
{remediation_rows}
</tbody></table>

<h2>Algorithm Distribution</h2>
<table><thead><tr><th>PQC Status</th><th>Count</th></tr></thead><tbody>
{algo_rows}
</tbody></table>

<h2>Asset Inventory</h2>
<table><thead><tr><th>Asset</th><th>Type</th><th>Environment</th><th>FQDN</th><th>IP</th><th>PQC Readiness</th><th>Findings</th></tr></thead><tbody>
{inventory_rows}
</tbody></table>

<h2>Findings Detail</h2>
<table><thead><tr><th>Asset</th><th>Finding Type</th><th>Severity</th><th>Risk</th><th>Status</th><th>Recommended Algorithm</th><th>Remediation</th><th>NIST Control</th></tr></thead><tbody>
{findings_rows}
</tbody></table>

<h2>Compliance Mapping</h2>
<table><thead><tr><th>Asset</th><th>Finding Type</th><th>NIST Control</th><th>Risk</th><th>Status</th><th>Recommended Algorithm</th><th>Remediation</th></tr></thead><tbody>
{mapping_rows}
</tbody></table>

<p class="meta">Generated by PQCrypt Sentinel</p>
</body></html>"""


async def generate_report(
    session: AsyncSession,
    report_id: str,
    report_type: str,
    fmt: str,
    scope_filters: Optional[Dict[str, Any]] = None,
    scan_ids: Optional[List[str]] = None,
) -> str:
    """
    Dispatcher that produces any supported report format.
    Updates the Report row with file_path and status.
    """
    stmt = select(Report).where(Report.id == report_id)
    result = await session.execute(stmt)
    report = result.scalar_one_or_none()
    if not report:
        raise ValueError(f"Report {report_id} not found")

    report.status = "generating"
    await session.commit()
    await session.refresh(report)

    fmt = fmt.lower()
    report_type = report_type.lower()

    try:
        if report_type == "cbom" and fmt == "json":
            file_path = await generate_cbom(session, report_id)
        elif report_type == "findings" and fmt == "csv":
            file_path = await generate_csv_findings_export(
                session, report_id, scope_filters
            )
        elif report_type == "executive" and fmt in ("pdf", "html"):
            file_path = await generate_pdf_executive_report(
                session, report_id, scope_filters, fmt=fmt
            )
        elif report_type == "compliance" and fmt in ("json", "html"):
            file_path = await generate_compliance_report(
                session, report_id, scope_filters, fmt=fmt
            )
        elif report_type == "sast" and fmt == "sarif":
            file_path = await generate_sarif_report(session, report_id, scan_ids or [])
        else:
            raise ValueError(
                f"Unsupported report_type/format combination: {report_type}/{fmt}"
            )

        report.status = "ready"
        report.file_path = file_path
        report.updated_at = datetime.now(timezone.utc)
        await session.commit()
        return file_path
    except Exception as e:
        logger.exception("Report generation failed for %s", report_id)
        report.status = "failed"
        report.error_message = str(e)
        report.updated_at = datetime.now(timezone.utc)
        await session.commit()
        raise
