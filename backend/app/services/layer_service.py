"""
Layer derivation helpers.

Maps assets, finding types, and discovery sources to the 7-layer
infrastructure taxonomy used by the dashboard.

Layer IDs are stable strings (L1..L7) so they can be persisted to the
``Finding.layer`` column and queried as a foreign-key-like attribute.
"""

from __future__ import annotations

from typing import Any, Optional

LAYER_DEFINITIONS = [
    {"id": "L1", "name": "Network", "description": "TLS, SSH, VPN/IKEv2, DNSSEC, OCSP, SMTP STARTTLS"},
    {"id": "L2", "name": "PKI", "description": "Root CA, Intermediate CAs, TLS Server Certs, Code-signing, TSA"},
    {"id": "L3", "name": "HSM/KMS", "description": "General HSMs, Payment HSMs (3DES), Cloud KMS"},
    {"id": "L4", "name": "Application", "description": "JWT Algorithms, Container Images, API Crypto"},
    {"id": "L5", "name": "Data", "description": "TDE Algorithms, Backup Encryption, Column-level Encryption"},
    {"id": "L6", "name": "Infrastructure", "description": "SSH Host Keys, Kerberos RC4, Windows CNG/Schannel"},
    {"id": "L7", "name": "Endpoint", "description": "Windows Cert Store, BitLocker, Firmware Signing"},
]

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
    "saas": "L4",
    "source_code": "L4",
    # L5 Data
    "database": "L5",
    "tde": "L5",
    "backup": "L5",
    "backup_encryption": "L5",
    "cloud_resource": "L5",
    # L6 Infrastructure
    "ssh_host_key": "L6",
    "kerberos": "L6",
    "windows_cng": "L6",
    # L7 Endpoint
    "endpoint": "L7",
    "windows_cert_store": "L7",
    "bitlocker": "L7",
    "firmware": "L7",
    "smart_card": "L7",
}

# Map finding_type -> default layer when the asset is not available.
FINDING_TYPE_TO_LAYER = {
    "weak_algorithm": "L2",
    "weak_key_size": "L2",
    "tls_version": "L1",
    "pqc_not_supported": "L1",
    "pqc_downgrade": "L1",
    "cert_expiring": "L2",
    "cert_expired": "L2",
    "self_signed": "L2",
    "unknown_ca": "L2",
    "ssh_weak_kex": "L1",
    "ssh_weak_host_key": "L6",
    "vpn_weak_ike": "L1",
    "hsm_vulnerable": "L3",
    "kms_vulnerable": "L3",
    "code_weak_crypto": "L4",
    "sbom_vulnerable_lib": "L4",
    "config_drift": "L6",
    "other": "L1",
}


def layer_for_asset(asset: Any) -> str:
    """Determine layer for an Asset-like object (or dict)."""
    if asset is None:
        return "L1"
    asset_type = (getattr(asset, "asset_type", "") or "").lower()
    if asset_type in ASSET_TO_LAYER:
        return ASSET_TO_LAYER[asset_type]
    disc_source = (getattr(asset, "discovery_source", "") or "").lower()
    if disc_source in ASSET_TO_LAYER:
        return ASSET_TO_LAYER[disc_source]
    meta = getattr(asset, "asset_metadata", None) or {}
    if isinstance(meta, dict):
        provider = (meta.get("provider") or "").lower()
        if provider in ASSET_TO_LAYER:
            return ASSET_TO_LAYER[provider]
        key_type = (meta.get("key_type") or "").lower()
        if "hsm" in key_type or "kms" in key_type:
            return "L3"
    return "L1"


def layer_for_finding(
    finding_type: Optional[str] = None,
    asset: Any = None,
) -> str:
    """Derive the layer for a finding.

    Priority: specific asset mapping -> finding_type -> L1 default.
    """
    layer_from_asset = layer_for_asset(asset)
    # If the asset yields a specific (non-default) layer, trust it.
    if asset is not None and layer_from_asset != "L1":
        return layer_from_asset
    # Otherwise (no asset or asset is generic), use the finding_type mapping.
    if finding_type and finding_type in FINDING_TYPE_TO_LAYER:
        return FINDING_TYPE_TO_LAYER[finding_type]
    return layer_from_asset


def all_layer_ids() -> list[str]:
    return [layer["id"] for layer in LAYER_DEFINITIONS]


def layer_name(layer_id: str) -> str:
    for layer in LAYER_DEFINITIONS:
        if layer["id"] == layer_id:
            return layer["name"]
    return layer_id
