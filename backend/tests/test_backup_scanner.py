"""Tests for the backup encryption scanner skeleton."""

from __future__ import annotations

from app.scanners.backup_scanner import (
    classify_backup_algorithm,
    scan_backup_inventory,
    scan_veeam_config,
)


def test_classify_vulnerable_algorithm():
    result = classify_backup_algorithm("3DES-CBC")
    assert result["pqc_status"] == "vulnerable"
    assert "Legacy/weak" in result["notes"]


def test_classify_classical_algorithm():
    result = classify_backup_algorithm("AES-256-GCM")
    assert result["pqc_status"] == "pqc_ready"


def test_classify_unknown_algorithm():
    result = classify_backup_algorithm("custom-cipher")
    assert result["pqc_status"] == "unknown"


def test_scan_inventory_finds_unencrypted():
    records = [
        {
            "source": "srv-01",
            "software": "Veeam",
            "encryption_enabled": False,
            "algorithm": None,
        },
    ]
    result = scan_backup_inventory(records)
    assert result["status"] == "success"
    assert result["assets_found"] == 1
    assert result["findings_found"] == 1
    assert result["findings"][0]["finding_type"] == "backup_unencrypted"
    assert result["assets"][0]["pqc_status"] == "vulnerable"


def test_scan_inventory_finds_weak_encryption():
    records = [
        {
            "source": "srv-02",
            "software": "Commvault",
            "encryption_enabled": True,
            "algorithm": "RC4",
        },
    ]
    result = scan_backup_inventory(records)
    assert result["findings_found"] == 1
    assert result["findings"][0]["finding_type"] == "backup_weak_encryption"


def test_scan_inventory_strong_encryption():
    records = [
        {
            "source": "srv-03",
            "software": "RMAN",
            "encryption_enabled": True,
            "algorithm": "AES-256-GCM",
        },
    ]
    result = scan_backup_inventory(records)
    assert result["findings_found"] == 0
    assert result["assets"][0]["pqc_status"] == "pqc_ready"


def test_scan_veeam_config_enabled():
    config = """
    [BackupOptions]
    Encryption Enabled: true
    Encryption Algorithm: AES-256
    """
    result = scan_veeam_config(config)
    assert result["status"] == "success"
    assert result["asset"]["encryption_enabled"] is True
    assert result["asset"]["algorithm"] == "AES-256"


def test_scan_veeam_config_disabled():
    config = "EnableEncryption = false"
    result = scan_veeam_config(config)
    assert result["asset"]["encryption_enabled"] is False
    assert result["findings_found"] == 1
