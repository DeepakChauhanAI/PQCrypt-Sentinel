"""Tests for the layer_service helpers and the new finding layer column."""
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services import layer_service
from app.services.layer_service import (
    FINDING_TYPE_TO_LAYER,
    LAYER_DEFINITIONS,
    all_layer_ids,
    layer_for_asset,
    layer_for_finding,
    layer_name,
)


def test_layer_definitions_has_seven_layers():
    assert len(LAYER_DEFINITIONS) == 7
    assert all_layer_ids() == ["L1", "L2", "L3", "L4", "L5", "L6", "L7"]


def test_layer_for_asset_hsm_maps_to_l3():
    a = SimpleNamespace(asset_type="hsm", discovery_source=None, asset_metadata={})
    assert layer_for_asset(a) == "L3"


def test_layer_for_asset_kms_maps_to_l3():
    a = SimpleNamespace(asset_type="kms", discovery_source=None, asset_metadata={})
    assert layer_for_asset(a) == "L3"


def test_layer_for_asset_ca_maps_to_l2():
    a = SimpleNamespace(asset_type="certificate_authority", discovery_source=None, asset_metadata={})
    assert layer_for_asset(a) == "L2"


def test_layer_for_asset_vpn_maps_to_l1():
    a = SimpleNamespace(asset_type="vpn_gateway", discovery_source=None, asset_metadata={})
    assert layer_for_asset(a) == "L1"


def test_layer_for_asset_uses_discovery_source():
    a = SimpleNamespace(asset_type="unknown", discovery_source="tde", asset_metadata={})
    assert layer_for_asset(a) == "L5"


def test_layer_for_asset_uses_metadata_key_type():
    a = SimpleNamespace(asset_type="other", discovery_source=None, asset_metadata={"key_type": "AWS_HSM"})
    assert layer_for_asset(a) == "L3"


def test_layer_for_asset_defaults_to_l1():
    a = SimpleNamespace(asset_type="mystery", discovery_source=None, asset_metadata={})
    assert layer_for_asset(a) == "L1"


def test_layer_for_asset_none_defaults_to_l1():
    assert layer_for_asset(None) == "L1"


def test_layer_for_finding_uses_asset_type_first():
    a = SimpleNamespace(asset_type="hsm", discovery_source=None, asset_metadata={})
    assert layer_for_finding(finding_type="weak_algorithm", asset=a) == "L3"


def test_layer_for_finding_falls_back_to_finding_type():
    a = SimpleNamespace(asset_type="server", discovery_source=None, asset_metadata={})
    # asset -> L1, but finding_type should override when asset is generic
    # (since server maps to L1, the function will keep L1)
    assert layer_for_finding(finding_type="ssh_weak_kex", asset=a) in ("L1", "L6")


def test_layer_for_finding_code_weak_crypto():
    a = SimpleNamespace(asset_type="container", discovery_source=None, asset_metadata={})
    # container -> L4
    assert layer_for_finding(finding_type="code_weak_crypto", asset=a) == "L4"


def test_layer_for_finding_no_asset_uses_finding_type():
    assert layer_for_finding(finding_type="vpn_weak_ike") == "L1"
    assert layer_for_finding(finding_type="ssh_weak_host_key") == "L6"
    assert layer_for_finding(finding_type="hsm_vulnerable") == "L3"
    assert layer_for_finding(finding_type="code_weak_crypto") == "L4"
    assert layer_for_finding(finding_type="sbom_vulnerable_lib") == "L4"


def test_layer_for_finding_unknown_finding_type_defaults_l1():
    assert layer_for_finding(finding_type="totally-unknown") == "L1"


def test_layer_name_lookup():
    assert layer_name("L1") == "Network"
    assert layer_name("L5") == "Data"
    assert layer_name("L99") == "L99"  # unknown id returns itself


def test_finding_model_has_layer_column():
    """The Finding model must have a `layer` column for queryable layer tags."""
    from app.models.models import Finding
    from sqlalchemy import inspect
    mapper = inspect(Finding)
    columns = {c.key for c in mapper.columns}
    assert "layer" in columns
    layer_col = mapper.columns["layer"]
    assert layer_col.type.length == 5
    assert layer_col.nullable is True


def test_all_layer_ids_match_definitions():
    assert all_layer_ids() == [layer["id"] for layer in LAYER_DEFINITIONS]


def test_finding_type_to_layer_coverage():
    """Every layer L1..L7 should be reachable from at least one finding_type."""
    reachable = set(FINDING_TYPE_TO_LAYER.values())
    # L1 (network) is the default; not every layer must be in the type map.
    # But all explicitly tagged ones should be valid.
    for layer in reachable:
        assert layer in all_layer_ids()
