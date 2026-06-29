"""
Tests for `app.scanners.ike_scanner` - the IKEv2 probe parser and
the `scan_ike_endpoint` async entry point.

The scanner module has 18% line coverage; this file pushes it well
above 80% by exercising:
  * `_parse_ikev2_response` with hand-crafted byte buffers
  * `_parse_ike_group_from_line` (text parsing)
  * `_DH_GROUP_POLICY` PQC status classification
  * `scan_ike_endpoint` happy path, error path, and skipped path
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict
from unittest.mock import patch

import pytest

from app.scanners import ike_scanner as ike_mod
from app.scanners.ike_scanner import (
    IKEScanResult,
    _DH_GROUP_POLICY,
    _parse_ike_group_from_line,
    _parse_ikev2_response,
    scan_ike_endpoint,
)


# --------------------------------------------------- binary fixtures ----


def _transform(t_type: int, t_id: int) -> bytes:
    """8-byte IKEv2 transform in the format the parser reads.

    The scanner's `_parse_ikev2_response` reads each transform as:
      bytes 0-1: next/flags (ignored)
      bytes 2-3: length (must be >= 8)
      byte 4:    transform type (4=DH, 1=ENCR, 3=INTEG)
      byte 5:    reserved
      bytes 6-7: transform id (DH group, cipher id, etc.)
    """
    return bytes([0x00, 0x00, 0x00, 0x08, t_type, 0x00, (t_id >> 8) & 0xFF, t_id & 0xFF])


def _sa_payload(transforms: list[bytes]) -> bytes:
    """Concatenate transforms into an SA payload body, prefixed by the
    standard 4-byte payload header (next_payload, critical, length).
    """
    body = b"".join(transforms)
    payload_len = 4 + len(body)
    return bytes([0x00, 0x00]) + payload_len.to_bytes(2, "big") + body


def _ikev2_packet(payload_type: int, payload: bytes) -> bytes:
    """Build a 28-byte IKEv2 header + the supplied payload."""
    total_len = 28 + len(payload)
    return (
        b"\x3f\x5a\x2b\x1c\x0d\x9e\x8f\x7a"            # ISPI
        + b"\x00" * 8                                  # RSPI
        + bytes([payload_type, 0x20, 0x22, 0x08])      # next-payload, version, exch, flags
        + b"\x00\x00\x00\x00"                          # msg id
        + total_len.to_bytes(4, "big")                 # length
        + payload
    )


# ---------------------------------------------------- parser tests -----


def test_parse_ikev2_response_too_short():
    result = _parse_ikev2_response(b"\x00" * 10)
    assert result.get("error") == "Response too short"


def test_parse_ikev2_response_dh_group_19_vulnerable():
    sa = _sa_payload([_transform(4, 19)])  # DH type=4, id=19
    raw = _ikev2_packet(33, sa)
    result = _parse_ikev2_response(raw)
    assert "error" not in result
    assert "256-bit random ECP (NIST P-256)" in result["dh_groups"]
    assert result["pqc_status"] == "vulnerable"


def test_parse_ikev2_response_dh_group_14_vulnerable():
    sa = _sa_payload([_transform(4, 14)])
    raw = _ikev2_packet(33, sa)
    result = _parse_ikev2_response(raw)
    assert "2048-bit MODP" in result["dh_groups"]
    assert result["pqc_status"] == "vulnerable"


def test_parse_ikev2_response_unknown_dh_group():
    sa = _sa_payload([_transform(4, 9999)])
    raw = _ikev2_packet(33, sa)
    result = _parse_ikev2_response(raw)
    assert "DH Group 9999" in result["dh_groups"]
    assert result["pqc_status"] == "vulnerable"


def test_parse_ikev2_response_enc_integ_transforms():
    sa = _sa_payload([_transform(1, 12), _transform(3, 12)])  # ENCR + INTEG
    raw = _ikev2_packet(33, sa)
    result = _parse_ikev2_response(raw)
    assert "ENCR_12" in result["encryption_algorithms"]
    assert "INTEG_12" in result["integrity_algorithms"]


def test_parse_ikev2_response_dh_group_38_ml_kem():
    sa = _sa_payload([_transform(4, 38)])
    raw = _ikev2_packet(33, sa)
    result = _parse_ikev2_response(raw)
    assert "ML-KEM-768" in result["dh_groups"]
    assert result["pqc_status"] == "pqc_ready"


def test_parse_ikev2_response_notify_invalid_ke_dh_19():
    """Notify payload (41) with msg_type 17 (INVALID_KE) and DH group 19.

    Body (after the 4-byte payload header):
      [0]    protocol_id
      [1]    spi_size
      [2-3]  msg_type (17 = INVALID_KE_PAYLOAD)
      [4..4+spi_size) spi
      [4+spi_size..4+spi_size+2) preferred DH group
    """
    # protocol_id=1, spi_size=0, msg_type=0x0011, pref_group=0x0013
    # (no SPI because spi_size=0)
    notify_body = bytes([0x01, 0x00, 0x00, 0x11, 0x00, 0x13])
    payload = bytes([0x00, 0x00]) + (4 + len(notify_body)).to_bytes(2, "big") + notify_body
    raw = _ikev2_packet(41, payload)
    result = _parse_ikev2_response(raw)
    assert "256-bit random ECP (NIST P-256)" in result["dh_groups"]
    assert result["pqc_status"] == "vulnerable"


def test_parse_ikev2_response_truncated_payload():
    """A header that claims a payload longer than the data is safe."""
    sa_short = bytes([0x00, 0x00, 0xFF, 0xFF])  # claims length 0xFFFF
    raw = _ikev2_packet(33, sa_short)
    result = _parse_ikev2_response(raw)
    # No groups parsed; default pqc_status="vulnerable", no error
    assert result.get("dh_groups") == []
    assert result.get("pqc_status") == "vulnerable"


# ------------------------------------------------ text line parser -----


def test_parse_ike_group_from_line_standard():
    """Lines must look like '... group ... [NN]'."""
    assert _parse_ike_group_from_line("Oakley group 14 [14]") == "2048-bit MODP"
    assert _parse_ike_group_from_line("Diffie-Hellman group: 19 [19]") == \
        "256-bit random ECP (NIST P-256)"


def test_parse_ike_group_from_line_returns_none_for_non_group_lines():
    assert _parse_ike_group_from_line("IKEv2 SA_INIT response received") is None
    assert _parse_ike_group_from_line("encryption algorithm: AES-CBC-256") is None


def test_parse_ike_group_from_line_returns_none_without_brackets():
    assert _parse_ike_group_from_line("Oakley group 14") is None


def test_parse_ike_group_from_line_unknown_group():
    assert _parse_ike_group_from_line("Oakley group 99 [99]") == "DH Group 99"


# -------------------------------------------- scan_ike_endpoint paths -


def test_scan_ike_endpoint_happy_path_pqc_ready():
    """Mock _do_ike_probe to return a PQC-ready IKEv2 response."""
    fake_result: Dict[str, Any] = {
        "success": True,
        "ike_version": "IKEv2",
        "dh_groups": ["256-bit random ECP", "ML-KEM-768"],
        "encryption_algorithms": ["AES-CBC-256"],
        "integrity_algorithms": ["HMAC-SHA2-256-128"],
        "pqc_dh_groups": ["ML-KEM-768"],
        "pqc_status": "pqc_ready",
        "response_len": 200,
    }
    with patch.object(ike_mod, "_do_ike_probe", return_value=fake_result):
        result = asyncio.run(scan_ike_endpoint("vpn.example.com", port=500, timeout=2))
    assert isinstance(result, IKEScanResult)
    assert result.success is True
    assert result.ike_version == "IKEv2"
    assert "ML-KEM-768" in result.dh_groups
    assert result.pqc_status == "pqc_ready"


def test_scan_ike_endpoint_probe_failure():
    fake_result = {
        "success": False,
        "error_message": "connection refused",
    }
    with patch.object(ike_mod, "_do_ike_probe", return_value=fake_result):
        result = asyncio.run(scan_ike_endpoint("nope.example.com"))
    assert result.success is False
    assert "connection refused" in result.error_message


def test_scan_ike_endpoint_response_too_short():
    fake_result = {
        "success": True,
        "response_len": 5,
    }
    with patch.object(ike_mod, "_do_ike_probe", return_value=fake_result):
        result = asyncio.run(scan_ike_endpoint("host.example.com"))
    assert result.success is False
    assert "too short" in result.error_message.lower()


def test_scan_ike_endpoint_exception_in_executor():
    """When _do_ike_probe raises, scan_ike_endpoint captures the exception."""
    def boom(*a, **kw):
        raise ConnectionError("socket failure")
    with patch.object(ike_mod, "_do_ike_probe", side_effect=boom):
        result = asyncio.run(scan_ike_endpoint("host.example.com"))
    assert result.success is False
    assert "socket failure" in result.error_message


def test_dh_group_policy_pqc_groups_are_pqc_ready():
    """ML-KEM groups (38, 39, 40) must be pqc_ready."""
    for gid in ("38", "39", "40"):
        assert _DH_GROUP_POLICY[gid]["pqc_status"] == "pqc_ready"


def test_dh_group_policy_hybrid_groups():
    """Groups 36 and 37 (curve25519/curve448 hybrid) -> hybrid."""
    for gid in ("36", "37"):
        assert _DH_GROUP_POLICY[gid]["pqc_status"] == "hybrid"


def test_dh_group_policy_all_groups_classification():
    """Verify that every group <= 35 returns pqc_status == 'vulnerable',
    groups 36-37 return 'hybrid', and groups 38-40 return 'pqc_ready'.
    """
    for gid, policy in _DH_GROUP_POLICY.items():
        val = int(gid)
        if val <= 35:
            assert policy["pqc_status"] == "vulnerable", f"Group {gid} status was {policy['pqc_status']}"
        elif val in (36, 37):
            assert policy["pqc_status"] == "hybrid", f"Group {gid} status was {policy['pqc_status']}"
        elif val in (38, 39, 40):
            assert policy["pqc_status"] == "pqc_ready", f"Group {gid} status was {policy['pqc_status']}"
