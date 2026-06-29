"""Unit tests for `app.utils.target_classifier.classify_target`.

The classifier is the single source of truth for deriving
``target_kind`` / ``target_label`` from a free-form scan target, and
for deciding whether a scan should be auto-wrapped in a ScanGroup.
These tests pin the expected behaviour for every shape the orchestrator
and the API layer can hand us.
"""
from __future__ import annotations

import pytest

from app.utils.target_classifier import (
    TargetClassification,
    classify_target,
    suggest_group_name,
)


# Table-driven cases ---------------------------------------------------------

@pytest.mark.parametrize(
    "target, expected_kind, expected_label, expected_groupable",
    [
        # None / empty
        (None, "other", "", False),
        ("", "other", "", False),
        ("   ", "other", "", False),
        # CIDR
        ("192.168.1.0/24", "network_range", "192.168.1.0/24", True),
        ("10.0.0.0/8", "network_range", "10.0.0.0/8", True),
        ("2001:db8::/32", "network_range", "2001:db8::/32", True),
        # Single IP
        ("10.0.0.1", "host", "10.0.0.1", False),
        ("192.168.1.187", "host", "192.168.1.187", False),
        # Single FQDN — groupable because the orchestrator DNS-enumerates
        ("scanme.pqc", "domain", "scanme.pqc", True),
        ("example.com", "domain", "example.com", True),
        # Comma-separated multi-host
        ("10.0.0.1,10.0.0.2,10.0.0.3", "network_range", "10.0.0.1,10.0.0.2,10.0.0.3", True),
        # Semicolons should be treated like commas
        ("10.0.0.1;10.0.0.2", "network_range", "10.0.0.1;10.0.0.2", True),
        # Connector-style single-endpoint targets
        ("ssh:10.0.0.1:22", "host", "ssh:10.0.0.1:22", False),
        ("winrm:host:5985", "host", "winrm:host:5985", False),
        ("pkcs11:/usr/lib/softhsm/libsofthsm2.so", "host", "pkcs11:/usr/lib/softhsm/libsofthsm2.so", False),
        ("aws:us-east-1", "host", "aws:us-east-1", False),
        # URL form: the classifier strips the protocol + path and
        # returns the host portion as the label. If the host looks
        # like an FQDN, the kind is "domain" (groupable).
        ("https://example.com/path", "domain", "example.com", True),
        ("http://10.0.0.1/", "host", "10.0.0.1", False),
        # Unknown — never raises, falls back to "other"
        ("!@#weird token", "other", "!@#weird token", False),
    ],
)
def test_classify_target(target, expected_kind, expected_label, expected_groupable):
    cls = classify_target(target)
    assert isinstance(cls, TargetClassification)
    assert cls.kind == expected_kind
    assert cls.label == expected_label
    assert cls.is_groupable is expected_groupable


def test_classify_target_preserves_whitespace_in_cidr():
    # A leading/trailing space is stripped but the core CIDR is intact.
    cls = classify_target("  192.168.1.0/24  ")
    assert cls.kind == "network_range"
    assert cls.label == "192.168.1.0/24"
    assert cls.is_groupable is True


def test_suggest_group_name_network_range():
    assert (
        suggest_group_name("192.168.1.0/24")
        == "Network scan: 192.168.1.0/24"
    )


def test_suggest_group_name_domain():
    assert (
        suggest_group_name("scanme.pqc")
        == "Domain scan: scanme.pqc"
    )


def test_suggest_group_name_host():
    assert (
        suggest_group_name("10.0.0.1")
        == "Host scan: 10.0.0.1"
    )


def test_suggest_group_name_falls_back_when_empty():
    # Even for None, the function returns a non-empty string so it
    # never violates the ScanGroup.name NOT NULL constraint.
    name = suggest_group_name(None, scan_type="full")
    assert isinstance(name, str)
    assert name  # non-empty


def test_suggest_group_name_includes_scan_type_for_unknown():
    # "other" target_kind, falls back to "<scan_type> scan: …"
    name = suggest_group_name("!@#weird", scan_type="full")
    assert "full" in name.lower()
