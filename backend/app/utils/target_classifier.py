"""Server-side derivation of `target_kind` / `target_label` from a raw target
string.

A single source of truth for the heuristic that maps a free-form scan target
("192.168.1.0/24", "host1,host2", "scanme.pqc", "ssh:10.0.0.1:22", ...) into
the canonical ``scan_target_kind_enum`` and decides whether the scan should
be auto-wrapped in a ``ScanGroup`` so it surfaces in the Scan Groups tab.

Before this helper existed, every scan-creation path left ``target_kind``
and ``target_label`` as NULL — the schema comment said the values "may be
derived server-side from the target string" but no derivation code was
actually written. That meant a CIDR range scan (which fans out to N hosts
via the orchestrator's network discovery) was indistinguishable from a
single-host scan at the data layer, and the resulting findings/assets had
no way to be associated with a parent group.
"""
from __future__ import annotations

import ipaddress
import re
from typing import NamedTuple, Optional


# Mirrors app.models.models.Scan.target_kind enum. Duplicated here so
# app.utils stays import-cheap (no SQLAlchemy dependency).
_VALID_KINDS = {
    "host", "cloud_account", "code_repo", "domain",
    "saas_tenant", "network_range", "interface", "other",
}


class TargetClassification(NamedTuple):
    """Result of classifying a free-form scan target string."""
    kind: str           # one of scan_target_kind_enum values
    label: str          # human-readable label (usually the cleaned target)
    is_groupable: bool  # True if the scan should be auto-wrapped in a ScanGroup


# Connector-style prefixes we recognise. The scan_orchestrator treats these
# as single-endpoint, so the kind is always "host".
_CONNECTOR_PREFIXES = (
    "ssh:", "winrm:", "kubernetes:", "oracle_tde:", "sqlserver_tde:",
    "pkcs11:", "kmip:", "adcs:", "jwt:", "windows_cert_store:",
    "aws:", "azure:", "gcp:",
)


def _looks_like_cidr(target: str) -> bool:
    """Return True if ``target`` is a valid IPv4/IPv6 CIDR block.

    Reuses the same permissive parser that scan_orchestrator.py uses at
    parse time (mask 0..128 accepted; leading/trailing whitespace
    tolerated; IPv6 with ``::`` allowed).
    """
    if "/" not in target:
        return False
    head, _, tail = target.partition("/")
    if not head or not tail:
        return False
    try:
        # ``strict=False`` accepts host bits set, which is what the
        # orchestrator also accepts.
        ipaddress.ip_network(target, strict=False)
        # Make sure the mask component is a plain integer in 0..128 —
        # this filters out URL-style paths like "https://x.com/foo".
        mask = int(tail)
        return 0 <= mask <= 128
    except (ValueError, ipaddress.AddressValueError, TypeError):
        return False


def _looks_like_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except (ValueError, TypeError):
        return False


def _looks_like_connector_prefix(target: str) -> bool:
    low = target.lower()
    return any(low.startswith(p) for p in _CONNECTOR_PREFIXES)


def _looks_like_passive_interface(target: str) -> bool:
    # The orchestrator uses an interface name (e.g. "eth0", "wlan0",
    # "any") when scan_type == "passive". Conservative heuristic:
    #   * no slashes, no spaces, no protocol prefix
    #   * only ASCII letters / digits / hyphens / underscores / dots
    #   * short (≤16 chars) — interface names never look like sentences
    if "/" in target or " " in target:
        return False
    if target.startswith("http://") or target.startswith("https://"):
        return False
    if not target or len(target) > 16:
        return False
    return bool(re.match(r"^[A-Za-z0-9_.\-]+$", target))


def _split_multi_host(target: str) -> list[str]:
    """Split a comma- or semicolon-separated list of hosts.

    Mirrors the same parser the orchestrator uses so we don't disagree on
    what counts as "one target". Trailing dots are stripped (FQDN form).
    """
    parts: list[str] = []
    for chunk in target.replace(";", ",").split(","):
        chunk = chunk.strip().strip(".")
        # strip protocol prefix
        if chunk.lower().startswith("https://"):
            chunk = chunk[8:]
        elif chunk.lower().startswith("http://"):
            chunk = chunk[7:]
        if chunk:
            parts.append(chunk)
    return parts


def _looks_like_fqdn(token: str) -> bool:
    """Cheap FQDN check: at least one dot, only DNS-safe chars, no slashes."""
    if "/" in token or " " in token:
        return False
    if token.count(".") < 1:
        return False
    return bool(re.match(r"^[A-Za-z0-9_.\-]+$", token))


def classify_target(target: Optional[str]) -> TargetClassification:
    """Map a raw scan target string to a (kind, label, is_groupable) tuple.

    Contract:
      * ``kind`` is always one of the ``scan_target_kind_enum`` values.
      * ``label`` is a human-readable representation suitable for the
        ``Scan.target_label`` column. Defaults to the cleaned target.
      * ``is_groupable`` is True iff the scan fans out to multiple assets
        (CIDR range, multi-host list, or domain that DNS-enumerates to
        many hosts) — these scans get auto-wrapped in a ``ScanGroup``.

    The function is intentionally permissive: unknown shapes fall back to
    ``("other", target, False)`` rather than raising, so a typo in a
    target string never blocks a scan from being created.
    """
    if target is None:
        return TargetClassification("other", "", False)

    cleaned = target.strip()
    if not cleaned:
        return TargetClassification("other", "", False)

    # 1. Connector-style single-endpoint scans ("ssh:host:22", "aws:…")
    if _looks_like_connector_prefix(cleaned):
        return TargetClassification("host", cleaned, False)

    # 2. URL form ("https://example.com/path"). The orchestrator strips
    # the protocol + path before doing network discovery, so the kind is
    # "host" (or "domain" if the host part looks like an FQDN), and the
    # label is the host portion (so the UI doesn't display the path).
    if cleaned.lower().startswith(("http://", "https://")):
        host = cleaned.split("://", 1)[1]
        # Drop the path component but keep the rest.
        host = host.split("/", 1)[0]
        if _looks_like_ip(host):
            return TargetClassification("host", host, False)
        if _looks_like_fqdn(host):
            return TargetClassification("domain", host, True)
        return TargetClassification("host", host, False)

    # 3. CIDR range (the most common "groupable" target)
    if _looks_like_cidr(cleaned):
        return TargetClassification("network_range", cleaned, True)

    # 4. Comma/semicolon separated multi-host list
    hosts = _split_multi_host(cleaned)
    if len(hosts) > 1:
        return TargetClassification("network_range", cleaned, True)

    # At this point we have a single host token.
    single = hosts[0] if hosts else cleaned

    # 5. Single IP
    if _looks_like_ip(single):
        return TargetClassification("host", single, False)

    # 6. Single FQDN — a domain DNS-enumerates to many hosts in the
    # orchestrator, so it is "groupable" from a grouping standpoint.
    if _looks_like_fqdn(single):
        return TargetClassification("domain", single, True)

    # 7. Looks like a passive sniffing target (interface name) — caller
    # usually sets scan_type="passive" but the classifier can be called
    # before the scan row is constructed.
    if _looks_like_passive_interface(single):
        return TargetClassification("interface", single, False)

    # 8. Fallback — single token that didn't match any of the above
    # patterns. Keep the original target verbatim and don't auto-wrap.
    if single not in _VALID_KINDS:
        return TargetClassification("other", single, False)
    return TargetClassification(single, single, False)


def suggest_group_name(target: Optional[str], scan_type: str | None = None) -> str:
    """Generate a human-readable default name for an auto-created ScanGroup.

    Examples:
        >>> suggest_group_name("192.168.1.0/24")
        'Network scan: 192.168.1.0/24'
        >>> suggest_group_name("scanme.pqc")
        'Domain scan: scanme.pqc'
        >>> suggest_group_name("10.0.0.1,10.0.0.2")
        'Network scan: 10.0.0.1,10.0.0.2'
    """
    cls = classify_target(target)
    if cls.kind == "network_range":
        return f"Network scan: {cls.label}"
    if cls.kind == "domain":
        return f"Domain scan: {cls.label}"
    if cls.kind == "host":
        return f"Host scan: {cls.label}"
    if cls.kind == "interface":
        return f"Interface scan: {cls.label}"
    if cls.kind == "cloud_account":
        return f"Cloud scan: {cls.label}"
    if cls.kind == "code_repo":
        return f"Code repo scan: {cls.label}"
    if cls.kind == "saas_tenant":
        return f"SaaS scan: {cls.label}"
    if scan_type:
        return f"{scan_type.replace('_', ' ').title()} scan: {cls.label or target or 'unknown'}"
    return f"Scan: {cls.label or target or 'unknown'}"
