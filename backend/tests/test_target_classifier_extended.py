import pytest
from app.utils.target_classifier import (
    classify_target,
    suggest_group_name,
    TargetClassification,
    _looks_like_cidr,
    _looks_like_ip,
    _looks_like_fqdn,
    _looks_like_passive_interface,
    _looks_like_connector_prefix,
    _split_multi_host,
)


class TestLooksLikeCidr:
    def test_valid_ipv4_cidr(self):
        assert _looks_like_cidr("192.168.1.0/24") is True

    def test_valid_ipv6_cidr(self):
        assert _looks_like_cidr("2001:db8::/32") is True

    def test_no_slash(self):
        assert _looks_like_cidr("192.168.1.0") is False

    def test_empty_parts(self):
        assert _looks_like_cidr("/24") is False
        assert _looks_like_cidr("192.168.1.0/") is False

    def test_invalid_mask(self):
        assert _looks_like_cidr("192.168.1.0/999") is False

    def test_url_like_path(self):
        assert _looks_like_cidr("https://example.com/path") is False

    def test_invalid_ip(self):
        assert _looks_like_cidr("999.999.999.999/24") is False


class TestLooksLikeIp:
    def test_valid_ipv4(self):
        assert _looks_like_ip("10.0.0.1") is True

    def test_valid_ipv6(self):
        assert _looks_like_ip("::1") is True

    def test_invalid(self):
        assert _looks_like_ip("not-an-ip") is False

    def test_none(self):
        assert _looks_like_ip(None) is False


class TestLooksLikeFqdn:
    def test_valid_fqdn(self):
        assert _looks_like_fqdn("example.com") is True

    def test_subdomain(self):
        assert _looks_like_fqdn("sub.example.com") is True

    def test_no_dot(self):
        assert _looks_like_fqdn("localhost") is False

    def test_with_slash(self):
        assert _looks_like_fqdn("example.com/path") is False

    def test_with_space(self):
        assert _looks_like_fqdn("example .com") is False


class TestLooksLikePassiveInterface:
    def test_eth0(self):
        assert _looks_like_passive_interface("eth0") is True

    def test_wlan0(self):
        assert _looks_like_passive_interface("wlan0") is True

    def test_any(self):
        assert _looks_like_passive_interface("any") is True

    def test_too_long(self):
        assert _looks_like_passive_interface("a" * 17) is False

    def test_with_slash(self):
        assert _looks_like_passive_interface("eth0/1") is False

    def test_with_space(self):
        assert _looks_like_passive_interface("eth 0") is False

    def test_http_prefix(self):
        assert _looks_like_passive_interface("http://eth0") is False


class TestLooksLikeConnectorPrefix:
    def test_ssh(self):
        assert _looks_like_connector_prefix("ssh:10.0.0.1:22") is True

    def test_aws(self):
        assert _looks_like_connector_prefix("aws:us-east-1") is True

    def test_no_prefix(self):
        assert _looks_like_connector_prefix("10.0.0.1") is False


class TestSplitMultiHost:
    def test_comma_separated(self):
        assert _split_multi_host("a.com,b.com") == ["a.com", "b.com"]

    def test_semicolon_separated(self):
        assert _split_multi_host("a.com;b.com") == ["a.com", "b.com"]

    def test_single_host(self):
        assert _split_multi_host("a.com") == ["a.com"]

    def test_strips_trailing_dot(self):
        assert _split_multi_host("a.com.") == ["a.com"]

    def test_strips_http_prefix(self):
        assert _split_multi_host("https://a.com") == ["a.com"]

    def test_strips_http_prefix_plain(self):
        assert _split_multi_host("http://a.com") == ["a.com"]

    def test_empty_string(self):
        assert _split_multi_host("") == []

    def test_whitespace_handling(self):
        assert _split_multi_host(" a.com , b.com ") == ["a.com", "b.com"]


class TestClassifyTargetExtended:
    def test_url_with_ip(self):
        cls = classify_target("http://10.0.0.1:8080/api")
        assert cls.kind == "host"
        assert cls.label == "10.0.0.1:8080"

    def test_passive_interface(self):
        cls = classify_target("eth0")
        assert cls.kind == "interface"
        assert cls.is_groupable is False

    def test_valid_enum_value_interface(self):
        # "other" matches passive interface regex (short, alphanumeric)
        cls = classify_target("other")
        assert cls.kind == "interface"

    def test_ipv6_address(self):
        cls = classify_target("::1")
        assert cls.kind == "host"

    def test_ipv6_cidr(self):
        cls = classify_target("2001:db8::/32")
        assert cls.kind == "network_range"
        assert cls.is_groupable is True


class TestSuggestGroupNameExtended:
    def test_interface(self):
        name = suggest_group_name("eth0")
        assert "Interface" in name

    def test_with_scan_type_fallback(self):
        name = suggest_group_name("!@#weird", scan_type="passive")
        assert "passive" in name.lower() or "Passive" in name

    def test_none_target_with_scan_type(self):
        name = suggest_group_name(None, scan_type="tls_only")
        assert isinstance(name, str)
        assert len(name) > 0

    def test_none_target_no_scan_type(self):
        name = suggest_group_name(None)
        assert isinstance(name, str)
        assert len(name) > 0
