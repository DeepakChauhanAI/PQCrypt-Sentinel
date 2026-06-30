import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import asyncio
import socket
from unittest.mock import patch, MagicMock, AsyncMock

from app.scanners.safe_target import (
    validate_ip,
    validate_cidr,
    validate_port,
    _resolve_sync,
    build_safe_target,
    resolve_safely,
    build_safe_target_async,
    _ip_is_safe,
    UnsafeTargetError,
)


class TestValidateIp:
    def test_multicast_address_rejected(self):
        with patch("app.scanners.safe_target.ALLOW_MULTICAST", False):
            with pytest.raises(UnsafeTargetError, match="not in the safe-target policy"):
                validate_ip("224.0.0.1")

    def test_reserved_address_rejected(self):
        with pytest.raises(UnsafeTargetError, match="not in the safe-target policy"):
            validate_ip("240.0.0.1")

    def test_unspecified_address_rejected(self):
        with pytest.raises(UnsafeTargetError, match="not in the safe-target policy"):
            validate_ip("0.0.0.0")

    def test_loopback_rejected_when_disabled(self):
        with patch("app.scanners.safe_target.ALLOW_LOOPBACK", False):
            with pytest.raises(UnsafeTargetError, match="not in the safe-target policy"):
                validate_ip("127.0.0.1")

    def test_private_rejected_when_disabled(self):
        with patch("app.scanners.safe_target.ALLOW_PRIVATE_RANGES", False):
            with pytest.raises(UnsafeTargetError, match="not in the safe-target policy"):
                validate_ip("192.168.1.1")

    def test_public_ip_accepted(self):
        validate_ip("8.8.8.8")


class TestValidateCidr:
    def test_empty_string_raises(self):
        with pytest.raises(UnsafeTargetError, match="empty network range"):
            validate_cidr("")

    def test_invalid_cidr_value_error(self):
        with pytest.raises(UnsafeTargetError, match="invalid CIDR"):
            validate_cidr("999.999.999.999/24")

    def test_public_range_too_large(self):
        with pytest.raises(UnsafeTargetError, match="too large for public scan"):
            validate_cidr("8.0.0.0/19")

    def test_private_range_accepted(self):
        validate_cidr("10.0.0.0/24")

    def test_single_ip_delegates_to_validate_ip(self):
        with patch("app.scanners.safe_target.ALLOW_LOOPBACK", False):
            with pytest.raises(UnsafeTargetError, match="not in the safe-target policy"):
                validate_cidr("127.0.0.1")


class TestResolveSync:
    def test_empty_host_returns_empty(self):
        assert _resolve_sync("") == []

    def test_ip_address_returns_as_is(self):
        result = _resolve_sync("8.8.8.8")
        assert result == ["8.8.8.8"]

    def test_dns_resolution_returns_ips(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (2, 1, 6, "", ("93.184.216.34", 0)),
                (2, 1, 6, "", ("93.184.216.35", 0)),
            ]
            result = _resolve_sync("example.com")
            assert "93.184.216.34" in result
            assert "93.184.216.35" in result

    def test_dns_failure_returns_empty(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("DNS failure")):
            result = _resolve_sync("nonexistent.invalid")
            assert result == []

    def test_deduplicates_ips(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (2, 1, 6, "", ("1.2.3.4", 0)),
                (2, 1, 6, "", ("1.2.3.4", 0)),
            ]
            result = _resolve_sync("dup.example.com")
            assert result == ["1.2.3.4"]


class TestBuildSafeTarget:
    def test_empty_host_raises(self):
        with pytest.raises(UnsafeTargetError, match="empty host"):
            build_safe_target("", 443)

    def test_no_safe_ips_after_resolution(self):
        with patch("app.scanners.safe_target._resolve_sync", return_value=["192.168.1.1"]), \
             patch("app.scanners.safe_target.ALLOW_PRIVATE_RANGES", False):
            with pytest.raises(UnsafeTargetError, match="resolved only to unsafe IPs"):
                build_safe_target("internal.host", 443)

    def test_unresolvable_host_raises(self):
        with patch("app.scanners.safe_target._resolve_sync", return_value=[]):
            with pytest.raises(UnsafeTargetError, match="could not be resolved"):
                build_safe_target("noexist.host", 443)

    def test_happy_path(self):
        with patch("app.scanners.safe_target._resolve_sync", return_value=["8.8.8.8"]):
            result = build_safe_target("dns.google", 443)
            assert result.host == "dns.google"
            assert result.ip == "8.8.8.8"
            assert result.port == 443


class TestResolveSafely:
    def test_all_unsafe_ips_raises(self):
        async def _test():
            with patch("app.scanners.safe_target._resolve_sync", return_value=["127.0.0.1"]), \
                 patch("app.scanners.safe_target.ALLOW_LOOPBACK", False):
                with pytest.raises(UnsafeTargetError, match="did not resolve to any safe IPs"):
                    await resolve_safely("localhost")

        asyncio.run(_test())

    def test_safe_ips_returned(self):
        async def _test():
            with patch("app.scanners.safe_target._resolve_sync", return_value=["8.8.8.8", "1.1.1.1"]):
                result = await resolve_safely("example.com")
                assert result == ["8.8.8.8", "1.1.1.1"]

        asyncio.run(_test())

    def test_mixed_safe_unsafe_filters(self):
        async def _test():
            with patch("app.scanners.safe_target._resolve_sync", return_value=["8.8.8.8", "127.0.0.1"]), \
                 patch("app.scanners.safe_target.ALLOW_LOOPBACK", False):
                result = await resolve_safely("mixed.host")
                assert result == ["8.8.8.8"]

        asyncio.run(_test())


class TestBuildSafeTargetAsync:
    def test_happy_path(self):
        async def _test():
            with patch("app.scanners.safe_target.resolve_safely", new_callable=AsyncMock) as mock_resolve:
                mock_resolve.return_value = ["93.184.216.34"]
                result = await build_safe_target_async("example.com", 443)
                assert result.host == "example.com"
                assert result.ip == "93.184.216.34"
                assert result.port == 443

        asyncio.run(_test())
