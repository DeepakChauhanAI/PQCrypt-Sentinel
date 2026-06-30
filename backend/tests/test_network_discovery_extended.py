import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio

from app.scanners.network_discovery import (
    discover_tls_hosts,
    enumerate_dns_targets,
    safe_resolve,
)


class TestEnumerateDNSTargets:
    def test_a_records(self):
        mock_answer = MagicMock()
        mock_answer.__str__ = lambda self: "93.184.216.34"
        with patch("dns.resolver.resolve") as mock_resolve:
            mock_resolve.side_effect = lambda d, rtype: (
                [mock_answer]
                if rtype == "A"
                else (_ for _ in ()).throw(Exception("no answer"))
            )
            result = enumerate_dns_targets("example.com")
            assert "93.184.216.34" in result["a_records"]

    def test_no_records(self):
        with patch("dns.resolver.resolve", side_effect=Exception("NXDOMAIN")):
            result = enumerate_dns_targets("nonexistent.example")
            assert result["a_records"] == []
            assert result["aaaa_records"] == []

    def test_mx_records(self):
        mock_mx = MagicMock()
        mock_mx.__str__ = lambda self: "10 mail.example.com"
        with patch("dns.resolver.resolve") as mock_resolve:

            def side_effect(domain, rtype):
                if rtype == "MX":
                    return [mock_mx]
                raise Exception("no answer")

            mock_resolve.side_effect = side_effect
            result = enumerate_dns_targets("example.com")
            assert "10 mail.example.com" in result["mx_records"]

    def test_unsafe_ip_filtered(self):
        mock_answer = MagicMock()
        mock_answer.__str__ = lambda self: "169.254.0.1"
        with patch("dns.resolver.resolve") as mock_resolve:
            mock_resolve.side_effect = lambda d, rtype: (
                [mock_answer]
                if rtype == "A"
                else (_ for _ in ()).throw(Exception("no"))
            )
            with patch(
                "app.scanners.network_discovery._ip_is_safe", return_value=False
            ):
                result = enumerate_dns_targets("evil.example")
                assert "169.254.0.1" not in result["a_records"]


class TestDiscoverTLSHosts:
    def test_nmap_not_found_falls_back(self):
        with patch(
            "asyncio.create_subprocess_exec", side_effect=FileNotFoundError
        ), patch(
            "app.scanners.network_discovery.discover_tls_hosts_fallback",
            new_callable=AsyncMock,
        ) as mock_fb:
            mock_fb.return_value = [{"ip": "10.0.0.1", "port": 443}]
            result = asyncio.run(discover_tls_hosts("10.0.0.0/30"))
            assert len(result) == 1
            mock_fb.assert_called_once()

    def test_nmap_generic_exception(self):
        with patch(
            "asyncio.create_subprocess_exec", side_effect=OSError("permission denied")
        ):
            with pytest.raises(RuntimeError, match="Failed to start nmap"):
                asyncio.run(discover_tls_hosts("10.0.0.0/30"))

    def test_nmap_nonzero_exit(self):
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error message"))
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            with pytest.raises(RuntimeError, match="nmap failed"):
                asyncio.run(discover_tls_hosts("10.0.0.0/30"))

    def test_nmap_invalid_xml(self):
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"not xml", b""))
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = asyncio.run(discover_tls_hosts("10.0.0.0/30"))
            assert result == []

    def test_nmap_success_with_hosts(self):
        xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="10.0.0.1" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="443">
                        <state state="open"/>
                        <service name="https" product="nginx" version="1.19"/>
                    </port>
                </ports>
            </host>
            <host>
                <status state="down"/>
                <address addr="10.0.0.2" addrtype="ipv4"/>
            </host>
        </nmaprun>"""
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(xml.encode(), b""))
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc), patch(
            "app.scanners.network_discovery.validate_ip"
        ), patch("app.scanners.network_discovery.validate_port"):
            result = asyncio.run(discover_tls_hosts("10.0.0.0/30"))
            assert len(result) == 1
            assert result[0]["ip"] == "10.0.0.1"
            assert result[0]["port"] == 443
            assert result[0]["service"] == "https"

    def test_nmap_filters_unsafe_ip(self):
        xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="127.0.0.1" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="443">
                        <state state="open"/>
                        <service name="https"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(xml.encode(), b""))
        from app.scanners.safe_target import UnsafeTargetError

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc), patch(
            "app.scanners.network_discovery.validate_ip",
            side_effect=UnsafeTargetError("loopback"),
        ):
            result = asyncio.run(discover_tls_hosts("10.0.0.0/30"))
            assert result == []

    def test_nmap_closed_port_skipped(self):
        xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="10.0.0.1" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="443">
                        <state state="closed"/>
                        <service name="https"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(xml.encode(), b""))
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc), patch(
            "app.scanners.network_discovery.validate_ip"
        ), patch("app.scanners.network_discovery.validate_port"):
            result = asyncio.run(discover_tls_hosts("10.0.0.0/30"))
            assert result == []

    def test_nmap_no_ports_node(self):
        xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="10.0.0.1" addrtype="ipv4"/>
            </host>
        </nmaprun>"""
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(xml.encode(), b""))
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc), patch(
            "app.scanners.network_discovery.validate_ip"
        ):
            result = asyncio.run(discover_tls_hosts("10.0.0.0/30"))
            assert result == []

    def test_nmap_ipv6_fallback(self):
        xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="2001:db8::1" addrtype="ipv6"/>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(xml.encode(), b""))
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc), patch(
            "app.scanners.network_discovery.validate_cidr"
        ), patch("app.scanners.network_discovery.validate_ip"), patch(
            "app.scanners.network_discovery.validate_port"
        ):
            result = asyncio.run(discover_tls_hosts("2001:db8::/128"))
            assert len(result) == 1

    def test_nmap_no_address_skipped(self):
        xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <ports>
                    <port protocol="tcp" portid="443">
                        <state state="open"/>
                        <service name="https"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(xml.encode(), b""))
        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = asyncio.run(discover_tls_hosts("10.0.0.0/30"))
            assert result == []

    def test_nmap_unsafe_port_skipped(self):
        xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="10.0.0.1" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="443">
                        <state state="open"/>
                        <service name="https"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(xml.encode(), b""))
        from app.scanners.safe_target import UnsafeTargetError

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc), patch(
            "app.scanners.network_discovery.validate_ip"
        ), patch(
            "app.scanners.network_discovery.validate_port",
            side_effect=UnsafeTargetError("unsafe port"),
        ):
            result = asyncio.run(discover_tls_hosts("10.0.0.0/30"))
            assert result == []


class TestSafeResolve:
    def test_calls_build_safe_target_async(self):
        with patch(
            "app.scanners.network_discovery.build_safe_target_async",
            new_callable=AsyncMock,
        ) as mock_build:
            mock_build.return_value = ("10.0.0.1", 443)
            result = asyncio.run(safe_resolve("10.0.0.1", 443))
            assert result == ("10.0.0.1", 443)
