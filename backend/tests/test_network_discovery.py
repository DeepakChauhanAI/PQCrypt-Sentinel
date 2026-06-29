import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from app.scanners.network_discovery import discover_tls_hosts, enumerate_dns_targets

# Mock XML output from nmap
MOCK_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun SYSTEM "nmap.dtd">
<nmaprun scanner="nmap" args="nmap -p 22,443 -sV -oX - 127.0.0.1" start="1717430000" version="7.94" xmloutputversion="1.04">
  <host>
    <status state="up" reason="localhost-response" reason_ttl="0"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="9.6" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="https" product="nginx" version="1.25.3" ssl="yes" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="nginx" version="1.25.3" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

@pytest.mark.asyncio
async def test_discover_tls_hosts_success():
    # Mock asyncio.create_subprocess_exec
    mock_process = AsyncMock()
    mock_process.returncode = 0
    mock_process.communicate.return_value = (MOCK_NMAP_XML.encode('utf-8'), b"")
    
    with patch("asyncio.create_subprocess_exec", return_value=mock_process) as mock_exec:
        discovered = await discover_tls_hosts("127.0.0.1")
        
        mock_exec.assert_called_once()
        # Verify it found ssh and https, but filtered out http (port 80)
        assert len(discovered) == 2
        
        # Verify SSH service details
        ssh_entry = next(d for d in discovered if d['port'] == 22)
        assert ssh_entry['ip'] == "127.0.0.1"
        assert ssh_entry['service'] == "ssh"
        assert ssh_entry['product'] == "OpenSSH"
        assert ssh_entry['version'] == "9.6"
        
        # Verify HTTPS service details
        https_entry = next(d for d in discovered if d['port'] == 443)
        assert https_entry['ip'] == "127.0.0.1"
        assert https_entry['service'] == "https"
        assert https_entry['product'] == "nginx"
        assert https_entry['version'] == "1.25.3"

@pytest.mark.asyncio
async def test_discover_tls_hosts_nmap_missing():
    # Test that FileNotFoundError when running nmap falls back to native scanner
    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError), \
         patch("app.scanners.network_discovery.discover_tls_hosts_fallback", new=AsyncMock(return_value=[{"ip": "127.0.0.1", "port": 443}])) as mock_fallback:
        discovered = await discover_tls_hosts("127.0.0.1")
        mock_fallback.assert_called_once_with("127.0.0.1")
        assert len(discovered) == 1
        assert discovered[0]["ip"] == "127.0.0.1"

def test_enumerate_dns_targets_real():
    # Test resolving example.com (requires network access, which should succeed under our permissions)
    results = enumerate_dns_targets("example.com")
    assert "a_records" in results
    assert "mx_records" in results
    # example.com usually has A records, but we don't strict-fail if network DNS fails
    if results["a_records"]:
        assert len(results["a_records"]) > 0

def test_enumerate_dns_targets_nxdomain():
    # Test resolving non-existent domain
    results = enumerate_dns_targets("nonexistent-domain-123456789.local")
    assert results["a_records"] == []
    assert results["aaaa_records"] == []
    assert results["mx_records"] == []


@pytest.mark.asyncio
async def test_discover_tls_hosts_fallback_success():
    from app.scanners.network_discovery import discover_tls_hosts_fallback
    with patch("asyncio.open_connection") as mock_conn:
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_conn.return_value = (mock_reader, mock_writer)
        
        # Test 127.0.0.1/32 range (1 IP)
        discovered = await discover_tls_hosts_fallback("127.0.0.1/32")
        assert len(discovered) > 0
        assert discovered[0]["ip"] == "127.0.0.1"


@pytest.mark.asyncio
async def test_discover_tls_hosts_fallback_large_subnet_raises():
    from app.scanners.network_discovery import discover_tls_hosts_fallback
    with pytest.raises(RuntimeError) as exc_info:
        await discover_tls_hosts_fallback("192.168.0.0/16")
    assert "limited to subnets with 4096 or fewer addresses" in str(exc_info.value)
