# Open-Source Integration Guide

**Product:** PQCrypt Sentinel PQC Discovery Platform  
**Version:** 1.0  
**Date:** June 2026  
**Author:** Engineering Team  
**Status:** Draft  

---

## 1. Overview

This document defines how PQCrypt Sentinel integrates open-source Python libraries and GitHub repositories to build its PQC discovery engine. The strategy is: **integrate, don't rebuild**. Our value is in the reconciliation, risk scoring, and dashboard layer — not in reimplementing battle-tested scanning tools.

---

## 2. Core Library Stack

### 2.1 pyshark — Passive & Active Packet Analysis

**Repo:** `https://github.com/KimiNewt/pyshark`  
**Install:** `pip install pyshark`  
**Dependency:** Requires tshark (Wireshark CLI) installed on the host

pyshark is a Python wrapper for tshark that provides deep protocol dissection. It's our primary tool for passive network monitoring and active TLS/SSH handshake analysis.

#### Use Cases in PQCrypt Sentinel

| Use Case | Mode | Description |
|---|---|---|
| **Passive TLS monitoring** | Live capture (SPAN port) | Observe real-time TLS handshakes on the wire |
| **PCAP file analysis** | Offline | Analyze pre-captured pcap files |
| **TLS handshake extraction** | Active/Passive | Extract ClientHello/ServerHello details |
| **Cipher suite enumeration** | Active/Passive | List all offered and negotiated cipher suites |
| **PQC key exchange detection** | Active/Passive | Detect ML-KEM hybrid groups in TLS extensions |
| **Certificate extraction** | Passive | Pull X.509 certificates from TLS handshakes |

#### Code Examples

**1. Live TLS Handshake Capture (Passive — SPAN Port)**

```python
import pyshark
import asyncio

async def capture_tls_handshakes(interface: str, duration_seconds: int = 60):
    """
    Capture TLS handshakes on a network interface.
    Use on a SPAN/mirror port to passively observe TLS negotiations.
    """
    cap = pyshark.LiveCapture(
        interface=interface,
        display_filter="tls.handshake.type == 1 or tls.handshake.type == 2",
        decode_as={"tcp.port==443": "tls"},
    )

    results = []
    for packet in cap.sniff_continuously(packet_count=100):
        try:
            if hasattr(packet, 'tls'):
                tls_layer = packet.tls
                
                # ClientHello (type 1)
                if hasattr(tls_layer, 'handshake_type') and tls_layer.handshake_type == '1':
                    result = {
                        'type': 'ClientHello',
                        'src_ip': packet.ip.src,
                        'dst_ip': packet.ip.dst,
                        'dst_port': packet.tcp.dstport,
                        'tls_version': getattr(tls_layer, 'handshake_version', None),
                        'cipher_suites': extract_cipher_suites(tls_layer),
                        'supported_groups': extract_supported_groups(tls_layer),
                        'timestamp': packet.sniff_time.isoformat(),
                    }
                    results.append(result)

                # ServerHello (type 2)
                if hasattr(tls_layer, 'handshake_type') and tls_layer.handshake_type == '2':
                    result = {
                        'type': 'ServerHello',
                        'src_ip': packet.ip.dst,  # server IP
                        'dst_ip': packet.ip.src,
                        'selected_cipher': getattr(tls_layer, 'handshake_ciphersuite', None),
                        'selected_group': getattr(tls_layer, 'handshake_extensions_key_share_group', None),
                        'tls_version': getattr(tls_layer, 'handshake_version', None),
                        'timestamp': packet.sniff_time.isoformat(),
                    }
                    results.append(result)
        except AttributeError:
            continue

    return results


def extract_cipher_suites(tls_layer) -> list:
    """Extract all offered cipher suites from ClientHello."""
    suites = []
    try:
        # pyshark exposes cipher suites as numbered fields
        for field_name in tls_layer.field_names:
            if 'handshake.ciphersuite' in field_name:
                val = getattr(tls_layer, field_name, None)
                if val:
                    suites.append(val)
    except Exception:
        pass
    return suites


def extract_supported_groups(tls_layer) -> list:
    """Extract supported groups (key exchange algorithms) from ClientHello."""
    groups = []
    try:
        for field_name in tls_layer.field_names:
            if 'handshake.extensions.supported_group' in field_name:
                val = getattr(tls_layer, field_name, None)
                if val:
                    groups.append(val)
    except Exception:
        pass
    return groups
```

**2. PQC-Specific TLS Extension Detection**

```python
# Known PQC and hybrid key exchange group IDs (IANA NamedGroup registry)
PQC_KEX_GROUPS = {
    # Pure PQC (experimental / future)
    0x01FC: "ML-KEM-512 (Kyber512)",
    0x01FD: "ML-KEM-768 (Kyber768)",
    0x0200: "ML-KEM-1024 (Kyber1024)",
    
    # Hybrid PQC (current best practice)
    0x2B92: "SecP256r1MLKEM768",
    0x2B93: "X25519MLKEM768",
    0x2B94: "SecP384r1MLKEM1024",
    
    # Experimental hybrids
    0xFE30: "X25519Kyber768Draft00",
    0x639A: "X25519Kyber768Draft00 (old codepoint)",
}

# PQC signature algorithm OIDs
PQC_SIGNATURE_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44 (Dilithium2)",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65 (Dilithium3)",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87 (Dilithium5)",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-256s",
    "1.3.6.1.4.1.62253.25642": "Falcon-512",
    "1.3.6.1.4.1.62253.25643": "Falcon-1024",
}

# Hybrid signature OIDs (composite)
HYBRID_SIGNATURE_OIDS = {
    "2.16.840.1.114027.80.4.1": "RSA-3072 + ML-DSA-65",
    "2.16.840.1.114027.80.4.2": "P-384 + ML-DSA-65",
    "2.16.840.1.114027.80.4.3": "P-521 + ML-DSA-87",
}


def classify_pqc_kex(group_id: int) -> dict:
    """Classify a TLS key exchange group as PQC or classical."""
    group_name = PQC_KEX_GROUPS.get(group_id, None)
    is_pqc = group_id in PQC_KEX_GROUPS
    is_hybrid = is_pqc and "Hybrid" in (group_name or "") or group_id in [
        0x2B92, 0x2B93, 0x2B94, 0xFE30, 0x639A
    ]
    
    return {
        "group_id": group_id,
        "group_name": group_name or f"Unknown ({hex(group_id)})",
        "is_pqc": is_pqc,
        "is_hybrid": is_hybrid,
        "pqc_status": "pqc_ready" if is_pqc and not is_hybrid else 
                      "hybrid" if is_hybrid else "vulnerable",
    }
```

**3. PCAP File Analysis (Offline Processing)**

```python
async def analyze_pcap_file(pcap_path: str) -> dict:
    """
    Analyze a pre-captured pcap file for PQC-relevant TLS data.
    Useful for customers who provide packet captures instead of live access.
    """
    cap = pyshark.FileCapture(
        input_file=pcap_path,
        display_filter="tls",
        decode_as={"tcp.port==443": "tls"},
    )

    findings = {
        "total_tls_handshakes": 0,
        "pqc_kex_negotiated": [],
        "vulnerable_kex": [],
        "certificates": [],
        "cipher_suites_seen": set(),
    }

    for packet in cap:
        try:
            if not hasattr(packet, 'tls'):
                continue

            tls = packet.tls
            
            # ServerHello — what was actually negotiated
            if hasattr(tls, 'handshake_type') and tls.handshake_type == '2':
                findings["total_tls_handshakes"] += 1
                
                cipher = getattr(tls, 'handshake_ciphersuite', None)
                if cipher:
                    findings["cipher_suites_seen"].add(cipher)

                # Check for PQC key exchange group
                group_id = getattr(tls, 'handshake_extensions_key_share_group', None)
                if group_id:
                    group_info = classify_pqc_kex(int(group_id))
                    if group_info["is_pqc"]:
                        findings["pqc_kex_negotiated"].append({
                            "server": packet.ip.dst,
                            "group": group_info,
                            "timestamp": packet.sniff_time.isoformat(),
                        })
                    else:
                        findings["vulnerable_kex"].append({
                            "server": packet.ip.dst,
                            "group_id": int(group_id),
                            "timestamp": packet.sniff_time.isoformat(),
                        })

            # Certificate message (type 11)
            if hasattr(tls, 'handshake_type') and tls.handshake_type == '11':
                cert_data = getattr(tls, 'handshake_certificate', None)
                if cert_data:
                    findings["certificates"].append({
                        "server": packet.ip.dst,
                        "raw_cert_hex": str(cert_data),
                        "timestamp": packet.sniff_time.isoformat(),
                    })

        except (AttributeError, ValueError):
            continue

    cap.close()
    findings["cipher_suites_seen"] = list(findings["cipher_suites_seen"])
    return findings
```

**4. SSH Handshake Analysis**

```python
async def capture_ssh_handshakes(interface: str, duration: int = 60):
    """
    Capture SSH key exchange init messages to detect PQC KEX algorithms.
    SSH KEX_INIT (type 20) contains the list of supported algorithms.
    """
    cap = pyshark.LiveCapture(
        interface=interface,
        display_filter="ssh.message_code == 20",  # KEX_INIT
    )

    results = []
    for packet in cap.sniff_continuously(packet_count=50):
        try:
            if hasattr(packet, 'ssh'):
                ssh = packet.ssh
                
                # Extract KEX algorithms offered
                kex_algos = []
                for field_name in ssh.field_names:
                    if 'ssh.kex_algorithms' in field_name:
                        val = getattr(ssh, field_name, None)
                        if val:
                            kex_algos.append(val)

                # Check for PQC KEX
                pqc_kex = [a for a in kex_algos if any(p in a for p in [
                    'mlkem', 'sntrup', 'kyber', 'ntrup', 'pqc'
                ])]

                results.append({
                    'src_ip': packet.ip.src,
                    'dst_ip': packet.ip.dst,
                    'kex_algorithms': kex_algos,
                    'pqc_kex_available': len(pqc_kex) > 0,
                    'pqc_kex_algorithms': pqc_kex,
                    'timestamp': packet.sniff_time.isoformat(),
                })
        except AttributeError:
            continue

    cap.close()
    return results
```

---

### 2.2 cryptography — Certificate Parsing & OID Detection

**Package:** `cryptography` (pyca/cryptography)  
**Install:** `pip install cryptography`  
**Repo:** `https://github.com/pyca/cryptography`

This is the foundational library for X.509 certificate parsing, signature algorithm detection, and PQC OID identification.

#### Use Cases

| Use Case | Description |
|---|---|
| **Certificate parsing** | Load PEM/DER certs, extract all fields |
| **Algorithm detection** | Get signature algorithm OID, public key algorithm |
| **Key size extraction** | RSA key bits, ECC curve identification |
| **Chain validation** | Verify cert chain, check expiry |
| **PQC OID matching** | Match OIDs against known PQC algorithm identifiers |

#### Code Examples

```python
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.x509.oid import ExtensionOID, NameOID
import ssl
import socket
from datetime import datetime, timezone


def fetch_and_parse_certificate(host: str, port: int = 443) -> dict:
    """Fetch TLS certificate from a host and parse it for PQC analysis."""
    
    # Fetch the certificate
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            negotiated_protocol = ssock.version()
            negotiated_cipher = ssock.cipher()

    # Parse the certificate
    cert = x509.load_der_x509_certificate(der_cert)
    
    # Extract signature algorithm
    sig_alg_oid = cert.signature_algorithm_oid.dotted_string
    sig_alg_name = cert.signature_algorithm_oid._name
    
    # Extract public key info
    public_key = cert.public_key()
    key_info = analyze_public_key(public_key)
    
    # Extract SANs
    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [name.value for name in san_ext.value]
    except x509.ExtensionNotFound:
        pass
    
    # Check for PQC
    pqc_info = classify_signature_algorithm(sig_alg_oid)
    
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, 'x'),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "is_expired": cert.not_valid_after_utc < datetime.now(timezone.utc),
        "sig_algorithm_oid": sig_alg_oid,
        "sig_algorithm_name": sig_alg_name,
        "public_key": key_info,
        "sans": sans,
        "tls_version": negotiated_protocol,
        "cipher_suite": negotiated_cipher,
        "pqc_analysis": pqc_info,
        "thumbprint": cert.fingerprint(hashes.SHA256()).hex(':'),
    }


def analyze_public_key(public_key) -> dict:
    """Analyze a public key for algorithm type and size."""
    
    if isinstance(public_key, rsa.RSAPublicKey):
        return {
            "algorithm": "RSA",
            "key_size": public_key.key_size,
            "is_quantum_vulnerable": True,
            "pqc_status": "vulnerable",
        }
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name
        return {
            "algorithm": "EC",
            "curve": curve_name,
            "key_size": public_key.key_size,
            "is_quantum_vulnerable": True,
            "pqc_status": "vulnerable",
        }
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        return {
            "algorithm": "Ed25519",
            "key_size": 256,
            "is_quantum_vulnerable": True,  # Not PQC
            "pqc_status": "vulnerable",
        }
    else:
        # Check for PQC key types (via OQS provider or raw key bytes)
        try:
            key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return {
                "algorithm": "Unknown",
                "raw_bytes_length": len(key_bytes),
                "is_quantum_vulnerable": False,
                "pqc_status": "unknown",
            }
        except Exception:
            return {
                "algorithm": "Unknown",
                "is_quantum_vulnerable": False,
                "pqc_status": "unknown",
            }


def classify_signature_algorithm(oid: str) -> dict:
    """Classify a signature algorithm OID as PQC or classical."""
    
    PQC_SIG_OIDS = {
        "2.16.840.1.101.3.4.3.17": {"name": "ML-DSA-44", "pqc_status": "pqc_ready"},
        "2.16.840.1.101.3.4.3.18": {"name": "ML-DSA-65", "pqc_status": "pqc_ready"},
        "2.16.840.1.101.3.4.3.19": {"name": "ML-DSA-87", "pqc_status": "pqc_ready"},
        "2.16.840.1.101.3.4.3.20": {"name": "SLH-DSA-SHA2-128s", "pqc_status": "pqc_ready"},
        "2.16.840.1.101.3.4.3.21": {"name": "SLH-DSA-SHA2-128f", "pqc_status": "pqc_ready"},
        "2.16.840.1.101.3.4.3.22": {"name": "SLH-DSA-SHA2-192s", "pqc_status": "pqc_ready"},
        "2.16.840.1.101.3.4.3.23": {"name": "SLH-DSA-SHA2-256s", "pqc_status": "pqc_ready"},
        "1.3.6.1.4.1.62253.25642": {"name": "Falcon-512", "pqc_status": "pqc_ready"},
        "1.3.6.1.4.1.62253.25643": {"name": "Falcon-1024", "pqc_status": "pqc_ready"},
        # Hybrid/composite
        "2.16.840.1.114027.80.4.1": {"name": "RSA3072+ML-DSA-65", "pqc_status": "hybrid"},
        "2.16.840.1.114027.80.4.2": {"name": "P384+ML-DSA-65", "pqc_status": "hybrid"},
        "2.16.840.1.114027.80.4.3": {"name": "P521+ML-DSA-87", "pqc_status": "hybrid"},
    }
    
    # Classical OIDs
    CLASSICAL_OIDS = {
        "1.2.840.113549.1.1.11": {"name": "SHA256-RSA", "pqc_status": "vulnerable"},
        "1.2.840.113549.1.1.12": {"name": "SHA384-RSA", "pqc_status": "vulnerable"},
        "1.2.840.113549.1.1.13": {"name": "SHA512-RSA", "pqc_status": "vulnerable"},
        "1.2.840.10045.4.3.2": {"name": "SHA256-ECDSA", "pqc_status": "vulnerable"},
        "1.2.840.10045.4.3.3": {"name": "SHA384-ECDSA", "pqc_status": "vulnerable"},
        "1.3.101.112": {"name": "Ed25519", "pqc_status": "vulnerable"},
    }
    
    if oid in PQC_SIG_OIDS:
        info = PQC_SIG_OIDS[oid]
        return {"is_pqc": True, "is_classical": False, **info}
    elif oid in CLASSICAL_OIDS:
        info = CLASSICAL_OIDS[oid]
        return {"is_pqc": False, "is_classical": True, **info}
    else:
        return {"is_pqc": False, "is_classical": False, "name": f"Unknown ({oid})", "pqc_status": "unknown"}
```

---

### 2.3 sslyze — Deep TLS Analysis (Python Library)

**Package:** `sslyze`  
**Install:** `pip install sslyze`  
**Repo:** `https://github.com/nabla-c0d3/sslyze`

SSLyze is a battle-tested TLS analysis tool. We use its Python API directly (not CLI).

```python
from sslyze import (
    ServerNetworkLocation,
    ServerScanRequest,
    ScanCommand,
)
from sslyze.scanner import Scanner
from sslyze.server_connectivity import check_connectivity


async def scan_tls_endpoint(host: str, port: int = 443) -> dict:
    """Deep TLS analysis using SSLyze Python API."""
    
    # Check connectivity
    server_location = ServerNetworkLocation(hostname=host, port=port)
    connectivity = check_connectivity(server_location)
    
    if not connectivity:
        return {"error": f"Cannot connect to {host}:{port}"}
    
    # Define scan commands
    scan_requests = [
        ServerScanRequest(
            server_info=connectivity,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.SSH_COMPRESSION,
            },
        ),
    ]
    
    # Run scan
    scanner = Scanner()
    results = []
    for result in scanner.get_results(scan_requests):
        results.append(result)
    
    # Process results
    findings = {
        "host": host,
        "port": port,
        "tls_versions": {},
        "certificate_info": None,
        "pqc_analysis": {},
    }
    
    for result in results:
        # Certificate info
        if result.scan_commands_results.get(ScanCommand.CERTIFICATE_INFO):
            cert_result = result.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
            findings["certificate_info"] = {
                "is_leaf_certificate_ev": cert_result.certificate_deployments[0].leaf_certificate_is_ev,
                "has_ct_scts": len(cert_result.certificate_deployments[0].scts) > 0,
            }
        
        # Cipher suites per TLS version
        for tls_cmd in [ScanCommand.TLS_1_3_CIPHER_SUITES, 
                        ScanCommand.TLS_1_2_CIPHER_SUITES,
                        ScanCommand.TLS_1_1_CIPHER_SUITES, 
                        ScanCommand.TLS_1_0_CIPHER_SUITES]:
            if result.scan_commands_results.get(tls_cmd):
                cipher_result = result.scan_commands_results[tls_cmd]
                findings["tls_versions"][tls_cmd.name] = {
                    "accepted_ciphers": [
                        {"name": cs.name, "key_size": cs.key_size}
                        for cs in cipher_result.accepted_cipher_suites
                    ],
                    "rejected_count": len(cipher_result.rejected_cipher_suites),
                }
    
    return findings
```

---

### 2.4 scapy — Packet Crafting & Protocol Analysis

**Package:** `scapy`  
**Install:** `pip install scapy`  
**Repo:** `https://github.com/secdev/scapy`

scapy is used for low-level packet crafting and protocol analysis — complementing pyshark for cases where we need to craft custom probes.

```python
from scapy.all import *
from scapy.layers.tls.all import *
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello


def probe_tls_with_pqc_groups(target_ip: str, port: int = 443) -> dict:
    """
    Craft a TLS ClientHello that advertises PQC key exchange groups
    to test if the server supports them.
    """
    # Build ClientHello with PQC groups in supported_groups extension
    client_hello = TLSClientHello(
        version=0x0303,  # TLS 1.2
        ciphers=[
            0x1301,  # TLS_AES_128_GCM_SHA256
            0x1302,  # TLS_AES_256_GCM_SHA384
            0x1303,  # TLS_CHACHA20_POLY1305_SHA256
            0xC02B,  # ECDHE-ECDSA-AES128-GCM-SHA256
            0xC02F,  # ECDHE-RSA-AES128-GCM-SHA256
        ],
        ext=TLS_Ext_SupportedGroups(
            groups=[
                0x2B93,  # X25519MLKEM768 (hybrid PQC)
                0x2B92,  # SecP256r1MLKEM768 (hybrid PQC)
                0x001D,  # x25519
                0x0017,  # secp256r1
            ]
        ),
    )
    
    # Send and receive
    pkt = IP(dst=target_ip) / TCP(dport=port, flags='S')
    syn_ack = sr1(pkt, timeout=5)
    
    if not syn_ack:
        return {"error": "No response"}
    
    # Complete TCP handshake, then send TLS
    # (Simplified — real implementation handles full handshake)
    return {"status": "probe_sent", "target": target_ip}
```

---

### 2.5 paramiko — SSH Analysis

**Package:** `paramiko`  
**Install:** `pip install paramiko`  
**Repo:** `https://github.com/paramiko/paramiko`

```python
import paramiko
import socket


def audit_ssh_endpoint(host: str, port: int = 22) -> dict:
    """Audit SSH server for PQC readiness."""
    
    sock = socket.create_connection((host, port), timeout=10)
    transport = paramiko.Transport(sock)
    transport.connect()
    
    # Get negotiated algorithms
    kex = transport.remote_kex_algos
    host_keys = transport.remote_key_algos
    ciphers = transport.remote_cipher_algos
    
    # Check for PQC KEX
    pqc_kex_keywords = ['mlkem', 'sntrup', 'kyber', 'ntrup', 'pqc']
    pqc_kex = [a for a in kex if any(kw in a.lower() for kw in pqc_kex_keywords)]
    
    # Check for PQC host key algorithms
    pqc_host_keys = [a for a in host_keys if any(kw in a.lower() for kw in pqc_kex_keywords)]
    
    transport.close()
    sock.close()
    
    return {
        "host": host,
        "port": port,
        "remote_kex_algorithms": list(kex),
        "remote_host_key_algorithms": list(host_keys),
        "remote_cipher_algorithms": list(ciphers),
        "pqc_kex_available": len(pqc_kex) > 0,
        "pqc_kex_algorithms": pqc_kex,
        "pqc_host_keys_available": len(pqc_host_keys) > 0,
        "pqc_host_key_algorithms": pqc_host_keys,
        "pqc_status": "pqc_ready" if pqc_kex else "vulnerable",
    }
```

---

### 2.6 python-nmap — Network Discovery

**Package:** `python-nmap`  
**Install:** `pip install python-nmap`  
**Requires:** nmap installed on host

```python
import nmap


def discover_tls_hosts(network_range: str) -> list:
    """Discover hosts with TLS services on a network range."""
    nm = nmap.PortScanner()
    
    # Scan for common TLS ports
    nm.scan(hosts=network_range, ports='443,8443,636,993,995,8883', arguments='-sV --script ssl-enum-ciphers')
    
    hosts = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                service = nm[host][proto][port]
                if service.get('name') in ['https', 'ldaps', 'imaps', 'pop3s', 'smtps', 'mqtt']:
                    hosts.append({
                        'ip': host,
                        'port': port,
                        'service': service.get('name'),
                        'version': service.get('version', ''),
                        'product': service.get('product', ''),
                    })
    return hosts
```

---

### 2.7 dnspython — DNS Enumeration

**Package:** `dnspython`  
**Install:** `pip install dnspython`

```python
import dns.resolver
import dns.zone
import dns.query


def enumerate_dns_targets(domain: str) -> dict:
    """Enumerate DNS records to discover TLS endpoints."""
    results = {
        "a_records": [],
        "aaaa_records": [],
        "cname_records": [],
        "mx_records": [],
        "srv_records": [],
    }
    
    for rtype in ['A', 'AAAA', 'CNAME', 'MX', 'SRV']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                results[f"{rtype.lower()}_records"].append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
    
    return results
```

---

### 2.8 boto3 — AWS Cloud Scanning

**Package:** `boto3`  
**Install:** `pip install boto3`

```python
import boto3


def scan_aws_kms_keys(region: str = 'us-east-1') -> list:
    """Inventory AWS KMS keys and check for PQC readiness."""
    kms = boto3.client('kms', region_name=region)
    
    keys = []
    paginator = kms.get_paginator('list_keys')
    
    for page in paginator.paginate():
        for key in page['Keys']:
            key_id = key['KeyId']
            detail = kms.describe_key(KeyId=key_id)
            key_meta = detail['KeyMetadata']
            
            keys.append({
                'key_id': key_id,
                'arn': key_meta['Arn'],
                'algorithm': key_meta['CustomerMasterKeySpec'],
                'key_usage': key_meta['KeyUsage'],
                'key_state': key_meta['KeyState'],
                'origin': key_meta['Origin'],
                'multi_region': key_meta.get('MultiRegion', False),
                'pqc_status': classify_kms_algorithm(key_meta['CustomerMasterKeySpec']),
            })
    
    return keys


def scan_aws_acm_certificates(region: str = 'us-east-1') -> list:
    """Inventory AWS ACM certificates."""
    acm = boto3.client('acm', region_name=region)
    
    certs = []
    paginator = acm.get_paginator('list_certificates')
    
    for page in paginator.paginate():
        for cert in page['CertificateSummaryList']:
            detail = acm.describe_certificate(CertificateArn=cert['CertificateArn'])
            cert_data = detail['Certificate']
            
            certs.append({
                'arn': cert['CertificateArn'],
                'domain': cert_data['DomainName'],
                'algorithm': cert_data.get('KeyAlgorithm', 'unknown'),
                'not_after': cert_data.get('NotAfter', '').isoformat() if cert_data.get('NotAfter') else None,
                'status': cert_data['Status'],
                'pqc_status': classify_kms_algorithm(cert_data.get('KeyAlgorithm', '')),
            })
    
    return certs


def classify_kms_algorithm(algorithm: str) -> str:
    """Classify a KMS/ACM key algorithm."""
    vulnerable = ['RSA_2048', 'RSA_3072', 'RSA_4096', 'EC_prime256v1', 'EC_secp384r1', 'EC_prime256v1']
    if any(v in algorithm for v in vulnerable):
        return 'vulnerable'
    elif 'ML-KEM' in algorithm or 'Kyber' in algorithm:
        return 'pqc_ready'
    return 'unknown'
```

---

## 3. GitHub Repository Integration

### 3.1 Repos to Integrate (CLI Wrappers)

These tools are integrated by wrapping their CLI output (JSON mode) as subprocess calls.

| Repo | Language | Integration | JSON Output | Effort |
|---|---|---|---|---|
| **pqcscan** | Rust | CLI binary, JSON output | Yes | 1-2 days |
| **testssl.sh** | Bash | CLI, JSON output (`--jsonfile`) | Yes | 2-3 days |
| **ssh-audit** | Python/Bash | CLI, JSON output (`-j`) | Yes | 1-2 days |
| **ike-scan** | C | CLI, custom parsing | No | 3-5 days |
| **Trivy** | Go | CLI, JSON output (`-f json`) | Yes | 1-2 days |
| **Semgrep** | Python/OCaml | CLI, JSON output (`--json`) | Yes | 2-3 days |

#### Example: pqcscan Integration

```python
import subprocess
import json
import asyncio


async def run_pqcscan(host: str, port: int = 443) -> dict:
    """Run pqcscan against a TLS endpoint."""
    
    cmd = [
        "pqcscan",
        "--target", f"{host}:{port}",
        "--output-format", "json",
        "--timeout", "30",
    ]
    
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    
    stdout, stderr = await proc.communicate()
    
    if proc.returncode != 0:
        return {"error": stderr.decode(), "host": host}
    
    result = json.loads(stdout.decode())
    
    # Normalize into our schema
    return {
        "host": host,
        "port": port,
        "tool": "pqcscan",
        "tls_version": result.get("tls_version"),
        "cipher_suite": result.get("cipher_suite"),
        "kex_group": result.get("key_exchange_group"),
        "kex_group_is_pqc": result.get("is_pqc", False),
        "certificate": result.get("certificate", {}),
        "pqc_status": "pqc_ready" if result.get("is_pqc") else "vulnerable",
        "raw_output": result,
    }


async def run_testssl(host: str, port: int = 443) -> dict:
    """Run testssl.sh in JSON mode."""
    
    json_file = f"/tmp/testssl_{host}_{port}.json"
    
    cmd = [
        "testssl.sh",
        "--jsonfile", json_file,
        "--color", "0",
        f"{host}:{port}",
    ]
    
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    
    await proc.communicate()
    
    # Parse JSON output
    try:
        with open(json_file, 'r') as f:
            results = json.load(f)
    except FileNotFoundError:
        return {"error": "testssl output not found", "host": host}
    
    # Extract PQC-relevant findings
    findings = {
        "host": host,
        "port": port,
        "tool": "testssl",
        "protocols": [],
        "cipher_suites": [],
        "vulnerabilities": [],
        "pqc_findings": [],
    }
    
    for entry in results:
        if entry.get("id") == "protocols":
            findings["protocols"] = entry.get("finding", [])
        elif "cipher" in entry.get("id", "").lower():
            findings["cipher_suites"].append(entry)
        elif entry.get("severity") in ["HIGH", "CRITICAL"]:
            findings["vulnerabilities"].append(entry)
    
    return findings
```

### 3.2 Repos to Study (Architecture Reference)

| Repo | What to Learn |
|---|---|
| **CryptoNext COMPASS** | Open discovery + commercial probe architecture. Study their scanner schema. |
| **IBM CBOMkit** | CycloneDX CBOM generation format. Use their Python lib for CBOM output. |
| **QRAMM CryptoScan** | SAST rules for crypto API detection. Import their Semgrep rules. |
| **CycloneDX Python lib** | `cyclonedx-python-lib` — direct CBOM generation |

### 3.3 Semgrep Crypto Rules Integration

```python
import subprocess
import json


def run_crypto_sast(repo_path: str) -> list:
    """Run Semgrep with crypto-specific rules to find hardcoded keys and weak crypto."""
    
    # Use QRAMM-influenced rules + custom patterns
    rules = [
        "p/python",
        "p/cwe-top-25",
        # Custom crypto rules
        "p/quantumshield-crypto",  # Our custom ruleset
    ]
    
    cmd = [
        "semgrep",
        "--config", "p/python",
        "--config", "p/cwe-top-25",
        "--json",
        "--quiet",
        repo_path,
    ]
    
    proc = subprocess.run(cmd, capture_output=True, text=True)
    
    if proc.returncode not in [0, 1]:  # 1 = findings found
        return []
    
    results = json.loads(proc.stdout)
    
    crypto_findings = []
    crypto_patterns = [
        'RSA_generate_key', 'EC_KEY_generate', 'DSA_generate',
        'MD5', 'SHA1', 'DES_', 'RC4', 'Blowfish',
        'hardcoded', 'private_key', 'BEGIN RSA PRIVATE KEY',
        'password =', 'secret =', 'api_key =',
    ]
    
    for result in results.get("results", []):
        code = result.get("extra", {}).get("lines", "")
        if any(pat.lower() in code.lower() for pat in crypto_patterns):
            crypto_findings.append({
                "file": result["path"],
                "line": result["start"]["line"],
                "code": code.strip(),
                "rule": result["check_id"],
                "severity": result["extra"]["severity"],
                "message": result["extra"]["message"],
            })
    
    return crypto_findings
```

---

## 4. Vendor PQC Readiness Database

A unique feature — no competitor has this. Build a database mapping software versions to PQC support.

```python
# Vendor PQC readiness knowledge base
VENDOR_PQC_DB = {
    "openssl": {
        "3.0": {"ml_kem": False, "ml_dsa": False, "notes": "No PQC support"},
        "3.2": {"ml_kem": False, "ml_dsa": False, "notes": "No PQC support"},
        "3.4": {"ml_kem": True, "ml_dsa": False, "notes": "ML-KEM via oqs-provider"},
        "3.5": {"ml_kem": True, "ml_dsa": True, "notes": "Native ML-KEM/ML-DSA support"},
    },
    "boringssl": {
        "2024-09": {"ml_kem": True, "ml_dsa": False, "notes": "X25519MLKEM768 enabled by default"},
    },
    "nss": {
        "3.101": {"ml_kem": True, "ml_dsa": False, "notes": "ML-KEM support added"},
    },
    "libressl": {
        "3.9": {"ml_kem": False, "ml_dsa": False, "notes": "No PQC support yet"},
    },
    "mbedtls": {
        "3.6": {"ml_kem": False, "ml_dsa": False, "notes": "No PQC support yet"},
    },
    "thales_luna": {
        "7.9": {"ml_kem": True, "ml_dsa": True, "notes": "PQC firmware update available"},
    },
    "aws_kms": {
        "2024-11": {"ml_kem": True, "ml_dsa": False, "notes": "ML-KEM key types available"},
    },
    "aws_cloudhsm": {
        "5.8": {"ml_kem": True, "ml_dsa": True, "notes": "Full PQC support"},
    },
    "azure_keyvault": {
        "2025-01": {"ml_kem": True, "ml_dsa": False, "notes": "ML-KEM preview"},
    },
    "windows": {
        "11_24H2": {"ml_kem": True, "ml_dsa": False, "notes": "ML-KEM via CNG"},
        "server_2025": {"ml_kem": True, "ml_dsa": True, "notes": "Full PQC via CNG"},
    },
    "openssh": {
        "9.0": {"ml_kem": False, "ml_dsa": False, "notes": "sntrup761x25519 experimental"},
        "9.9": {"ml_kem": True, "ml_dsa": False, "notes": "mlkem768x25519 support"},
    },
}


def get_pqc_readiness(software: str, version: str) -> dict:
    """Look up PQC readiness for a specific software version."""
    sw_db = VENDOR_PQC_DB.get(software.lower(), {})
    
    # Find closest version match
    for db_version, info in sorted(sw_db.items(), reverse=True):
        if version.startswith(db_version) or db_version in version:
            return {
                "software": software,
                "version": version,
                "matched_version": db_version,
                "ml_kem": info["ml_kem"],
                "ml_dsa": info["ml_dsa"],
                "notes": info["notes"],
                "pqc_ready": info["ml_kem"] and info["ml_dsa"],
            }
    
    return {
        "software": software,
        "version": version,
        "ml_kem": None,
        "ml_dsa": None,
        "notes": "Unknown — not in vendor database",
        "pqc_ready": None,
    }
```

---

## 5. Complete Scanner Worker Architecture

```python
# scanner/workers/tls_worker.py

import asyncio
from dataclasses import dataclass
from typing import Optional
import pyshark
from cryptography import x509
import ssl
import socket


@dataclass
class TLSScanResult:
    host: str
    port: int
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    kex_group: Optional[str]
    kex_group_id: Optional[int]
    is_pqc: bool
    is_hybrid: bool
    pqc_status: str
    certificate: Optional[dict]
    error: Optional[str] = None


async def scan_tls_endpoint(host: str, port: int = 443, timeout: int = 10) -> TLSScanResult:
    """
    Complete TLS endpoint scan combining:
    1. ssl module for basic handshake
    2. cryptography lib for cert parsing
    3. PQC OID classification
    """
    try:
        # Step 1: TLS handshake
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                tls_version = ssock.version()
                cipher_info = ssock.cipher()
                der_cert = ssock.getpeercert(binary_form=True)

        # Step 2: Parse certificate
        cert = x509.load_der_x509_certificate(der_cert)
        sig_alg_oid = cert.signature_algorithm_oid.dotted_string
        pub_key = cert.public_key()
        
        # Step 3: Classify
        from .pqc_classifier import classify_signature_algorithm, classify_public_key
        
        sig_info = classify_signature_algorithm(sig_alg_oid)
        key_info = classify_public_key(pub_key)
        
        # Determine overall PQC status
        if sig_info["is_pqc"] and key_info["is_pqc"]:
            pqc_status = "pqc_ready"
        elif sig_info.get("is_hybrid") or key_info.get("is_hybrid"):
            pqc_status = "hybrid"
        else:
            pqc_status = "vulnerable"

        return TLSScanResult(
            host=host,
            port=port,
            tls_version=tls_version,
            cipher_suite=cipher_info[0] if cipher_info else None,
            kex_group=cipher_info[1] if cipher_info else None,
            kex_group_id=None,
            is_pqc=pqc_status == "pqc_ready",
            is_hybrid=pqc_status == "hybrid",
            pqc_status=pqc_status,
            certificate={
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "sig_algorithm_oid": sig_alg_oid,
                "sig_algorithm_name": sig_info["name"],
                "pub_key_algorithm": key_info["algorithm"],
                "pub_key_size": key_info.get("key_size"),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "thumbprint": cert.fingerprint(
                    __import__('cryptography').hazmat.primitives.hashes.SHA256()
                ).hex(':'),
            },
        )
    except Exception as e:
        return TLSScanResult(
            host=host, port=port,
            tls_version=None, cipher_suite=None,
            kex_group=None, kex_group_id=None,
            is_pqc=False, is_hybrid=False,
            pqc_status="error",
            certificate=None,
            error=str(e),
        )
```

---

## 6. Integration Priority Matrix

| Library/Tool | Phase | Effort | Value | Priority |
|---|---|---|---|---|
| **cryptography** | MVP | 2 days | Foundation for all cert analysis | Critical |
| **pyshark** | MVP | 3 days | Passive monitoring + PCAP analysis | High |
| **sslyze** (Python API) | MVP | 2 days | Deep TLS analysis | Critical |
| **paramiko** | MVP | 1 day | SSH audit | High |
| **python-nmap** | Phase 2 | 2 days | Network discovery | Medium |
| **dnspython** | Phase 2 | 1 day | DNS enumeration | Medium |
| **boto3** | Phase 2 | 3 days | AWS cloud scanning | High |
| **azure-mgmt** | Phase 2 | 3 days | Azure cloud scanning | Medium |
| **google-cloud** | Phase 2 | 3 days | GCP cloud scanning | Medium |
| **pqcscan** (CLI) | MVP | 1 day | PQC handshake detection | Critical |
| **testssl.sh** (CLI) | MVP | 2 days | Comprehensive TLS grading | High |
| **ssh-audit** (CLI) | MVP | 1 day | SSH config audit | High |
| **Trivy** (CLI) | Phase 2 | 2 days | Container/SBOM scanning | Medium |
| **Semgrep** (CLI) | Phase 2 | 3 days | SAST crypto rules | Medium |
| **CycloneDX lib** | MVP | 1 day | CBOM output | High |
| **ike-scan** (CLI) | Phase 3 | 3 days | VPN/IPsec scanning | Low |
