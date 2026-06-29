import asyncio
import json
import logging
import shutil
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


async def run_cli_tool(
    command: List[str],
    timeout: int = 30,
    json_output_path: Optional[str] = None,
) -> Dict[str, Any]:
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout + 10
        )
    except asyncio.TimeoutError:
        if proc:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()
            except Exception:
                pass
        return {
            "success": False,
            "error": "CLI tool timed out",
            "tool": command[0],
            "exit_code": None,
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"{command[0]} not found on PATH",
            "tool": command[0],
            "skipped": True,
        }
    except Exception as exc:
        return {
            "success": False,
            "error": str(exc),
            "tool": command[0],
            "skipped": True,
        }

    raw = stdout.decode("utf-8", errors="ignore")
    err = stderr.decode("utf-8", errors="ignore")
    parsed: Any = raw

    if json_output_path and Path(json_output_path).exists():
        try:
            with open(json_output_path, "r", encoding="utf-8") as f:
                parsed = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to parse CLI JSON output: %s", exc)
            parsed = raw

    return {
        "success": proc.returncode == 0,
        "tool": command[0],
        "exit_code": proc.returncode,
        "stdout": raw,
        "stderr": err,
        "raw_output": parsed,
        "error": None if proc.returncode == 0 else err.strip() or raw.strip(),
    }


def _windows_temp_dir() -> str:
    base = os.environ.get("TEMP", r"C:\Users\chauh\AppData\Local\Temp")
    target = os.path.join(base, "kilo")
    os.makedirs(target, exist_ok=True)
    return target


async def run_pqcscan(host: str, port: int = 443) -> Dict[str, Any]:
    if not shutil.which("pqcscan"):
        return {"success": False, "tool": "pqcscan", "skipped": True, "error": "pqcscan not found on PATH"}
    json_path = os.path.join(_windows_temp_dir(), f"pqcscan_{host}_{port}.json")
    cmd = [
        "pqcscan",
        "--target", f"{host}:{port}",
        "--output-format", "json",
        "--timeout", "30",
        "--json-output", json_path,
    ]
    result = await run_cli_tool(cmd, json_output_path=json_path)
    if not result.get("success") and not result.get("skipped"):
        return result
    raw = result.get("raw_output", {})
    if isinstance(raw, str):
        return result
    return {
        "tool": "pqcscan",
        "host": host,
        "port": port,
        "success": True,
        "tls_version": raw.get("tls_version"),
        "cipher_suite": raw.get("cipher_suite"),
        "kex_group": raw.get("key_exchange_group"),
        "kex_group_is_pqc": raw.get("is_pqc", False),
        "pqc_status": "pqc_ready" if raw.get("is_pqc") else "vulnerable",
        "certificate": raw.get("certificate", {}),
        "raw_output": raw,
    }


async def run_ssh_audit(host: str, port: int = 22) -> Dict[str, Any]:
    if not shutil.which("ssh-audit"):
        return {"success": False, "tool": "ssh-audit", "skipped": True, "error": "ssh-audit not found on PATH"}
    json_path = os.path.join(_windows_temp_dir(), f"ssh_audit_{host}_{port}.json")
    cmd = [
        "ssh-audit",
        "-j",
        "-p", str(port),
        host,
    ]
    result = await run_cli_tool(cmd, json_output_path=json_path)
    if not result.get("success") and not result.get("skipped"):
        return result
    raw = result.get("raw_output", {})
    if isinstance(raw, str):
        return result
    algorithms = raw.get("algorithms", {})
    kex_algos = algorithms.get("kex", [])
    pqc_keywords = ["mlkem", "sntrup", "kyber", "ntrup", "pqc"]
    pqc_kex = [a for a in kex_algos if any(kw in a.lower() for kw in pqc_keywords)]
    host_key_algos = algorithms.get("key", [])
    return {
        "tool": "ssh-audit",
        "host": host,
        "port": port,
        "success": True,
        "kex_algorithms": kex_algos,
        "pqc_kex_available": len(pqc_kex) > 0,
        "pqc_kex_algorithms": pqc_kex,
        "host_key_algorithms": host_key_algos,
        "pqc_status": "pqc_ready" if pqc_kex else "vulnerable",
        "raw_output": raw,
    }


async def run_testssl(host: str, port: int = 443) -> Dict[str, Any]:
    if not shutil.which("testssl.sh"):
        return {"success": False, "tool": "testssl.sh", "skipped": True, "error": "testssl.sh not found on PATH"}
    tmp_dir = _windows_temp_dir()
    json_path = os.path.join(tmp_dir, f"testssl_{host}_{port}.json")
    cmd = [
        "testssl.sh",
        "--jsonfile", json_path,
        "--color", "0",
        f"{host}:{port}",
    ]
    result = await run_cli_tool(cmd, timeout=120)
    if not result.get("success") and not result.get("skipped"):
        return result
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            findings_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "tool": "testssl.sh",
            "host": host,
            "port": port,
            "success": False,
            "error": "testssl.sh JSON output not found",
        }
    finally:
        try:
            os.remove(json_path)
        except OSError:
            pass

    protocols: List[Dict[str, Any]] = []
    cipher_suites: List[Dict[str, Any]] = []
    vulnerabilities: List[Dict[str, Any]] = []
    pqc_findings: List[Dict[str, Any]] = []

    if isinstance(findings_data, list):
        entries = findings_data
    elif isinstance(findings_data, dict):
        entries = findings_data.get("findings", findings_data.get("results", []))
    else:
        entries = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        eid = str(entry.get("id", entry.get("finding_id", ""))).lower()
        if "protocol" in eid:
            protocols.append(entry)
        elif "cipher" in eid:
            cipher_suites.append(entry)
        severity = str(entry.get("severity", "")).upper()
        if severity in {"HIGH", "CRITICAL"}:
            vulnerabilities.append(entry)
        if any(p in json.dumps(entry).lower() for p in ["ml-kem", "mlkem", "kyber", "pqc", "hybrid"]):
            pqc_findings.append(entry)

    return {
        "tool": "testssl.sh",
        "host": host,
        "port": port,
        "success": True,
        "protocols": protocols,
        "cipher_suites": cipher_suites,
        "vulnerabilities": vulnerabilities,
        "pqc_findings": pqc_findings,
        "raw_output": findings_data,
    }


async def run_ike_scan(host: str, port: int = 500) -> Dict[str, Any]:
    if not shutil.which("ike-scan"):
        return {"success": False, "tool": "ike-scan", "skipped": True, "error": "ike-scan not found on PATH"}
    from app.scanners.ike_scanner import _DH_GROUP_POLICY
    cmd = [
        "ike-scan",
        "--ikev2",
        "-M",
        f"{host}:{port}",
    ]
    result = await run_cli_tool(cmd, timeout=30)
    if not result.get("success") and not result.get("skipped"):
        return result
    stdout = result.get("stdout", "")
    dh_groups: List[str] = []
    encryption: List[str] = []
    integrity: List[str] = []
    ike_version = "IKEv2"
    for line in stdout.splitlines():
        line_lower = line.lower()
        if "encryption algorithm" in line_lower or "enc =" in line_lower:
            parts = line.split(":", 1)
            if len(parts) == 2:
                encryption.append(parts[1].strip())
        if "hash algorithm" in line_lower or "hash =" in line_lower:
            parts = line.split(":", 1)
            if len(parts) == 2:
                integrity.append(parts[1].strip())
        if "group" in line_lower and "[" in line:
            try:
                num = line.split("[")[1].split("]")[0].strip()
                name = _DH_GROUP_POLICY.get(num, {}).get("name", f"DH Group {num}")
                dh_groups.append(name)
            except (IndexError, ValueError):
                pass
    pqc_dh_groups = [g for g in dh_groups if any(p in g.lower() for p in ["ml-kem", "mlkem", "kyber", "hybrid"])]
    pqc_status = "pqc_ready" if pqc_dh_groups else "vulnerable" if dh_groups else "unknown"
    return {
        "tool": "ike-scan",
        "host": host,
        "port": port,
        "success": True,
        "ike_version": ike_version,
        "dh_groups": dh_groups,
        "encryption_algorithms": encryption,
        "integrity_algorithms": integrity,
        "pqc_dh_groups": pqc_dh_groups,
        "pqc_status": pqc_status,
        "raw_output": stdout,
    }


async def run_trivy(target: str) -> Dict[str, Any]:
    if not shutil.which("trivy"):
        return {"success": False, "tool": "trivy", "skipped": True, "error": "trivy not found on PATH"}
    cmd = [
        "trivy",
        "filesystem",
        "--format", "json",
        "--scanners", "vuln,secret",
        target,
    ]
    result = await run_cli_tool(cmd, timeout=120)
    if not result.get("success") and not result.get("skipped"):
        return result
    raw = result.get("raw_output", [])
    if isinstance(raw, str):
        return result
    crypto_patterns = ["crypto", "openssl", "libcrypto", "ssl", "tls", "cryptography", "rsa", "ecdsa", "dilithium", "ml-kem"]
    crypto_results = []
    all_results = raw if isinstance(raw, list) else [raw]
    for entry in all_results:
        if not isinstance(entry, dict):
            continue
        text = json.dumps(entry).lower()
        if any(p in text for p in crypto_patterns):
            crypto_results.append(entry)
    return {
        "tool": "trivy",
        "target": target,
        "success": True,
        "total_results": len(all_results),
        "crypto_related": len(crypto_results),
        "findings": crypto_results,
        "raw_output": raw,
    }


async def run_semgrep(repo_path: str, configs: Optional[List[str]] = None) -> Dict[str, Any]:
    if not shutil.which("semgrep"):
        return {"success": False, "tool": "semgrep", "skipped": True, "error": "semgrep not found on PATH"}
    if configs is None:
        configs = ["p/python", "p/cwe-top-25", "p/owasp-top-ten"]
    cmd = ["semgrep", "--json", "--quiet", *([item for c in configs for item in ("--config", c)])]
    result = await run_cli_tool(cmd + [repo_path], timeout=120)
    if not result.get("success") and not result.get("skipped"):
        return result
    raw = result.get("raw_output", {})
    if isinstance(raw, str):
        return result
    results = raw.get("results", []) if isinstance(raw, dict) else []
    crypto_patterns = [
        "RSA_generate_key", "EC_KEY_generate", "DSA_generate",
        "MD5", "SHA1", "DES_", "RC4", "Blowfish",
        "hardcoded", "private_key", "BEGIN RSA PRIVATE KEY",
        "password =", "secret =", "api_key =",
    ]
    crypto_findings = []
    for res in results:
        if not isinstance(res, dict):
            continue
        code = str(res.get("extra", {}).get("lines", ""))
        if any(pat.lower() in code.lower() for pat in crypto_patterns):
            crypto_findings.append({
                "file": res.get("path"),
                "line": res.get("start", {}).get("line"),
                "code": code.strip(),
                "rule": res.get("check_id"),
                "severity": res.get("extra", {}).get("severity"),
                "message": res.get("extra", {}).get("message"),
            })
    return {
        "tool": "semgrep",
        "target": repo_path,
        "success": True,
        "total_results": len(results),
        "crypto_findings": len(crypto_findings),
        "findings": crypto_findings,
        "raw_output": raw,
    }
