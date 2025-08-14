import asyncio
import json
import re
import socket
import contextlib
from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Tuple

from importlib import resources

from svscan.scanners.network_scanner import scan_targets


@dataclass
class ServiceFingerprint:
    service: str
    port: int
    evidence: str
    meta: Dict[str, Any]


async def _read_banner(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        try:
            # Give the service a moment to speak first (SSH/FTP often do)
            await asyncio.sleep(0.1)
            data = await asyncio.wait_for(reader.read(256), timeout=timeout)
            banner = data.decode(errors="ignore").strip()
            return banner if banner else None
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    except Exception:
        return None


async def _http_server_header(host: str, port: int, timeout: float) -> Optional[Tuple[str, Dict[str, str]]]:
    request = f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: svscan/0.1\r\n\r\n".encode()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        try:
            writer.write(request)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
            raw = data.decode(errors="ignore")
            headers: Dict[str, str] = {}
            lines = raw.split("\r\n")
            for line in lines[1:]:
                if not line:
                    break
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            server = headers.get("server")
            if server:
                return server, headers
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    except Exception:
        return None
    return None


async def fingerprint_services(host: str, open_ports: List[int], timeout: float) -> List[ServiceFingerprint]:
    tasks: List[asyncio.Task] = []
    results: List[ServiceFingerprint] = []

    async def fp_http(port: int) -> None:
        res = await _http_server_header(host, port, timeout)
        if res is not None:
            server, headers = res
            results.append(ServiceFingerprint(service="http", port=port, evidence=server, meta={"headers": headers}))

    async def fp_ssh(port: int) -> None:
        banner = await _read_banner(host, port, timeout)
        if banner:
            results.append(ServiceFingerprint(service="ssh", port=port, evidence=banner, meta={}))

    async def fp_ftp(port: int) -> None:
        banner = await _read_banner(host, port, timeout)
        if banner:
            results.append(ServiceFingerprint(service="ftp", port=port, evidence=banner, meta={}))

    async def fp_smtp(port: int) -> None:
        banner = await _read_banner(host, port, timeout)
        if banner:
            results.append(ServiceFingerprint(service="smtp", port=port, evidence=banner, meta={}))

    for p in open_ports:
        if p in (80, 8080, 8000):
            tasks.append(asyncio.create_task(fp_http(p)))
        elif p == 22:
            tasks.append(asyncio.create_task(fp_ssh(p)))
        elif p == 21:
            tasks.append(asyncio.create_task(fp_ftp(p)))
        elif p == 25:
            tasks.append(asyncio.create_task(fp_smtp(p)))

    if tasks:
        await asyncio.gather(*tasks)
    return results


def load_vuln_db() -> List[Dict[str, Any]]:
    with resources.files("svscan.data").joinpath("vuln_db.json").open("r", encoding="utf-8") as f:
        return json.load(f)


def match_vulnerabilities(fingerprints: List[ServiceFingerprint], db: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for fp in fingerprints:
        for rule in db:
            if rule.get("service") != fp.service:
                continue
            match = rule.get("match", {})
            mtype = match.get("type")
            pattern = match.get("pattern")
            if not mtype or not pattern:
                continue
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue

            evidence_value: Optional[str] = None
            if mtype == "banner_regex":
                evidence_value = fp.evidence
            elif mtype == "header_regex":
                header_name = match.get("header", "server").lower()
                headers = fp.meta.get("headers", {}) if fp.meta else {}
                evidence_value = headers.get(header_name)
            else:
                continue

            if evidence_value and regex.search(evidence_value):
                findings.append(
                    {
                        "id": rule.get("id"),
                        "severity": rule.get("severity", "info"),
                        "description": rule.get("description", ""),
                        "references": rule.get("references", []),
                        "service": fp.service,
                        "port": fp.port,
                        "evidence": evidence_value,
                    }
                )
    return findings


async def run_vuln_scan(
    targets: List[str],
    ports: List[int],
    timeout: float = 0.8,
    concurrency: int = 200,
) -> List[Dict[str, Any]]:
    net_results = await scan_targets(targets, ports, timeout=timeout, concurrency=concurrency)
    db = load_vuln_db()

    out: List[Dict[str, Any]] = []
    for host in net_results:
        open_ports = host.get("open_ports", [])
        fps = await fingerprint_services(host["host"], open_ports, timeout)
        findings = match_vulnerabilities(fps, db)
        out.append({"host": host["host"], "open_ports": open_ports, "findings": findings})
    return out