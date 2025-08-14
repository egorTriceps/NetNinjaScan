import asyncio
import socket
from dataclasses import dataclass
from ipaddress import ip_network, ip_address
from typing import Iterable, List, Dict, Any


DEFAULT_COMMON_PORTS = [22, 80, 443]


@dataclass
class HostScanResult:
    host: str
    open_ports: List[int]


def parse_ports(ports_arg: str) -> List[int]:
    """Parse comma-separated ports into a sorted unique list of ints."""
    ports: List[int] = []
    for part in ports_arg.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start = int(start_str)
            end = int(end_str)
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def expand_targets(targets: Iterable[str]) -> List[str]:
    """Expand IPs/hostnames/CIDRs into a list of IP strings.

    Hostnames are resolved to a single IP; CIDRs are expanded (IPv4 only by default).
    """
    result: List[str] = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        try:
            # Try CIDR expansion
            if "/" in t:
                net = ip_network(t, strict=False)
                for ip in net.hosts():
                    result.append(str(ip))
                continue
            # Try IP literal
            _ = ip_address(t)
            result.append(t)
        except ValueError:
            # Resolve hostname
            try:
                resolved = socket.gethostbyname(t)
                result.append(resolved)
            except socket.gaierror:
                # Skip unresolved
                pass
    # De-duplicate preserving order
    seen = set()
    unique: List[str] = []
    for ip in result:
        if ip in seen:
            continue
        seen.add(ip)
        unique.append(ip)
    return unique


async def _probe_port(host: str, port: int, timeout: float) -> bool:
    loop = asyncio.get_running_loop()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setblocking(False)
            await asyncio.wait_for(loop.sock_connect(sock, (host, port)), timeout=timeout)
            return True
    except Exception:
        return False


async def _scan_host(host: str, ports: List[int], timeout: float, sem: asyncio.Semaphore) -> HostScanResult:
    open_ports: List[int] = []

    async def probe(p: int) -> None:
        async with sem:
            is_open = await _probe_port(host, p, timeout)
            if is_open:
                open_ports.append(p)

    await asyncio.gather(*(probe(p) for p in ports))
    open_ports.sort()
    return HostScanResult(host=host, open_ports=open_ports)


async def scan_targets(
    targets: Iterable[str],
    ports: List[int] = None,
    timeout: float = 0.5,
    concurrency: int = 200,
) -> List[Dict[str, Any]]:
    """Scan targets for open TCP ports using async connect.

    Returns a list of dicts for easy JSON serialization.
    """
    if ports is None:
        ports = DEFAULT_COMMON_PORTS
    ips = expand_targets(targets)
    sem = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(*(_scan_host(ip, ports, timeout, sem) for ip in ips))
    return [{"host": r.host, "open_ports": r.open_ports} for r in results]