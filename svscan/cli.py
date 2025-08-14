import asyncio
import json
from typing import List, Optional

import typer

from svscan.version import VERSION
from svscan.scanners.network_scanner import (
    scan_targets,
    parse_ports,
)
from svscan.scanners.vuln_scanner import run_vuln_scan

app = typer.Typer(no_args_is_help=True, help="SVScan: modular network and vulnerability scanner")

net_app = typer.Typer(help="Network scanning commands")
vuln_app = typer.Typer(help="Vulnerability scanning commands")

app.add_typer(net_app, name="net")
app.add_typer(vuln_app, name="vuln")


@app.command()
def version() -> None:
    """Show version information."""
    typer.echo(f"svscan {VERSION}")


@net_app.command("scan")
def net_scan(
    targets: List[str] = typer.Argument(..., help="Targets: IPs, hostnames, or CIDRs (e.g. 192.168.1.0/24)"),
    ports: str = typer.Option("22,80,443", "--ports", "-p", help="Comma-separated ports"),
    timeout: float = typer.Option(0.5, help="Per-connection timeout (seconds)"),
    concurrency: int = typer.Option(200, help="Max concurrent connections"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write results to file (json)"),
    as_json: bool = typer.Option(False, "--json", help="Print JSON to stdout"),
) -> None:
    """Run a TCP connect network scan."""
    port_list = parse_ports(ports)
    results = asyncio.run(scan_targets(targets, port_list, timeout=timeout, concurrency=concurrency))

    if as_json or output:
        data = json.dumps(results, indent=2)
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(data)
        if as_json:
            typer.echo(data)
    else:
        for host_result in results:
            typer.echo(f"Host: {host_result['host']}")
            open_ports = host_result.get("open_ports", [])
            if not open_ports:
                typer.echo("  No open ports found")
            else:
                for port in open_ports:
                    typer.echo(f"  Port {port}")


@vuln_app.command("scan")
def vuln_scan(
    targets: List[str] = typer.Argument(..., help="Targets: IPs, hostnames, or CIDRs"),
    ports: str = typer.Option("22,80,443", "--ports", "-p", help="Comma-separated ports"),
    timeout: float = typer.Option(0.8, help="Per-connection timeout (seconds)"),
    concurrency: int = typer.Option(200, help="Max concurrent connections"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write results to file (json)"),
    as_json: bool = typer.Option(False, "--json", help="Print JSON to stdout"),
) -> None:
    """Run a vulnerability scan (network scan + lightweight fingerprinting + DB match)."""
    port_list = parse_ports(ports)
    results = asyncio.run(run_vuln_scan(targets, port_list, timeout=timeout, concurrency=concurrency))

    if as_json or output:
        data = json.dumps(results, indent=2)
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(data)
        if as_json:
            typer.echo(data)
    else:
        for host in results:
            typer.echo(f"Host: {host['host']}")
            if not host.get("findings"):
                typer.echo("  No vulnerabilities found (based on local signatures)")
                continue
            for finding in host["findings"]:
                typer.echo(
                    f"  [{finding['severity'].upper()}] {finding['id']} on {finding['service']}\n"
                    f"    Evidence: {finding.get('evidence', '')}\n"
                    f"    Description: {finding.get('description', '')}"
                )