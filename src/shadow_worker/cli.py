"""
Shadow Worker CLI - Command-line interface for security operations.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.tree import Tree

from shadow_worker import __version__
from shadow_worker.core.config import ShadowConfig
from shadow_worker.core.engine import ShadowEngine
from shadow_worker.core.scanner import Severity

console = Console()


def async_command(f):
    """Decorator to run async commands."""
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))
    return wrapper


@click.group()
@click.version_option(version=__version__, prog_name="Shadow Worker")
@click.option("--config", "-c", type=click.Path(), help="Path to configuration file")
@click.option("--debug", is_flag=True, help="Enable debug output")
@click.pass_context
def main(ctx: click.Context, config: str | None, debug: bool) -> None:
    """
    Shadow Worker - Defensive Security Operations Framework

    A comprehensive security platform for vulnerability scanning,
    SIEM operations, and threat detection on YOUR OWN infrastructure.
    """
    ctx.ensure_object(dict)

    # Load configuration
    if config:
        ctx.obj["config"] = ShadowConfig.load(config)
    else:
        ctx.obj["config"] = ShadowConfig.load_from_env()

    ctx.obj["debug"] = debug

    if debug:
        import structlog
        structlog.configure(
            wrapper_class=structlog.make_filtering_bound_logger(0),
        )


@main.command()
@click.option("--output", "-o", type=click.Path(), help="Output file for config")
@click.pass_context
def init(ctx: click.Context, output: str | None) -> None:
    """Initialize a new Shadow Worker configuration."""
    output_path = Path(output or "shadow-config.yaml")

    if output_path.exists():
        if not click.confirm(f"{output_path} already exists. Overwrite?"):
            return

    config = ShadowConfig()
    config.save(output_path)

    console.print(f"[green]Configuration created: {output_path}[/green]")
    console.print("\n[yellow]Important:[/yellow] Before scanning, you must:")
    console.print("  1. Add your authorized targets to the config")
    console.print("  2. Set 'authorization_confirmed: true'")


@main.command()
@click.argument("target")
@click.option("--type", "-t", "scan_type",
              type=click.Choice(["sast", "dast", "full", "quick"]),
              default="full", help="Type of scan to perform")
@click.option("--output", "-o", type=click.Path(), help="Output file for results")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["json", "table", "sarif"]),
              default="table", help="Output format")
@click.pass_context
@async_command
async def scan(
    ctx: click.Context,
    target: str,
    scan_type: str,
    output: str | None,
    output_format: str
) -> None:
    """
    Run a security scan against a target.

    TARGET can be a URL, IP address, or file/directory path.

    Examples:
      shadow scan https://myapp.example.com
      shadow scan ./my-project --type sast
      shadow scan 192.168.1.1 --type quick
    """
    config = ctx.obj["config"]

    # Verify authorization
    if not config.authorization_confirmed:
        console.print("[red]Error: Authorization not confirmed.[/red]")
        console.print("Set 'authorization_confirmed: true' in your config after")
        console.print("adding your authorized targets.")
        sys.exit(1)

    console.print(Panel.fit(
        f"[bold]Shadow Worker Security Scan[/bold]\n"
        f"Target: {target}\n"
        f"Type: {scan_type}",
        border_style="blue"
    ))

    engine = ShadowEngine(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Initializing...", total=None)

        async with engine.run():
            progress.update(task, description="Scanning...")
            result = await engine.scan(target, scan_type)

        progress.update(task, description="Complete!")

    # Display results
    if output_format == "table":
        _display_findings_table(result.findings)
    elif output_format == "json":
        data = {
            "scan_id": str(result.scan_id),
            "target": result.target,
            "status": result.status.value,
            "findings": [f.to_dict() for f in result.findings],
            "summary": {
                "total": result.total_findings,
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "info": result.info_count,
            }
        }
        if output:
            Path(output).write_text(json.dumps(data, indent=2))
            console.print(f"[green]Results saved to {output}[/green]")
        else:
            console.print_json(json.dumps(data))
    elif output_format == "sarif":
        sarif = _to_sarif(result)
        if output:
            Path(output).write_text(json.dumps(sarif, indent=2))
            console.print(f"[green]SARIF results saved to {output}[/green]")
        else:
            console.print_json(json.dumps(sarif))

    # Summary
    console.print(Panel(
        f"[bold]Scan Complete[/bold]\n"
        f"Duration: {result.duration_seconds:.2f}s\n"
        f"Total Findings: {result.total_findings}\n"
        f"Critical: {result.critical_count} | High: {result.high_count} | "
        f"Medium: {result.medium_count} | Low: {result.low_count}",
        border_style="green" if result.critical_count == 0 else "red"
    ))


@main.command()
@click.argument("path")
@click.option("--base-url", "-u", help="Base URL for endpoints")
@click.option("--output", "-o", type=click.Path(), help="Output file")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["json", "table", "openapi"]),
              default="table")
@click.pass_context
@async_command
async def discover(
    ctx: click.Context,
    path: str,
    base_url: str | None,
    output: str | None,
    output_format: str
) -> None:
    """
    Discover API endpoints from source code using OWASP Noir.

    PATH should be a directory containing source code.

    Examples:
      shadow discover ./my-api
      shadow discover ./my-api --base-url https://api.example.com
      shadow discover ./my-api --format openapi -o openapi.json
    """
    from shadow_worker.scanners.noir import NoirScanner

    console.print(f"[bold]Discovering endpoints in:[/bold] {path}")

    scanner = NoirScanner()
    result = await scanner.scan(path, base_url or "")

    if output_format == "table":
        table = Table(title="Discovered API Endpoints")
        table.add_column("Method", style="cyan")
        table.add_column("URL", style="green")
        table.add_column("Source", style="yellow")
        table.add_column("Framework", style="magenta")

        for endpoint in result.endpoints:
            table.add_row(
                endpoint.method,
                endpoint.url,
                f"{endpoint.source_file}:{endpoint.source_line}",
                endpoint.framework
            )

        console.print(table)

    elif output_format == "json":
        data = {
            "endpoints": [e.to_dict() for e in result.endpoints],
            "technologies": result.technologies,
            "frameworks": result.frameworks,
            "total": result.total_endpoints,
        }
        if output:
            Path(output).write_text(json.dumps(data, indent=2))
            console.print(f"[green]Results saved to {output}[/green]")
        else:
            console.print_json(json.dumps(data))

    elif output_format == "openapi":
        spec = await scanner.generate_openapi_spec(result.endpoints)
        if output:
            Path(output).write_text(json.dumps(spec, indent=2))
            console.print(f"[green]OpenAPI spec saved to {output}[/green]")
        else:
            console.print_json(json.dumps(spec))

    console.print(f"\n[bold]Total endpoints:[/bold] {result.total_endpoints}")
    console.print(f"[bold]Technologies:[/bold] {', '.join(result.technologies)}")
    console.print(f"[bold]Frameworks:[/bold] {', '.join(result.frameworks)}")


@main.command()
@click.argument("path")
@click.option("--recursive", "-r", is_flag=True, help="Scan recursively")
@click.option("--output", "-o", type=click.Path(), help="Output file")
@click.pass_context
@async_command
async def detect(
    ctx: click.Context,
    path: str,
    recursive: bool,
    output: str | None
) -> None:
    """
    Detect threats using YARA rules and custom signatures.

    PATH can be a file or directory to scan.

    Examples:
      shadow detect ./suspicious-file.exe
      shadow detect ./uploads -r
    """
    from shadow_worker.detection.detector import ThreatDetector

    config = ctx.obj["config"]

    console.print(f"[bold]Scanning for threats:[/bold] {path}")

    detector = ThreatDetector(config.detection)
    await detector.start()

    target = Path(path)

    if target.is_file():
        detections = await detector.scan_file(target)
    else:
        detections = await detector.scan_directory(target, recursive=recursive)

    await detector.stop()

    if not detections:
        console.print("[green]No threats detected.[/green]")
        return

    table = Table(title="Threat Detections")
    table.add_column("Severity", style="red")
    table.add_column("Type", style="cyan")
    table.add_column("Rule", style="yellow")
    table.add_column("File", style="green")

    for detection in detections:
        table.add_row(
            detection.severity.value.upper(),
            detection.threat_type.value,
            detection.rule_name,
            detection.filename
        )

    console.print(table)

    if output:
        data = [d.to_dict() for d in detections]
        Path(output).write_text(json.dumps(data, indent=2))
        console.print(f"[green]Results saved to {output}[/green]")


@main.command()
@click.option("--interval", "-i", type=int, default=3600, help="Scan interval in seconds")
@click.pass_context
@async_command
async def monitor(ctx: click.Context, interval: int) -> None:
    """
    Continuously monitor configured targets.

    Runs periodic security scans and SIEM operations.
    """
    config = ctx.obj["config"]

    if not config.authorization_confirmed:
        console.print("[red]Error: Authorization not confirmed.[/red]")
        sys.exit(1)

    targets = config.targets.hosts + config.targets.domains

    if not targets:
        console.print("[red]Error: No targets configured.[/red]")
        sys.exit(1)

    console.print(Panel.fit(
        f"[bold]Continuous Monitoring[/bold]\n"
        f"Targets: {len(targets)}\n"
        f"Interval: {interval}s",
        border_style="blue"
    ))

    engine = ShadowEngine(config)

    async with engine.run():
        console.print("[green]Monitoring started. Press Ctrl+C to stop.[/green]")

        try:
            async for result in engine.continuous_monitor(targets, interval):
                _display_scan_summary(result)
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping monitor...[/yellow]")


@main.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show Shadow Worker status and configuration."""
    config = ctx.obj["config"]

    tree = Tree("[bold]Shadow Worker Configuration[/bold]")

    # Targets
    targets_tree = tree.add("[cyan]Targets[/cyan]")
    targets_tree.add(f"Hosts: {len(config.targets.hosts)}")
    targets_tree.add(f"Networks: {len(config.targets.networks)}")
    targets_tree.add(f"Domains: {len(config.targets.domains)}")
    targets_tree.add(f"Authorized: {'✓' if config.authorization_confirmed else '✗'}")

    # SIEM
    siem_tree = tree.add("[cyan]SIEM[/cyan]")
    siem_tree.add(f"Enabled: {config.siem.enabled}")
    siem_tree.add(f"Storage: {config.siem.storage_backend}")

    # Detection
    detection_tree = tree.add("[cyan]Detection[/cyan]")
    detection_tree.add(f"Enabled: {config.detection.enabled}")
    detection_tree.add(f"YARA: {config.detection.yara_rules_path}")
    detection_tree.add(f"Suricata: {config.detection.suricata_enabled}")

    # Scanners
    scanners_tree = tree.add("[cyan]Scanners[/cyan]")
    scanners_tree.add(f"SAST: {config.sast.enabled}")
    scanners_tree.add(f"DAST: {config.dast.enabled}")
    scanners_tree.add(f"Web3: {config.web3.enabled}")

    # Alerting
    alert_tree = tree.add("[cyan]Alerting[/cyan]")
    alert_tree.add(f"Enabled: {config.alerting.enabled}")
    alert_tree.add(f"Slack: {'✓' if config.alerting.slack_webhook else '✗'}")
    alert_tree.add(f"Discord: {'✓' if config.alerting.discord_webhook else '✗'}")
    alert_tree.add(f"Email: {'✓' if config.alerting.email_smtp_host else '✗'}")

    console.print(tree)


def _display_findings_table(findings: list[Any]) -> None:
    """Display findings in a table."""
    if not findings:
        console.print("[green]No vulnerabilities found.[/green]")
        return

    table = Table(title="Security Findings")
    table.add_column("Severity", style="bold")
    table.add_column("Title")
    table.add_column("Location")
    table.add_column("Category")

    severity_styles = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }

    for finding in sorted(findings, key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value)):
        style = severity_styles.get(finding.severity, "")
        table.add_row(
            f"[{style}]{finding.severity.value.upper()}[/{style}]",
            finding.title[:50],
            finding.location[:40],
            finding.category.value
        )

    console.print(table)


def _display_scan_summary(result: Any) -> None:
    """Display a brief scan summary."""
    status_color = "green" if result.critical_count == 0 else "red"
    console.print(
        f"[{status_color}]Scan complete:[/{status_color}] {result.target} - "
        f"C:{result.critical_count} H:{result.high_count} M:{result.medium_count} L:{result.low_count}"
    )


def _to_sarif(result: Any) -> dict[str, Any]:
    """Convert scan result to SARIF format."""
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Shadow Worker",
                        "version": __version__,
                        "informationUri": "https://github.com/shadow-worker/shadow-worker",
                    }
                },
                "results": [
                    {
                        "ruleId": f"{f.scanner}/{f.category.value}",
                        "level": {
                            "critical": "error",
                            "high": "error",
                            "medium": "warning",
                            "low": "note",
                            "info": "note",
                        }.get(f.severity.value, "note"),
                        "message": {"text": f.title},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.location},
                                    "region": {"startLine": f.line_number or 1}
                                }
                            }
                        ] if f.location else []
                    }
                    for f in result.findings
                ]
            }
        ]
    }


if __name__ == "__main__":
    main()
