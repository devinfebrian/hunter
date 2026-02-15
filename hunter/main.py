"""Hunter CLI - Main entry point"""

import asyncio
import logging
import os
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from hunter.models import Target, ScopeRule, ScanSession, Endpoint
from hunter.config import settings
from hunter.recon.subdomain import SubdomainEnumerator
from hunter.recon.probe import HTTPProber
# Import agents
from hunter.agents.sqli import SQLiAgent
from hunter.agents.xss import XSSAgent
from hunter.report.markdown import MarkdownReporter

# Setup logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Setup console (force UTF-8 on Windows)
import sys
if sys.platform == "win32":
    import codecs
    # Set stdout to UTF-8
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

console = Console(force_terminal=True, force_interactive=True)

# Typer app
app = typer.Typer(
    name="hunter",
    help="Autonomous Bug Bounty Agent",
    add_completion=False,
)


def version_callback(value: bool):
    """Show version and exit"""
    if value:
        from hunter import __version__
        console.print(f"Hunter v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-v",
        help="Show version",
        callback=version_callback,
        is_eager=True
    )
):
    """Hunter - Autonomous Bug Bounty Agent"""
    pass


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain or URL"),
    scope: Optional[str] = typer.Option(
        None, "--scope", "-s",
        help="Scope pattern (e.g., '*.example.com')"
    ),
    scope_file: Optional[str] = typer.Option(
        None, "--scope-file", "-S",
        help="File containing scope rules"
    ),
    output: str = typer.Option(
        "./output", "--output", "-o",
        help="Output directory"
    ),
    safe_mode: bool = typer.Option(
        True, "--safe-mode/--no-safe-mode",
        help="Enable safe mode (no destructive operations)"
    ),
    max_time: int = typer.Option(
        30, "--max-time", "-t",
        help="Maximum scan time in minutes"
    ),
    recon_only: bool = typer.Option(
        False, "--recon-only",
        help="Only run reconnaissance, skip vulnerability testing"
    ),
    agents: Optional[str] = typer.Option(
        "sqli,xss", "--agents", "-a",
        help="Comma-separated list of agents to run (sqli,xss)"
    ),
):
    """Run a security scan against a target"""
    
    # Show banner
    console.print(Panel.fit(
        "[bold cyan]Hunter[/bold cyan] - Autonomous Bug Bounty Agent\n"
        "[dim]SQLi & XSS Detection | Safe by Default | Production Ready[/dim]",
        border_style="cyan"
    ))
    
    # Update settings
    settings.safe_mode = safe_mode
    settings.output_dir = output
    
    # Validate API key
    if not settings.kimi_api_key:
        console.print("[red]Error: Kimi API key not set.[/red]")
        console.print("[yellow]Get your API key from: https://platform.moonshot.cn/[/yellow]")
        console.print("[yellow]Set it via: $env:HUNTER_KIMI_API_KEY='your-key'[/yellow]")
        raise typer.Exit(1)
    
    # Parse scope rules
    scope_rules = _parse_scope(scope, scope_file, target)
    
    # Create target
    target_obj = Target(
        domain=target.replace("https://", "").replace("http://", "").strip("/"),
        scope_rules=scope_rules
    )
    
    # Parse agents
    agent_list = [a.strip().lower() for a in agents.split(",")] if agents else ["sqli"]
    
    # Run scan
    try:
        asyncio.run(_run_scan(target_obj, recon_only, max_time, agent_list))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(130)


async def _run_scan(target: Target, recon_only: bool, max_time: int, agents: List[str]):
    """Run the full scan workflow"""
    
    session = ScanSession(target=target)
    
    console.print(f"\n[bold]Target:[/bold] {target.domain}")
    console.print(f"[bold]Scope:[/bold] {', '.join([r.pattern for r in target.scope_rules]) or target.domain}")
    console.print(f"[bold]Safe Mode:[/bold] {'Enabled' if settings.safe_mode else 'Disabled'}\n")
    
    # Stage 1: Reconnaissance
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        # Subdomain enumeration
        task = progress.add_task("Enumerating subdomains...", total=None)
        enumerator = SubdomainEnumerator()
        subdomains = await enumerator.enumerate(target.domain)
        progress.update(task, description=f"Found {len(subdomains)} subdomains")
        
        # HTTP probing
        task = progress.add_task("Probing for live services...", total=None)
        prober = HTTPProber()
        urls = await prober.discover_urls(target.domain, subdomains)
        endpoints = await prober.probe(urls)
        progress.update(task, description=f"Found {len(endpoints)} live endpoints")
    
    # Display recon results
    _display_endpoints(endpoints)
    
    if recon_only:
        console.print("\n[green]Reconnaissance complete. Skipping vulnerability testing.[/green]")
        return
    
    # Stage 2: Vulnerability Analysis
    console.print(f"\n[bold]Starting Vulnerability Analysis...[/bold]")
    console.print(f"[dim]Agents: {', '.join(agents)}[/dim]\n")
    
    # Run each agent
    for agent_name in agents:
        if agent_name == "sqli":
            await _run_sqli_agent(endpoints, session)
        elif agent_name == "xss":
            await _run_xss_agent(endpoints, session)
        else:
            console.print(f"[yellow]Unknown agent: {agent_name}[/yellow]")


async def _run_sqli_agent(endpoints: List[Endpoint], session: ScanSession):
    """Run SQL Injection agent"""
    console.print("[cyan]Running SQL Injection tests...[/cyan]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        task = progress.add_task("SQLi testing...", total=len(endpoints))
        
        try:
            async with SQLiAgent() as agent:
                for endpoint in endpoints[:5]:
                    progress.update(task, description=f"SQLi: {endpoint.url[:50]}...")
                    
                    try:
                        findings = await agent.analyze(endpoint)
                        for finding in findings:
                            session.add_finding(finding)
                    except Exception as e:
                        logger.error(f"SQLi error: {e}")
                    
                    progress.advance(task)
        except Exception as e:
            logger.error(f"SQLi agent failed: {e}")
            console.print(f"[yellow]SQLi agent error: {e}[/yellow]")


async def _run_xss_agent(endpoints: List[Endpoint], session: ScanSession):
    """Run XSS agent"""
    console.print("[cyan]Running XSS tests...[/cyan]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        task = progress.add_task("XSS testing...", total=len(endpoints))
        
        try:
            async with XSSAgent() as agent:
                for endpoint in endpoints[:5]:
                    progress.update(task, description=f"XSS: {endpoint.url[:50]}...")
                    
                    try:
                        findings = await agent.analyze(endpoint)
                        for finding in findings:
                            session.add_finding(finding)
                    except Exception as e:
                        logger.error(f"XSS error: {e}")
                    
                    progress.advance(task)
        except Exception as e:
            logger.error(f"XSS agent failed: {e}")
            console.print(f"[yellow]XSS agent error: {e}[/yellow]")
    
    # Stage 3: Reporting
    session.end_time = __import__('datetime').datetime.utcnow()
    session.status = "completed"
    
    # Generate report
    reporter = MarkdownReporter()
    report_path = reporter.generate(session)
    
    # Display results
    _display_results(session)
    console.print(f"\n[green]Report saved to:[/green] {report_path}")


def _parse_scope(scope: Optional[str], scope_file: Optional[str], target: str) -> List[ScopeRule]:
    """Parse scope from CLI arguments"""
    rules = []
    
    if scope:
        rules.append(ScopeRule(pattern=scope, include=True))
    
    if scope_file and os.path.exists(scope_file):
        with open(scope_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if line.startswith("-"):
                        rules.append(ScopeRule(pattern=line[1:].strip(), include=False))
                    else:
                        rules.append(ScopeRule(pattern=line, include=True))
    
    # Default scope
    if not rules:
        rules.append(ScopeRule(pattern=f"*.{target}", include=True))
        rules.append(ScopeRule(pattern=target, include=True))
    
    return rules


def _display_endpoints(endpoints: List[Endpoint]):
    """Display discovered endpoints in a table"""
    if not endpoints:
        console.print("[yellow]No live endpoints found[/yellow]")
        return
    
    table = Table(title=f"Discovered Endpoints ({len(endpoints)})")
    table.add_column("URL", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Technology", style="magenta")
    
    for ep in endpoints[:20]:  # Show first 20
        table.add_row(
            ep.url[:60] + "..." if len(ep.url) > 60 else ep.url,
            str(ep.status_code),
            ep.technology or "-"
        )
    
    if len(endpoints) > 20:
        table.add_row(f"... and {len(endpoints) - 20} more", "", "")
    
    console.print(table)


def _display_results(session: ScanSession):
    """Display scan results"""
    confirmed = session.get_confirmed_findings()
    
    if not confirmed:
        console.print("\n[green]No confirmed vulnerabilities found.[/green]")
        return
    
    console.print(f"\n[bold]Confirmed Findings: {len(confirmed)}[/bold]\n")
    
    table = Table(title="Vulnerability Summary")
    table.add_column("Type", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("URL", style="blue")
    table.add_column("Parameter", style="yellow")
    
    severity_colors = {
        "critical": "red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "blue"
    }
    
    for finding in confirmed:
        # Handle both enum and string values
        sev = finding.severity.value if hasattr(finding.severity, 'value') else finding.severity
        vuln_type = finding.vulnerability_type.value if hasattr(finding.vulnerability_type, 'value') else finding.vulnerability_type
        
        color = severity_colors.get(sev, "white")
        table.add_row(
            vuln_type.upper(),
            f"[{color}]{sev.upper()}[/{color}]",
            finding.url[:50] + "..." if len(finding.url) > 50 else finding.url,
            finding.parameter or "-"
        )
    
    console.print(table)


if __name__ == "__main__":
    app()
