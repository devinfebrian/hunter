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
# Try to import browser-based agent, fallback to basic
try:
    from hunter.agents.browser_sqli_agent import BrowserSQLiAgent
    BROWSER_AVAILABLE = True
except ImportError:
    BROWSER_AVAILABLE = False
    from hunter.agents.sqli_agent import SQLiAgent as BrowserSQLiAgent
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
):
    """Run a security scan against a target"""
    
    # Show banner
    console.print(Panel.fit(
        "[bold cyan]Hunter[/bold cyan] - Autonomous Bug Bounty Agent\n"
        "[dim]SQL Injection Detection | Safe by Default | Production Ready[/dim]",
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
    
    # Run scan
    try:
        asyncio.run(_run_scan(target_obj, recon_only, max_time))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(130)


async def _run_scan(target: Target, recon_only: bool, max_time: int):
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
    console.print("\n[bold]Starting Autonomous SQL Injection Analysis...[/bold]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        task = progress.add_task("Initializing agent...", total=len(endpoints))
        
        # Use browser-based agent for better form interaction
        if BROWSER_AVAILABLE:
            console.print("[cyan]Using browser automation for form testing...[/cyan]")
            console.print("[dim]Note: Install Playwright browsers with: playwright install chromium[/dim]\n")
        
        try:
            async with BrowserSQLiAgent() as agent:
                for endpoint in endpoints[:5]:  # Test first 5 endpoints
                    progress.update(task, description=f"Analyzing {endpoint.url[:60]}...")
                    
                    try:
                        findings = await agent.analyze(endpoint)
                        for finding in findings:
                            session.add_finding(finding)
                    except Exception as e:
                        logger.error(f"Error analyzing {endpoint.url}: {e}")
                    
                    progress.advance(task)
        except Exception as e:
            logger.error(f"Browser agent failed: {e}")
            console.print(f"[yellow]Browser automation error: {e}[/yellow]")
            console.print("[yellow]Try running: playwright install chromium[/yellow]")
    
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
