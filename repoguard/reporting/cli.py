"""
RepoGuard Module D1: Command Line Interface (CLI)
Interactive terminal output powered by the `rich` library.
Features formatted tables, progress bars, colored badges, and report export flags.
"""

import sys
import argparse
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box

from repoguard.core.engine import RepoGuardEngine
from repoguard.core.models import ScanReport, Severity


if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(legacy_windows=False, soft_wrap=True)


def print_banner():
    banner_text = Text()
    banner_text.append("🛡️  REPO GUARD ", style="bold cyan")
    banner_text.append("• Protect Every Repository\n", style="bold white")
    banner_text.append("Open Source Security, Compliance & Repository Hygiene Inspector\n", style="dim slate")
    banner_text.append("University of Mumbai | Recent Open Source Project Lab (ITL709)", style="italic blue")

    console.print(Panel(banner_text, box=box.ROUNDED, border_style="cyan", padding=(1, 2)))


def render_cli_report(report: ScanReport):
    summary = report.summary

    # Score Color Mapping
    if summary.health_score >= 90:
        score_style = "bold green"
    elif summary.health_score >= 70:
        score_style = "bold blue"
    elif summary.health_score >= 55:
        score_style = "bold yellow"
    else:
        score_style = "bold red"

    # Header Summary Panel
    summary_grid = Table.grid(expand=True, padding=(0, 2))
    summary_grid.add_column(ratio=1)
    summary_grid.add_column(ratio=1)
    summary_grid.add_column(ratio=1)

    summary_grid.add_row(
        f"Target Repo: [bold]{report.repo_name}[/bold]\nPath: [dim]{report.repo_path}[/dim]",
        f"Health Score: [{score_style}]{summary.health_score}/100[/{score_style}] (Grade: [{score_style}]{summary.grade}[/{score_style}])\nProject License: [cyan]{summary.project_license.spdx_id if summary.project_license else 'Unknown'}[/cyan]",
        f"Files Scanned: [cyan]{summary.files_scanned}[/cyan]\nDuration: [cyan]{summary.scan_duration_seconds:.2f}s[/cyan]"
    )

    summary_grid.add_row(
        "",
        f"Critical Issues: [bold red]{summary.critical_count}[/bold red]",
        f"Warnings: [bold yellow]{summary.warning_count}[/bold yellow]"
    )

    console.print(Panel(summary_grid, title="[bold white]Audit Summary[/bold white]", border_style="cyan", box=box.ROUNDED))

    # 1. AST Security Findings
    if report.ast_issues:
        ast_table = Table(title="🛡️ AST Security Vulnerabilities", box=box.ROUNDED, header_style="bold cyan")
        ast_table.add_column("Rule ID", style="bold dim", width=14)
        ast_table.add_column("Severity", justify="center", width=12)
        ast_table.add_column("Location", style="cyan", width=26)
        ast_table.add_column("Vulnerability Title & Recommendation", ratio=1)

        for issue in report.ast_issues:
            sev_badge = "[bold red]CRITICAL[/bold red]" if issue.severity == Severity.CRITICAL else "[bold yellow]WARNING[/bold yellow]"
            loc = f"{issue.file_path}:{issue.line_number or 0}"
            desc = f"[bold]{issue.title}[/bold]\n[dim]{issue.description}[/dim]\n[green]💡 Fix: {issue.recommendation}[/green]"
            ast_table.add_row(issue.id, sev_badge, loc, desc)

        console.print(ast_table)
    else:
        console.print("[bold green]✓ AST Security Scanner:[/bold green] No dangerous calls or AST vulnerabilities detected.\n")

    # 2. License & Dependency Audit
    if report.dependencies:
        lic_table = Table(title="📜 Dependency Manifest & License Audit", box=box.ROUNDED, header_style="bold cyan")
        lic_table.add_column("Package", style="bold", width=22)
        lic_table.add_column("Version", width=12)
        lic_table.add_column("Declared License", width=20)
        lic_table.add_column("Category", width=18)
        lic_table.add_column("Compatibility", justify="center", width=16)

        for dep in report.dependencies:
            comp = dep.license.compatibility
            if comp == "INCOMPATIBLE":
                comp_badge = "[bold red]INCOMPATIBLE[/bold red]"
            elif comp == "WARNING":
                comp_badge = "[bold yellow]WARNING[/bold yellow]"
            else:
                comp_badge = "[bold green]COMPATIBLE[/bold green]"

            lic_table.add_row(
                dep.package_name,
                dep.specified_version,
                dep.license.spdx_id,
                dep.license.category.value if hasattr(dep.license.category, "value") else str(dep.license.category),
                comp_badge
            )

        console.print(lic_table)
    else:
        console.print("[dim]• No requirements.txt manifest found in repository.[/dim]\n")

    # 3. Secrets Scanner
    if report.secret_issues:
        sec_table = Table(title="🔑 Secrets & Hardcoded Credentials Detection", box=box.ROUNDED, header_style="bold cyan")
        sec_table.add_column("Rule ID", style="bold dim", width=15)
        sec_table.add_column("Severity", justify="center", width=12)
        sec_table.add_column("Location", style="cyan", width=24)
        sec_table.add_column("Masked Token", style="red", width=22)
        sec_table.add_column("Remediation", ratio=1)

        for sec in report.secret_issues:
            sev_badge = "[bold red]CRITICAL[/bold red]" if sec.severity == Severity.CRITICAL else "[bold yellow]WARNING[/bold yellow]"
            loc = f"{sec.file_path}:{sec.line_number or 0}"
            sec_table.add_row(
                sec.id,
                sev_badge,
                loc,
                sec.masked_value or "••••••••",
                sec.recommendation
            )

        console.print(sec_table)
    else:
        console.print("[bold green]✓ Secrets Scanner:[/bold green] No hardcoded API keys, tokens, or credentials found.\n")

    # 4. Repo Hygiene Checklist
    hyg_table = Table(title="📋 Open Source Repository Hygiene Checklist", box=box.ROUNDED, header_style="bold cyan")
    hyg_table.add_column("Baseline File", style="bold", width=22)
    hyg_table.add_column("Required", justify="center", width=12)
    hyg_table.add_column("Status", justify="center", width=14)
    hyg_table.add_column("File Size", justify="right", width=12)
    hyg_table.add_column("Health Notes & Guidance", ratio=1)

    for chk in report.hygiene_checks:
        if chk.status == "PASS":
            status_badge = "[bold green]PASS[/bold green]"
        elif chk.status == "WARNING":
            status_badge = "[bold yellow]WARNING[/bold yellow]"
        else:
            status_badge = "[bold red]MISSING[/bold red]"

        req_str = "Yes" if chk.required else "Recommended"
        size_str = f"{chk.file_size_bytes} B" if chk.exists else "-"
        notes = chk.description if chk.exists else f"[yellow]{chk.recommendation}[/yellow]"

        hyg_table.add_row(chk.file_name, req_str, status_badge, size_str, notes)

    console.print(hyg_table)

    # 5. Additional Hygiene Flags
    if report.other_hygiene_issues:
        non_baseline = [i for i in report.other_hygiene_issues if not i.id.startswith("HYG-MISSING")]
        if non_baseline:
            extra_table = Table(title="⚠️ Additional Hygiene Warnings", box=box.ROUNDED, header_style="bold yellow")
            extra_table.add_column("Issue ID", width=16)
            extra_table.add_column("File", style="cyan", width=24)
            extra_table.add_column("Details & Remediation", ratio=1)
            for item in non_baseline:
                extra_table.add_row(item.id, item.file_path, f"{item.title}: {item.recommendation}")
            console.print(extra_table)

    # Footer note
    console.print("\n[dim]Audit completed with RepoGuard Static Analysis Engine. Zero code executed on disk.[/dim]\n")


def run_cli_scan(repo_path: str, export_html: Optional[str] = None, export_json: Optional[str] = None) -> ScanReport:
    print_banner()

    engine = RepoGuardEngine()
    path = Path(repo_path).resolve()

    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] Repository path does not exist: {path}")
        sys.exit(1)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning repository...", total=100)
        progress.update(task, advance=15, description="[cyan]Module A: AST Security Parsing...")
        time_to_sleep = 0.05
        # Run scan
        report = engine.scan(path, save_to_db=True)
        progress.update(task, advance=85, description="[green]Scan Complete!")

    render_cli_report(report)

    # Handle Exports
    if export_html:
        from repoguard.reporting.html_report import generate_html_report
        out_html = Path(export_html)
        html_content = generate_html_report(report)
        out_html.write_text(html_content, encoding="utf-8")
        console.print(f"[bold green]✓ Standalone HTML Report exported to:[/bold green] [underline]{out_html.resolve()}[/underline]")

    if export_json:
        import json
        out_json = Path(export_json)
        out_json.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[bold green]✓ JSON Report exported to:[/bold green] [underline]{out_json.resolve()}[/underline]")

    return report
