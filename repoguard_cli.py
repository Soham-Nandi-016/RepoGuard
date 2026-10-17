#!/usr/bin/env python3
"""
RepoGuard CLI Entrypoint
Run security and compliance audits from terminal or launch the modern web dashboard.
"""

import sys
import argparse
from pathlib import Path

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="RepoGuard: Automated Open Source Security, Compliance & Repository Hygiene Inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python repoguard_cli.py --path samples/vulnerable_repo
  python repoguard_cli.py --path . --export-html repoguard_report.html
  python repoguard_cli.py --path . --export-json audit.json
  python repoguard_cli.py --serve --port 8000
        """
    )
    parser.add_argument(
        "--path",
        "-p",
        type=str,
        default=".",
        help="Path to the target repository directory (default: current directory)"
    )
    parser.add_argument(
        "--export-html",
        type=str,
        nargs="?",
        const="repoguard_report.html",
        help="Export self-contained HTML report (default: repoguard_report.html)"
    )
    parser.add_argument(
        "--export-json",
        type=str,
        nargs="?",
        const="repoguard_report.json",
        help="Export machine-readable JSON report"
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Launch the modern FastAPI web dashboard"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host address for web server (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for web server (default: 8000)"
    )

    args = parser.parse_args()

    if args.serve:
        import uvicorn
        from rich.console import Console
        from rich.panel import Panel
        from rich import box

        console = Console(legacy_windows=False)
        url = f"http://{args.host}:{args.port}"
        msg = f"[bold green]RepoGuard Web Server starting![/bold green]\n\n" \
              f"Dashboard URL: [bold underline cyan]{url}[/bold underline cyan]\n" \
              f"Light Theme Dashboard - Live Static Analysis - Report Exporter\n" \
              f"Press [bold red]Ctrl+C[/bold red] to stop the server."
        console.print(Panel(msg, title="[bold]RepoGuard Dashboard[/bold]", border_style="cyan", box=box.ROUNDED))

        uvicorn.run("repoguard.web.app:app", host=args.host, port=args.port, reload=False)
    else:
        from repoguard.reporting.cli import run_cli_scan
        report = run_cli_scan(
            repo_path=args.path,
            export_html=args.export_html,
            export_json=args.export_json
        )
        # Exit with non-zero code if critical security issues exist for CI/CD usage
        if report.summary.critical_count > 0:
            sys.exit(1)
        sys.exit(0)


if __name__ == "__main__":
    main()
