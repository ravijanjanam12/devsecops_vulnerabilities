"""Command-line interface for secagent."""

from __future__ import annotations

import json
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from .agent import SecurityAgent
from .config import Config
from .models import Severity

app = typer.Typer(add_completion=False, help="OpenAI-powered security scan + auto-remediation agent.")
console = Console()


def _severity_style(sev: str) -> str:
    return {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}.get(sev, "white")


def _print_findings(findings) -> None:
    if not findings:
        console.print("[green]No security findings.[/green]")
        return
    table = Table(title="Security findings", show_lines=False)
    table.add_column("Severity")
    table.add_column("Location")
    table.add_column("CWE")
    table.add_column("Title")
    for f in sorted(findings, key=lambda x: -x.severity.rank):
        table.add_row(
            f"[{_severity_style(f.severity.value)}]{f.severity.value}[/]",
            f.location(),
            f.cwe or "-",
            f.title,
        )
    console.print(table)


@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to the git repository."),
    only: Optional[List[str]] = typer.Option(None, "--file", help="Limit to specific repo-relative file(s)."),
    json_out: bool = typer.Option(False, "--json", help="Emit findings as JSON."),
):
    """Scan a repository for security issues (no changes made)."""
    config = Config.from_env()
    agent = SecurityAgent(config, log=lambda m: console.print(f"[dim]{m}[/dim]"))
    result = agent.scan(path, only=list(only) if only else None)
    if json_out:
        console.print_json(json.dumps({"findings": [f.model_dump(mode="json") for f in result.findings]}))
    else:
        _print_findings(result.findings)


@app.command()
def remediate(
    path: str = typer.Argument(".", help="Path to the git repository."),
    only: Optional[List[str]] = typer.Option(None, "--file", help="Limit to specific repo-relative file(s)."),
    min_severity: str = typer.Option(None, "--min-severity", help="low|medium|high|critical."),
    base: Optional[str] = typer.Option(None, "--base", help="Base branch for the PR (default: current)."),
    branch: Optional[str] = typer.Option(None, "--branch", help="Name of the fix branch to create."),
    no_pr: bool = typer.Option(False, "--no-pr", help="Commit locally but do not open a PR."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Scan and generate fixes without touching git."),
):
    """Scan, auto-remediate, and open a pull request with the fixes."""
    config = Config.from_env()
    min_sev = Severity(min_severity.lower()) if min_severity else None
    agent = SecurityAgent(config, log=lambda m: console.print(f"[dim]{m}[/dim]"))
    result = agent.run(
        path,
        only=list(only) if only else None,
        base_branch=base,
        branch_name=branch,
        open_pr=not no_pr,
        dry_run=dry_run,
        min_severity=min_sev,
    )
    _print_findings(result.scan.findings)
    console.print()
    console.print_json(json.dumps(result.summary()))
    if result.pr and result.pr.url:
        console.print(f"\n[bold green]Pull request:[/bold green] {result.pr.url}")
    elif result.pr and result.pr.message:
        console.print(f"\n[yellow]{result.pr.message}[/yellow]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
