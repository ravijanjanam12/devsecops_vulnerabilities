"""MCP server exposing secagent as tools.

Runs over stdio so it can be registered with any MCP client (Claude Desktop,
Cowork, Claude Code, etc.). Exposes three tools:

  - security_scan:        scan a repo and return findings
  - security_remediate:   scan, fix, and (optionally) open a PR
  - list_scannable_files: preview which files would be scanned

Register (Claude Desktop / Cowork `mcpServers` config):

  {
    "mcpServers": {
      "secagent": {
        "command": "secagent-mcp",
        "env": {
          "OPENAI_API_KEY": "sk-...",
          "GITHUB_TOKEN": "ghp_...",
          "SECAGENT_MODEL": "gpt-4o"
        }
      }
    }
  }
"""

from __future__ import annotations

import json
from typing import List, Optional

from mcp.server.fastmcp import FastMCP

from .agent import SecurityAgent
from .config import Config
from .models import Severity
from .repo import collect_files

mcp = FastMCP("secagent")


def _config() -> Config:
    return Config.from_env()


@mcp.tool()
def list_scannable_files(path: str = ".", max_file_kb: int = 200) -> str:
    """List the source files that would be scanned in the repository at `path`.

    Args:
        path: Path to the git repository (default: current directory).
        max_file_kb: Skip files larger than this many KB.
    """
    cfg = _config()
    files = collect_files(path, exclude=cfg.exclude, max_file_kb=max_file_kb)
    return json.dumps({"count": len(files), "files": files}, indent=2)


@mcp.tool()
def security_scan(path: str = ".", files: Optional[List[str]] = None) -> str:
    """Scan a git repository for security vulnerabilities using an OpenAI model.

    Makes no changes to the repository. Returns a JSON report of findings with
    severity, location, description, and recommended fix.

    Args:
        path: Path to the git repository (default: current directory).
        files: Optional list of repo-relative files to restrict the scan to.
    """
    cfg = _config()
    agent = SecurityAgent(cfg)
    scan = agent.scan(path, only=files)
    report = {
        "counts": scan.counts(),
        "total_findings": len(scan.findings),
        "findings": [f.model_dump(mode="json") for f in scan.findings],
    }
    return json.dumps(report, indent=2)


@mcp.tool()
def security_remediate(
    path: str = ".",
    files: Optional[List[str]] = None,
    min_severity: str = "medium",
    base_branch: Optional[str] = None,
    branch_name: Optional[str] = None,
    open_pr: bool = True,
    dry_run: bool = False,
) -> str:
    """Scan, auto-remediate, and open a pull request with the security fixes.

    Uses an OpenAI model to both find and fix vulnerabilities. Applies fixes on
    a new branch, commits them, and (unless disabled) opens a GitHub PR.

    Args:
        path: Path to the git repository (default: current directory).
        files: Optional list of repo-relative files to restrict work to.
        min_severity: Minimum severity to remediate (low|medium|high|critical).
        base_branch: Base branch for the PR (default: current branch).
        branch_name: Name for the fix branch (default: auto-generated).
        open_pr: Whether to push and open a PR (requires GITHUB_TOKEN).
        dry_run: If true, generate fixes but make no git changes.
    """
    cfg = _config()
    try:
        min_sev = Severity(min_severity.lower())
    except ValueError:
        min_sev = Severity.MEDIUM

    agent = SecurityAgent(cfg)
    result = agent.run(
        path,
        only=files,
        base_branch=base_branch,
        branch_name=branch_name,
        open_pr=open_pr,
        dry_run=dry_run,
        min_severity=min_sev,
    )
    payload = result.summary()
    payload["fixes"] = [
        {"file": fx.file, "explanation": fx.explanation, "addressed": fx.addressed_findings}
        for fx in result.fixes
    ]
    if result.pr:
        payload["pr_message"] = result.pr.message
        payload["pr_number"] = result.pr.number
    return json.dumps(payload, indent=2)


def main() -> None:
    """Entry point: run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
