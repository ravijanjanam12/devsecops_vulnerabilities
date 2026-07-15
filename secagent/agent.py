"""Orchestrator: scan -> remediate -> branch/commit/PR."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .config import Config
from .git_ops import (
    GitRemediationRunner,
    PRResult,
    build_commit_message,
    build_pr_body,
    detect_remote_slug,
    _default_branch_name,
)
from .models import FileFix, ScanResult, Severity
from .remediator import Remediator
from .scanner import SecurityScanner

Logger = Callable[[str], None]


@dataclass
class AgentResult:
    scan: ScanResult
    fixes: List[FileFix] = field(default_factory=list)
    pr: Optional[PRResult] = None
    dry_run: bool = False

    def summary(self) -> dict:
        return {
            "counts": self.scan.counts(),
            "total_findings": len(self.scan.findings),
            "files_fixed": len(self.fixes),
            "dry_run": self.dry_run,
            "pr_url": self.pr.url if self.pr else None,
            "branch": self.pr.branch if self.pr else None,
        }


class SecurityAgent:
    def __init__(self, config: Config, log: Optional[Logger] = None):
        self.config = config
        self.log = log or (lambda _m: None)

    def scan(self, root: str, only: Optional[List[str]] = None) -> ScanResult:
        scanner = SecurityScanner(self.config)
        return scanner.scan_repo(root, only=only, progress=lambda p: self.log(f"scanning {p}"))

    def run(
        self,
        root: str,
        only: Optional[List[str]] = None,
        base_branch: Optional[str] = None,
        branch_name: Optional[str] = None,
        open_pr: bool = True,
        dry_run: bool = False,
        min_severity: Optional[Severity] = None,
    ) -> AgentResult:
        min_sev = min_severity or self.config.min_fix_severity

        # 1. Scan
        self.log("Starting security scan...")
        scan = self.scan(root, only=only)
        self.log(f"Scan complete: {len(scan.findings)} finding(s).")

        targets = scan.by_min_severity(min_sev)
        if not targets:
            self.log(f"No findings at severity >= {min_sev.value}; nothing to remediate.")
            return AgentResult(scan=scan, dry_run=dry_run)

        # 2. Remediate
        self.log(f"Remediating {len(targets)} finding(s) at severity >= {min_sev.value}...")
        remediator = Remediator(self.config)
        fixes = remediator.fix_findings(root, targets, progress=lambda p: self.log(f"fixing {p}"))
        self.log(f"Generated fixes for {len(fixes)} file(s).")

        if not fixes:
            return AgentResult(scan=scan, dry_run=dry_run)

        result = AgentResult(scan=scan, fixes=fixes, dry_run=dry_run)

        if dry_run:
            self.log("Dry run: skipping git operations.")
            return result

        # 3. Branch / commit / PR
        runner = GitRemediationRunner(root, github_token=self.config.github_token)
        base = base_branch or runner.current_branch()
        branch = branch_name or _default_branch_name()

        changed = runner.apply_fixes(fixes)
        committed = runner.commit_on_branch(changed, branch, build_commit_message(fixes))
        pr = PRResult(branch=branch, committed=committed)

        if committed and open_pr:
            slug = detect_remote_slug(runner.repo)
            if not slug:
                pr.message = "Committed locally; could not detect a GitHub remote to open a PR."
                self.log(pr.message)
            elif not self.config.github_token:
                pr.message = "Committed locally; GITHUB_TOKEN not set so no PR was opened."
                self.log(pr.message)
            else:
                self.log(f"Pushing branch {branch} and opening PR against {base}...")
                runner.push_branch(branch)
                pr.pushed = True
                url, number = runner.open_pull_request(
                    slug=slug,
                    branch=branch,
                    base=base,
                    title=f"fix(security): auto-remediate {len(fixes)} file(s)",
                    body=build_pr_body(scan, fixes, min_sev.value),
                )
                pr.url, pr.number = url, number
                self.log(f"Opened PR #{number}: {url}")
        elif committed:
            pr.message = f"Committed to local branch '{branch}'. PR creation skipped."

        result.pr = pr
        return result
