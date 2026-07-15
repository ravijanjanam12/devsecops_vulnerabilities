"""OpenAI-based remediator.

Given a file and the findings against it, asks the model to return a fully
patched version of that file. Fixes are grouped per-file so a single edit can
address several findings at once.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional

from .config import Config
from .models import FileFix, Finding
from .openai_client import OpenAIJSONClient
from .repo import read_file

SYSTEM_PROMPT = """You are a senior application security engineer remediating vulnerabilities.
You are given a source file and a list of confirmed security findings against it.
Produce a corrected version of the ENTIRE file that fixes every finding while:
- Preserving all existing functionality and public behavior.
- Keeping code style, imports, and formatting consistent with the original.
- Making the smallest change necessary to remove each vulnerability.
- Never introducing placeholders, TODOs, or omitted sections ("... rest unchanged").
  You must output the complete file, top to bottom.
- For hardcoded secrets: replace with an environment-variable lookup and do not
  invent a new secret value.

If a finding cannot be safely fixed without more context, leave that code as-is
and explain why in the explanation field, rather than guessing."""

USER_TEMPLATE = """File path: {path}

Findings to fix:
{findings_block}

--- BEGIN ORIGINAL FILE ---
{content}
--- END ORIGINAL FILE ---

Respond with a JSON object of the exact form:
{{
  "changed": true,
  "new_content": "the complete corrected file contents",
  "explanation": "what you changed and why",
  "addressed_findings": ["finding title 1", "finding title 2"]
}}
Set "changed" to false and omit "new_content" if you make no changes."""


def _findings_block(findings: List[Finding]) -> str:
    lines = []
    for i, f in enumerate(findings, 1):
        loc = f"lines {f.line_start}-{f.line_end}" if f.line_start else "location unknown"
        cwe = f" [{f.cwe}]" if f.cwe else ""
        lines.append(
            f"{i}. ({f.severity.value}){cwe} {f.title} @ {loc}\n"
            f"   Problem: {f.description}\n"
            f"   Suggested fix: {f.recommendation}"
        )
    return "\n".join(lines)


class Remediator:
    def __init__(self, config: Config):
        config.require_openai()
        self.config = config
        self.client = OpenAIJSONClient(config.openai_api_key, config.model)

    def fix_file(self, root: str, rel_path: str, findings: List[Finding]) -> Optional[FileFix]:
        original = read_file(root, rel_path)
        payload = self.client.complete_json(
            system=SYSTEM_PROMPT,
            user=USER_TEMPLATE.format(
                path=rel_path,
                findings_block=_findings_block(findings),
                content=original,
            ),
            max_tokens=8192,
        )
        if not payload.get("changed"):
            return None
        new_content = payload.get("new_content")
        if not new_content or new_content == original:
            return None
        return FileFix(
            file=rel_path,
            new_content=new_content,
            explanation=payload.get("explanation", ""),
            addressed_findings=payload.get("addressed_findings", []) or [],
        )

    def fix_findings(
        self,
        root: str,
        findings: List[Finding],
        progress=None,
    ) -> List[FileFix]:
        grouped: Dict[str, List[Finding]] = defaultdict(list)
        for f in findings:
            grouped[f.file].append(f)

        fixes: List[FileFix] = []
        for rel_path, file_findings in grouped.items():
            if progress:
                progress(rel_path)
            fix = self.fix_file(root, rel_path, file_findings)
            if fix:
                fixes.append(fix)
        return fixes
