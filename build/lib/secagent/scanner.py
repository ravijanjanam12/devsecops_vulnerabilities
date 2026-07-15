"""OpenAI-based security scanner.

Sends each source file to the model and asks for a structured list of
vulnerabilities. LLM-only: no external static-analysis tools required.
"""

from __future__ import annotations

from typing import List, Optional

from .config import Config
from .models import Finding, ScanResult, Severity
from .openai_client import OpenAIJSONClient
from .repo import collect_files, read_file

SYSTEM_PROMPT = """You are a senior application security engineer performing a code review.
You identify real, exploitable security vulnerabilities in source code. You focus on:
- Injection (SQL, command, LDAP, template, XSS)
- Broken authentication / authorization and insecure session handling
- Hardcoded secrets, credentials, private keys, API tokens
- Insecure deserialization and unsafe use of eval/exec/pickle
- Path traversal and unsafe file handling
- SSRF, open redirects, and unvalidated input used in requests
- Weak or misused cryptography (MD5/SHA1 for passwords, static IVs, ECB)
- Insecure configuration (debug on, permissive CORS, disabled TLS verification)
- Sensitive data exposure and verbose error handling

Rules:
- Report ONLY genuine security issues, not style or performance nits.
- Do not invent issues. If the file is clean, return an empty list.
- Prefer precise line numbers (1-based) for the vulnerable code.
- Use a CWE identifier when you are confident of one."""

USER_TEMPLATE = """Review the following file for security vulnerabilities.

File path: {path}

--- BEGIN FILE (line-numbered) ---
{numbered}
--- END FILE ---

Respond with a JSON object of the exact form:
{{
  "findings": [
    {{
      "title": "short vulnerability name",
      "severity": "low|medium|high|critical",
      "cwe": "CWE-89 or null",
      "line_start": 12,
      "line_end": 14,
      "description": "why this is exploitable",
      "recommendation": "how to fix it"
    }}
  ]
}}
Return {{"findings": []}} if there are no security issues."""


def _number_lines(content: str, limit: int = 1200) -> str:
    lines = content.splitlines()
    truncated = lines[:limit]
    body = "\n".join(f"{i + 1:>5}  {line}" for i, line in enumerate(truncated))
    if len(lines) > limit:
        body += f"\n... (truncated, {len(lines) - limit} more lines)"
    return body


class SecurityScanner:
    def __init__(self, config: Config):
        config.require_openai()
        self.config = config
        self.client = OpenAIJSONClient(config.openai_api_key, config.model)

    def scan_file(self, root: str, rel_path: str) -> List[Finding]:
        content = read_file(root, rel_path)
        if not content.strip():
            return []
        payload = self.client.complete_json(
            system=SYSTEM_PROMPT,
            user=USER_TEMPLATE.format(path=rel_path, numbered=_number_lines(content)),
        )
        findings: List[Finding] = []
        for raw in payload.get("findings", []) or []:
            try:
                findings.append(
                    Finding(
                        file=rel_path,
                        title=raw.get("title", "Unspecified issue"),
                        severity=Severity((raw.get("severity") or "medium").lower()),
                        cwe=raw.get("cwe"),
                        line_start=raw.get("line_start"),
                        line_end=raw.get("line_end"),
                        description=raw.get("description", ""),
                        recommendation=raw.get("recommendation", ""),
                    )
                )
            except Exception:
                # Skip malformed entries rather than fail the whole scan.
                continue
        return findings

    def scan_repo(
        self,
        root: str,
        only: Optional[List[str]] = None,
        progress=None,
    ) -> ScanResult:
        files = collect_files(
            root,
            exclude=self.config.exclude,
            max_file_kb=self.config.max_file_kb,
            only=only,
        )
        result = ScanResult()
        for rel in files:
            if progress:
                progress(rel)
            result.findings.extend(self.scan_file(root, rel))
        return result
