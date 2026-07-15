"""Configuration loaded from environment / .env."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

from dotenv import load_dotenv

from .models import Severity

load_dotenv()

DEFAULT_EXCLUDES = [
    "**/node_modules/**",
    "**/.git/**",
    "**/dist/**",
    "**/build/**",
    "**/*.min.js",
    "**/vendor/**",
    "**/.venv/**",
    "**/__pycache__/**",
]


def _split(value: str) -> List[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


@dataclass
class Config:
    openai_api_key: str = ""
    github_token: str = ""
    model: str = "gpt-4o"
    exclude: List[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    max_file_kb: int = 200
    min_fix_severity: Severity = Severity.MEDIUM

    @classmethod
    def from_env(cls) -> "Config":
        excludes = os.getenv("SECAGENT_EXCLUDE")
        min_sev = os.getenv("SECAGENT_MIN_FIX_SEVERITY", "medium").lower()
        return cls(
            openai_api_key=os.getenv("OPENAI_API_KEY", ""),
            github_token=os.getenv("GITHUB_TOKEN", ""),
            model=os.getenv("SECAGENT_MODEL", "gpt-4o"),
            exclude=_split(excludes) if excludes else list(DEFAULT_EXCLUDES),
            max_file_kb=int(os.getenv("SECAGENT_MAX_FILE_KB", "200")),
            min_fix_severity=Severity(min_sev if min_sev in {s.value for s in Severity} else "medium"),
        )

    def require_openai(self) -> None:
        if not self.openai_api_key:
            raise RuntimeError("OPENAI_API_KEY is not set. Add it to your environment or .env file.")

    def require_github(self) -> None:
        if not self.github_token:
            raise RuntimeError("GITHUB_TOKEN is not set. Add a token with `repo` scope to open PRs.")
