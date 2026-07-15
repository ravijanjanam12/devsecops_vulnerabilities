"""Shared data models used across scanner, remediator, and orchestrator."""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Finding(BaseModel):
    """A single security issue reported by the scanner."""

    file: str = Field(..., description="Repo-relative path to the affected file.")
    title: str = Field(..., description="Short name of the vulnerability.")
    severity: Severity = Field(Severity.MEDIUM)
    cwe: Optional[str] = Field(None, description="CWE identifier, e.g. CWE-89.")
    line_start: Optional[int] = Field(None, description="1-based first affected line.")
    line_end: Optional[int] = Field(None, description="1-based last affected line.")
    description: str = Field("", description="Why this is a vulnerability.")
    recommendation: str = Field("", description="How it should be fixed.")

    def location(self) -> str:
        if self.line_start and self.line_end and self.line_start != self.line_end:
            return f"{self.file}:{self.line_start}-{self.line_end}"
        if self.line_start:
            return f"{self.file}:{self.line_start}"
        return self.file


class FileFix(BaseModel):
    """A proposed replacement for the full contents of a single file."""

    file: str
    new_content: str
    explanation: str = ""
    addressed_findings: List[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    findings: List[Finding] = Field(default_factory=list)

    def by_min_severity(self, minimum: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity.rank >= minimum.rank]

    def counts(self) -> dict:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out
