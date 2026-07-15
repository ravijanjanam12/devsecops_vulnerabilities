"""Repo traversal helpers: enumerate scannable source files."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Iterable, List, Optional

# Extensions we treat as source code worth scanning.
CODE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".go", ".rb", ".php", ".cs", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".rs", ".kt", ".kts", ".scala", ".swift", ".m", ".mm",
    ".sh", ".bash", ".ps1",
    ".sql", ".html", ".vue", ".svelte",
    ".yml", ".yaml", ".tf", ".dockerfile",
    ".env", ".ini", ".cfg", ".toml", ".json",
}

# Files worth scanning even without a matching extension.
CODE_FILENAMES = {"Dockerfile", "Makefile", ".env", ".npmrc"}


def _binary_looking(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(2048)
        return b"\x00" in chunk
    except OSError:
        return True


def _excluded(rel_path: str, patterns: Iterable[str]) -> bool:
    normalized = rel_path.replace(os.sep, "/")
    for pattern in patterns:
        if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch("/" + normalized, pattern):
            return True
    return False


def collect_files(
    root: str,
    exclude: Iterable[str],
    max_file_kb: int = 200,
    only: Optional[Iterable[str]] = None,
) -> List[str]:
    """Return repo-relative paths of source files to scan.

    `only`, if provided, restricts the result to that explicit set of
    repo-relative paths (used to scan just the files changed in a diff).
    """
    root_path = Path(root).resolve()
    only_set = {p.replace(os.sep, "/") for p in only} if only else None
    max_bytes = max_file_kb * 1024
    results: List[str] = []

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Prune obvious heavy directories early for speed.
        dirnames[:] = [
            d for d in dirnames
            if d not in {".git", "node_modules", ".venv", "__pycache__", "dist", "build"}
        ]
        for name in filenames:
            abs_path = Path(dirpath) / name
            rel = str(abs_path.relative_to(root_path)).replace(os.sep, "/")

            if only_set is not None and rel not in only_set:
                continue
            if _excluded(rel, exclude):
                continue

            ext = abs_path.suffix.lower()
            if ext not in CODE_EXTENSIONS and name not in CODE_FILENAMES:
                continue
            try:
                if abs_path.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            if _binary_looking(abs_path):
                continue
            results.append(rel)

    return sorted(results)


def read_file(root: str, rel_path: str) -> str:
    with open(Path(root) / rel_path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()
