"""Defensive helpers: path confinement, bounded parsing, hashing and redaction."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 25 * 1024 * 1024  # SBOMs for large images can be big; cap anyway
MAX_SMALL_JSON_BYTES = 2 * 1024 * 1024  # bundles, provenance, release records


class SecurityError(ValueError):
    """Raised when input violates a safety constraint (traversal, size, type)."""


def resolve_within(base: Path, candidate: str | Path, *, must_exist: bool = True) -> Path:
    """Resolve ``candidate`` relative to ``base`` and refuse anything outside ``base``.

    Symlinks are resolved before the containment check, so a link pointing
    outside the base directory is rejected as well.
    """
    base_resolved = base.resolve()
    raw = Path(candidate)
    target = (raw if raw.is_absolute() else base_resolved / raw).resolve()
    if target != base_resolved and base_resolved not in target.parents:
        raise SecurityError(f"path escapes allowed directory: {candidate}")
    if must_exist and not target.exists():
        raise SecurityError(f"path does not exist: {candidate}")
    return target


def ensure_allowed_root(path: str | Path, allowed_roots: list[Path]) -> Path:
    """Confine user-supplied project paths to configured roots (API/dashboard input)."""
    candidate = Path(path).expanduser()
    for root in allowed_roots:
        try:
            resolved = resolve_within(root, candidate, must_exist=True)
        except SecurityError:
            continue
        return resolved
    raise SecurityError(
        "project path is not inside an allowed analysis root "
        "(configure SENTINEL_ALLOWED_ROOTS to permit additional directories)"
    )


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bounded(path: Path, max_bytes: int) -> bytes:
    if not path.is_file():
        raise SecurityError(f"not a regular file: {path.name}")
    size = path.stat().st_size
    if size > max_bytes:
        raise SecurityError(f"{path.name} is {size} bytes; limit is {max_bytes}")
    return path.read_bytes()


def load_json_bounded(path: Path, max_bytes: int = MAX_JSON_BYTES) -> Any:
    data = read_bounded(path, max_bytes)
    return parse_json_bytes(data, max_bytes)


def parse_json_bytes(data: bytes, max_bytes: int = MAX_JSON_BYTES) -> Any:
    if len(data) > max_bytes:
        raise SecurityError(f"JSON document exceeds {max_bytes} bytes")
    try:
        return json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SecurityError(f"invalid JSON: {exc.msg if hasattr(exc, 'msg') else exc}") from exc


_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED PRIVATE KEY]",
    ),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED AWS KEY]"),
    (re.compile(r"(?i)(AccountKey|SharedAccessSignature|sig)=([^;&\s]+)"), r"\1=[REDACTED]"),
    (
        re.compile(
            r"(?i)\b([\w-]*(?:password|passwd|secret|token|api[_-]?key))"
            r"(\s*[=:]\s*)(\"?)([^\s\"']{4,})"
        ),
        r"\1\2\3[REDACTED]",
    ),
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._\-]+"), r"\1[REDACTED]"),
]


def redact(text: str) -> str:
    """Remove secrets that commonly leak through tool output and error messages."""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def redact_json(document: str) -> str:
    """Redact a serialised JSON document, keeping it parseable.

    Tool output is already redacted where it is captured; this is a second line of
    defence. If a substitution would break JSON escaping, the original (already
    source-redacted) document is kept rather than storing corrupt data.
    """
    redacted = redact(document)
    try:
        json.loads(redacted)
    except json.JSONDecodeError:
        return document
    return redacted


def truncate(text: str, limit: int = 4000) -> str:
    return (
        text if len(text) <= limit else text[:limit] + f"... [truncated {len(text) - limit} chars]"
    )


@contextmanager
def private_tempdir(prefix: str = "sentinel-") -> Iterator[Path]:
    """A 0700 temporary directory that is always removed."""
    with tempfile.TemporaryDirectory(prefix=prefix) as tmp:
        path = Path(tmp)
        path.chmod(0o700)
        yield path


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(name: str, default: str = "upload.bin") -> str:
    """Reduce an untrusted filename to a harmless basename."""
    base = Path(name or "").name
    cleaned = _SAFE_NAME.sub("_", base).strip("._")
    return cleaned[:128] or default
