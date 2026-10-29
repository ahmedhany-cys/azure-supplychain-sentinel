"""The only place Sentinel executes external programs.

* argv lists only; ``shell=False`` always, so file names can never be interpreted
  as shell syntax;
* a hard timeout, after which the whole process group is killed;
* captured output is size-capped and secret-redacted before it is stored;
* a minimal environment: tools do not inherit tokens or cloud credentials
  from the caller unless they are explicitly passed through.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.core.security import redact, truncate

_PASSTHROUGH_ENV = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
)
MAX_CAPTURE_BYTES = 64 * 1024 * 1024


@dataclass
class ToolResult:
    argv: list[str]
    returncode: int | None
    stdout: bytes = b""
    stderr: str = ""
    timed_out: bool = False
    not_found: bool = False
    duration_s: float = 0.0
    error: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not (self.timed_out or self.not_found or self.error) and self.returncode == 0


def which(binary: str) -> str | None:
    if os.sep in binary:
        path = Path(binary)
        return str(path) if path.is_file() and os.access(path, os.X_OK) else None
    return shutil.which(binary)


def run_tool(
    argv: list[str],
    *,
    timeout: int,
    cwd: Path | None = None,
    env_extra: dict[str, str] | None = None,
) -> ToolResult:
    if not argv or not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise TypeError("argv must be a non-empty list of strings")
    resolved = which(argv[0])
    if resolved is None:
        return ToolResult(
            argv=argv, returncode=None, not_found=True, error=f"executable not found: {argv[0]}"
        )
    env = {k: v for k, v in os.environ.items() if k in _PASSTHROUGH_ENV}
    env.update(env_extra or {})
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            [resolved, *argv[1:]],
            cwd=str(cwd) if cwd else None,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,  # own process group so a timeout kills children too
        )
    except OSError as exc:
        return ToolResult(argv=argv, returncode=None, error=f"failed to start: {exc.strerror}")
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        stdout, stderr = proc.communicate()
        return ToolResult(
            argv=argv,
            returncode=None,
            timed_out=True,
            stderr=truncate(redact(stderr.decode(errors="replace"))),
            duration_s=round(time.monotonic() - started, 3),
            error=f"timed out after {timeout}s",
        )
    result = ToolResult(
        argv=argv,
        returncode=proc.returncode,
        stdout=stdout[:MAX_CAPTURE_BYTES],
        stderr=truncate(redact(stderr.decode(errors="replace"))),
        duration_s=round(time.monotonic() - started, 3),
    )
    if len(stdout) > MAX_CAPTURE_BYTES:
        result.error = "tool output exceeded capture limit"
    return result


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()


def tool_version(binary: str, args: list[str], timeout: int = 15) -> str | None:
    """Best-effort version string; returns None when the tool is missing or fails."""
    result = run_tool([binary, *args], timeout=timeout)
    if not result.ok:
        return None
    text = result.stdout.decode(errors="replace")
    for line in text.splitlines():
        lowered = line.lower()
        if "version" in lowered and ":" in line:
            value = line.split(":", 1)[1].strip()
            if value:
                return value.lstrip("v")
    first = text.strip().splitlines()
    return first[0].strip() if first else None
