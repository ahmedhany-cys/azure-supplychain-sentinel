"""Runtime settings loaded from environment variables.

Every setting has a safe local default so the application works without any
cloud resources. Secrets are never read from here; signing passwords are only
read at the moment they are needed and are never stored on the settings object.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _env_path(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value).expanduser().resolve() if value else default.resolve()


def _env_int(name: str, default: int, minimum: int = 1, maximum: int = 3600) -> int:
    try:
        value = int(os.environ.get(name, default))
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def _env_paths(name: str, default: list[Path]) -> list[Path]:
    raw = os.environ.get(name)
    if not raw:
        return [p.resolve() for p in default]
    return [Path(p).expanduser().resolve() for p in raw.split(os.pathsep) if p.strip()]


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(
        default_factory=lambda: _env_path("SENTINEL_DATA_DIR", REPO_ROOT / ".sentinel")
    )
    # Only directories under these roots may be analysed through the API/dashboard.
    allowed_roots: list[Path] = field(
        default_factory=lambda: _env_paths("SENTINEL_ALLOWED_ROOTS", [REPO_ROOT / "examples"])
    )
    policy_path: Path = field(
        default_factory=lambda: _env_path(
            "SENTINEL_POLICY", REPO_ROOT / "config" / "policy.default.yaml"
        )
    )
    syft_bin: str = field(default_factory=lambda: os.environ.get("SENTINEL_SYFT_BIN", "syft"))
    osv_bin: str = field(
        default_factory=lambda: os.environ.get("SENTINEL_OSV_SCANNER_BIN", "osv-scanner")
    )
    cosign_bin: str = field(default_factory=lambda: os.environ.get("SENTINEL_COSIGN_BIN", "cosign"))
    syft_timeout: int = field(default_factory=lambda: _env_int("SENTINEL_SYFT_TIMEOUT", 120))
    osv_timeout: int = field(default_factory=lambda: _env_int("SENTINEL_OSV_TIMEOUT", 120))
    cosign_timeout: int = field(default_factory=lambda: _env_int("SENTINEL_COSIGN_TIMEOUT", 60))
    max_upload_bytes: int = field(
        default_factory=lambda: (
            _env_int("SENTINEL_MAX_UPLOAD_MB", 50, minimum=1, maximum=1024) * 1024 * 1024
        )
    )
    # "auto" uses an external tool when installed; "off" never invokes it.
    use_syft: str = field(default_factory=lambda: os.environ.get("SENTINEL_USE_SYFT", "auto"))
    use_cosign: str = field(default_factory=lambda: os.environ.get("SENTINEL_USE_COSIGN", "auto"))
    api_token: str | None = field(default_factory=lambda: os.environ.get("SENTINEL_API_TOKEN"))

    @property
    def db_path(self) -> Path:
        return self.data_dir / "sentinel.db"


def get_settings() -> Settings:
    return Settings()
