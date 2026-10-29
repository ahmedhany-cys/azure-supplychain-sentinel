"""Package identity helpers: purl parsing, ecosystem names, name normalisation."""

from __future__ import annotations

import re

from packageurl import PackageURL
from packaging.utils import canonicalize_version
from packaging.version import InvalidVersion

# purl type -> OSV ecosystem name
PURL_TO_ECOSYSTEM = {
    "pypi": "PyPI",
    "npm": "npm",
    "golang": "Go",
    "maven": "Maven",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
    "pub": "Pub",
    "hex": "Hex",
    "deb": "Debian",
    "apk": "Alpine",
    "rpm": "RPM",
    "github": "GitHub Actions",
}
ECOSYSTEM_TO_PURL = {v.lower(): k for k, v in PURL_TO_ECOSYSTEM.items()}


def parse_purl(purl: str | None) -> PackageURL | None:
    if not purl:
        return None
    try:
        return PackageURL.from_string(purl)
    except ValueError:
        return None


def ecosystem_from_purl(purl: str | None) -> str | None:
    parsed = parse_purl(purl)
    if parsed is None:
        return None
    return PURL_TO_ECOSYSTEM.get(parsed.type, parsed.type)


def normalize_name(ecosystem: str | None, name: str) -> str:
    eco = (ecosystem or "").lower()
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()  # PEP 503
    if eco in {"npm", "go", "crates.io", "rubygems", "nuget", "packagist"}:
        return name.lower()
    return name


def component_key(ecosystem: str | None, name: str) -> str:
    return f"{(ecosystem or 'unknown').lower()}:{normalize_name(ecosystem, name)}"


def make_purl(ecosystem: str | None, name: str, version: str | None) -> str | None:
    purl_type = ECOSYSTEM_TO_PURL.get((ecosystem or "").lower())
    if purl_type is None:
        return None
    namespace = None
    pkg_name = name
    if purl_type == "npm" and name.startswith("@") and "/" in name:
        namespace, pkg_name = name.split("/", 1)
    if purl_type == "pypi":
        pkg_name = normalize_name("PyPI", name)
    return PackageURL(
        type=purl_type, namespace=namespace, name=pkg_name, version=version
    ).to_string()


def version_key(ecosystem: str | None, version: str | None) -> str | None:
    """Comparable version string: PyPI versions are canonicalised (``2.10.0`` == ``2.10``)."""
    if version is None or (ecosystem or "").lower() != "pypi":
        return version
    try:
        return canonicalize_version(version)
    except InvalidVersion:
        return version
