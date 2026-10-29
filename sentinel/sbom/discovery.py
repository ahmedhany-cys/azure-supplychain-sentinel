"""Read-only manifest discovery and native lockfile parsing.

Nothing in this module executes project code: ``setup.py``, install scripts
and build files are only ever *detected*, never run. Native parsers exist for
formats whose resolved versions and dependency relationships can be read
reliably from the file itself; everything else is reported as unsupported
rather than guessed.
"""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from sentinel.core.models import Component, DiscoveryResult, ManifestInfo
from sentinel.core.security import SecurityError, read_bounded, resolve_within
from sentinel.sbom.identity import component_key, make_purl, normalize_name

MAX_MANIFEST_BYTES = 10 * 1024 * 1024
MAX_FILES_WALKED = 20_000
MAX_DEPTH = 8
SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "site-packages",
    ".terraform",
}

# filename -> (ecosystem, kind, natively supported, note)
KNOWN_MANIFESTS: dict[str, tuple[str, str, bool, str | None]] = {
    "package-lock.json": ("npm", "npm lockfile", True, None),
    "poetry.lock": ("PyPI", "Poetry lockfile", True, None),
    "package.json": (
        "npm",
        "npm manifest",
        False,
        "manifest without resolved versions; a lockfile is required for exact versions",
    ),
    "pyproject.toml": (
        "PyPI",
        "Python project metadata",
        False,
        "declares ranges, not resolved versions; use a lockfile or pinned requirements",
    ),
    "setup.py": (
        "PyPI",
        "setuptools script",
        False,
        "executable build script; never executed by Sentinel",
    ),
    "Pipfile.lock": ("PyPI", "Pipenv lockfile", False, "no native parser; Syft may catalog it"),
    "yarn.lock": ("npm", "Yarn lockfile", False, "no native parser; Syft may catalog it"),
    "pnpm-lock.yaml": ("npm", "pnpm lockfile", False, "no native parser; Syft may catalog it"),
    "go.mod": ("Go", "Go module", False, "no native parser; Syft may catalog it"),
    "go.sum": ("Go", "Go checksums", False, "no native parser; Syft may catalog it"),
    "Cargo.lock": ("crates.io", "Cargo lockfile", False, "no native parser; Syft may catalog it"),
    "Gemfile.lock": (
        "RubyGems",
        "Bundler lockfile",
        False,
        "no native parser; Syft may catalog it",
    ),
    "composer.lock": (
        "Packagist",
        "Composer lockfile",
        False,
        "no native parser; Syft may catalog it",
    ),
    "pom.xml": (
        "Maven",
        "Maven POM",
        False,
        "transitive versions need Maven resolution; Syft may catalog declared ones",
    ),
    "build.gradle": ("Maven", "Gradle build script", False, "executable build script; not parsed"),
    "build.gradle.kts": (
        "Maven",
        "Gradle build script",
        False,
        "executable build script; not parsed",
    ),
    "packages.lock.json": (
        "NuGet",
        "NuGet lockfile",
        False,
        "no native parser; Syft may catalog it",
    ),
}


def _is_requirements_file(name: str) -> bool:
    return name.endswith(".txt") and name.startswith("requirements")


def discover(root: Path) -> DiscoveryResult:
    root = root.resolve()
    if not root.is_dir():
        raise SecurityError("project path must be a directory")
    result = DiscoveryResult(root=str(root))
    walked = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root)
        if len(rel_dir.parts) >= MAX_DEPTH:
            dirnames[:] = []
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for filename in sorted(filenames):
            walked += 1
            if walked > MAX_FILES_WALKED:
                result.warnings.append(
                    f"stopped after {MAX_FILES_WALKED} files; discovery is incomplete"
                )
                return result
            rel = str(rel_dir / filename) if rel_dir.parts else filename
            if (Path(dirpath) / filename).is_symlink():
                continue
            if _is_requirements_file(filename):
                result.manifests.append(
                    ManifestInfo(
                        path=rel, ecosystem="PyPI", kind="pip requirements", supported=True
                    )
                )
            elif filename in KNOWN_MANIFESTS:
                eco, kind, supported, note = KNOWN_MANIFESTS[filename]
                result.manifests.append(
                    ManifestInfo(path=rel, ecosystem=eco, kind=kind, supported=supported, note=note)
                )
    _mark_covered(result)
    if not result.manifests:
        result.warnings.append("no recognised package manifests or lockfiles were found")
    elif not result.supported:
        result.warnings.append(
            "manifests were found but none can be parsed natively; component discovery "
            "depends on Syft and may be incomplete"
        )
    return result


# Manifests that only declare ranges are resolved by a sibling lockfile when one exists.
_COVERED_BY = {
    "package.json": ("package-lock.json",),
    "pyproject.toml": ("poetry.lock", "requirements.txt"),
}


def _mark_covered(result: DiscoveryResult) -> None:
    supported = {m.path for m in result.supported}
    for manifest in result.unsupported:
        path = Path(manifest.path)
        for lock in _COVERED_BY.get(path.name, ()):
            sibling = str(path.with_name(lock))
            if sibling in supported:
                manifest.covered_by = sibling
                break


@dataclass
class ParseOutcome:
    components: list[Component] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def parse_project(root: Path, discovery: DiscoveryResult) -> ParseOutcome:
    outcome = ParseOutcome()
    for manifest in discovery.supported:
        path = resolve_within(root, manifest.path)
        try:
            if manifest.kind == "pip requirements":
                part = parse_requirements(path, root)
            elif manifest.kind == "npm lockfile":
                part = parse_package_lock(path)
            elif manifest.kind == "Poetry lockfile":
                part = parse_poetry_lock(path)
            else:  # pragma: no cover - guarded by KNOWN_MANIFESTS
                continue
        except (SecurityError, ValueError, KeyError, TypeError) as exc:
            outcome.warnings.append(f"{manifest.path}: could not be parsed ({exc})")
            continue
        for comp in part.components:
            comp.locations = [manifest.path]
        outcome.components.extend(part.components)
        outcome.warnings.extend(f"{manifest.path}: {w}" for w in part.warnings)
    outcome.components = dedupe_components(outcome.components)
    return outcome


def dedupe_components(components: list[Component]) -> list[Component]:
    """Merge entries for the same package version found in several manifests."""
    seen: dict[tuple[str, str | None], Component] = {}
    for comp in components:
        key = (comp.key, comp.version)
        if key in seen:
            existing = seen[key]
            existing.locations = sorted(set(existing.locations + comp.locations))
            if existing.scope != "direct" and comp.scope == "direct":
                existing.scope = "direct"
            existing.introduced_via = sorted(set(existing.introduced_via + comp.introduced_via))
        else:
            seen[key] = comp
    return list(seen.values())


# --------------------------------------------------------------------------- pip


def parse_requirements(path: Path, root: Path, _depth: int = 0) -> ParseOutcome:
    """Parse pinned requirements, using pip-compile ``# via`` annotations when present."""
    outcome = ParseOutcome()
    text = read_bounded(path, MAX_MANIFEST_BYTES).decode("utf-8", errors="replace")
    logical: list[tuple[str, list[str]]] = []  # (requirement line, via-annotations)
    pending = ""
    annotated = "# via" in text
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("#"):
            comment = stripped.lstrip("#").strip()
            if logical and comment.startswith("via"):
                rest = comment[3:].strip()
                if rest:
                    logical[-1][1].append(rest)
            elif logical and logical[-1][1] is not None and raw_line.startswith("    #   "):
                logical[-1][1].append(comment)
            continue
        line = (pending + " " + stripped).strip() if pending else stripped
        if line.endswith("\\"):
            pending = line[:-1]
            continue
        pending = ""
        if line:
            logical.append((line, []))

    for line, via in logical:
        content = line.split(" #", 1)[0].strip()
        if content.startswith(("-r ", "--requirement ")):
            if _depth >= 3:
                outcome.warnings.append("nested -r includes deeper than 3 levels ignored")
                continue
            target = content.split(None, 1)[1].strip()
            try:
                included = resolve_within(root, path.parent / target)
            except SecurityError as exc:
                outcome.warnings.append(f"include {target!r} rejected: {exc}")
                continue
            sub = parse_requirements(included, root, _depth + 1)
            outcome.components.extend(sub.components)
            outcome.warnings.extend(sub.warnings)
            continue
        if content.startswith("-"):
            if content.startswith(("-e", "--editable")):
                outcome.warnings.append(f"editable/local requirement not inventoried: {content}")
            continue
        content = " ".join(tok for tok in content.split() if not tok.startswith("--hash"))
        try:
            req = Requirement(content)
        except InvalidRequirement:
            outcome.warnings.append(f"unparseable requirement skipped: {content[:80]}")
            continue
        if req.url:
            outcome.warnings.append(f"{req.name}: URL requirement; version cannot be verified")
        version = None
        specs = list(req.specifier)
        if len(specs) == 1 and specs[0].operator in {"==", "==="} and "*" not in specs[0].version:
            version = specs[0].version
        else:
            outcome.warnings.append(
                f"{req.name}: not pinned to an exact version ({req.specifier or 'any'}); "
                "version recorded as unknown"
            )
        parents = [p for p in via if not p.startswith(("-r", "-c"))]
        if annotated:
            scope = (
                "direct"
                if any(p.startswith("-r") for p in via)
                else ("transitive" if parents else "unknown")
            )
        else:
            scope = "unknown"
        outcome.components.append(
            Component(
                name=normalize_name("PyPI", req.name),
                version=version,
                ecosystem="PyPI",
                purl=make_purl("PyPI", req.name, version),
                scope=scope,
                introduced_via=sorted(normalize_name("PyPI", p) for p in parents),
                found_by="sentinel-requirements-parser",
            )
        )
    if not annotated and outcome.components:
        outcome.warnings.append(
            "no pip-compile '# via' annotations; direct vs transitive cannot be determined"
        )
    return outcome


# --------------------------------------------------------------------------- npm


def parse_package_lock(path: Path) -> ParseOutcome:
    outcome = ParseOutcome()
    data = json.loads(read_bounded(path, MAX_MANIFEST_BYTES))
    version = data.get("lockfileVersion")
    packages = data.get("packages")
    if version not in (2, 3) or not isinstance(packages, dict):
        raise ValueError(f"lockfileVersion {version!r} not supported (need 2 or 3)")
    root_entry = packages.get("", {})
    direct_names: set[str] = set()
    for field_name in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        direct_names.update((root_entry.get(field_name) or {}).keys())
    parents: dict[str, set[str]] = {}
    entries: list[tuple[str, str, dict]] = []
    for key, entry in packages.items():
        if not key or not isinstance(entry, dict) or entry.get("link"):
            continue
        name = entry.get("name") or key.rsplit("node_modules/", 1)[-1]
        entries.append((key, name, entry))
        for dep in entry.get("dependencies") or {}:
            parents.setdefault(dep, set()).add(name)
    dev_count = 0
    for key, name, entry in entries:
        pkg_version = entry.get("version")
        if not pkg_version:
            outcome.warnings.append(f"{name}: no version in lockfile entry")
        is_top_level = key == f"node_modules/{name}"
        scope = "direct" if is_top_level and name in direct_names else "transitive"
        if entry.get("dev"):
            dev_count += 1
        outcome.components.append(
            Component(
                name=name,
                version=pkg_version,
                ecosystem="npm",
                purl=make_purl("npm", name, pkg_version),
                scope=scope,
                introduced_via=sorted(parents.get(name, set())) if scope == "transitive" else [],
                licenses=[entry["license"]] if isinstance(entry.get("license"), str) else [],
                found_by="sentinel-npm-lock-parser",
            )
        )
    if dev_count:
        outcome.warnings.append(f"{dev_count} development-only packages are included")
    return outcome


# ------------------------------------------------------------------------ poetry


def parse_poetry_lock(path: Path) -> ParseOutcome:
    outcome = ParseOutcome()
    data = tomllib.loads(read_bounded(path, MAX_MANIFEST_BYTES).decode())
    direct: set[str] | None = None
    pyproject = path.parent / "pyproject.toml"
    if pyproject.is_file() and not pyproject.is_symlink():
        meta = tomllib.loads(read_bounded(pyproject, MAX_MANIFEST_BYTES).decode())
        direct = set()
        poetry_deps = meta.get("tool", {}).get("poetry", {}).get("dependencies", {})
        direct.update(normalize_name("PyPI", n) for n in poetry_deps if n.lower() != "python")
        for spec in meta.get("project", {}).get("dependencies", []):
            try:
                direct.add(normalize_name("PyPI", Requirement(spec).name))
            except InvalidRequirement:
                continue
    parents: dict[str, set[str]] = {}
    for pkg in data.get("package", []):
        for dep in pkg.get("dependencies") or {}:
            parents.setdefault(normalize_name("PyPI", dep), set()).add(
                normalize_name("PyPI", pkg["name"])
            )
    for pkg in data.get("package", []):
        name = normalize_name("PyPI", pkg["name"])
        scope = "unknown" if direct is None else "direct" if name in direct else "transitive"
        outcome.components.append(
            Component(
                name=name,
                version=pkg.get("version"),
                ecosystem="PyPI",
                purl=make_purl("PyPI", name, pkg.get("version")),
                scope=scope,
                introduced_via=sorted(parents.get(name, set())) if scope != "direct" else [],
                found_by="sentinel-poetry-lock-parser",
            )
        )
    if direct is None:
        outcome.warnings.append("pyproject.toml not found; direct vs transitive unknown")
    return outcome


def project_identities(root: Path, discovery: DiscoveryResult) -> set[str]:
    """Component keys that identify the analysed project itself (not its dependencies)."""
    keys: set[str] = set()
    for manifest in discovery.manifests:
        path = root / manifest.path
        if path.is_symlink() or not path.is_file():
            continue
        name = Path(manifest.path).name
        try:
            if name in {"package.json", "package-lock.json"}:
                data = json.loads(read_bounded(path, MAX_MANIFEST_BYTES))
                root_name = data.get("name") or (data.get("packages", {}).get("", {}).get("name"))
                if isinstance(root_name, str) and root_name:
                    keys.add(component_key("npm", root_name))
            elif name == "pyproject.toml":
                meta = tomllib.loads(read_bounded(path, MAX_MANIFEST_BYTES).decode())
                for candidate in (
                    meta.get("project", {}).get("name"),
                    meta.get("tool", {}).get("poetry", {}).get("name"),
                ):
                    if isinstance(candidate, str) and candidate:
                        keys.add(component_key("PyPI", candidate))
        except (SecurityError, ValueError, tomllib.TOMLDecodeError):
            continue
    return keys
