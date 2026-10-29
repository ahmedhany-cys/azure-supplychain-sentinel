import json
from pathlib import Path

import pytest

from sentinel.core.security import SecurityError
from sentinel.sbom.discovery import (
    discover,
    parse_package_lock,
    parse_poetry_lock,
    parse_project,
    parse_requirements,
    project_identities,
)

from ..conftest import EXAMPLES


def _by_name(components):
    return {c.name: c for c in components}


def test_pip_compile_annotations_give_direct_and_transitive(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "certifi==2020.12.5\n    # via requests\n"
        "idna==3.4\n    # via\n    #   -r requirements.in\n    #   requests\n"
        "requests==2.25.1\n    # via -r requirements.in\n"
    )
    out = parse_requirements(req, tmp_path)
    comps = _by_name(out.components)
    assert comps["requests"].scope == "direct"
    assert comps["certifi"].scope == "transitive"
    assert comps["certifi"].introduced_via == ["requests"]
    assert comps["idna"].scope == "direct"  # multi-line via block naming -r
    assert comps["requests"].purl == "pkg:pypi/requests@2.25.1"


def test_plain_requirements_scope_is_unknown_not_guessed(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("Flask==3.0.0\nWerkzeug==3.0.1\n")
    out = parse_requirements(req, tmp_path)
    assert {c.scope for c in out.components} == {"unknown"}
    assert any("direct vs transitive cannot be determined" in w for w in out.warnings)
    assert _by_name(out.components)["flask"].version == "3.0.0"


def test_unpinned_requirements_have_unknown_version(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests>=2.0\nurllib3\nsix==1.*\n")
    out = parse_requirements(req, tmp_path)
    assert all(c.version is None for c in out.components)
    assert len([w for w in out.warnings if "not pinned" in w]) == 3


def test_hash_continuation_lines_and_markers(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "pyyaml==6.0.3 ; python_version >= '3.8' \\\n"
        "    --hash=sha256:aaaa \\\n    --hash=sha256:bbbb\n"
    )
    comps = _by_name(parse_requirements(req, tmp_path).components)
    assert comps["pyyaml"].version == "6.0.3"


def test_nested_include_is_followed_inside_root(tmp_path: Path):
    (tmp_path / "base.txt").write_text("six==1.16.0\n")
    req = tmp_path / "requirements.txt"
    req.write_text("-r base.txt\nattrs==23.1.0\n")
    names = {c.name for c in parse_requirements(req, tmp_path).components}
    assert names == {"six", "attrs"}


def test_include_escaping_project_root_is_rejected(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "secret.txt").write_text("leaked==1.0\n")
    req = project / "requirements.txt"
    req.write_text("-r ../secret.txt\n")
    out = parse_requirements(req, project)
    assert out.components == []
    assert any("rejected" in w for w in out.warnings)


def test_package_lock_direct_transitive_and_parents():
    lock = EXAMPLES / "03-dependency-drift" / "project" / "package-lock.json"
    comps = _by_name(parse_package_lock(lock).components)
    assert comps["left-pad"].scope == "direct"
    assert comps["debug"].scope == "direct"
    assert comps["ms"].scope == "transitive"
    assert comps["ms"].introduced_via == ["debug"]
    assert comps["ms"].version == "2.1.3"
    assert "notification-service" not in comps  # the project itself is not a dependency


def test_package_lock_v1_is_rejected(tmp_path: Path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    with pytest.raises(ValueError, match="lockfileVersion"):
        parse_package_lock(lock)


def test_scoped_npm_package_purl(tmp_path: Path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"@types/node": "20.0.0"}},
                    "node_modules/@types/node": {"version": "20.0.0"},
                },
            }
        )
    )
    comp = parse_package_lock(lock).components[0]
    assert comp.name == "@types/node"
    assert comp.purl == "pkg:npm/%40types/node@20.0.0"


def test_poetry_lock_uses_pyproject_for_direct(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\nname = "svc"\n[tool.poetry.dependencies]\npython = "^3.12"\n'
        'requests = "^2.31"\n'
    )
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
        '[package.dependencies]\nurllib3 = ">=1.21.1"\n\n'
        '[[package]]\nname = "urllib3"\nversion = "2.0.7"\n'
    )
    comps = _by_name(parse_poetry_lock(tmp_path / "poetry.lock").components)
    assert comps["requests"].scope == "direct"
    assert comps["urllib3"].scope == "transitive"
    assert comps["urllib3"].introduced_via == ["requests"]


def test_discovery_reports_unsupported_and_never_executes(tmp_path: Path):
    (tmp_path / "setup.py").write_text("raise SystemExit('must never run')\n")
    (tmp_path / "go.mod").write_text("module example.com/x\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package-lock.json").write_text("{}")
    result = discover(tmp_path)
    kinds = {m.path: m for m in result.manifests}
    assert set(kinds) == {"setup.py", "go.mod"}
    assert not kinds["setup.py"].supported
    assert "never executed" in kinds["setup.py"].note
    assert any("none can be parsed natively" in w for w in result.warnings)


def test_manifest_covered_by_sibling_lockfile():
    result = discover(EXAMPLES / "03-dependency-drift" / "project")
    pkg = next(m for m in result.manifests if m.path == "package.json")
    assert pkg.covered_by == "package-lock.json"


def test_empty_directory_warns(tmp_path: Path):
    assert "no recognised package manifests" in discover(tmp_path).warnings[0]


def test_discovery_requires_directory(tmp_path: Path):
    file = tmp_path / "x.txt"
    file.write_text("x")
    with pytest.raises(SecurityError):
        discover(file)


def test_symlinked_manifest_is_ignored(tmp_path: Path):
    outside = tmp_path / "outside.txt"
    outside.write_text("evil==1.0\n")
    project = tmp_path / "p"
    project.mkdir()
    (project / "requirements.txt").symlink_to(outside)
    assert discover(project).manifests == []


def test_unparseable_lockfile_is_reported_not_fatal(tmp_path: Path):
    (tmp_path / "package-lock.json").write_text("{not json")
    result = discover(tmp_path)
    outcome = parse_project(tmp_path, result)
    assert outcome.components == []
    assert any("could not be parsed" in w for w in outcome.warnings)


def test_project_identities_from_package_json():
    project = EXAMPLES / "03-dependency-drift" / "project"
    assert project_identities(project, discover(project)) == {"npm:notification-service"}
