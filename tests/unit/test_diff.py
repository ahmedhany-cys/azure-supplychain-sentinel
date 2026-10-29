from sentinel.core.models import ChangeType, Component, Inventory, Severity, Vulnerability
from sentinel.sbom.builder import build_sbom, load_sbom
from sentinel.sbom.diff import diff_inventories

from ..conftest import EXAMPLES


def _c(name, version, eco="npm", purl=None, scope="direct"):
    return Component(
        name=name,
        version=version,
        ecosystem=eco,
        scope=scope,
        purl=purl or f"pkg:{eco.lower()}/{name}@{version}",
    )


def _v(vid, pkg, aliases=()):
    return Vulnerability(
        id=vid,
        aliases=list(aliases),
        package=pkg,
        version="1",
        ecosystem="npm",
        severity=Severity.HIGH,
    )


def test_scenario_03_changes_are_reported_exactly(settings):
    baseline = load_sbom((EXAMPLES / "03-dependency-drift" / "baseline.cdx.json").read_bytes())
    candidate = build_sbom(EXAMPLES / "03-dependency-drift" / "project", settings)
    diff = diff_inventories(baseline.inventory, candidate.inventory)
    summary = {(c.change, c.name, c.old_version, c.new_version) for c in diff.changes}
    assert summary == {
        (ChangeType.ADDED, "left-pad", None, "1.3.0"),
        (ChangeType.UPGRADED, "debug", "4.3.4", "4.4.1"),
        (ChangeType.UPGRADED, "ms", "2.1.2", "2.1.3"),
    }
    ms = next(c for c in diff.changes if c.name == "ms")
    assert ms.scope == "transitive" and ms.introduced_via == ["debug"]


def test_all_change_types():
    base = Inventory(
        components=[
            _c("a", "1.0.0"),
            _c("b", "2.0.0"),
            _c("c", "1.0.0"),
            _c("gone", "1.0.0"),
            _c("moved", "1.0.0", purl="pkg:npm/moved@1.0.0"),
            _c("scoped", "1.0.0", scope="transitive"),
            _c("weird", "abc"),
        ]
    )
    cand = Inventory(
        components=[
            _c("a", "1.1.0"),
            _c("b", "1.9.0"),
            _c("c", "1.0.0"),
            _c("new", "0.1.0"),
            _c("moved", "1.0.0", purl="pkg:npm/moved@1.0.0?repository_url=https://evil.example"),
            _c("scoped", "1.0.0", scope="direct"),
            _c("weird", "xyz"),
        ]
    )
    diff = diff_inventories(base, cand)
    kinds = {c.name: c.change for c in diff.changes}
    assert kinds == {
        "a": ChangeType.UPGRADED,
        "b": ChangeType.DOWNGRADED,
        "gone": ChangeType.REMOVED,
        "new": ChangeType.ADDED,
        "moved": ChangeType.IDENTIFIER_CHANGED,
        "scoped": ChangeType.SCOPE_CHANGED,
        "weird": ChangeType.VERSION_CHANGED,
    }


def test_generator_package_id_qualifiers_are_not_identifier_changes():
    base = Inventory(components=[_c("x", "1.0", purl="pkg:npm/x@1.0?package-id=aaa")])
    cand = Inventory(components=[_c("x", "1.0", purl="pkg:npm/x@1.0?package-id=bbb")])
    assert diff_inventories(base, cand).changes == []


def test_pypi_names_are_normalised():
    base = Inventory(components=[_c("PyYAML", "6.0", eco="PyPI")])
    cand = Inventory(components=[_c("pyyaml", "6.0.1", eco="PyPI")])
    diff = diff_inventories(base, cand)
    assert [c.change for c in diff.changes] == [ChangeType.UPGRADED]


def test_multiple_installed_versions():
    base = Inventory(components=[_c("dup", "1.0.0"), _c("dup", "2.0.0")])
    cand = Inventory(components=[_c("dup", "2.0.0"), _c("dup", "3.0.0")])
    changes = {
        (c.change, c.old_version, c.new_version) for c in diff_inventories(base, cand).changes
    }
    assert changes == {(ChangeType.UPGRADED, "1.0.0", "3.0.0")}


def test_new_and_resolved_vulnerabilities_use_alias_identity():
    base = Inventory(components=[_c("a", "1")])
    old = [_v("GHSA-1", "a", ["CVE-1"]), _v("GHSA-2", "a")]
    new = [_v("PYSEC-9", "a", ["CVE-1"]), _v("GHSA-3", "a")]  # CVE-1 is the same issue
    diff = diff_inventories(base, base, baseline_vulns=old, candidate_vulns=new)
    assert diff.vulnerability_comparison_available
    assert [v.id for v in diff.new_vulnerabilities] == ["GHSA-3"]
    assert diff.resolved_vulnerabilities == ["GHSA-2"]


def test_vulnerability_comparison_unavailable_without_both_scans():
    base = Inventory(components=[_c("a", "1")])
    diff = diff_inventories(base, base, baseline_vulns=None, candidate_vulns=[])
    assert not diff.vulnerability_comparison_available
    assert diff.changes == []
