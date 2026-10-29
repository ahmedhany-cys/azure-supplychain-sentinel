"""Compare two dependency inventories.

The diff reports *facts* (added, removed, version moved, identifier changed). It never
labels a package malicious; whether a change needs review or blocks a release is the
policy engine's decision.
"""

from __future__ import annotations

from packaging.version import InvalidVersion, Version

from sentinel.core.models import (
    ChangeType,
    Component,
    DependencyChange,
    DependencyDiff,
    Inventory,
    Vulnerability,
)


def _compare_versions(old: str | None, new: str | None) -> ChangeType:
    if old is None or new is None:
        return ChangeType.VERSION_CHANGED
    try:
        old_v, new_v = Version(old), Version(new)
    except InvalidVersion:
        return ChangeType.VERSION_CHANGED
    return ChangeType.UPGRADED if new_v > old_v else ChangeType.DOWNGRADED


def _change(
    kind: ChangeType,
    comp: Component,
    *,
    old: Component | None = None,
    new: Component | None = None,
    note: str | None = None,
) -> DependencyChange:
    return DependencyChange(
        change=kind,
        key=comp.key,
        name=comp.name,
        ecosystem=comp.ecosystem,
        old_version=old.version if old else None,
        new_version=new.version if new else None,
        old_purl=old.purl if old else None,
        new_purl=new.purl if new else None,
        scope=(new or old or comp).scope,
        introduced_via=(new or comp).introduced_via,
        note=note,
    )


def diff_inventories(
    baseline: Inventory,
    candidate: Inventory,
    *,
    baseline_label: str = "baseline",
    candidate_label: str = "candidate",
    baseline_vulns: list[Vulnerability] | None = None,
    candidate_vulns: list[Vulnerability] | None = None,
) -> DependencyDiff:
    old_index, new_index = baseline.by_key(), candidate.by_key()
    changes: list[DependencyChange] = []
    for key in sorted(set(old_index) | set(new_index)):
        olds = {c.version: c for c in old_index.get(key, [])}
        news = {c.version: c for c in new_index.get(key, [])}
        if not olds:
            changes.extend(_change(ChangeType.ADDED, c, new=c) for c in news.values())
            continue
        if not news:
            changes.extend(_change(ChangeType.REMOVED, c, old=c) for c in olds.values())
            continue
        removed = [v for v in olds if v not in news]
        added = [v for v in news if v not in olds]
        if len(removed) == 1 and len(added) == 1:
            old_c, new_c = olds[removed[0]], news[added[0]]
            changes.append(
                _change(
                    _compare_versions(old_c.version, new_c.version), new_c, old=old_c, new=new_c
                )
            )
        else:
            for v in removed:
                changes.append(
                    _change(
                        ChangeType.REMOVED,
                        olds[v],
                        old=olds[v],
                        note="one of several installed versions",
                    )
                )
            for v in added:
                changes.append(
                    _change(
                        ChangeType.ADDED,
                        news[v],
                        new=news[v],
                        note="additional version of an existing package",
                    )
                )
        for version in set(olds) & set(news):
            old_c, new_c = olds[version], news[version]
            if old_c.purl and new_c.purl and _purl_core(old_c.purl) != _purl_core(new_c.purl):
                changes.append(
                    _change(
                        ChangeType.IDENTIFIER_CHANGED,
                        new_c,
                        old=old_c,
                        new=new_c,
                        note="same name and version but different package URL",
                    )
                )
            elif (
                old_c.scope in {"direct", "transitive"}
                and new_c.scope in {"direct", "transitive"}
                and old_c.scope != new_c.scope
            ):
                changes.append(
                    _change(
                        ChangeType.SCOPE_CHANGED,
                        new_c,
                        old=old_c,
                        new=new_c,
                        note=f"{old_c.scope} -> {new_c.scope}",
                    )
                )

    result = DependencyDiff(
        baseline_label=baseline_label,
        candidate_label=candidate_label,
        changes=changes,
        baseline_count=len(baseline.components),
        candidate_count=len(candidate.components),
    )
    if baseline_vulns is not None and candidate_vulns is not None:
        result.vulnerability_comparison_available = True
        known = [v.identity for v in baseline_vulns]
        for vuln in candidate_vulns:
            if not any(vuln.identity & ids for ids in known):
                result.new_vulnerabilities.append(vuln)
        current = [v.identity for v in candidate_vulns]
        result.resolved_vulnerabilities = sorted(
            v.id for v in baseline_vulns if not any(v.identity & ids for ids in current)
        )
    return result


def _purl_core(purl: str) -> str:
    """Drop the package-id style qualifiers some generators add; keep repository qualifiers."""
    base, _, qualifiers = purl.partition("?")
    kept = [q for q in qualifiers.split("&") if q and not q.startswith("package-id=")]
    return base + ("?" + "&".join(sorted(kept)) if kept else "")
