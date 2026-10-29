from dataclasses import replace
from pathlib import Path

import pytest

from sentinel.config import REPO_ROOT, Settings
from sentinel.dashboard import data
from sentinel.demo import run_scenarios
from sentinel.policies.model import load_policy
from sentinel.storage.db import Store


@pytest.fixture(scope="module")
def module_settings(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("dash")
    return replace(
        Settings(),
        data_dir=tmp / "data",
        use_syft="off",
        use_cosign="off",
        osv_bin=str(tmp / "no-osv"),
    )


@pytest.fixture(scope="module")
def module_policy():
    return load_policy(REPO_ROOT / "config" / "policy.default.yaml")


@pytest.fixture(scope="module")
def _seeded(module_settings, module_policy):
    store = Store(module_settings.db_path)
    run_scenarios(module_settings, store=store, policy=module_policy)
    return store


@pytest.fixture
def records(_seeded):
    return _seeded, [_seeded.get(r["id"]) for r in _seeded.list()]


def test_overview_metrics_from_real_runs(records):
    _, recs = records
    metrics = data.overview_metrics(recs)
    assert metrics["releases"] == 6 and metrics["analyses"] >= 6
    assert metrics["results"] == {"PASS": 1, "FAIL": 3, "INDETERMINATE": 2}
    assert metrics["severities"]["CRITICAL"] >= 1 and metrics["severities"]["HIGH"] >= 1
    assert metrics["demo_only"] is True
    assert "3 of 6 latest release decisions are blocked" in data.risk_summary(metrics)


def test_latest_per_release_keeps_newest(records, module_settings, module_policy):
    store, _ = records
    run_scenarios(module_settings, store=store, policy=module_policy, only="02-clean-release")
    recs = [store.get(r["id"]) for r in store.list()]
    latest = data.latest_per_release(recs)
    assert len(latest) == 6
    billing = next(r for r in latest if r.name == "billing-api 1.8.0")
    assert billing.id == recs[0].id


def test_components_frame_links_vulnerabilities(records):
    _, recs = records
    rec = next(r for r in recs if r.demo_scenario == "01-vulnerable-dependency")
    frame = data.components_frame(rec)
    pyyaml = frame[frame["package"] == "pyyaml"].iloc[0]
    assert pyyaml["vulns"] >= 1 and pyyaml["max severity"] == "CRITICAL"
    assert pyyaml["scope"] == "direct"
    idna = frame[frame["package"] == "idna"].iloc[0]
    assert idna["vulns"] >= 1  # version 2.10 vs OSV's 2.10.0 still linked


def test_filters(records):
    _, recs = records
    rec = next(r for r in recs if r.demo_scenario == "01-vulnerable-dependency")
    frame = data.components_frame(rec)
    assert set(data.filter_components(frame, search="URLLIB")["package"]) == {"urllib3"}
    assert set(data.filter_components(frame, scopes=["direct"])["package"]) == {
        "jinja2",
        "pyyaml",
        "requests",
    }
    assert (data.filter_components(frame, vulnerable_only=True)["vulns"] > 0).all()
    # regex metacharacters are treated literally
    assert data.filter_components(frame, search=".*").empty


def test_diff_frame_and_changed_filter(records):
    _, recs = records
    rec = next(r for r in recs if r.demo_scenario == "03-dependency-drift")
    diff = data.diff_frame(rec)
    assert set(diff["change"]) == {"added", "upgraded"}
    changed = data.filter_components(data.components_frame(rec), changed_only=True)
    assert set(changed["package"]) == {"left-pad", "debug", "ms"}


def test_empty_frames_have_columns(records):
    _, recs = records
    rec = next(r for r in recs if r.demo_scenario == "02-clean-release")
    assert data.vulnerabilities_frame(rec).empty
    assert "severity" in data.vulnerabilities_frame(rec).columns
    assert data.diff_frame(rec).empty
    assert "created" in data.history_frame([]).columns


def test_history_frame_labels_demo(records):
    store, _ = records
    frame = data.history_frame(store.list())
    assert frame["source"].str.startswith("demo:").all()


def test_fmt_ts_and_display_path():
    assert data.fmt_ts("2026-10-29T09:27:00+00:00") == "2026-10-29 09:27 UTC"
    assert data.fmt_ts(None) == "-"
    assert data.fmt_ts("not a date") == "not a date"
    assert data.display_path(REPO_ROOT / "examples") == "examples"
    assert data.display_path(Path.home() / "proj").startswith("~/")


def test_find_release_records_and_projects():
    releases = data.find_release_records([REPO_ROOT / "examples"])
    assert len(releases) == 6
    projects = data.find_projects([REPO_ROOT / "examples"])
    assert REPO_ROOT / "examples" / "03-dependency-drift" / "baseline-project" in projects
