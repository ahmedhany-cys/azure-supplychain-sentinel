"""Run the demonstration scenarios in ``examples/`` and check their expected decisions."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

from sentinel.config import REPO_ROOT, Settings
from sentinel.core.service import Outcome, gate_release, settings_with
from sentinel.policies.model import LoadedPolicy, load_policy
from sentinel.storage.db import Store

EXAMPLES = REPO_ROOT / "examples"
HANGING_SCANNER = REPO_ROOT / "scripts" / "fault_injection" / "hanging_osv_scanner.py"


@dataclass
class Scenario:
    id: str
    title: str
    release: Path
    expected: str
    explanation: str
    fault: str | None = None


@dataclass
class ScenarioRun:
    scenario: Scenario
    outcome: Outcome

    @property
    def matched(self) -> bool:
        decision = self.outcome.record.decision
        return decision is not None and decision.result.value == self.scenario.expected


def load_scenarios(examples: Path = EXAMPLES) -> list[Scenario]:
    data = yaml.safe_load((examples / "scenarios.yaml").read_text())
    return [
        Scenario(
            id=s["id"],
            title=s["title"],
            release=examples / s["release"],
            expected=s["expected"],
            explanation=s["explanation"].strip(),
            fault=s.get("fault"),
        )
        for s in data["scenarios"]
    ]


def scenario_settings(base: Settings, fault: str | None) -> Settings:
    if fault is None:
        return base
    if fault == "osv_timeout":
        # The stub is executed directly (shebang), never through a shell.
        return settings_with(base, osv_bin=str(HANGING_SCANNER), osv_timeout=3)
    if fault == "osv_missing":
        return settings_with(base, osv_bin=str(REPO_ROOT / "does-not-exist" / "osv-scanner"))
    raise ValueError(f"unknown fault injection {fault!r}")


def run_scenarios(
    settings: Settings,
    *,
    only: str | None = None,
    store: Store | None = None,
    policy: LoadedPolicy | None = None,
) -> list[ScenarioRun]:
    policy = policy or load_policy(settings.policy_path)
    runs = []
    for scenario in load_scenarios():
        if only and scenario.id != only:
            continue
        outcome = gate_release(
            scenario.release,
            scenario_settings(settings, scenario.fault),
            policy,
            store=store,
            demo_scenario=scenario.id,
        )
        runs.append(ScenarioRun(scenario, outcome))
    return runs


def print_runs(runs: list[ScenarioRun], stream=sys.stdout) -> None:
    width = max((len(r.scenario.id) for r in runs), default=10)
    for run in runs:
        decision = run.outcome.record.decision
        got = decision.result.value if decision else "NONE"
        mark = "ok " if run.matched else "MISMATCH"
        stream.write(
            f"{mark:8} {run.scenario.id:<{width}}  expected {run.scenario.expected:<13} got {got}\n"
        )
