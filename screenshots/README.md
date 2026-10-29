# Screenshots

Captured on 2026-10-29 from the dashboard running locally (`streamlit run sentinel/dashboard/app.py`)
against the six demonstration scenarios, using `scripts/capture_screenshots.py` (Playwright + Chrome,
1440×900 @2x). Nothing is mocked; scenario data is labelled as demonstration data in the UI.

| File | Shows |
|---|---|
| `01-security-overview.png` | Overview: releases analysed, dependencies, CRITICAL/HIGH count, decisions, latest decision per release |
| `02-vulnerability-findings.png` | Scenario 01 in the Dependency Explorer, filtered to vulnerable packages, with linked OSV advisories |
| `03-sbom-viewer.png` | Scenario 03 SBOM: CycloneDX 1.7 from Syft, validation, scope composition, discovery coverage |
| `04-policy-fail-explained.png` | Release Policy Center: scenario 01 FAIL with per-check status and blocking findings |
| `05-signature-verified.png` | Scenario 02: signature verified (native + Cosign), matching digests, trusted signer |
| `06-tampered-artifact-rejected.png` | Scenario 04 artifact uploaded through the verify form: digest mismatch, Cosign rejects, provenance invalid |
| `07-dependency-diff.png` | Scenario 03: added `left-pad`, upgraded `debug` and transitive `ms` vs the baseline SBOM |
| `08-project-analysis-gate-run.png` | Running a release gate from the Project Analysis page |
| `09-github-actions-run.png` | Public GitHub Actions run #2 (commit `b9916b7`) with every job passing; captured from github.com after publication |
