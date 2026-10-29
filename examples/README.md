# Demonstration scenarios

Six reproducible release candidates. Each directory contains:

| Path | Content |
|---|---|
| `release.yaml` | release record (paths are relative and may not leave the directory) |
| `project/` | the project being released (minimal code + lockfiles; never executed) |
| `dist/` | deterministic tarball, Cosign-signed Sigstore bundle, SLSA v1 provenance (DSSE) |
| `evidence/` | osv-scanner output recorded on 2026-10-29 for offline replay |

`scenarios.yaml` lists the expected decision for each; `fixture-manifest.json` records digests and
tool versions. See [../docs/demo-scenarios.md](../docs/demo-scenarios.md).

Scenario 01 pins real package versions with **publicly known vulnerabilities** - they are listed in
a lockfile for analysis only. Do not install them.

The demo signing key's private half was destroyed after signing; the public key is
`config/keys/sentinel-demo-release.pub`. Rebuild everything (new key, re-recorded advisories) with
`python scripts/build_demo_fixtures.py --record-osv`.
