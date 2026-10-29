# Demonstration scenarios

All scenarios are deterministic and offline by default. Run them with:

```bash
sentinel demo --check          # all six, verify expected decisions (CI does this)
sentinel gate examples/03-dependency-drift/release.yaml --out /tmp/evidence
sentinel demo --store          # store them in the database for the dashboard
```

## How the fixtures were built

`scripts/build_demo_fixtures.py` (run 2026-10-29 with Cosign 3.1.4, Syft 1.55.0,
OSV-Scanner 2.7.0):

1. packs each scenario's `project/` into a reproducible tarball (fixed mtime, sorted entries);
2. generates an ephemeral demo key pair with `cosign generate-key-pair` inside a 0700 temporary
   directory, signs each tarball with `cosign sign-blob --bundle`, and creates SLSA v1
   provenance with `cosign attest-blob --type slsaprovenance1`;
3. writes only the public key to `config/keys/sentinel-demo-release.pub`; the private key is
   deleted with the temporary directory, so no one can create new signatures that verify;
4. records live `osv-scanner --all-packages` output (paths reduced to file names) into
   `evidence/*.recorded.json` with tool version, command and capture time;
5. writes `release.yaml` and `examples/fixture-manifest.json` (digests per scenario).

The projects contain only a minimal `app.py`/`index.js` and lockfiles. No malware, exploit code
or install scripts are included. Version choices for scenario 01 are real releases with public
advisories; do not install them. The source repositories (`example.com`) and the builder ID
(`sentinel.local`) are fictional.

Re-running the script rotates the demo key and re-records OSV data; recorded advisories will
then reflect the new date.

## Scenarios

### 01 - Vulnerable dependency → FAIL

`requirements.txt` (pip-compile annotation format) pins `pyyaml==5.3.1`, `jinja2==2.11.2`,
`requests==2.25.1` directly and `urllib3 1.26.4`, `certifi 2020.12.5`, `idna 2.10`, `chardet`,
`markupsafe` transitively. The recorded scan reports 27 distinct advisory groups; 14 are HIGH or
CRITICAL, for example **GHSA-8q59-q68h-6hv4 / CVE-2020-14343** in PyYAML 5.3.1 (CVSS 9.8, fixed in
5.4). Signature and provenance verify, so the vulnerability rule alone fails the release.
Report: [sample-reports/01-vulnerable-dependency.md](sample-reports/01-vulnerable-dependency.md).

### 02 - Clean release → PASS

Dependencies resolved with pip-compile on 2026-10-29 (`requests 2.34.2`, `pyyaml 6.0.3`, ...). The
recorded scan of 6 packages returned no advisories at capture time. Signature verified by the
native verifier and Cosign; provenance reaches trust level `trusted`.

### 03 - Unexpected dependency change → INDETERMINATE

Baseline and candidate `package-lock.json` files were generated with
`npm install --package-lock-only --ignore-scripts`. Against `baseline.cdx.json` (a Syft SBOM of the
baseline), the candidate:

- adds **left-pad 1.3.0** as a direct dependency (not in `allowed_new_packages` → review);
- upgrades **debug 4.3.4 → 4.4.1** (info);
- moves transitive **ms 2.1.2 → 2.1.3**, introduced via debug (info).

No new vulnerabilities were introduced (both scans recorded). Because a human must confirm the new
dependency, the release is INDETERMINATE rather than PASS. Adding `npm:left-pad` to the allow list
turns it into PASS; adding it to `denied_packages` turns it into FAIL.
Decision JSON: [sample-reports/03-dependency-drift.decision.json](sample-reports/03-dependency-drift.decision.json).

### 04 - Tampered artifact → FAIL

After signing, `app.py` was modified and the tarball rebuilt under the same name. Three
independent checks fail: the artifact SHA-256 differs from the signed digest, from the
`expected_sha256` pinned in the release record, and from the provenance subject (trust level stops
at `well-formed`). Cosign `verify-blob` also rejects it.
Report: [sample-reports/04-tampered-artifact.md](sample-reports/04-tampered-artifact.md).

### 05 - Missing provenance → FAIL

Correctly signed artifact, no provenance. The policy requires provenance and
`missing_required_evidence: FAIL`. With `INDETERMINATE` configured instead, the same input yields
INDETERMINATE (covered by `test_missing_provenance_outcome_is_configurable`).

### 06 - External scanner unavailable → INDETERMINATE

The scenario declares a **live** scan. The demo runner injects a fault: `osv-scanner` is replaced
by `scripts/fault_injection/hanging_osv_scanner.py`, which never answers, with a 3-second timeout.
The runner kills the process group, the scan status becomes `timeout`, and the decision is
INDETERMINATE even though every other check passes. Running `sentinel gate` on the same record
without fault injection performs a real live scan. A missing binary (`osv_missing`) and network
errors are covered by unit tests.
