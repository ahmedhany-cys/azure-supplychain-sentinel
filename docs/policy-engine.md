# Policy engine

The policy is a YAML file (`config/policy.default.yaml`) validated by a strict schema: unknown
keys are rejected and the vulnerability threshold cannot be `UNKNOWN` or `NONE`. Every decision
records the policy name, version and the SHA-256 of the policy file.

## Concepts

**Checks** - `sbom`, `vulnerability_scan`, `dependency_diff`, `artifact_signature`, `provenance`.
Each ends in one status:

| Status | Completed? | Meaning |
|---|---|---|
| `PASSED` | yes | evaluated, nothing actionable |
| `WARNING` | yes | evaluated, `review` or `warn` findings |
| `FAILED` | yes | evaluated, at least one `block` finding |
| `ERROR` | no | attempted, did not complete (timeout, tool failure, unsupported input) |
| `UNAVAILABLE` | no | could not be attempted (tool or data missing) |
| `SKIPPED` / `NOT_APPLICABLE` | no | not requested / no input (e.g. no baseline) |

**Findings** - each has a *kind* (what it is) and an *action* (what the policy says to do):

| Kind | Example |
|---|---|
| `confirmed_vulnerability` | an advisory reported by osv-scanner for an installed version |
| `suspicious_indicator` | an unapproved new dependency, a downgrade, a changed package URL |
| `policy_violation` | invalid SBOM, digest mismatch, required provenance missing |
| `data_unavailable` | vulnerability intelligence unavailable, unsupported manifest |
| `scan_error` | a tool ran and failed |
| `informational` | upgrades, removed packages, newly introduced vulnerability attribution |

| Action | Effect |
|---|---|
| `block` | release FAILs |
| `review` | manual review required (INDETERMINATE by default) |
| `warn` | recorded, non-blocking |
| `info` | recorded only |

## Decision procedure

1. Any `block` finding → **FAIL**.
2. Otherwise, any **required** check that did not complete → **INDETERMINATE**.
3. Otherwise, any `review` finding and `decision.review_outcome: INDETERMINATE` → **INDETERMINATE**.
4. Otherwise → **PASS**.

FAIL takes precedence over INDETERMINATE because a known blocking problem is a definite answer
even if other checks are incomplete. INDETERMINATE is never reported as success: the CLI exits
with code 2 and CI treats it as a failure.

## Rules in the default policy

| Area | Rule | Default |
|---|---|---|
| required checks | `required_checks` | sbom, vulnerability_scan, artifact_signature, provenance |
| sbom | `require_schema_valid`, `min_components` | true, 1 (block) |
| vulnerabilities | `block_at_or_above` | HIGH |
| | `below_threshold` (MEDIUM/LOW) | warn |
| | `unknown_severity` | review |
| | `exceptions` (id, package, reason, approved_by, expires) | none; expired exceptions stop applying and raise a warning |
| dependency changes | added / downgraded / version_changed / identifier_changed | review |
| | removed / upgraded / scope_changed | info |
| | `allowed_new_packages` (e.g. `npm:left-pad`) | none |
| | `denied_packages` | `npm:event-stream` (block) |
| signing | `trusted_keys` | demo key (replace for real use) |
| provenance | `require_signature`, `require_source_match`, `trusted_builders` | true, true, demo builder |
| decision | `missing_required_evidence` | FAIL (alternative: INDETERMINATE) |
| | `review_outcome` | INDETERMINATE (alternative: PASS) |

## How each check maps to findings

- **sbom**: invalid schema or too few components → `block`; Syft failure with native fallback →
  `warn`; manifests that could not be inventoried (and are not covered by a sibling lockfile) →
  `warn`.
- **vulnerability_scan**: per advisory group, severity vs threshold; unavailable/timeout/error/no
  packages → check not completed; partial coverage → `warn`.
- **dependency_diff**: per change type as configured; denied packages always `block`.
- **artifact_signature**: digest mismatch, invalid signature, untrusted signer, malformed bundle →
  `block`; unsupported (keyless), empty trust store, tool error → not completed; missing
  signature/artifact → `missing_required_evidence`.
- **provenance**: invalid, unsigned (when required), untrusted, malformed → `block`; missing →
  `missing_required_evidence`.

## Source-only analyses

`sentinel scan` and the dashboard's *Source analysis* evaluate only `sbom` and
`vulnerability_scan` (those that are required by the policy) and state in the reasons that this is
not a release decision.

## Example: adding a risk exception

```yaml
vulnerabilities:
  exceptions:
    - id: CVE-2024-3651
      package: idna
      reason: Only used to parse trusted internal hostnames; upgrade tracked in SEC-142
      approved_by: security-lead
      expires: 2026-12-31
```

The finding remains in the report (action `info`, with the justification) and automatically
becomes blocking again after the expiry date.
