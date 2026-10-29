import json

from sentinel.core.models import ProvenanceStatus
from sentinel.provenance.slsa import normalize_source_uri, verify_provenance
from sentinel.signing import keys

from ..conftest import DEMO_BUILDER, EXAMPLES, REPO_ROOT

SHA = "ab" * 32


def _verify(path, keypair, *, sha=SHA, builders=(DEMO_BUILDER,), **kw):
    return verify_provenance(
        path,
        artifact_sha256=sha,
        trusted_keys=[keys.load_public_key(keypair[1])],
        trusted_builders=list(builders),
        **kw,
    )


def test_signed_bound_trusted_provenance_verifies(make_provenance, keypair):
    result = _verify(
        make_provenance(SHA),
        keypair,
        expected_source_uri="https://example.com/demo/app",
        expected_revision="a" * 40,
    )
    assert result.status == ProvenanceStatus.VERIFIED and result.verified
    assert result.trust_level == "trusted"
    assert result.builder_id == DEMO_BUILDER
    assert result.source_revision == "a" * 40


def test_missing_provenance(keypair):
    result = _verify(None, keypair)
    assert result.status == ProvenanceStatus.MISSING and not result.verified


def test_unsigned_statement_is_not_trusted(make_provenance, keypair):
    result = _verify(make_provenance(SHA, sign=False), keypair)
    assert result.status == ProvenanceStatus.UNSIGNED
    assert result.trust_level == "subject-bound"  # well-formed and bound, but not authenticated


def test_provenance_for_a_different_artifact_is_invalid(make_provenance, keypair):
    result = _verify(make_provenance("cd" * 32), keypair)
    assert result.status == ProvenanceStatus.INVALID
    assert any(
        c.name == "subject matches artifact digest" and c.passed is False for c in result.checks
    )


def test_untrusted_builder(make_provenance, keypair):
    result = _verify(make_provenance(SHA, builder="https://evil.example/builder"), keypair)
    assert result.status == ProvenanceStatus.UNTRUSTED
    assert result.trust_level == "authenticated"


def test_signed_by_untrusted_key(make_provenance, keypair, other_keypair):
    path = make_provenance(SHA, key_path=other_keypair[0])
    result = _verify(path, keypair)
    assert result.status == ProvenanceStatus.UNTRUSTED
    assert result.signer_key_id is None


def test_missing_required_fields(make_provenance, keypair):
    def drop_builder(stmt):
        del stmt["predicate"]["runDetails"]["builder"]

    result = _verify(make_provenance(SHA, mutate=drop_builder), keypair)
    assert result.status == ProvenanceStatus.INVALID
    assert any("runDetails.builder.id" in c.detail for c in result.checks)


def test_wrong_predicate_type(make_provenance, keypair):
    def old_predicate(stmt):
        stmt["predicateType"] = "https://slsa.dev/provenance/v0.2"

    assert _verify(make_provenance(SHA, mutate=old_predicate), keypair).status == (
        ProvenanceStatus.INVALID
    )


def test_source_revision_mismatch(make_provenance, keypair):
    result = _verify(make_provenance(SHA), keypair, expected_revision="b" * 40)
    assert result.status == ProvenanceStatus.INVALID
    assert any(
        c.name == "source matches release record" and c.passed is False for c in result.checks
    )


def test_inconsistent_timestamps(make_provenance, keypair):
    def backwards(stmt):
        stmt["predicate"]["runDetails"]["metadata"]["finishedOn"] = "2025-01-01T00:00:00Z"

    assert _verify(make_provenance(SHA, mutate=backwards), keypair).status == (
        ProvenanceStatus.INVALID
    )


def test_malformed_documents(tmp_path, keypair):
    for i, content in enumerate(
        ["not json", "[]", json.dumps({"payloadType": "x", "payload": "e30="})]
    ):
        path = tmp_path / f"bad{i}.json"
        path.write_text(content)
        assert _verify(path, keypair).status == ProvenanceStatus.MALFORMED


def test_tampered_payload_breaks_signature(make_provenance, keypair, tmp_path):
    import base64

    envelope = json.loads(make_provenance(SHA).read_text())
    statement = json.loads(base64.b64decode(envelope["payload"]))
    statement["predicate"]["runDetails"]["builder"]["id"] = DEMO_BUILDER  # unchanged
    statement["subject"][0]["digest"]["sha256"] = "ef" * 32  # attacker re-points subject
    envelope["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(envelope))
    result = _verify(path, keypair, sha="ef" * 32)
    assert result.status == ProvenanceStatus.UNTRUSTED  # signature no longer verifies
    assert result.signer_key_id is None


def test_cosign_attest_blob_fixture_verifies_natively():
    dist = EXAMPLES / "02-clean-release" / "dist"
    from sentinel.core.security import sha256_file

    result = verify_provenance(
        dist / "billing-api-1.8.0.provenance.sigstore.json",
        artifact_sha256=sha256_file(dist / "billing-api-1.8.0.tar.gz"),
        trusted_keys=[keys.load_public_key(REPO_ROOT / "config/keys/sentinel-demo-release.pub")],
        trusted_builders=[DEMO_BUILDER],
    )
    assert result.verified, result.details
    assert result.format == "Sigstore bundle (DSSE)"


def test_normalize_source_uri():
    assert normalize_source_uri("git+https://GitHub.com/o/r.git@refs/heads/main") == (
        "github.com/o/r"
    )
    assert normalize_source_uri("https://github.com/o/r/") == "github.com/o/r"
    assert normalize_source_uri(None) == ""
