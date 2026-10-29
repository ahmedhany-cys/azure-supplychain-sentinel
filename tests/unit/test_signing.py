import base64
import json
import stat
from pathlib import Path

import pytest

from sentinel.core.models import SignatureStatus
from sentinel.core.security import SecurityError
from sentinel.signing import keys
from sentinel.signing.bundle import parse_message_bundle
from sentinel.signing.verify import verify_artifact

from ..conftest import EXAMPLES, FIXTURES, REPO_ROOT

DEMO_PUB = REPO_ROOT / "config" / "keys" / "sentinel-demo-release.pub"


def _trust(*pubs: Path):
    return [keys.load_public_key(p) for p in pubs]


def test_valid_signature_from_trusted_key_passes(signed_artifact, keypair, settings):
    artifact, bundle = signed_artifact
    result = verify_artifact(artifact, bundle, _trust(keypair[1]), settings)
    assert result.status == SignatureStatus.VERIFIED and result.verified
    assert result.actual_sha256 == result.signed_sha256
    assert result.signer_name == "test-signer"
    assert result.signer_key_id == keys.load_public_key(keypair[1]).key_id


def test_tampered_artifact_is_rejected(signed_artifact, keypair, settings):
    artifact, bundle = signed_artifact
    artifact.write_bytes(artifact.read_bytes() + b"injected")
    result = verify_artifact(artifact, bundle, _trust(keypair[1]), settings)
    assert result.status == SignatureStatus.DIGEST_MISMATCH
    assert not result.verified
    assert result.actual_sha256 != result.signed_sha256


def test_untrusted_signer_is_rejected(signed_artifact, other_keypair, settings):
    artifact, bundle = signed_artifact
    result = verify_artifact(artifact, bundle, _trust(other_keypair[1]), settings)
    assert result.status == SignatureStatus.UNTRUSTED_SIGNER
    assert not result.verified


def test_untrusted_cosign_signed_fixture_is_rejected(settings):
    artifact = FIXTURES / "signing" / "release-signed-by-untrusted-key.tar.gz"
    bundle = FIXTURES / "signing" / f"{artifact.name}.sigstore.json"
    result = verify_artifact(artifact, bundle, _trust(DEMO_PUB), settings)
    assert result.status == SignatureStatus.UNTRUSTED_SIGNER
    # and it *does* verify when its own key is trusted: the rejection is about trust
    own = verify_artifact(
        artifact, bundle, _trust(FIXTURES / "signing" / "untrusted-signer.pub"), settings
    )
    assert own.verified


def test_signature_must_cover_the_artifact_not_just_exist(
    signed_artifact, keypair, settings, tmp_path
):
    """A valid bundle for a *different* file must not validate this one."""
    _, bundle = signed_artifact
    other = tmp_path / "other.bin"
    other.write_bytes(b"different content")
    result = verify_artifact(other, bundle, _trust(keypair[1]), settings)
    assert result.status == SignatureStatus.DIGEST_MISMATCH


def test_forged_digest_field_does_not_help(signed_artifact, keypair, settings, tmp_path):
    """Rewriting the bundle's digest to match a tampered file must still fail."""
    artifact, bundle = signed_artifact
    artifact.write_bytes(b"malicious replacement")
    doc = json.loads(bundle.read_text())
    import hashlib

    doc["messageSignature"]["messageDigest"]["digest"] = base64.b64encode(
        hashlib.sha256(artifact.read_bytes()).digest()
    ).decode()
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(doc))
    result = verify_artifact(artifact, forged, _trust(keypair[1]), settings)
    assert result.status == SignatureStatus.INVALID_SIGNATURE
    assert not result.verified


def test_corrupted_signature_bytes(signed_artifact, keypair, settings, tmp_path):
    artifact, bundle = signed_artifact
    doc = json.loads(bundle.read_text())
    sig = bytearray(base64.b64decode(doc["messageSignature"]["signature"]))
    sig[-1] ^= 0xFF
    doc["messageSignature"]["signature"] = base64.b64encode(bytes(sig)).decode()
    doc["verificationMaterial"]["publicKey"]["hint"] = keys.load_public_key(keypair[1]).key_id
    broken = tmp_path / "broken.json"
    broken.write_text(json.dumps(doc))
    assert verify_artifact(artifact, broken, _trust(keypair[1]), settings).status == (
        SignatureStatus.INVALID_SIGNATURE
    )


def test_expected_digest_pin_is_enforced(signed_artifact, keypair, settings):
    artifact, bundle = signed_artifact
    result = verify_artifact(
        artifact, bundle, _trust(keypair[1]), settings, expected_sha256="0" * 64
    )
    assert result.status == SignatureStatus.DIGEST_MISMATCH


@pytest.mark.parametrize(
    "content",
    ["{}", "[]", "not json", '{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}'],
)
def test_malformed_bundles(signed_artifact, keypair, settings, tmp_path, content):
    artifact, _ = signed_artifact
    bad = tmp_path / "bad.json"
    bad.write_text(content)
    result = verify_artifact(artifact, bad, _trust(keypair[1]), settings)
    assert result.status == SignatureStatus.MALFORMED_BUNDLE


def test_missing_inputs_and_empty_trust_store(signed_artifact, keypair, settings, tmp_path):
    artifact, bundle = signed_artifact
    assert verify_artifact(artifact, None, _trust(keypair[1]), settings).status == (
        SignatureStatus.MISSING_SIGNATURE
    )
    assert verify_artifact(tmp_path / "nope", bundle, _trust(keypair[1]), settings).status == (
        SignatureStatus.MISSING_ARTIFACT
    )
    assert verify_artifact(artifact, bundle, [], settings).status == (
        SignatureStatus.NO_TRUSTED_KEYS
    )


def test_keyless_bundle_is_not_silently_accepted(signed_artifact, keypair, settings, tmp_path):
    artifact, bundle = signed_artifact
    doc = json.loads(bundle.read_text())
    doc["verificationMaterial"] = {"certificate": {"rawBytes": "AAAA"}}
    keyless = tmp_path / "keyless.json"
    keyless.write_text(json.dumps(doc))
    result = verify_artifact(artifact, keyless, _trust(keypair[1]), settings)
    assert result.status == SignatureStatus.UNSUPPORTED and not result.verified


def test_cosign_signed_demo_fixture_verifies_natively(settings):
    sdir = EXAMPLES / "02-clean-release" / "dist"
    artifact = sdir / "billing-api-1.8.0.tar.gz"
    result = verify_artifact(
        artifact, sdir / f"{artifact.name}.sigstore.json", _trust(DEMO_PUB), settings
    )
    assert result.verified


def test_key_id_matches_cosign_hint():
    bundle = EXAMPLES / "02-clean-release" / "dist" / "billing-api-1.8.0.tar.gz.sigstore.json"
    assert parse_message_bundle(bundle).key_hint == keys.load_public_key(DEMO_PUB).key_id


def test_private_key_file_is_refused_as_trust_anchor(keypair):
    with pytest.raises(SecurityError, match="private key"):
        keys.load_public_key(keypair[0])


def test_generated_private_key_is_encrypted_and_0600(keypair):
    priv, pub = keypair
    assert stat.S_IMODE(priv.stat().st_mode) == 0o600
    assert b"ENCRYPTED PRIVATE KEY" in priv.read_bytes()
    assert b"PRIVATE" not in pub.read_bytes()


def test_keygen_requires_password_and_refuses_overwrite(tmp_path, monkeypatch, keypair):
    monkeypatch.delenv(keys.PASSWORD_ENV, raising=False)
    with pytest.raises(SecurityError, match=keys.PASSWORD_ENV):
        keys.generate_keypair(tmp_path / "k2")
    monkeypatch.setenv(keys.PASSWORD_ENV, "x" * 12)
    with pytest.raises(SecurityError, match="refusing to overwrite"):
        keys.generate_keypair(keypair[0].parent, "test-signer")


def test_wrong_password_error_does_not_leak(keypair, monkeypatch):
    monkeypatch.setenv(keys.PASSWORD_ENV, "wrong-password-value")
    with pytest.raises(SecurityError) as exc:
        keys.load_private_key(keypair[0])
    assert "wrong-password-value" not in str(exc.value)
    assert "BEGIN" not in str(exc.value)
