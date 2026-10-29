"""Artifact signature verification against an explicit trust store.

A signature is accepted only when **all** of the following hold:

1. the SHA-256 of the artifact bytes on disk equals the digest inside the bundle;
2. if the release record pins an expected digest, the artifact matches it too;
3. the signature verifies, over the *actual* digest, under a key in the trust store;
4. if Cosign is installed (and not disabled), ``cosign verify-blob`` agrees.

The mere presence of a signature, or a key hint inside the bundle, proves nothing:
the hint is unauthenticated and is only used to explain failures.
"""

from __future__ import annotations

from pathlib import Path

from sentinel.config import Settings
from sentinel.core.models import SignatureStatus, SignatureVerification
from sentinel.core.runner import run_tool, tool_version, which
from sentinel.core.security import SecurityError, sha256_file
from sentinel.signing.bundle import parse_message_bundle, verify_digest_signature
from sentinel.signing.keys import TrustedKey


def _fail(
    result: SignatureVerification, status: SignatureStatus, detail: str
) -> SignatureVerification:
    result.status = status
    result.verified = False
    result.details.append(detail)
    return result


def verify_artifact(
    artifact: Path | None,
    bundle: Path | None,
    trusted_keys: list[TrustedKey],
    settings: Settings,
    *,
    expected_sha256: str | None = None,
) -> SignatureVerification:
    result = SignatureVerification(
        status=SignatureStatus.ERROR,
        artifact=artifact.name if artifact else None,
        expected_sha256=expected_sha256.lower() if expected_sha256 else None,
        trusted_keys=[k.info() for k in trusted_keys],
        methods=["native-ecdsa-p256"],
    )
    if artifact is None or not artifact.is_file():
        return _fail(result, SignatureStatus.MISSING_ARTIFACT, "artifact file not found")
    result.actual_sha256 = sha256_file(artifact)
    if bundle is None or not bundle.is_file():
        return _fail(
            result,
            SignatureStatus.MISSING_SIGNATURE,
            "no signature bundle was supplied for the artifact",
        )
    if not trusted_keys:
        return _fail(
            result,
            SignatureStatus.NO_TRUSTED_KEYS,
            "the policy trust store is empty; no signer can be trusted",
        )
    try:
        message = parse_message_bundle(bundle)
    except SecurityError as exc:
        return _fail(result, SignatureStatus.MALFORMED_BUNDLE, f"signature bundle rejected: {exc}")
    result.signed_sha256 = message.digest_hex
    result.claimed_key_hint = message.key_hint
    if message.has_certificate:
        return _fail(
            result,
            SignatureStatus.UNSUPPORTED,
            "certificate-based (keyless) bundles require identity verification with "
            "`cosign verify-blob --certificate-identity ... --certificate-oidc-issuer ...`;"
            " this release gate is configured for key-based trust only",
        )

    if message.digest_hex != result.actual_sha256:
        _fail(
            result,
            SignatureStatus.DIGEST_MISMATCH,
            "artifact digest does not match the digest that was signed: the artifact was "
            "modified after signing or the wrong bundle was supplied",
        )
    if result.expected_sha256 and result.expected_sha256 != result.actual_sha256:
        _fail(
            result,
            SignatureStatus.DIGEST_MISMATCH,
            "artifact digest does not match the digest pinned in the release record",
        )

    matched: TrustedKey | None = None
    for key in trusted_keys:
        if verify_digest_signature(key.public_key, result.actual_sha256, message.signature):
            matched = key
            break

    if result.status == SignatureStatus.DIGEST_MISMATCH:
        _cosign_cross_check(result, artifact, bundle, trusted_keys, settings, expect_ok=False)
        return result

    if matched is None:
        trusted_ids = {k.key_id for k in trusted_keys}
        if message.key_hint and message.key_hint not in trusted_ids:
            _fail(
                result,
                SignatureStatus.UNTRUSTED_SIGNER,
                "the signature does not verify under any trusted key; the bundle names a "
                f"signer key ({message.key_hint[:16]}...) that is not in the trust store",
            )
        else:
            _fail(
                result,
                SignatureStatus.INVALID_SIGNATURE,
                "the signature does not verify under any trusted key",
            )
        _cosign_cross_check(result, artifact, bundle, trusted_keys, settings, expect_ok=False)
        return result

    result.signer_key_id = matched.key_id
    result.signer_name = matched.name
    result.status = SignatureStatus.VERIFIED
    result.verified = True
    result.details.append(
        f"signature verified over sha256:{result.actual_sha256} with trusted key '{matched.name}'"
    )
    _cosign_cross_check(result, artifact, bundle, [matched], settings, expect_ok=True)
    result.details.append(
        "transparency log not checked: key-based offline signing does not upload to Rekor"
    )
    return result


def _cosign_cross_check(
    result: SignatureVerification,
    artifact: Path,
    bundle: Path,
    keys: list[TrustedKey],
    settings: Settings,
    *,
    expect_ok: bool,
) -> None:
    if settings.use_cosign == "off" or not which(settings.cosign_bin):
        result.details.append(
            "cosign CLI not used (not installed or disabled); native verifier only"
        )
        return
    result.methods.append("cosign-verify-blob")
    result.cosign_version = tool_version(settings.cosign_bin, ["version"])
    any_ok = False
    for key in keys[:3]:
        if key.path is None:
            continue
        run = run_tool(
            [
                settings.cosign_bin,
                "verify-blob",
                "--key",
                str(key.path),
                "--bundle",
                str(bundle),
                "--insecure-ignore-tlog=true",
                str(artifact),
            ],
            timeout=settings.cosign_timeout,
        )
        if run.timed_out or run.not_found:
            result.details.append(f"cosign verify-blob did not complete: {run.error}")
            result.cosign_verified = None
            if expect_ok:
                _fail(
                    result,
                    SignatureStatus.ERROR,
                    "cosign cross-check could not complete; failing closed",
                )
            return
        if run.returncode == 0:
            any_ok = True
            break
    result.cosign_verified = any_ok
    if any_ok != expect_ok:
        _fail(
            result,
            SignatureStatus.ERROR,
            "native verifier and cosign disagree; failing closed "
            f"(native={'ok' if expect_ok else 'rejected'}, cosign={'ok' if any_ok else 'rejected'})",
        )
    else:
        result.details.append(
            f"cosign verify-blob {'accepted' if any_ok else 'rejected'} the "
            "signature (consistent with native verification)"
        )
