"""Sigstore bundle (v0.3) handling for key-based blob signatures.

Cosign 3.x writes this format for ``cosign sign-blob --key ... --bundle``. Sentinel
can both produce it (development workflow) and verify it natively, which keeps
tests deterministic when Cosign is not installed. When Cosign *is* installed the
verifier additionally runs ``cosign verify-blob`` and requires both to agree.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from sentinel.core.security import MAX_SMALL_JSON_BYTES, SecurityError, load_json_bounded
from sentinel.signing.keys import key_id, load_private_key, sign_digest

BUNDLE_MEDIA_TYPES = (
    "application/vnd.dev.sigstore.bundle.v0.3+json",
    "application/vnd.dev.sigstore.bundle+json;version=0.3",
    "application/vnd.dev.sigstore.bundle+json;version=0.2",
)


@dataclass
class MessageSignature:
    digest_hex: str
    signature: bytes
    key_hint: str | None
    has_certificate: bool
    has_tlog_entries: bool


def _b64(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SecurityError(f"bundle {label} is not valid base64") from exc


def parse_message_bundle(path: Path) -> MessageSignature:
    doc = load_json_bounded(path, MAX_SMALL_JSON_BYTES)
    if not isinstance(doc, dict) or doc.get("mediaType") not in BUNDLE_MEDIA_TYPES:
        raise SecurityError("not a supported Sigstore bundle (mediaType)")
    msg = doc.get("messageSignature")
    if not isinstance(msg, dict):
        raise SecurityError("bundle has no messageSignature (DSSE bundles are attestations)")
    digest = msg.get("messageDigest") or {}
    if digest.get("algorithm") != "SHA2_256":
        raise SecurityError(f"unsupported digest algorithm {digest.get('algorithm')!r}")
    digest_bytes = _b64(str(digest.get("digest", "")), "digest")
    if len(digest_bytes) != 32:
        raise SecurityError("bundle digest is not a SHA-256 value")
    material = doc.get("verificationMaterial") or {}
    hint = (material.get("publicKey") or {}).get("hint")
    return MessageSignature(
        digest_hex=digest_bytes.hex(),
        signature=_b64(str(msg.get("signature", "")), "signature"),
        key_hint=hint,
        has_certificate=bool(material.get("certificate") or material.get("x509CertificateChain")),
        has_tlog_entries=bool(material.get("tlogEntries")),
    )


def verify_digest_signature(
    public_key: ec.EllipticCurvePublicKey, digest_hex: str, signature: bytes
) -> bool:
    try:
        public_key.verify(
            signature, bytes.fromhex(digest_hex), ec.ECDSA(Prehashed(hashes.SHA256()))
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def sign_blob(artifact: Path, private_key_path: Path, bundle_path: Path) -> Path:
    """Write a Cosign-compatible key-based Sigstore bundle for ``artifact``."""
    private_key = load_private_key(private_key_path)
    digest = hashlib.sha256()
    with artifact.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    raw_digest = digest.digest()
    signature = sign_digest(private_key, raw_digest)
    bundle = {
        "mediaType": BUNDLE_MEDIA_TYPES[0],
        "verificationMaterial": {"publicKey": {"hint": key_id(private_key.public_key())}},
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(raw_digest).decode(),
            },
            "signature": base64.b64encode(signature).decode(),
        },
    }
    bundle_path.write_text(json.dumps(bundle))
    return bundle_path
