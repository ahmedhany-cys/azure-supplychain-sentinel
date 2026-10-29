"""Key handling for the local development signing workflow.

Production signing should use Cosign with a KMS-backed key (for example Azure Key
Vault via ``azurekms://``) or keyless signing; see docs/security-controls.md.
This module exists so the project and its tests can sign and verify offline.

Private keys are always written encrypted (PKCS#8 + password from an environment
variable), with 0600 permissions, and never logged.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sentinel.core.models import TrustedKeyInfo
from sentinel.core.security import SecurityError, read_bounded

PASSWORD_ENV = "SENTINEL_SIGNING_PASSWORD"  # noqa: S105 - env var name
MAX_KEY_BYTES = 16 * 1024


def key_id(public_key: ec.EllipticCurvePublicKey) -> str:
    """Base64 SHA-256 of the DER SubjectPublicKeyInfo; matches Cosign's bundle key hint."""
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


@dataclass(frozen=True)
class TrustedKey:
    name: str
    public_key: ec.EllipticCurvePublicKey
    path: Path | None = None

    @property
    def key_id(self) -> str:
        return key_id(self.public_key)

    def info(self) -> TrustedKeyInfo:
        return TrustedKeyInfo(
            name=self.name, key_id=self.key_id, path=self.path.name if self.path else None
        )


def load_public_key(path: Path, name: str | None = None) -> TrustedKey:
    data = read_bounded(path, MAX_KEY_BYTES)
    if b"PRIVATE KEY" in data:
        raise SecurityError(f"{path.name} contains a private key; trust stores take public keys")
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError as exc:
        raise SecurityError(f"{path.name} is not a PEM public key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SecurityError(f"{path.name}: only ECDSA P-256 keys are supported")
    return TrustedKey(name=name or path.stem, public_key=key, path=path)


def generate_keypair(out_dir: Path, prefix: str = "sentinel-dev") -> tuple[Path, Path]:
    password = os.environ.get(PASSWORD_ENV)
    if not password:
        raise SecurityError(f"set {PASSWORD_ENV} to encrypt the private key")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_dir.chmod(0o700)
    private = ec.generate_private_key(ec.SECP256R1())
    priv_path, pub_path = out_dir / f"{prefix}.key", out_dir / f"{prefix}.pub"
    if priv_path.exists():
        raise SecurityError(f"{priv_path.name} already exists; refusing to overwrite a key")
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode()),
    )
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    pub_path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return priv_path, pub_path


def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    password = os.environ.get(PASSWORD_ENV)
    data = read_bounded(path, MAX_KEY_BYTES)
    try:
        key = serialization.load_pem_private_key(
            data, password=password.encode() if password else None
        )
    except (ValueError, TypeError) as exc:
        # Never include key material or the password in the message.
        raise SecurityError(f"could not load private key {path.name} (wrong password?)") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise SecurityError("only ECDSA P-256 private keys are supported")
    return key


def sign_digest(private_key: ec.EllipticCurvePrivateKey, digest: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

    return private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
