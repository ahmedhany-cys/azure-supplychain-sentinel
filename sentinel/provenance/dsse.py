"""DSSE (Dead Simple Signing Envelope) encode/verify for in-toto attestations."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from sentinel.core.security import SecurityError
from sentinel.signing.keys import TrustedKey, key_id

IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def pae(payload_type: str, payload: bytes) -> bytes:
    """Pre-Authentication Encoding from the DSSE v1 specification."""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def decode_envelope(envelope: dict[str, Any]) -> tuple[str, bytes, list[dict[str, Any]]]:
    payload_type = envelope.get("payloadType")
    if payload_type != IN_TOTO_PAYLOAD_TYPE:
        raise SecurityError(f"unexpected DSSE payloadType {payload_type!r}")
    try:
        payload = base64.b64decode(str(envelope.get("payload", "")), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SecurityError("DSSE payload is not valid base64") from exc
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list):
        raise SecurityError("DSSE envelope has no signatures list")
    return payload_type, payload, signatures


def verify_envelope(envelope: dict[str, Any], keys: list[TrustedKey]) -> TrustedKey | None:
    payload_type, payload, signatures = decode_envelope(envelope)
    message = pae(payload_type, payload)
    for sig in signatures:
        try:
            raw = base64.b64decode(str(sig.get("sig", "")), validate=True)
        except (binascii.Error, ValueError, AttributeError):
            continue
        for key in keys:
            try:
                key.public_key.verify(raw, message, ec.ECDSA(hashes.SHA256()))
            except (InvalidSignature, ValueError):
                continue
            return key
    return None


def sign_statement(statement: dict[str, Any], private_key: ec.EllipticCurvePrivateKey) -> dict:
    payload = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode()
    signature = private_key.sign(pae(IN_TOTO_PAYLOAD_TYPE, payload), ec.ECDSA(hashes.SHA256()))
    return {
        "payloadType": IN_TOTO_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {"keyid": key_id(private_key.public_key()), "sig": base64.b64encode(signature).decode()}
        ],
    }
