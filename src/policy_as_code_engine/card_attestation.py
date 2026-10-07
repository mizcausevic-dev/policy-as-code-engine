"""Verify a buyer-pinned v2 Ed25519 attestation over a Decision Card.

The verifier follows hash-attestation-rs's ``jcs-rfc8785-v1`` profile. A key
URL in a card or attestation never establishes trust by itself: callers must
pin the buyer ID, URL, and 32-byte public key outside the card.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field

from .models import StrictModel


class CardAttestation(StrictModel):
    algorithm: Literal["ed25519"]
    hash_profile: Literal["jcs-rfc8785-v1"]
    signed_hash: str = Field(..., min_length=71, max_length=71)
    signature: str = Field(..., min_length=88, max_length=88)
    key_url: str = Field(..., min_length=1, max_length=512)
    signed_at: str = Field(..., min_length=20, max_length=40)


def verify_card_attestation(
    card: dict[str, Any],
    attestation: CardAttestation,
    *,
    trusted_key_url: str,
    trusted_public_key: bytes,
    now: datetime | None = None,
) -> None:
    """Raise ValueError unless the pinned buyer key signed this exact card."""
    if attestation.key_url != trusted_key_url or len(trusted_public_key) != 32:
        raise ValueError("Decision Card attestation has no matching trusted buyer key")
    try:
        signed_at = datetime.fromisoformat(attestation.signed_at.replace("Z", "+00:00"))
    except ValueError as err:
        raise ValueError("Decision Card attestation signed_at is invalid") from err
    if signed_at.tzinfo is None:
        raise ValueError("Decision Card attestation signed_at requires a timezone")
    clock = now or datetime.now(UTC)
    if signed_at > clock + timedelta(minutes=5):
        raise ValueError("Decision Card attestation is dated in the future")
    try:
        card_bytes = rfc8785.dumps(card)
        digest = "sha256:" + hashlib.sha256(card_bytes).hexdigest()
        if not secrets.compare_digest(digest, attestation.signed_hash):
            raise ValueError("Decision Card content does not match its attestation")
        metadata = {
            "algorithm": attestation.algorithm,
            "hash_profile": attestation.hash_profile,
            "key_url": attestation.key_url,
            "signed_at": attestation.signed_at,
            "signed_hash": attestation.signed_hash,
        }
        message = b"hash-attestation/v2\x00" + rfc8785.dumps(metadata)
        signature = base64.b64decode(attestation.signature, validate=True)
        if len(signature) != 64:
            raise ValueError("Decision Card attestation signature has invalid length")
        Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(signature, message)
    except (rfc8785.CanonicalizationError, InvalidSignature, ValueError, binascii.Error) as err:
        raise ValueError("Decision Card attestation verification failed") from err
