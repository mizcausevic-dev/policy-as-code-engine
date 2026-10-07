"""Cross-language v2 attestation acceptance vectors from hash-attestation-rs."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from policy_as_code_engine.card_attestation import CardAttestation, verify_card_attestation

PUBLIC_KEY = bytes.fromhex("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c")


def test_rust_v2_unicode_and_number_vector_verifies_in_python() -> None:
    body = {
        "name": "Café",
        "x": 1e-7,
        "negzero": -0.0,
        "דּ": "Hebrew",
        "😀": "Emoji",
        "nested": {"b": 2, "a": 1},
    }
    attestation = CardAttestation(
        algorithm="ed25519",
        hash_profile="jcs-rfc8785-v1",
        signed_hash="sha256:2ec69677ffa05c1cb85954219ca2065693bd7b7d0f028ff4fbbc1974baac61a8",
        signature="080Io/0nKVkZa6DGRkfyl32dGaIIyoY0T17NNRnUZjAdEckaaas+KohIabqdUflBQ9VpdrMN5FPtUbrqVEb3DA==",
        key_url="https://vendor.example/.well-known/keys/aeo",
        signed_at="2026-10-07T12:00:00Z",
    )
    verify_card_attestation(
        body,
        attestation,
        trusted_key_url=attestation.key_url,
        trusted_public_key=PUBLIC_KEY,
        now=datetime(2026, 10, 8, tzinfo=UTC),
    )


@pytest.mark.parametrize("bad_value", [2**53 + 1, "\ud800"])
def test_non_i_json_input_fails_closed(bad_value: object) -> None:
    attestation = CardAttestation(
        algorithm="ed25519",
        hash_profile="jcs-rfc8785-v1",
        signed_hash="sha256:2ec69677ffa05c1cb85954219ca2065693bd7b7d0f028ff4fbbc1974baac61a8",
        signature="080Io/0nKVkZa6DGRkfyl32dGaIIyoY0T17NNRnUZjAdEckaaas+KohIabqdUflBQ9VpdrMN5FPtUbrqVEb3DA==",
        key_url="https://vendor.example/.well-known/keys/aeo",
        signed_at="2026-10-07T12:00:00Z",
    )
    with pytest.raises(ValueError, match="verification failed"):
        verify_card_attestation(
            {"value": bad_value},
            attestation,
            trusted_key_url=attestation.key_url,
            trusted_public_key=PUBLIC_KEY,
            now=datetime(2026, 10, 8, tzinfo=UTC),
        )
