"""Synthetic-only tenant and restart probes for the opt-in pilot API."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from policy_as_code_engine.pilot_app import _empty_evaluation_body, app


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@pytest.fixture
def pilot(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[dict[str, Any]]:
    issuer_key = Ed25519PrivateKey.generate()
    buyer_key = Ed25519PrivateKey.generate()
    public_key = issuer_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    db_path = tmp_path / "pilot.sqlite3"
    monkeypatch.setenv("POLICY_PILOT_DB_PATH", str(db_path))
    monkeypatch.setenv("POLICY_PILOT_ISSUER", "synthetic-test-issuer")
    monkeypatch.setenv("POLICY_PILOT_AUDIENCE", "policy-pilot-test")
    monkeypatch.setenv("POLICY_PILOT_ISSUER_PUBLIC_KEY_B64", base64.b64encode(public_key).decode("ascii"))
    monkeypatch.delenv("POLICY_PILOT_ALLOW_SYNTHETIC", raising=False)
    monkeypatch.delenv("POLICY_PILOT_DENY_ALL", raising=False)
    with TestClient(app) as client:
        yield {"client": client, "db_path": db_path, "issuer_key": issuer_key, "buyer_key": buyer_key}


def _token(
    issuer_key: Ed25519PrivateKey,
    *,
    tenant: str = "tenant-a",
    role: str = "admin",
    vendor_id: str = "vendor-a",
    audience: str = "policy-pilot-test",
    expired: bool = False,
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": "synthetic-test-issuer",
        "aud": audience,
        "sub": "synthetic-operator",
        "tenant": tenant,
        "role": role,
        "iat": now - 60 if expired else now,
        "nbf": now - 60 if expired else now,
        "exp": now - 1 if expired else now + 120,
    }
    if role == "evaluate":
        claims.update({"action": "use", "vendor_id": vendor_id})
    header = _b64url(b'{"alg":"EdDSA","typ":"JWT"}')
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    unsigned = f"{header}.{payload}"
    return f"{unsigned}.{_b64url(issuer_key.sign(unsigned.encode('ascii')))}"


def _auth(pilot: dict[str, Any], **claims: Any) -> dict[str, str]:
    return {"Authorization": "Bearer " + _token(pilot["issuer_key"], **claims)}


def _enroll(
    pilot: dict[str, Any],
    *,
    tenant: str = "tenant-a",
    key_id: str = "buyer-key-v1",
    signing_pair: Ed25519PrivateKey | None = None,
) -> None:
    signer = signing_pair or pilot["buyer_key"]
    public_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    response = pilot["client"].post(
        "/v1/keys",
        headers=_auth(pilot, tenant=tenant),
        json={
            "key_id": key_id,
            "buyer_id": "buyer-a",
            "key_url": "https://buyer.example/.well-known/keys/decision-card",
            "public_key_b64": base64.b64encode(public_key).decode("ascii"),
        },
    )
    assert response.status_code == 201, response.text


def _signed_card(
    buyer_key: Ed25519PrivateKey,
    *,
    decision_id: str = "synthetic-001",
    conditional: bool = False,
    key_id: str = "buyer-key-v1",
    expiry_days: int = 1,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    card: dict[str, Any] = {
        "decision_card_version": "0.1",
        "decision_id": decision_id,
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "buyer": {"id": "buyer-a", "name": "Synthetic Buyer", "type": "test"},
        "decision": {
            "status": "approved-with-conditions" if conditional else "approved",
            "effective_until": (now + timedelta(days=expiry_days)).isoformat(),
        },
        "subject": {"vendor_name": "Synthetic Vendor", "vendor_id": "vendor-a"},
        "rationale": "Synthetic test approval only.",
    }
    if conditional:
        card["conditions"] = [
            {"id": "condition-1", "description": "Synthetic condition", "enforcement": "gate"}
        ]
    digest = "sha256:" + hashlib.sha256(rfc8785.dumps(card)).hexdigest()
    metadata = {
        "algorithm": "ed25519",
        "hash_profile": "jcs-rfc8785-v1",
        "signed_hash": digest,
        "key_url": "https://buyer.example/.well-known/keys/decision-card",
        "signed_at": now.isoformat(),
    }
    signature = buyer_key.sign(b"hash-attestation/v2\x00" + rfc8785.dumps(metadata))
    return {
        "key_id": key_id,
        "card": card,
        "attestation": {**metadata, "signature": base64.b64encode(signature).decode("ascii")},
    }


def _register(
    pilot: dict[str, Any],
    *,
    conditional: bool = False,
    decision_id: str = "synthetic-001",
    key_id: str = "buyer-key-v1",
    signing_pair: Ed25519PrivateKey | None = None,
) -> str:
    response = pilot["client"].post(
        "/v1/cards",
        headers=_auth(pilot),
        json=_signed_card(
            signing_pair or pilot["buyer_key"],
            conditional=conditional,
            decision_id=decision_id,
            key_id=key_id,
        ),
    )
    assert response.status_code == 201, response.text
    return response.json()["bundle_id"]


def test_default_deny_and_opt_in_allow_with_durable_receipt(
    pilot: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client: TestClient = pilot["client"]
    assert client.get("/readyz").json() == {"status": "ready", "allow_enabled": False}
    _enroll(pilot)
    bundle_id = _register(pilot)
    endpoint = f"/v1/bundles/{bundle_id}/evaluate"
    response = client.post(endpoint, headers=_auth(pilot, role="evaluate"))
    assert response.status_code == 200
    assert response.json()["decision"] == "deny"
    assert response.json()["reason_code"] == "deny_all"
    monkeypatch.setenv("POLICY_PILOT_ALLOW_SYNTHETIC", "1")
    monkeypatch.setenv("POLICY_PILOT_DENY_ALL", "0")
    allowed = client.post(endpoint, headers=_auth(pilot, role="evaluate"))
    assert allowed.status_code == 200
    assert allowed.json()["decision"] == "allow"
    monkeypatch.setenv("POLICY_PILOT_DENY_ALL", "1")
    rolled_back = client.post(endpoint, headers=_auth(pilot, role="evaluate"))
    assert rolled_back.status_code == 200 and rolled_back.json()["reason_code"] == "deny_all"
    with sqlite3.connect(pilot["db_path"]) as connection:
        assert connection.execute("SELECT count(*) FROM receipts").fetchone()[0] == 5
    assert allowed.headers["cache-control"] == "no-store"


def test_cross_tenant_role_audience_and_vendor_scope(
    pilot: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client: TestClient = pilot["client"]
    _enroll(pilot)
    bundle_id = _register(pilot)
    endpoint = f"/v1/bundles/{bundle_id}/evaluate"
    monkeypatch.setenv("POLICY_PILOT_ALLOW_SYNTHETIC", "1")
    monkeypatch.setenv("POLICY_PILOT_DENY_ALL", "0")
    assert client.post(endpoint, headers=_auth(pilot, tenant="tenant-b", role="evaluate")).status_code == 404
    wrong_vendor = client.post(endpoint, headers=_auth(pilot, role="evaluate", vendor_id="vendor-b"))
    assert wrong_vendor.status_code == 200 and wrong_vendor.json()["decision"] == "deny"
    assert client.post(endpoint, headers=_auth(pilot)).status_code == 403
    assert client.post("/v1/keys", headers=_auth(pilot, role="evaluate"), json={}).status_code == 403
    assert client.post(endpoint, headers=_auth(pilot, role="evaluate", audience="wrong")).status_code == 403
    assert client.post(endpoint, headers=_auth(pilot, role="evaluate", expired=True)).status_code == 403
    assert client.get("/v1/receipts", headers=_auth(pilot, tenant="tenant-b")).json() == {"receipts": []}
    assert client.post(endpoint, headers={"Authorization": "Bearer a.b.c"}).status_code == 403
    assert (
        client.post("/v1/keys/buyer-key-v1/revoke", headers=_auth(pilot, tenant="tenant-b")).status_code
        == 404
    )
    assert (
        client.post(f"/v1/bundles/{bundle_id}/revoke", headers=_auth(pilot, tenant="tenant-b")).status_code
        == 404
    )
    assert client.post("/evaluate", headers=_auth(pilot), json={}).status_code == 404
    assert client.get("/bundles", headers=_auth(pilot)).status_code == 404


def test_key_revocation_and_receipts_survive_restart(
    pilot: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client: TestClient = pilot["client"]
    _enroll(pilot)
    bundle_id = _register(pilot)
    endpoint = f"/v1/bundles/{bundle_id}/evaluate"
    monkeypatch.setenv("POLICY_PILOT_ALLOW_SYNTHETIC", "1")
    monkeypatch.setenv("POLICY_PILOT_DENY_ALL", "0")
    assert client.post(endpoint, headers=_auth(pilot, role="evaluate")).json()["decision"] == "allow"
    revoked = client.post("/v1/keys/buyer-key-v1/revoke", headers=_auth(pilot))
    assert revoked.status_code == 200
    assert client.post(endpoint, headers=_auth(pilot, role="evaluate")).json()["decision"] == "deny"
    with TestClient(app) as restarted:
        assert restarted.get("/readyz").status_code == 200
        again = restarted.post(endpoint, headers=_auth(pilot, role="evaluate"))
        assert again.status_code == 200 and again.json()["reason_code"] == "revoked"
        events = [
            receipt["event"]
            for receipt in restarted.get("/v1/receipts", headers=_auth(pilot)).json()["receipts"]
        ]
        assert "key_revoked" in events and events.count("evaluation") == 3


def test_key_rotation_overlap_then_old_key_revocation(
    pilot: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client: TestClient = pilot["client"]
    _enroll(pilot)
    old_bundle = _register(pilot)
    new_buyer_key = Ed25519PrivateKey.generate()
    _enroll(pilot, key_id="buyer-key-v2", signing_pair=new_buyer_key)
    new_bundle = _register(
        pilot,
        decision_id="synthetic-002",
        key_id="buyer-key-v2",
        signing_pair=new_buyer_key,
    )
    monkeypatch.setenv("POLICY_PILOT_ALLOW_SYNTHETIC", "1")
    monkeypatch.setenv("POLICY_PILOT_DENY_ALL", "0")
    eval_headers = _auth(pilot, role="evaluate")
    assert (
        client.post(f"/v1/bundles/{old_bundle}/evaluate", headers=eval_headers).json()["decision"] == "allow"
    )
    assert (
        client.post(f"/v1/bundles/{new_bundle}/evaluate", headers=eval_headers).json()["decision"] == "allow"
    )
    assert client.post("/v1/keys/buyer-key-v1/revoke", headers=_auth(pilot)).status_code == 200
    with TestClient(app) as restarted:
        assert (
            restarted.post(f"/v1/bundles/{old_bundle}/evaluate", headers=eval_headers).json()["decision"]
            == "deny"
        )
        assert (
            restarted.post(f"/v1/bundles/{new_bundle}/evaluate", headers=eval_headers).json()["decision"]
            == "allow"
        )


def test_condition_and_card_revocation(pilot: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    client: TestClient = pilot["client"]
    _enroll(pilot)
    bundle_id = _register(pilot, conditional=True)
    endpoint = f"/v1/bundles/{bundle_id}/evaluate"
    monkeypatch.setenv("POLICY_PILOT_ALLOW_SYNTHETIC", "1")
    monkeypatch.setenv("POLICY_PILOT_DENY_ALL", "0")
    assert client.post(endpoint, headers=_auth(pilot, role="evaluate")).json()["decision"] == "deny"
    until = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    asserted = client.put(
        f"/v1/bundles/{bundle_id}/conditions/condition-1",
        headers=_auth(pilot),
        json={"satisfied": True, "valid_until": until},
    )
    assert asserted.status_code == 200, asserted.text
    with TestClient(app) as restarted:
        assert restarted.post(endpoint, headers=_auth(pilot, role="evaluate")).json()["decision"] == "allow"
        assert restarted.post(f"/v1/bundles/{bundle_id}/revoke", headers=_auth(pilot)).status_code == 200
        assert (
            restarted.post(endpoint, headers=_auth(pilot, role="evaluate")).json()["reason_code"] == "revoked"
        )


def test_audit_write_failure_prevents_allow(pilot: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    client: TestClient = pilot["client"]
    _enroll(pilot)
    bundle_id = _register(pilot)
    monkeypatch.setenv("POLICY_PILOT_ALLOW_SYNTHETIC", "1")
    monkeypatch.setenv("POLICY_PILOT_DENY_ALL", "0")
    with sqlite3.connect(pilot["db_path"]) as connection:
        connection.execute(
            "CREATE TRIGGER block_receipt BEFORE INSERT ON receipts "
            "BEGIN SELECT RAISE(FAIL, 'synthetic audit outage'); END"
        )
    response = client.post(f"/v1/bundles/{bundle_id}/evaluate", headers=_auth(pilot, role="evaluate"))
    assert response.status_code == 503
    assert response.json() == {"detail": "pilot state unavailable"}


def test_audit_failure_rolls_back_key_enrollment(pilot: dict[str, Any]) -> None:
    with sqlite3.connect(pilot["db_path"]) as connection:
        connection.execute(
            "CREATE TRIGGER block_receipt BEFORE INSERT ON receipts "
            "BEGIN SELECT RAISE(FAIL, 'synthetic audit outage'); END"
        )
    signer: Ed25519PrivateKey = pilot["buyer_key"]
    public_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    response = pilot["client"].post(
        "/v1/keys",
        headers=_auth(pilot),
        json={
            "key_id": "buyer-key-v1",
            "buyer_id": "buyer-a",
            "key_url": "https://buyer.example/.well-known/keys/decision-card",
            "public_key_b64": base64.b64encode(public_key).decode("ascii"),
        },
    )
    assert response.status_code == 503
    with sqlite3.connect(pilot["db_path"]) as connection:
        assert connection.execute("SELECT count(*) FROM buyer_keys").fetchone()[0] == 0


def test_tampered_card_and_unconfigured_state_fail_closed(
    pilot: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _enroll(pilot)
    payload = _signed_card(pilot["buyer_key"])
    payload["card"]["subject"]["vendor_id"] = "tampered-vendor"
    assert pilot["client"].post("/v1/cards", headers=_auth(pilot), json=payload).status_code == 400
    too_long = _signed_card(pilot["buyer_key"], decision_id="synthetic-long", expiry_days=31)
    assert pilot["client"].post("/v1/cards", headers=_auth(pilot), json=too_long).status_code == 400
    monkeypatch.delenv("POLICY_PILOT_DB_PATH")
    assert pilot["client"].get("/readyz").status_code == 503
    assert pilot["client"].get("/healthz").status_code == 200


def test_local_input_boundary(pilot: dict[str, Any]) -> None:
    client: TestClient = pilot["client"]
    headers = {**_auth(pilot), "Content-Type": "application/json"}
    duplicate = client.post("/v1/keys", headers=headers, content=b'{"key_id":"a","key_id":"b"}')
    assert duplicate.status_code == 400
    oversized = client.post("/v1/keys", headers=headers, content=b"x" * 131_073)
    assert oversized.status_code == 413
    nested = client.post("/v1/keys", headers=headers, content=b'{"x":' + b"[" * 64 + b"0" + b"]" * 64 + b"}")
    assert nested.status_code == 400
    deeply_nested = client.post(
        "/v1/keys", headers=headers, content=b'{"x":' + b"[" * 1100 + b"0" + b"]" * 1100 + b"}"
    )
    assert deeply_nested.status_code == 400
    assert (
        client.post(
            "/v1/bundles/unknown/evaluate", headers=_auth(pilot, role="evaluate"), json={}
        ).status_code
        == 400
    )
    with TestClient(app, client=("203.0.113.7", 12345)) as remote:
        assert remote.get("/healthz").status_code == 403


@pytest.mark.asyncio
async def test_headerless_evaluation_body_is_rejected() -> None:
    request_scope: dict[str, Any] = {
        "type": "http",
        "method": "POST",
        "path": "/v1/bundles/synthetic/evaluate",
        "headers": [],
    }

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    request = Request(request_scope, receive)
    with pytest.raises(HTTPException) as error:
        await _empty_evaluation_body(request)
    assert error.value.status_code == 400


def test_readiness_detects_missing_schema_table(pilot: dict[str, Any]) -> None:
    assert pilot["client"].get("/readyz").status_code == 200
    with sqlite3.connect(pilot["db_path"]) as connection:
        connection.execute("DROP TABLE conditions")
    assert pilot["client"].get("/readyz").status_code == 503
    public_key = (
        pilot["buyer_key"]
        .public_key()
        .public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    )
    response = pilot["client"].post(
        "/v1/keys",
        headers=_auth(pilot),
        json={
            "key_id": "buyer-key-v1",
            "buyer_id": "buyer-a",
            "key_url": "https://buyer.example/.well-known/keys/decision-card",
            "public_key_b64": base64.b64encode(public_key).decode("ascii"),
        },
    )
    assert response.status_code == 503
