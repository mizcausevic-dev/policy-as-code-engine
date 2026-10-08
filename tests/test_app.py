"""End-to-end tests for the FastAPI app."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from policy_as_code_engine.app import _RequestBoundary, app

ADMIN_TOKEN = "test-admin-token-with-at-least-32-characters"
EVALUATE_TOKEN = "test-evaluate-token-with-at-least-32-characters"
BUYER_KEY_URL = "https://buyer.example/.well-known/keys/decision-card"
BUYER_PUBLIC_KEY = bytes.fromhex("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c")
RUST_VECTOR_HASH = "sha256:e8924577948f1fd79eae6a3541e8ed61dd64c41ad1a69ebf6ea0ebe16b627ca3"
RUST_VECTOR_SIGNATURE = (
    "tCT0O11Rp2yGzRqLTxgSn11lnQehw0DjEMPZOiYLvibqVV5Dlz5Wb8r0EXA5bl3xw5DQnL3isRDYZVJQi48CAA=="
)


@pytest.fixture(autouse=True)
def configure_api_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POLICY_ENGINE_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.setenv("POLICY_ENGINE_EVALUATE_TOKEN", EVALUATE_TOKEN)
    monkeypatch.setenv(
        "POLICY_ENGINE_BUYER_KEYS_JSON",
        json.dumps({"buyer-1": {BUYER_KEY_URL: base64.b64encode(BUYER_PUBLIC_KEY).decode("ascii")}}),
    )


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app, headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}) as c:
        yield c


def _simple_bundle(bundle_id: str = "b1") -> dict[str, Any]:
    return {
        "bundle_id": bundle_id,
        "policies": [
            {
                "id": "p",
                "default_effect": "deny",
                "rules": [
                    {
                        "id": "admin-allow",
                        "effect": "allow",
                        "when": {"kind": "eq", "field": "subject.role", "value": "admin"},
                    }
                ],
            }
        ],
    }


def _decision_card(**overrides: Any) -> dict[str, Any]:
    card: dict[str, Any] = {
        "decision_card_version": "0.1",
        "decision_id": "TEST-001",
        "issued_at": "2026-10-07T12:00:00Z",
        "buyer": {"id": "buyer-1", "name": "Test Buyer", "type": "school-district"},
        "decision": {"status": "approved", "effective_until": "2026-12-31T00:00:00Z"},
        "subject": {"vendor_name": "AcmeTutor", "vendor_id": "vendor-1"},
        "rationale": "Approved after review.",
    }
    card.update(overrides)
    return card


def _signed_request(card: dict[str, Any], *, actions: list[str] | None = None) -> dict[str, Any]:
    digest = "sha256:" + hashlib.sha256(rfc8785.dumps(card)).hexdigest()
    attestation = {
        "algorithm": "ed25519",
        "hash_profile": "jcs-rfc8785-v1",
        "signed_hash": digest,
        "key_url": BUYER_KEY_URL,
        "signed_at": "2026-10-07T12:00:00Z",
    }
    payload = b"hash-attestation/v2\x00" + rfc8785.dumps(attestation)
    signature = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32)).sign(payload)
    attestation["signature"] = base64.b64encode(signature).decode("ascii")
    return {"card": card, "attestation": attestation, "allowed_actions": actions or ["use"]}


class TestMeta:
    def test_root(self, client: TestClient) -> None:
        r = client.get("/")
        assert r.status_code == 200
        assert r.json()["name"] == "policy-as-code-engine"

    def test_healthz(self, client: TestClient) -> None:
        assert client.get("/healthz").json() == {"status": "ok"}


class TestAuthorization:
    def test_missing_or_wrong_token_fails_closed(self, client: TestClient) -> None:
        assert client.get("/bundles", headers={"Authorization": ""}).status_code == 401
        assert client.get("/bundles", headers={"Authorization": "Bearer wrong"}).status_code == 403
        assert client.get("/bundles").headers["cache-control"] == "no-store"

    def test_evaluator_role_cannot_register_or_read_bundles(self, client: TestClient) -> None:
        evaluator = {"Authorization": f"Bearer {EVALUATE_TOKEN}"}
        assert client.post("/bundles", json=_simple_bundle(), headers=evaluator).status_code == 403
        assert client.get("/bundles", headers=evaluator).status_code == 403
        assert (
            client.post(
                "/evaluate", json={"bundle": _simple_bundle(), "context": {}}, headers=evaluator
            ).status_code
            == 403
        )
        assert client.post("/bundles", json=_simple_bundle()).status_code == 201
        response = client.post(
            "/bundles/b1/evaluate",
            json={"subject": {"role": "admin"}},
            headers=evaluator,
        )
        assert response.status_code == 200
        assert response.json()["decision"]["kind"] == "allow"

    def test_unconfigured_or_reused_credentials_are_unavailable(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("POLICY_ENGINE_ADMIN_TOKEN")
        assert client.post("/bundles", json=_simple_bundle()).status_code == 503
        monkeypatch.setenv("POLICY_ENGINE_ADMIN_TOKEN", EVALUATE_TOKEN)
        assert client.post("/bundles", json=_simple_bundle()).status_code == 503


class TestBundleLifecycle:
    def test_register_then_evaluate(self, client: TestClient) -> None:
        r = client.post("/bundles", json=_simple_bundle())
        assert r.status_code == 201

        r = client.post(
            "/bundles/b1/evaluate",
            json={"subject": {"role": "admin"}, "data": {}, "resource": None, "action": None},
        )
        assert r.status_code == 200
        assert r.json()["decision"]["kind"] == "allow"

    def test_evaluate_unknown_bundle_is_404(self, client: TestClient) -> None:
        r = client.post(
            "/bundles/missing/evaluate",
            json={"data": {}, "subject": None, "action": None, "resource": None},
        )
        assert r.status_code == 404

    def test_list_bundles(self, client: TestClient) -> None:
        client.post("/bundles", json=_simple_bundle("listed-1"))
        client.post("/bundles", json=_simple_bundle("listed-2"))
        r = client.get("/bundles")
        ids = r.json()["bundle_ids"]
        assert "listed-1" in ids
        assert "listed-2" in ids

    def test_get_bundle(self, client: TestClient) -> None:
        client.post("/bundles", json=_simple_bundle("g1"))
        r = client.get("/bundles/g1")
        assert r.status_code == 200
        assert r.json()["bundle_id"] == "g1"

    def test_get_unknown_bundle_404(self, client: TestClient) -> None:
        assert client.get("/bundles/nope").status_code == 404

    def test_duplicate_id_cannot_overwrite_bundle(self, client: TestClient) -> None:
        assert client.post("/bundles", json=_simple_bundle()).status_code == 201
        assert client.post("/bundles", json=_simple_bundle()).status_code == 409
        assert client.get("/bundles/b1").json()["policies"][0]["rules"][0]["id"] == "admin-allow"


@pytest.mark.asyncio
async def test_stalled_request_body_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("policy_as_code_engine.app.MAX_BODY_READ_SECONDS", 0.01)
    messages: list[dict[str, Any]] = []
    reads = 0

    async def downstream(_scope: Any, _receive: Any, _send: Any) -> None:
        raise AssertionError("stalled body must not reach the app")

    async def receive() -> dict[str, Any]:
        nonlocal reads
        reads += 1
        if reads == 1:
            return {"type": "http.request", "body": b"{", "more_body": True}
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await _RequestBoundary(downstream)({"type": "http", "method": "POST", "path": "/bundles"}, receive, send)
    assert messages[0]["status"] == 408


class TestOneShotEvaluate:
    def test_oneshot(self, client: TestClient) -> None:
        body = {
            "bundle": _simple_bundle("ad-hoc"),
            "context": {"subject": {"role": "admin"}, "data": {}, "resource": None, "action": None},
        }
        r = client.post("/evaluate", json=body)
        assert r.status_code == 200
        assert r.json()["decision"]["kind"] == "allow"

    def test_oneshot_deny_default(self, client: TestClient) -> None:
        body = {
            "bundle": _simple_bundle("ad-hoc-2"),
            "context": {
                "subject": {"role": "viewer"},
                "data": {},
                "resource": None,
                "action": None,
            },
        }
        r = client.post("/evaluate", json=body)
        assert r.json()["decision"]["kind"] == "deny"


class TestDecisionCardBridge:
    def test_rust_signed_approved_card_yields_scoped_bundle(self, client: TestClient) -> None:
        body = {
            "card": _decision_card(),
            "allowed_actions": ["use"],
            "attestation": {
                "algorithm": "ed25519",
                "hash_profile": "jcs-rfc8785-v1",
                "signed_hash": RUST_VECTOR_HASH,
                "signature": RUST_VECTOR_SIGNATURE,
                "key_url": BUYER_KEY_URL,
                "signed_at": "2026-10-07T12:00:00Z",
            },
        }
        r = client.post("/bundles/from-decision-card", json=body)
        assert r.status_code == 201
        bundle = r.json()
        assert bundle["bundle_id"].startswith("decision-card-")
        assert bundle["policies"][0]["default_effect"] == "deny"
        assert bundle["card_scope"]["vendor_id"] == "vendor-1"
        scoped = client.post(
            f"/bundles/{bundle['bundle_id']}/evaluate",
            json={"action": "use", "resource": {"vendor_id": "vendor-1"}},
        )
        assert scoped.json()["decision"]["kind"] == "allow"
        for context in (
            {"action": "delete", "resource": {"vendor_id": "vendor-1"}},
            {"action": "use", "resource": {"vendor_id": "unrelated"}},
            {"data": {"action": "use", "resource": {"vendor_id": "vendor-1"}}},
        ):
            unrelated = client.post(f"/bundles/{bundle['bundle_id']}/evaluate", json=context)
            assert unrelated.json()["decision"]["kind"] == "deny"

    def test_unsigned_and_tampered_positive_cards_are_rejected(self, client: TestClient) -> None:
        card = _decision_card(decision_id="UNSIGNED")
        assert (
            client.post(
                "/bundles/from-decision-card",
                json={"card": card, "allowed_actions": ["use"]},
            ).status_code
            == 400
        )
        signed = _signed_request(card)
        signed["card"]["subject"]["vendor_id"] = "unrelated"
        assert client.post("/bundles/from-decision-card", json=signed).status_code == 400
        signed_before_issue = _signed_request(
            _decision_card(decision_id="BEFORE-ISSUE", issued_at="2026-10-08T12:00:00Z")
        )
        assert client.post("/bundles/from-decision-card", json=signed_before_issue).status_code == 400
        broader_action = _signed_request(_decision_card(decision_id="DELETE-ACTION"), actions=["delete"])
        assert client.post("/bundles/from-decision-card", json=broader_action).status_code == 400

    def test_tampered_metadata_and_wrong_buyer_key_are_rejected(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        signed = _signed_request(_decision_card(decision_id="META-TAMPER"))
        signed["attestation"]["signed_at"] = "2026-10-07T12:00:01Z"
        assert client.post("/bundles/from-decision-card", json=signed).status_code == 400
        signed = _signed_request(_decision_card(decision_id="WRONG-KEY"))
        monkeypatch.setenv(
            "POLICY_ENGINE_BUYER_KEYS_JSON",
            json.dumps({"buyer-1": {BUYER_KEY_URL: base64.b64encode(bytes([9] * 32)).decode("ascii")}}),
        )
        assert client.post("/bundles/from-decision-card", json=signed).status_code == 400
        malformed = _signed_request(_decision_card(decision_id="BAD-BASE64"))
        malformed["attestation"]["signature"] = "!" * 88
        assert client.post("/bundles/from-decision-card", json=malformed).status_code == 400

    def test_key_url_is_covered_by_signature_even_if_both_urls_are_pinned(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        other_url = "https://buyer.example/.well-known/keys/other"
        public_b64 = base64.b64encode(BUYER_PUBLIC_KEY).decode("ascii")
        monkeypatch.setenv(
            "POLICY_ENGINE_BUYER_KEYS_JSON",
            json.dumps({"buyer-1": {BUYER_KEY_URL: public_b64, other_url: public_b64}}),
        )
        signed = _signed_request(_decision_card(decision_id="KEY-URL-TAMPER"))
        signed["attestation"]["key_url"] = other_url
        assert client.post("/bundles/from-decision-card", json=signed).status_code == 400

    def test_wrong_buyer_or_missing_trust_anchor_is_rejected(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        signed = _signed_request(
            _decision_card(
                decision_id="WRONG-BUYER", buyer={"id": "other", "name": "Other", "type": "school-district"}
            )
        )
        assert client.post("/bundles/from-decision-card", json=signed).status_code == 503
        monkeypatch.delenv("POLICY_ENGINE_BUYER_KEYS_JSON")
        assert (
            client.post("/bundles/from-decision-card", json=_signed_request(_decision_card())).status_code
            == 503
        )

    def test_duplicate_json_keys_and_non_json_numbers_are_rejected(self, client: TestClient) -> None:
        raw = json.dumps(_signed_request(_decision_card(decision_id="DUPLICATE")))
        raw = raw.replace('"vendor_id": "vendor-1"', '"vendor_id": "vendor-1", "vendor_id": "other"')
        assert (
            client.post(
                "/bundles/from-decision-card", content=raw, headers={"Content-Type": "application/json"}
            ).status_code
            == 400
        )
        raw = json.dumps(_signed_request(_decision_card(decision_id="NAN")))
        raw = raw.replace('"allowed_actions": ["use"]', '"allowed_actions": ["use"], "bad": NaN')
        assert (
            client.post(
                "/bundles/from-decision-card", content=raw, headers={"Content-Type": "application/json"}
            ).status_code
            == 400
        )
        raw = json.dumps(_signed_request(_decision_card(decision_id="LARGE-NUM")))
        raw = raw.replace('"rationale":', '"criteria": {"weight": 9007199254740993}, "rationale":')
        response = client.post(
            "/bundles/from-decision-card", content=raw, headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "invalid or ambiguous JSON body"

    def test_body_limit_is_enforced(self, client: TestClient) -> None:
        response = client.post(
            "/bundles/from-decision-card",
            content=b"x" * 131_073,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413

    def test_rejected_card_yields_deny_bundle(self, client: TestClient) -> None:
        r = client.post(
            "/bundles/from-decision-card",
            json={"card": _decision_card(decision={"status": "rejected"})},
        )
        assert r.status_code == 201
        bundle = r.json()
        assert bundle["policies"][0]["default_effect"] == "deny"

    def test_approved_with_conditions_produces_per_condition_policies(self, client: TestClient) -> None:
        r = client.post(
            "/bundles/from-decision-card",
            json=_signed_request(
                _decision_card(
                    decision={
                        "status": "approved-with-conditions",
                        "effective_until": "2026-12-31T00:00:00Z",
                    },
                    conditions=[
                        {"id": "dpa-signed", "description": "DPA on file"},
                        {"id": "bias-audit-fresh", "description": "Bias audit refreshed"},
                    ],
                )
            ),
        )
        assert r.status_code == 201
        bundle = r.json()
        assert len(bundle["policies"]) == 2

    def test_bridge_then_evaluate_round_trip(self, client: TestClient) -> None:
        r = client.post(
            "/bundles/from-decision-card",
            json=_signed_request(
                _decision_card(
                    decision_id="ROUND-TRIP-1",
                    decision={
                        "status": "approved-with-conditions",
                        "effective_until": "2026-12-31T00:00:00Z",
                    },
                    conditions=[{"id": "dpa-signed", "description": "DPA on file"}],
                )
            ),
        )
        assert r.status_code == 201
        bundle_id = r.json()["bundle_id"]

        # Without satisfaction signal -> deny
        r = client.post(
            f"/bundles/{bundle_id}/evaluate",
            json={
                "data": {},
                "subject": None,
                "action": "use",
                "resource": {"vendor_id": "vendor-1"},
            },
        )
        assert r.json()["decision"]["kind"] == "deny"

        # Evaluation caller's booleans are rejected, even when true.
        r = client.post(
            f"/bundles/{bundle_id}/evaluate",
            json={
                "data": {"conditions_satisfied": {"dpa-signed": True}},
                "subject": None,
                "action": "use",
                "resource": {"vendor_id": "vendor-1"},
            },
        )
        assert r.status_code == 400

        assertion = client.put(
            f"/bundles/{bundle_id}/conditions/dpa-signed",
            json={"satisfied": True, "valid_until": (datetime.now(UTC) + timedelta(days=1)).isoformat()},
        )
        assert assertion.status_code == 200
        assert (
            client.put(
                f"/bundles/{bundle_id}/conditions/dpa-signed",
                json={"satisfied": True, "valid_until": (datetime.now(UTC) + timedelta(days=1)).isoformat()},
                headers={"Authorization": f"Bearer {EVALUATE_TOKEN}"},
            ).status_code
            == 403
        )
        r = client.post(
            f"/bundles/{bundle_id}/evaluate",
            json={"action": "use", "resource": {"vendor_id": "vendor-1"}},
        )
        assert r.json()["decision"]["kind"] == "allow"

        stale = client.put(
            f"/bundles/{bundle_id}/conditions/dpa-signed",
            json={"satisfied": True, "valid_until": "2020-01-01T00:00:00Z"},
        )
        assert stale.status_code == 400
        long_lived = client.put(
            f"/bundles/{bundle_id}/conditions/dpa-signed",
            json={"satisfied": True, "valid_until": (datetime.now(UTC) + timedelta(days=8)).isoformat()},
        )
        assert long_lived.status_code == 400

    def test_invalid_card_400(self, client: TestClient) -> None:
        r = client.post("/bundles/from-decision-card", json={"card": {"decision_id": "x"}})
        assert r.status_code == 400

    def test_invalid_card_types_return_400(self, client: TestClient) -> None:
        r = client.post("/bundles/from-decision-card", json={"card": _decision_card(decision=None)})
        assert r.status_code == 400
        r = client.post("/bundles/from-decision-card", json={"card": _decision_card(decision={"status": []})})
        assert r.status_code == 400

    def test_invalid_effective_window_returns_400(self, client: TestClient) -> None:
        r = client.post(
            "/bundles/from-decision-card",
            json=_signed_request(
                _decision_card(decision={"status": "approved", "effective_until": "not-a-date"})
            ),
        )
        assert r.status_code == 400

    def test_validation_errors_do_not_echo_sensitive_card_values(self, client: TestClient) -> None:
        marker = "PRIVATE-BUYER-MARKER-90210"
        invalid_card = _decision_card(decision={"status": "approved", "effective_until": marker})
        response = client.post("/bundles/from-decision-card", json=_signed_request(invalid_card))
        assert response.status_code == 400
        assert marker not in response.text
        response = client.post(
            "/bundles/from-decision-card",
            json={"card": _decision_card(), "attestation": {"signature": marker}},
        )
        assert response.status_code == 422
        assert marker not in response.text

    def test_newer_card_version_returns_400(self, client: TestClient) -> None:
        r = client.post(
            "/bundles/from-decision-card",
            json={"card": _decision_card(decision_card_version="0.2", data_vault_targets=[{"id": "x"}])},
        )
        assert r.status_code == 400


class TestAuditStreamWiring:
    """The four endpoints that emit governance events must do so when
    AUDIT_STREAM_URL and AUDIT_STREAM_TOKEN are set, and stay silent when disabled."""

    def _emit_capture(self, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, list[dict[str, Any]]]:
        monkeypatch.setenv("AUDIT_STREAM_URL", "https://audit.local")
        monkeypatch.setenv("AUDIT_STREAM_TOKEN", "a" * 32)
        captured: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["Authorization"] == f"Bearer {'a' * 32}"
            captured.append(json.loads(request.content.decode("utf-8")))
            return httpx.Response(201, json={"event_id": len(captured)})

        # Spin up the lifespan first so app.state.http_client exists,
        # then swap it for one backed by MockTransport.
        c = TestClient(app, headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
        c.__enter__()
        app.state.http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return c, captured

    def test_register_emits_policy_bundle_registered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        c, captured = self._emit_capture(monkeypatch)
        try:
            r = c.post("/bundles", json=_simple_bundle("audit-reg"))
            assert r.status_code == 201
        finally:
            c.__exit__(None, None, None)
        kinds = [e["kind"] for e in captured]
        assert "policy_bundle_registered" in kinds
        evt = next(e for e in captured if e["kind"] == "policy_bundle_registered")
        assert evt["source"] == "policy-as-code-engine"
        assert evt["payload"]["bundle_id"] == "audit-reg"
        assert evt["payload"]["policy_count"] == 1
        assert "source" not in evt["payload"]

    def test_evaluate_allow_emits_request_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        c, captured = self._emit_capture(monkeypatch)
        try:
            c.post("/bundles", json=_simple_bundle("audit-ev"))
            captured.clear()  # drop registration event so we only see the evaluate event
            r = c.post(
                "/bundles/audit-ev/evaluate",
                json={
                    "subject": {"role": "admin"},
                    "data": {},
                    "resource": None,
                    "action": None,
                },
            )
            assert r.status_code == 200
        finally:
            c.__exit__(None, None, None)
        allowed = next(e for e in captured if e["kind"] == "request_allowed")
        assert "reason" not in allowed["payload"]

    def test_evaluate_deny_emits_request_denied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        c, captured = self._emit_capture(monkeypatch)
        try:
            c.post("/bundles", json=_simple_bundle("audit-deny"))
            captured.clear()
            r = c.post(
                "/bundles/audit-deny/evaluate",
                json={
                    "subject": {"role": "viewer"},
                    "data": {},
                    "resource": None,
                    "action": None,
                },
            )
            assert r.status_code == 200
        finally:
            c.__exit__(None, None, None)
        assert any(e["kind"] == "request_denied" for e in captured)

    def test_oneshot_evaluate_emits_decision(self, monkeypatch: pytest.MonkeyPatch) -> None:
        c, captured = self._emit_capture(monkeypatch)
        try:
            r = c.post(
                "/evaluate",
                json={
                    "bundle": _simple_bundle("oneshot-aud"),
                    "context": {
                        "subject": {"role": "admin"},
                        "data": {},
                        "resource": None,
                        "action": None,
                    },
                },
            )
            assert r.status_code == 200
        finally:
            c.__exit__(None, None, None)
        assert any(e["kind"] == "request_allowed" for e in captured)

    def test_from_decision_card_emits_registration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        c, captured = self._emit_capture(monkeypatch)
        try:
            r = c.post("/bundles/from-decision-card", json=_signed_request(_decision_card()))
            assert r.status_code == 201
        finally:
            c.__exit__(None, None, None)
        assert any(e["kind"] == "policy_bundle_registered" for e in captured)

    def test_condition_assertion_emits_minimal_event(self, monkeypatch: pytest.MonkeyPatch) -> None:
        c, captured = self._emit_capture(monkeypatch)
        try:
            card = _decision_card(
                decision_id="AUDIT-COND",
                decision={"status": "approved-with-conditions", "effective_until": "2026-12-31T00:00:00Z"},
                conditions=[{"id": "dpa-signed", "description": "Sensitive human-authored description"}],
            )
            response = c.post("/bundles/from-decision-card", json=_signed_request(card))
            assert response.status_code == 201
            captured.clear()
            bundle_id = response.json()["bundle_id"]
            response = c.put(
                f"/bundles/{bundle_id}/conditions/dpa-signed",
                json={"satisfied": True, "valid_until": (datetime.now(UTC) + timedelta(days=1)).isoformat()},
            )
            assert response.status_code == 200
        finally:
            c.__exit__(None, None, None)
        event = next(e for e in captured if e["kind"] == "policy_condition_asserted")
        assert event["payload"]["condition_id"] == "dpa-signed"
        assert "description" not in event["payload"]

    def test_no_emit_when_audit_stream_url_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AUDIT_STREAM_URL", raising=False)
        captured: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(json.loads(request.content.decode("utf-8")))
            return httpx.Response(201)

        c = TestClient(app, headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
        c.__enter__()
        try:
            app.state.http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            r = c.post("/bundles", json=_simple_bundle("audit-off"))
            assert r.status_code == 201
        finally:
            c.__exit__(None, None, None)
        assert captured == []
