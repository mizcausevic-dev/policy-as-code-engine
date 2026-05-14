"""End-to-end tests for the FastAPI app."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from policy_as_code_engine.app import app


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as c:
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
        "decision_id": "TEST-API-001",
        "issued_at": "2026-05-14T19:00:00Z",
        "buyer": {"name": "Springfield USD", "type": "school-district"},
        "decision": {"status": "approved"},
        "subject": {"vendor_name": "AcmeTutor"},
        "rationale": "Looks fine.",
    }
    card.update(overrides)
    return card


class TestMeta:
    def test_root(self, client: TestClient) -> None:
        r = client.get("/")
        assert r.status_code == 200
        assert r.json()["name"] == "policy-as-code-engine"

    def test_healthz(self, client: TestClient) -> None:
        assert client.get("/healthz").json() == {"status": "ok"}


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
    def test_approved_card_yields_allow_bundle(self, client: TestClient) -> None:
        r = client.post("/bundles/from-decision-card", json=_decision_card())
        assert r.status_code == 201
        bundle = r.json()
        assert bundle["bundle_id"].startswith("decision-card-")
        assert bundle["policies"][0]["default_effect"] == "allow"

    def test_rejected_card_yields_deny_bundle(self, client: TestClient) -> None:
        r = client.post(
            "/bundles/from-decision-card",
            json=_decision_card(decision={"status": "rejected"}),
        )
        assert r.status_code == 201
        bundle = r.json()
        assert bundle["policies"][0]["default_effect"] == "deny"

    def test_approved_with_conditions_produces_per_condition_policies(self, client: TestClient) -> None:
        r = client.post(
            "/bundles/from-decision-card",
            json=_decision_card(
                decision={"status": "approved-with-conditions"},
                conditions=[
                    {"id": "dpa-signed", "description": "DPA on file"},
                    {"id": "bias-audit-fresh", "description": "Bias audit refreshed"},
                ],
            ),
        )
        assert r.status_code == 201
        bundle = r.json()
        assert len(bundle["policies"]) == 2

    def test_bridge_then_evaluate_round_trip(self, client: TestClient) -> None:
        r = client.post(
            "/bundles/from-decision-card",
            json=_decision_card(
                decision_id="ROUND-TRIP-1",
                decision={"status": "approved-with-conditions"},
                conditions=[{"id": "dpa-signed", "description": "DPA on file"}],
            ),
        )
        assert r.status_code == 201
        bundle_id = r.json()["bundle_id"]

        # Without satisfaction signal -> deny
        r = client.post(
            f"/bundles/{bundle_id}/evaluate",
            json={
                "data": {"conditions_satisfied": {}},
                "subject": None,
                "action": None,
                "resource": None,
            },
        )
        assert r.json()["decision"]["kind"] == "deny"

        # With satisfaction signal -> allow
        r = client.post(
            f"/bundles/{bundle_id}/evaluate",
            json={
                "data": {"conditions_satisfied": {"dpa-signed": True}},
                "subject": None,
                "action": None,
                "resource": None,
            },
        )
        assert r.json()["decision"]["kind"] == "allow"

    def test_invalid_card_400(self, client: TestClient) -> None:
        r = client.post("/bundles/from-decision-card", json={"decision_id": "x"})
        assert r.status_code == 400
