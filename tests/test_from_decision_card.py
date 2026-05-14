"""Tests for the Decision Card -> PolicyBundle bridge."""

from __future__ import annotations

from typing import Any

import pytest

from policy_as_code_engine.evaluator import PolicyEvaluator
from policy_as_code_engine.from_decision_card import policy_bundle_from_decision_card
from policy_as_code_engine.models import EvaluationContext


def _minimal_card(**overrides: Any) -> dict[str, Any]:
    card: dict[str, Any] = {
        "decision_card_version": "0.1",
        "decision_id": "TEST-001",
        "issued_at": "2026-05-14T19:00:00Z",
        "buyer": {"name": "Springfield USD", "type": "school-district"},
        "decision": {"status": "approved"},
        "subject": {"vendor_name": "AcmeTutor"},
        "rationale": "Looks fine.",
    }
    card.update(overrides)
    return card


class TestApprovedFlow:
    def test_approved_yields_allow_all(self) -> None:
        card = _minimal_card()
        bundle = policy_bundle_from_decision_card(card)
        assert len(bundle.policies) == 1
        assert bundle.policies[0].default_effect == "allow"

        result = PolicyEvaluator().evaluate(bundle, EvaluationContext())
        assert result.decision.kind == "allow"


class TestRejectedFlow:
    @pytest.mark.parametrize(
        "status",
        ["rejected", "rejected-with-remediation", "withdrawn", "expired", "pending"],
    )
    def test_rejected_or_terminal_yields_deny_all(self, status: str) -> None:
        card = _minimal_card(decision={"status": status})
        bundle = policy_bundle_from_decision_card(card)
        result = PolicyEvaluator().evaluate(bundle, EvaluationContext())
        assert result.decision.kind == "deny"


class TestApprovedWithConditions:
    def test_each_condition_becomes_its_own_policy(self) -> None:
        card = _minimal_card(
            decision={"status": "approved-with-conditions"},
            conditions=[
                {"id": "dpa-signed", "description": "DPA must be on file"},
                {"id": "bias-audit-fresh", "description": "Bias audit refreshed in last 12mo"},
            ],
        )
        bundle = policy_bundle_from_decision_card(card)
        assert len(bundle.policies) == 2
        ids = {p.id for p in bundle.policies}
        assert ids == {"TEST-001__condition__dpa-signed", "TEST-001__condition__bias-audit-fresh"}

    def test_allow_only_when_all_conditions_satisfied(self) -> None:
        card = _minimal_card(
            decision={"status": "approved-with-conditions"},
            conditions=[
                {"id": "dpa-signed", "description": "DPA must be on file"},
                {"id": "bias-audit-fresh", "description": "Bias audit refreshed"},
            ],
        )
        bundle = policy_bundle_from_decision_card(card)
        evaluator = PolicyEvaluator()

        # None satisfied -> deny (combined result follows deny-trumps rule).
        none = EvaluationContext(data={"conditions_satisfied": {}})
        assert evaluator.evaluate(bundle, none).decision.kind == "deny"

        # Only one satisfied -> still deny (the other policy denies).
        partial = EvaluationContext(data={"conditions_satisfied": {"dpa-signed": True}})
        assert evaluator.evaluate(bundle, partial).decision.kind == "deny"

        # Both satisfied -> allow.
        full = EvaluationContext(
            data={
                "conditions_satisfied": {
                    "dpa-signed": True,
                    "bias-audit-fresh": True,
                }
            }
        )
        assert evaluator.evaluate(bundle, full).decision.kind == "allow"

    def test_approved_with_conditions_but_empty_list_fails_safe(self) -> None:
        # Card itself would fail upstream validation, but defensive handling
        # is part of the contract.
        card = _minimal_card(
            decision={"status": "approved-with-conditions"},
            conditions=[],
        )
        bundle = policy_bundle_from_decision_card(card)
        assert PolicyEvaluator().evaluate(bundle, EvaluationContext()).decision.kind == "deny"

    def test_condition_without_id_is_rejected(self) -> None:
        card = _minimal_card(
            decision={"status": "approved-with-conditions"},
            conditions=[{"description": "no id here"}],
        )
        with pytest.raises(ValueError, match="condition must carry"):
            policy_bundle_from_decision_card(card)


class TestShapeValidation:
    def test_missing_decision_raises(self) -> None:
        with pytest.raises(ValueError, match="decision"):
            policy_bundle_from_decision_card({"decision_id": "x", "subject": {"vendor_name": "v"}})

    def test_missing_status_raises(self) -> None:
        with pytest.raises(ValueError, match="status"):
            policy_bundle_from_decision_card(
                {"decision_id": "x", "decision": {}, "subject": {"vendor_name": "v"}}
            )

    def test_missing_vendor_raises(self) -> None:
        with pytest.raises(ValueError, match="vendor_name"):
            policy_bundle_from_decision_card(
                {"decision_id": "x", "decision": {"status": "approved"}, "subject": {}}
            )
