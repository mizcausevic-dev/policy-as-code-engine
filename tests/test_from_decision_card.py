"""Tests for the Decision Card -> PolicyBundle bridge."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from policy_as_code_engine.card_attestation import CardAttestation
from policy_as_code_engine.evaluator import PolicyEvaluator
from policy_as_code_engine.from_decision_card import (
    policy_bundle_from_decision_card as _policy_bundle_from_decision_card,
)
from policy_as_code_engine.models import EvaluationContext


def _minimal_card(**overrides: Any) -> dict[str, Any]:
    card: dict[str, Any] = {
        "decision_card_version": "0.1",
        "decision_id": "TEST-001",
        "issued_at": "2026-05-14T19:00:00Z",
        "buyer": {"id": "buyer-1", "name": "Springfield USD", "type": "school-district"},
        "decision": {"status": "approved", "effective_until": "2999-01-01T00:00:00Z"},
        "subject": {"vendor_name": "AcmeTutor", "vendor_id": "vendor-1"},
        "rationale": "Looks fine.",
    }
    card.update(overrides)
    if (
        isinstance(card.get("decision"), dict)
        and card["decision"].get("status") == "approved-with-conditions"
    ):
        card["decision"].setdefault("effective_until", "2999-01-01T00:00:00Z")
    return card


def policy_bundle_from_decision_card(card: dict[str, Any], *, actions: list[str] | None = None) -> Any:
    allowed_actions = actions if actions is not None else ["use"]
    decision = card.get("decision")
    status = decision.get("status") if isinstance(decision, dict) else None
    if not isinstance(status, str) or status not in {"approved", "approved-with-conditions"}:
        return _policy_bundle_from_decision_card(card, allowed_actions=allowed_actions)
    key_url = "https://buyer.example/.well-known/keys/decision-card"
    signed_hash = "sha256:" + hashlib.sha256(rfc8785.dumps(card)).hexdigest()
    fields = {
        "algorithm": "ed25519",
        "hash_profile": "jcs-rfc8785-v1",
        "signed_hash": signed_hash,
        "key_url": key_url,
        "signed_at": "2026-10-07T12:00:00Z",
    }
    private_key = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32))
    signature = private_key.sign(b"hash-attestation/v2\x00" + rfc8785.dumps(fields))
    attestation = CardAttestation(**fields, signature=base64.b64encode(signature).decode("ascii"))
    public_key = private_key.public_key().public_bytes_raw()
    return _policy_bundle_from_decision_card(
        card,
        allowed_actions=allowed_actions,
        attestation=attestation,
        trusted_key_url=key_url,
        trusted_public_key=public_key,
    )


def _context(data: dict[str, Any] | None = None) -> EvaluationContext:
    return EvaluationContext(data=data or {}, action="use", resource={"vendor_id": "vendor-1"})


class TestApprovedFlow:
    def test_unverified_library_card_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="trusted buyer attestation"):
            _policy_bundle_from_decision_card(_minimal_card(), allowed_actions=["use"])

    def test_broader_action_mapping_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="only permits"):
            policy_bundle_from_decision_card(_minimal_card(), actions=["delete"])

    def test_approved_yields_scoped_allow(self) -> None:
        card = _minimal_card()
        bundle = policy_bundle_from_decision_card(card)
        assert len(bundle.policies) == 1
        assert bundle.policies[0].default_effect == "deny"

        result = PolicyEvaluator().evaluate(bundle, _context())
        assert result.decision.kind == "allow"
        assert PolicyEvaluator().evaluate_policy(bundle.policies[0], _context()).kind == "deny"

    @pytest.mark.parametrize(
        "context",
        [
            EvaluationContext(action="delete", resource={"vendor_id": "vendor-1"}),
            EvaluationContext(action="use", resource={"vendor_id": "unrelated"}),
            EvaluationContext(data={"action": "use", "resource": {"vendor_id": "vendor-1"}}),
        ],
    )
    def test_unrelated_action_or_vendor_denied(self, context: EvaluationContext) -> None:
        bundle = policy_bundle_from_decision_card(_minimal_card())
        assert PolicyEvaluator().evaluate(bundle, context).decision.kind == "deny"


class TestRejectedFlow:
    @pytest.mark.parametrize(
        "status",
        ["rejected", "rejected-with-remediation", "withdrawn", "expired", "pending"],
    )
    def test_rejected_or_terminal_yields_deny_all(self, status: str) -> None:
        card = _minimal_card(decision={"status": status})
        bundle = policy_bundle_from_decision_card(card)
        result = PolicyEvaluator().evaluate(bundle, _context())
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
        none = _context({"conditions_satisfied": {}})
        assert evaluator.evaluate(bundle, none).decision.kind == "deny"

        # Only one satisfied -> still deny (the other policy denies).
        partial = _context({"conditions_satisfied": {"dpa-signed": True}})
        assert evaluator.evaluate(bundle, partial).decision.kind == "deny"

        # Both satisfied -> allow.
        full = EvaluationContext(
            action="use",
            resource={"vendor_id": "vendor-1"},
            data={
                "conditions_satisfied": {
                    "dpa-signed": True,
                    "bias-audit-fresh": True,
                }
            },
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
        assert PolicyEvaluator().evaluate(bundle, _context()).decision.kind == "deny"

    def test_condition_without_id_is_rejected(self) -> None:
        card = _minimal_card(
            decision={"status": "approved-with-conditions"},
            conditions=[{"description": "no id here"}],
        )
        with pytest.raises(ValueError, match="condition must carry"):
            policy_bundle_from_decision_card(card)

    def test_dotted_condition_id_is_literal_key(self) -> None:
        card = _minimal_card(
            decision={"status": "approved-with-conditions"},
            conditions=[{"id": "risk.review", "description": "Review completed"}],
        )
        bundle = policy_bundle_from_decision_card(card)
        result = PolicyEvaluator().evaluate(
            bundle,
            _context({"conditions_satisfied": {"risk.review": True}}),
        )
        assert result.decision.kind == "allow"

    def test_numeric_truthy_signal_is_denied(self) -> None:
        card = _minimal_card(
            decision={"status": "approved-with-conditions"},
            conditions=[{"id": "dpa-signed", "description": "DPA on file"}],
        )
        bundle = policy_bundle_from_decision_card(card)
        result = PolicyEvaluator().evaluate(
            bundle,
            _context({"conditions_satisfied": {"dpa-signed": 1}}),
        )
        assert result.decision.kind == "deny"

    def test_duplicate_condition_id_is_rejected(self) -> None:
        card = _minimal_card(
            decision={"status": "approved-with-conditions"},
            conditions=[
                {"id": "dpa-signed", "description": "First"},
                {"id": "dpa-signed", "description": "Second"},
            ],
        )
        with pytest.raises(ValueError, match="duplicate condition id"):
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

    @pytest.mark.parametrize(
        "overrides",
        [
            {"decision": None},
            {"decision": {"status": []}},
            {"subject": None},
            {"conditions": {"id": "x"}},
        ],
    )
    def test_wrong_types_are_rejected(self, overrides: dict[str, Any]) -> None:
        with pytest.raises(ValueError):
            policy_bundle_from_decision_card(_minimal_card(**overrides))

    def test_approved_card_with_conditions_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="approved cards with conditions"):
            policy_bundle_from_decision_card(
                _minimal_card(conditions=[{"id": "dpa-signed", "description": "DPA on file"}])
            )

    @pytest.mark.parametrize("version", [None, "0.2", "0.3"])
    def test_unsupported_card_version_is_rejected(self, version: str | None) -> None:
        with pytest.raises(ValueError, match=r"only Decision Card version 0\.1"):
            policy_bundle_from_decision_card(_minimal_card(decision_card_version=version))

    def test_unknown_governance_field_cannot_be_silently_ignored(self) -> None:
        with pytest.raises(ValueError, match="unsupported Decision Card fields"):
            policy_bundle_from_decision_card(_minimal_card(data_vault_targets=[{"id": "x"}]))

    def test_unknown_nested_governance_field_is_rejected(self) -> None:
        card = _minimal_card()
        card["subject"]["retention_envelope"] = {"days": 30}
        with pytest.raises(ValueError, match=r"unsupported Decision Card\.subject fields"):
            policy_bundle_from_decision_card(card)

    def test_approved_card_with_withdrawal_or_terminal_history_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="withdrawal"):
            policy_bundle_from_decision_card(_minimal_card(withdrawal={"at": "2026-10-07T12:00:00Z"}))
        with pytest.raises(ValueError, match="conflicting terminal event"):
            policy_bundle_from_decision_card(
                _minimal_card(history=[{"event": "withdrawn", "at": "2026-10-07T12:00:00Z"}])
            )

    def test_past_effective_until_denies_at_evaluation(self) -> None:
        card = _minimal_card(decision={"status": "approved", "effective_until": "2020-01-01T00:00:00Z"})
        bundle = policy_bundle_from_decision_card(card)
        assert PolicyEvaluator().evaluate(bundle, EvaluationContext()).decision.kind == "deny"

    def test_future_effective_from_denies_at_evaluation(self) -> None:
        card = _minimal_card(
            decision={
                "status": "approved",
                "effective_from": "2999-01-01T00:00:00Z",
                "effective_until": "2999-12-31T00:00:00Z",
            }
        )
        bundle = policy_bundle_from_decision_card(card)
        assert PolicyEvaluator().evaluate(bundle, EvaluationContext()).decision.kind == "deny"

    def test_offset_free_effective_timestamp_is_rejected(self) -> None:
        card = _minimal_card(decision={"status": "approved", "effective_until": "2999-01-01T00:00:00"})
        with pytest.raises(ValueError, match="timezone"):
            policy_bundle_from_decision_card(card)
