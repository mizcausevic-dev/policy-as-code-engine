"""
Bridge: AI Procurement Decision Card -> PolicyBundle.

The decision card spec encodes a buyer's posture toward a vendor as a `decision`
plus zero or more `conditions[]`. This module converts that human-authored
artifact into something a service can enforce automatically:

    decision.status = "rejected*"                     -> single deny-all policy
    decision.status = "approved"                      -> scoped allow policy
    decision.status = "approved-with-conditions"      -> per-condition policy +
                                                         fail-safe deny-all default
    decision.status = "withdrawn" / "expired" / etc.  -> single deny-all policy

For each condition we emit one Policy whose default_effect is `deny` and whose
single rule allows when the condition is *known to be satisfied* (signal field
`conditions_satisfied.{condition_id} == true` on the EvaluationContext).
The library caller must authenticate the final card and derive condition
signals from trusted checks. The HTTP adapter requires a buyer-key attestation
and keeps condition assertions behind its admin credential.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .card_attestation import CardAttestation, verify_card_attestation
from .models import (
    AllOfMatcher,
    AlwaysMatcher,
    DecisionCardScope,
    FieldMatcher,
    Policy,
    PolicyBundle,
    Rule,
)

_REJECT_STATUSES = {"rejected", "rejected-with-remediation", "withdrawn", "expired"}
_APPROVE_STATUSES = {"approved"}
_CONDITIONAL_STATUSES = {"approved-with-conditions"}
_CARD_V01_FIELDS = {
    "decision_card_version",
    "decision_id",
    "issued_at",
    "buyer",
    "decision_maker",
    "decision",
    "subject",
    "criteria",
    "conditions",
    "rationale",
    "history",
    "appeals",
    "publication",
    "signatures",
    "withdrawal",
}
_DECISION_V01_FIELDS = {"status", "effective_from", "effective_until", "scope"}
_BUYER_V01_FIELDS = {"name", "type", "category", "jurisdiction", "url", "contact", "id"}
_SUBJECT_V01_FIELDS = {"vendor_name", "product_name", "vendor_id", "documents_reviewed"}
_CONDITION_V01_FIELDS = {"id", "description", "enforcement", "violation_response", "verification_uri"}
_ALLOWED_APPROVAL_HISTORY_EVENTS = {
    "review_started",
    "documents_collected",
    "review_completed",
    "approved",
    "approved-with-conditions",
    "pending",
}


def policy_bundle_from_decision_card(
    card: dict[str, Any],
    *,
    allowed_actions: list[str] | None = None,
    attestation: CardAttestation | None = None,
    trusted_key_url: str | None = None,
    trusted_public_key: bytes | None = None,
) -> PolicyBundle:
    """
    Build a PolicyBundle from a v0.1 Decision Card dict (matching the upstream
    `decision-card.schema.json`).

    The returned bundle is **runtime-evaluatable** — every policy's first
    matching rule fires `allow` or `deny`. Conditions become policies whose
    satisfaction is signalled by `conditions_satisfied.{id}` on the context.
    Positive cards require a v2 signature and an independently pinned buyer
    public key. The library still trusts its caller to map buyer.id to that key
    and derive condition signals. The HTTP API owns that mapping and keeps
    condition signals under its admin credential.
    """
    _validate_minimal_shape(card)
    decision_id = card["decision_id"]
    decision = card["decision"]
    status = decision["status"]
    vendor = card["subject"]["vendor_name"]
    conditions = card.get("conditions") or []
    source = f"decision-card:{decision_id}"
    effective_from = decision.get("effective_from")
    effective_until = decision.get("effective_until")

    card_scope: DecisionCardScope | None = None
    if status in _APPROVE_STATUSES | _CONDITIONAL_STATUSES:
        issued_at = card.get("issued_at")
        if not isinstance(issued_at, str):
            raise ValueError("approved Decision Cards require issued_at")
        try:
            parsed_issued_at = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
        except ValueError as err:
            raise ValueError("approved Decision Cards require timezone-qualified issued_at") from err
        if parsed_issued_at.tzinfo is None:
            raise ValueError("approved Decision Cards require timezone-qualified issued_at")
        if not isinstance(card.get("rationale"), str) or not card["rationale"].strip():
            raise ValueError("approved Decision Cards require a rationale")
        if card.get("withdrawal") is not None:
            raise ValueError("an approved Decision Card cannot contain withdrawal data")
        history = card.get("history") or []
        if not isinstance(history, list) or any(
            not isinstance(event, dict)
            or not isinstance(event.get("event"), str)
            or event["event"] not in _ALLOWED_APPROVAL_HISTORY_EVENTS
            for event in history
        ):
            raise ValueError("approved Decision Card history has a conflicting terminal event")
        buyer = card.get("buyer")
        if not isinstance(buyer, dict) or not isinstance(buyer.get("id"), str) or not buyer["id"].strip():
            raise ValueError("approved Decision Cards require buyer.id for authority binding")
        if not isinstance(buyer.get("name"), str) or not buyer["name"].strip():
            raise ValueError("approved Decision Cards require buyer.name")
        if not isinstance(buyer.get("type"), str) or not buyer["type"].strip():
            raise ValueError("approved Decision Cards require buyer.type")
        if attestation is None or trusted_key_url is None or trusted_public_key is None:
            raise ValueError("approved Decision Cards require a trusted buyer attestation")
        verify_card_attestation(
            card,
            attestation,
            trusted_key_url=trusted_key_url,
            trusted_public_key=trusted_public_key,
        )
        signed_at = datetime.fromisoformat(attestation.signed_at.replace("Z", "+00:00"))
        if signed_at < parsed_issued_at:
            raise ValueError("Decision Card cannot be attested before issued_at")
        vendor_id = card["subject"].get("vendor_id")
        if not isinstance(vendor_id, str) or not vendor_id.strip():
            raise ValueError("approved Decision Cards require subject.vendor_id for resource binding")
        if effective_until is None:
            raise ValueError("approved Decision Cards require decision.effective_until")
        if allowed_actions != ["use"]:
            raise ValueError("Decision Card conversion only permits allowed_actions=['use']")
        card_scope = DecisionCardScope(
            vendor_id=vendor_id,
            allowed_actions=allowed_actions,
            condition_ids=[c["id"] for c in conditions],
        )

    if status in _REJECT_STATUSES:
        return _bundle(
            decision_id,
            source,
            [_deny_all_policy(decision_id, status, vendor)],
            effective_from,
            effective_until,
        )

    if status in _APPROVE_STATUSES:
        assert card_scope is not None
        if conditions:
            raise ValueError("approved cards with conditions must use approved-with-conditions")
        return _bundle(
            decision_id,
            source,
            [_approved_policy(decision_id, vendor, card_scope)],
            effective_from,
            effective_until,
            card_scope,
        )

    if status in _CONDITIONAL_STATUSES:
        assert card_scope is not None
        if not conditions:
            # The card itself should have failed validation upstream, but be
            # defensive: an approved-with-conditions card with no conditions
            # is treated as deny-all to fail safe.
            return _bundle(
                decision_id,
                source,
                [_deny_all_policy(decision_id, status, vendor)],
                effective_from,
                effective_until,
            )
        policies = [_condition_policy(decision_id, c, card_scope) for c in conditions]
        return _bundle(decision_id, source, policies, effective_from, effective_until, card_scope)

    # Any unknown / pending status: fail safe.
    return _bundle(
        decision_id, source, [_deny_all_policy(decision_id, status, vendor)], effective_from, effective_until
    )


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _bundle(
    decision_id: str,
    source: str,
    policies: list[Policy],
    effective_from: str | None,
    effective_until: str | None,
    card_scope: DecisionCardScope | None = None,
) -> PolicyBundle:
    return PolicyBundle.model_validate(
        {
            "bundle_id": f"decision-card-{decision_id}",
            "version": "0.1.0",
            "description": f"Generated from Decision Card {decision_id!r}.",
            "source": source,
            "effective_from": effective_from,
            "effective_until": effective_until,
            "card_scope": card_scope,
            "policies": policies,
        }
    )


def _scope_matcher(scope: DecisionCardScope) -> AllOfMatcher:
    return AllOfMatcher(
        matchers=[
            FieldMatcher(kind="eq", field="resource.vendor_id", value=scope.vendor_id),
            FieldMatcher(kind="in", field="action", value=scope.allowed_actions),
        ]
    )


def _approved_policy(decision_id: str, vendor: str, scope: DecisionCardScope) -> Policy:
    return Policy(
        id=f"{decision_id}__approved",
        card_derived=True,
        description=f"Vendor {vendor!r} is approved within the operator's runtime scope.",
        default_effect="deny",
        rules=[
            Rule(
                id="approved-allow",
                effect="allow",
                when=_scope_matcher(scope),
                description=f"Decision Card {decision_id!r} approved vendor {vendor!r}.",
                tags=["approved"],
            )
        ],
    )


def _deny_all_policy(decision_id: str, status: str, vendor: str) -> Policy:
    return Policy(
        id=f"{decision_id}__{status}",
        description=f"Vendor {vendor!r} is {status}; all requests denied.",
        default_effect="deny",
        rules=[
            Rule(
                id=f"{status}-deny",
                effect="deny",
                when=AlwaysMatcher(),
                description=f"Decision Card {decision_id!r} status={status!r} for vendor {vendor!r}.",
                tags=[status],
            )
        ],
    )


def _condition_policy(decision_id: str, condition: dict[str, Any], scope: DecisionCardScope) -> Policy:
    """
    Translate a single condition into a single policy:
      - rule 1: ALLOW when conditions_satisfied.{id} is true
      - default: DENY (fail-safe)
    """
    cid = condition.get("id")
    if not cid or not isinstance(cid, str):
        raise ValueError("each condition must carry a non-empty `id`")
    description = condition.get("description") or f"Condition {cid!r}"
    return Policy(
        id=f"{decision_id}__condition__{cid}",
        card_derived=True,
        description=description,
        default_effect="deny",
        rules=[
            Rule(
                id=f"{cid}-satisfied",
                effect="allow",
                when=AllOfMatcher(
                    matchers=[
                        _scope_matcher(scope),
                        FieldMatcher(
                            kind="eq",
                            field="conditions_satisfied." + _escape_path_segment(cid),
                            value=True,
                        ),
                    ],
                ),
                description=description,
                tags=["condition", cid],
            )
        ],
    )


def _escape_path_segment(segment: str) -> str:
    return segment.replace("\\", "\\\\").replace(".", "\\.")


def _validate_minimal_shape(card: dict[str, Any]) -> None:
    for k in ("decision_id", "decision", "subject"):
        if k not in card:
            raise ValueError(f"Decision Card is missing required key {k!r}")
    if not isinstance(card["decision_id"], str) or not card["decision_id"].strip():
        raise ValueError("Decision Card.decision_id must be a non-empty string")
    decision = card["decision"]
    if not isinstance(decision, dict):
        raise ValueError("Decision Card.decision must be an object")
    if "status" not in decision:
        raise ValueError("Decision Card.decision is missing required key 'status'")
    if not isinstance(decision["status"], str):
        raise ValueError("Decision Card.decision.status must be a string")
    subject = card["subject"]
    if not isinstance(subject, dict):
        raise ValueError("Decision Card.subject must be an object")
    if "vendor_name" not in subject:
        raise ValueError("Decision Card.subject is missing required key 'vendor_name'")
    if not isinstance(subject["vendor_name"], str) or not subject["vendor_name"].strip():
        raise ValueError("Decision Card.subject.vendor_name must be a non-empty string")
    if card.get("decision_card_version") != "0.1":
        raise ValueError("only Decision Card version 0.1 is supported")
    unknown_fields = set(card) - _CARD_V01_FIELDS
    if unknown_fields:
        raise ValueError(f"unsupported Decision Card fields: {sorted(unknown_fields)}")
    unknown_decision_fields = set(decision) - _DECISION_V01_FIELDS
    if unknown_decision_fields:
        raise ValueError(f"unsupported Decision Card.decision fields: {sorted(unknown_decision_fields)}")
    buyer = card.get("buyer")
    if buyer is not None:
        if not isinstance(buyer, dict):
            raise ValueError("Decision Card.buyer must be an object")
        unknown_buyer_fields = set(buyer) - _BUYER_V01_FIELDS
        if unknown_buyer_fields:
            raise ValueError(f"unsupported Decision Card.buyer fields: {sorted(unknown_buyer_fields)}")
    unknown_subject_fields = set(subject) - _SUBJECT_V01_FIELDS
    if unknown_subject_fields:
        raise ValueError(f"unsupported Decision Card.subject fields: {sorted(unknown_subject_fields)}")
    conditions = card.get("conditions")
    if conditions is None:
        return
    if not isinstance(conditions, list):
        raise ValueError("Decision Card.conditions must be a list")
    seen: set[str] = set()
    for condition in conditions:
        if not isinstance(condition, dict):
            raise ValueError("each condition must be an object")
        unknown_condition_fields = set(condition) - _CONDITION_V01_FIELDS
        if unknown_condition_fields:
            raise ValueError(
                f"unsupported Decision Card.condition fields: {sorted(unknown_condition_fields)}"
            )
        cid = condition.get("id")
        if not isinstance(cid, str) or not cid.strip():
            raise ValueError("each condition must carry a non-empty `id`")
        if cid in seen:
            raise ValueError(f"duplicate condition id: {cid!r}")
        seen.add(cid)
