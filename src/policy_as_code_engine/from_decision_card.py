"""
Bridge: AI Procurement Decision Card -> PolicyBundle.

The decision card spec encodes a buyer's posture toward a vendor as a `decision`
plus zero or more `conditions[]`. This module converts that human-authored
artifact into something a service can enforce automatically:

    decision.status = "rejected*"                     -> single deny-all policy
    decision.status = "approved"                      -> single allow-all policy
    decision.status = "approved-with-conditions"      -> per-condition policy +
                                                         fail-safe deny-all default
    decision.status = "withdrawn" / "expired" / etc.  -> single deny-all policy

For each condition we emit one Policy whose default_effect is `deny` and whose
single rule allows when the condition is *known to be satisfied* (signal field
`conditions_satisfied.{condition_id} == true` on the EvaluationContext).
Callers wire their own satisfaction signal into the context — e.g. result of a
verification job, a recent attestation timestamp, an external compliance check.

This is the most important hook in the package: it's what closes the loop
between the Kinetic Gain Protocol Suite (spec #11) and runtime enforcement.
"""

from __future__ import annotations

from typing import Any

from .models import (
    AlwaysMatcher,
    FieldMatcher,
    Policy,
    PolicyBundle,
    Rule,
)

_REJECT_STATUSES = {"rejected", "rejected-with-remediation", "withdrawn", "expired"}
_APPROVE_STATUSES = {"approved"}
_CONDITIONAL_STATUSES = {"approved-with-conditions"}


def policy_bundle_from_decision_card(card: dict[str, Any]) -> PolicyBundle:
    """
    Build a PolicyBundle from a v0.1 Decision Card dict (matching the upstream
    `decision-card.schema.json`).

    The returned bundle is **runtime-evaluatable** — every policy's first
    matching rule fires `allow` or `deny`. Conditions become policies whose
    satisfaction is signalled by `conditions_satisfied.{id}` on the context.
    """
    _validate_minimal_shape(card)
    decision_id = card["decision_id"]
    status = card["decision"]["status"]
    vendor = card["subject"]["vendor_name"]
    conditions = card.get("conditions") or []
    source = f"decision-card:{decision_id}"

    if status in _REJECT_STATUSES:
        return _bundle(decision_id, source, [_deny_all_policy(decision_id, status, vendor)])

    if status in _APPROVE_STATUSES:
        return _bundle(decision_id, source, [_allow_all_policy(decision_id, vendor)])

    if status in _CONDITIONAL_STATUSES:
        if not conditions:
            # The card itself should have failed validation upstream, but be
            # defensive: an approved-with-conditions card with no conditions
            # is treated as deny-all to fail safe.
            return _bundle(decision_id, source, [_deny_all_policy(decision_id, status, vendor)])
        policies = [_condition_policy(decision_id, c) for c in conditions]
        return _bundle(decision_id, source, policies)

    # Any unknown / pending status: fail safe.
    return _bundle(decision_id, source, [_deny_all_policy(decision_id, status, vendor)])


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _bundle(decision_id: str, source: str, policies: list[Policy]) -> PolicyBundle:
    return PolicyBundle(
        bundle_id=f"decision-card-{decision_id}",
        version="0.1.0",
        description=f"Generated from Decision Card {decision_id!r}.",
        source=source,
        policies=policies,
    )


def _allow_all_policy(decision_id: str, vendor: str) -> Policy:
    return Policy(
        id=f"{decision_id}__approved",
        description=f"Vendor {vendor!r} is approved; all requests permitted.",
        default_effect="allow",
        rules=[
            Rule(
                id="approved-allow",
                effect="allow",
                when=AlwaysMatcher(),
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


def _condition_policy(decision_id: str, condition: dict[str, Any]) -> Policy:
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
        description=description,
        default_effect="deny",
        rules=[
            Rule(
                id=f"{cid}-satisfied",
                effect="allow",
                when=FieldMatcher(
                    kind="eq",
                    field=f"conditions_satisfied.{cid}",
                    value=True,
                ),
                description=description,
                tags=["condition", cid],
            )
        ],
    )


def _validate_minimal_shape(card: dict[str, Any]) -> None:
    for k in ("decision_id", "decision", "subject"):
        if k not in card:
            raise ValueError(f"Decision Card is missing required key {k!r}")
    if "status" not in card["decision"]:
        raise ValueError("Decision Card.decision is missing required key 'status'")
    if "vendor_name" not in card["subject"]:
        raise ValueError("Decision Card.subject is missing required key 'vendor_name'")
