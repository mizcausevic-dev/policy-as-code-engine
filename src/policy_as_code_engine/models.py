"""
Pydantic v2 models for policies, rules, matchers, and evaluation results.

A `PolicyBundle` is the top-level object — a named, versioned collection of
`Policy` objects. Each `Policy` is a list of `Rule` objects, evaluated in
declared order; the first match wins (deny rules trump allow rules at the
PolicyBundle level — see `EvaluationResult.combine`).

A `Rule` has:
    - id          stable identifier for telemetry
    - effect      "allow" | "deny"
    - description optional human-readable note
    - when        a `Matcher` — the predicate over the EvaluationContext

A `Matcher` is one of the supported operators. Matchers are recursive: `all_of`,
`any_of`, and `not_` wrap child matchers, so the result is a small DSL that
covers ~95% of real-world request gates without having to ship a parser.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


DecisionKind = Literal["allow", "deny", "not_applicable"]
Effect = Literal["allow", "deny"]


# ---------------------------------------------------------------------------
# Matchers — the DSL
# ---------------------------------------------------------------------------


class FieldMatcher(StrictModel):
    """Compare a JSON-pointer-ish dotted path against a literal value."""

    kind: Literal[
        "eq",
        "ne",
        "gt",
        "gte",
        "lt",
        "lte",
        "in",
        "not_in",
        "contains",
        "missing",
        "exists",
        "regex",
        "starts_with",
        "ends_with",
    ]
    field: str = Field(..., min_length=1)
    value: Any = None

    @model_validator(mode="after")
    def _check_value_required(self) -> FieldMatcher:
        if self.kind in ("exists", "missing"):
            return self
        if self.value is None:
            raise ValueError(f"matcher {self.kind!r} requires a `value`")
        if self.kind in ("in", "not_in") and not isinstance(self.value, list):
            raise ValueError(f"matcher {self.kind!r} requires `value` to be a list")
        return self


class AllOfMatcher(StrictModel):
    kind: Literal["all_of"] = "all_of"
    matchers: list[Matcher] = Field(..., min_length=1)


class AnyOfMatcher(StrictModel):
    kind: Literal["any_of"] = "any_of"
    matchers: list[Matcher] = Field(..., min_length=1)


class NotMatcher(StrictModel):
    kind: Literal["not"] = "not"
    matcher: Matcher


class AlwaysMatcher(StrictModel):
    """Useful as a catch-all final rule (effectively the default)."""

    kind: Literal["always"] = "always"


Matcher = FieldMatcher | AllOfMatcher | AnyOfMatcher | NotMatcher | AlwaysMatcher


# Pydantic v2 forward-ref resolution for the recursive aliases.
AllOfMatcher.model_rebuild()
AnyOfMatcher.model_rebuild()
NotMatcher.model_rebuild()


# ---------------------------------------------------------------------------
# Rules / policies / bundles
# ---------------------------------------------------------------------------


class Rule(StrictModel):
    id: str = Field(..., min_length=1)
    effect: Effect
    when: Matcher
    description: str | None = None
    tags: list[str] | None = None


class Policy(StrictModel):
    """A named ordered list of rules. First match wins."""

    id: str = Field(..., min_length=1)
    description: str | None = None
    default_effect: Effect = "deny"
    rules: list[Rule] = Field(..., min_length=1)


class PolicyBundle(StrictModel):
    """The unit a service loads at startup. Versioned."""

    bundle_id: str = Field(..., min_length=1)
    version: str = "0.1.0"
    description: str | None = None
    source: str | None = Field(
        default=None,
        description="Where the bundle came from (a Decision Card id, URL, file path).",
    )
    policies: list[Policy] = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


class EvaluationContext(StrictModel):
    """
    The thing rules are evaluated against. Free-form `data` so callers can pour
    in whatever shape the rules expect (subject, action, resource, claims, ...).
    """

    data: dict[str, Any] = Field(default_factory=dict)
    subject: dict[str, Any] | None = None
    action: str | None = None
    resource: dict[str, Any] | None = None

    def lookup(self, path: str) -> Any:
        """
        Dotted-path lookup over the merged context. Returns the sentinel
        `_MISSING` when any segment doesn't exist, so `exists` / `missing`
        matchers behave correctly.
        """
        merged: dict[str, Any] = {**self.data}
        if self.subject is not None:
            merged["subject"] = self.subject
        if self.action is not None:
            merged["action"] = self.action
        if self.resource is not None:
            merged["resource"] = self.resource

        cur: Any = merged
        for segment in path.split("."):
            if isinstance(cur, dict) and segment in cur:
                cur = cur[segment]
            elif isinstance(cur, list):
                try:
                    cur = cur[int(segment)]
                except (ValueError, IndexError):
                    return _MISSING
            else:
                return _MISSING
        return cur


_MISSING: Any = object()


class Decision(StrictModel):
    kind: DecisionKind
    matched_policy_id: str | None = None
    matched_rule_id: str | None = None
    reason: str | None = None


class EvaluationResult(StrictModel):
    """
    Bundle-wide result. Per-policy decisions are kept in `policy_decisions` so
    operators can see *why* the final outcome happened. Combining rule:

        - If ANY policy returns `deny`, the bundle returns `deny`.
        - Else if ANY policy returns `allow`, the bundle returns `allow`.
        - Else `not_applicable`.
    """

    bundle_id: str
    decision: Decision
    policy_decisions: list[Decision]

    @classmethod
    def combine(cls, bundle_id: str, policy_decisions: list[Decision]) -> EvaluationResult:
        deny = next((d for d in policy_decisions if d.kind == "deny"), None)
        if deny is not None:
            return cls(bundle_id=bundle_id, decision=deny, policy_decisions=policy_decisions)
        allow = next((d for d in policy_decisions if d.kind == "allow"), None)
        if allow is not None:
            return cls(bundle_id=bundle_id, decision=allow, policy_decisions=policy_decisions)
        return cls(
            bundle_id=bundle_id,
            decision=Decision(kind="not_applicable", reason="no policy applied"),
            policy_decisions=policy_decisions,
        )
