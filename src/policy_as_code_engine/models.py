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

import regex
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


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
    field: str = Field(..., min_length=1, max_length=256)
    value: Any = None

    @model_validator(mode="after")
    def _check_value_required(self) -> FieldMatcher:
        if self.kind in ("exists", "missing"):
            return self
        if self.value is None:
            raise ValueError(f"matcher {self.kind!r} requires a `value`")
        if self.kind in ("in", "not_in") and not isinstance(self.value, list):
            raise ValueError(f"matcher {self.kind!r} requires `value` to be a list")
        if self.kind == "regex":
            if not isinstance(self.value, str):
                raise ValueError("regex matcher requires a string pattern")
            if len(self.value) > 256:
                raise ValueError("regex matcher pattern exceeds 256 characters")
            try:
                regex.compile(self.value)
            except regex.error as err:
                raise ValueError(f"invalid regex matcher pattern: {err}") from err
        return self


class AllOfMatcher(StrictModel):
    kind: Literal["all_of"] = "all_of"
    matchers: list[Matcher] = Field(..., min_length=1, max_length=32)


class AnyOfMatcher(StrictModel):
    kind: Literal["any_of"] = "any_of"
    matchers: list[Matcher] = Field(..., min_length=1, max_length=32)


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
    id: str = Field(..., min_length=1, max_length=128)
    effect: Effect
    when: Matcher
    description: str | None = None
    tags: list[str] | None = Field(default=None, max_length=32)


class Policy(StrictModel):
    """A named ordered list of rules. First match wins."""

    id: str = Field(..., min_length=1, max_length=128)
    card_derived: bool = False
    description: str | None = None
    default_effect: Effect = "deny"
    rules: list[Rule] = Field(..., min_length=1, max_length=64)

    @model_validator(mode="after")
    def _check_matcher_complexity(self) -> Policy:
        for rule in self.rules:
            stack: list[tuple[Matcher, int]] = [(rule.when, 1)]
            nodes = 0
            while stack:
                matcher, depth = stack.pop()
                nodes += 1
                if depth > 16 or nodes > 256:
                    raise ValueError("matcher tree exceeds depth or node limit")
                if isinstance(matcher, (AllOfMatcher, AnyOfMatcher)):
                    stack.extend((child, depth + 1) for child in matcher.matchers)
                elif isinstance(matcher, NotMatcher):
                    stack.append((matcher.matcher, depth + 1))
        return self


class DecisionCardScope(StrictModel):
    """Operator-approved runtime scope, separate from the signed buyer card."""

    vendor_id: str = Field(..., min_length=1, max_length=512)
    allowed_actions: list[str] = Field(..., min_length=1, max_length=16)
    condition_ids: list[str] = Field(default_factory=list, max_length=32)


class PolicyBundle(StrictModel):
    """The unit a service loads at startup. Versioned."""

    bundle_id: str = Field(..., min_length=1, max_length=128)
    version: str = "0.1.0"
    description: str | None = None
    source: str | None = Field(
        default=None,
        description="Where the bundle came from (a Decision Card id, URL, file path).",
    )
    effective_from: AwareDatetime | None = None
    effective_until: AwareDatetime | None = None
    card_scope: DecisionCardScope | None = None
    policies: list[Policy] = Field(..., min_length=1, max_length=32)

    @model_validator(mode="after")
    def _check_effective_window(self) -> PolicyBundle:
        if (
            self.effective_from is not None
            and self.effective_until is not None
            and self.effective_until <= self.effective_from
        ):
            raise ValueError("effective_until must be after effective_from")
        return self


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
        for segment in _path_segments(path):
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


def _path_segments(path: str) -> list[str]:
    """Split dotted paths, allowing literal dots and backslashes in a key."""
    segments: list[str] = []
    current: list[str] = []
    escaped = False
    for char in path:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ".":
            segments.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    segments.append("".join(current))
    return segments


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
