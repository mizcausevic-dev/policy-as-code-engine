"""
Policy evaluator. The hot path.

`PolicyEvaluator.evaluate(bundle, context)` walks every policy in the bundle,
finds the first rule whose `when` matches, and emits a `Decision` for that
policy. The bundle-level result then combines those per-policy decisions
(deny > allow > not_applicable).

The matcher logic lives in `_match()` and uses `EvaluationContext.lookup()`
for dotted-path traversal. Special-case: the `_MISSING` sentinel from
`models.lookup` is recognised so `exists` / `missing` matchers work correctly
without requiring the rule author to know about the sentinel.
"""

from __future__ import annotations

import re
from typing import Any

from .models import (
    _MISSING,
    AllOfMatcher,
    AlwaysMatcher,
    AnyOfMatcher,
    Decision,
    EvaluationContext,
    EvaluationResult,
    FieldMatcher,
    Matcher,
    NotMatcher,
    Policy,
    PolicyBundle,
    Rule,
)


class PolicyEvaluator:
    """Stateless evaluator. Cheap to construct; reuse one per process."""

    __slots__ = ("_regex_cache",)

    def __init__(self) -> None:
        # Compiled-regex cache so repeated evaluations don't pay the parse cost.
        self._regex_cache: dict[str, re.Pattern[str]] = {}

    def evaluate(self, bundle: PolicyBundle, context: EvaluationContext) -> EvaluationResult:
        policy_decisions: list[Decision] = []
        for policy in bundle.policies:
            policy_decisions.append(self._evaluate_policy(policy, context))
        return EvaluationResult.combine(bundle.bundle_id, policy_decisions)

    def evaluate_policy(self, policy: Policy, context: EvaluationContext) -> Decision:
        """Evaluate a single policy. Useful when callers manage bundles externally."""
        return self._evaluate_policy(policy, context)

    # ---- internals -----------------------------------------------------

    def _evaluate_policy(self, policy: Policy, context: EvaluationContext) -> Decision:
        for rule in policy.rules:
            if self._match(rule.when, context):
                return Decision(
                    kind=rule.effect,
                    matched_policy_id=policy.id,
                    matched_rule_id=rule.id,
                    reason=rule.description or f"matched rule {rule.id!r}",
                )
        # No rule matched — fall back to the policy default.
        return Decision(
            kind=policy.default_effect,
            matched_policy_id=policy.id,
            matched_rule_id=None,
            reason=f"no rule matched; policy default_effect={policy.default_effect!r}",
        )

    def _match(self, matcher: Matcher, context: EvaluationContext) -> bool:
        if isinstance(matcher, AlwaysMatcher):
            return True
        if isinstance(matcher, AllOfMatcher):
            return all(self._match(m, context) for m in matcher.matchers)
        if isinstance(matcher, AnyOfMatcher):
            return any(self._match(m, context) for m in matcher.matchers)
        if isinstance(matcher, NotMatcher):
            return not self._match(matcher.matcher, context)
        if isinstance(matcher, FieldMatcher):
            return self._match_field(matcher, context)
        # Exhaustive over the Matcher union — this is unreachable.
        raise TypeError(f"unknown matcher type: {type(matcher).__name__}")  # pragma: no cover

    def _match_field(self, matcher: FieldMatcher, context: EvaluationContext) -> bool:
        actual = context.lookup(matcher.field)
        present = actual is not _MISSING
        kind = matcher.kind

        if kind == "exists":
            return present
        if kind == "missing":
            return not present
        if not present:
            return False  # any other matcher against a missing field is False

        try:
            return bool(_COMPARE[kind](self, actual, matcher.value))
        except KeyError:  # pragma: no cover - safety
            raise TypeError(f"unsupported field matcher kind: {kind}") from None

    # ---- comparison helpers --------------------------------------------

    @staticmethod
    def _eq(actual: Any, expected: Any) -> bool:
        return bool(actual == expected)

    @staticmethod
    def _ne(actual: Any, expected: Any) -> bool:
        return bool(actual != expected)

    @staticmethod
    def _gt(actual: Any, expected: Any) -> bool:
        try:
            return bool(actual > expected)
        except TypeError:
            return False

    @staticmethod
    def _gte(actual: Any, expected: Any) -> bool:
        try:
            return bool(actual >= expected)
        except TypeError:
            return False

    @staticmethod
    def _lt(actual: Any, expected: Any) -> bool:
        try:
            return bool(actual < expected)
        except TypeError:
            return False

    @staticmethod
    def _lte(actual: Any, expected: Any) -> bool:
        try:
            return bool(actual <= expected)
        except TypeError:
            return False

    @staticmethod
    def _in(actual: Any, expected: Any) -> bool:
        return actual in expected

    @staticmethod
    def _not_in(actual: Any, expected: Any) -> bool:
        return actual not in expected

    @staticmethod
    def _contains(actual: Any, expected: Any) -> bool:
        if isinstance(actual, (list, tuple, set, str)):
            return expected in actual
        if isinstance(actual, dict):
            return expected in actual
        return False

    def _regex(self, actual: Any, expected: Any) -> bool:
        if not isinstance(actual, str) or not isinstance(expected, str):
            return False
        pattern = self._regex_cache.get(expected)
        if pattern is None:
            pattern = re.compile(expected)
            self._regex_cache[expected] = pattern
        return pattern.search(actual) is not None

    @staticmethod
    def _starts_with(actual: Any, expected: Any) -> bool:
        return isinstance(actual, str) and isinstance(expected, str) and actual.startswith(expected)

    @staticmethod
    def _ends_with(actual: Any, expected: Any) -> bool:
        return isinstance(actual, str) and isinstance(expected, str) and actual.endswith(expected)


# Dispatch table for FieldMatcher.kind. Kept module-level so `_match_field`
# stays a tight if/else-free hot path.
_COMPARE: dict[str, Any] = {
    "eq": lambda self, a, b: PolicyEvaluator._eq(a, b),
    "ne": lambda self, a, b: PolicyEvaluator._ne(a, b),
    "gt": lambda self, a, b: PolicyEvaluator._gt(a, b),
    "gte": lambda self, a, b: PolicyEvaluator._gte(a, b),
    "lt": lambda self, a, b: PolicyEvaluator._lt(a, b),
    "lte": lambda self, a, b: PolicyEvaluator._lte(a, b),
    "in": lambda self, a, b: PolicyEvaluator._in(a, b),
    "not_in": lambda self, a, b: PolicyEvaluator._not_in(a, b),
    "contains": lambda self, a, b: PolicyEvaluator._contains(a, b),
    "regex": lambda self, a, b: self._regex(a, b),
    "starts_with": lambda self, a, b: PolicyEvaluator._starts_with(a, b),
    "ends_with": lambda self, a, b: PolicyEvaluator._ends_with(a, b),
}


# Unused at runtime — re-export so tests can build `Rule(...)` directly.
__all__ = ["PolicyEvaluator", "Rule"]
