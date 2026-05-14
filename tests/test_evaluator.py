"""Unit tests for the policy evaluator."""

from __future__ import annotations

import pytest

from policy_as_code_engine.evaluator import PolicyEvaluator
from policy_as_code_engine.models import (
    AllOfMatcher,
    AlwaysMatcher,
    AnyOfMatcher,
    EvaluationContext,
    FieldMatcher,
    NotMatcher,
    Policy,
    PolicyBundle,
    Rule,
)


def _bundle(*policies: Policy, bundle_id: str = "b") -> PolicyBundle:
    return PolicyBundle(bundle_id=bundle_id, policies=list(policies))


def _allow_when(matcher: FieldMatcher | AllOfMatcher | AnyOfMatcher | NotMatcher | AlwaysMatcher) -> Rule:
    return Rule(id="r-allow", effect="allow", when=matcher)


def _deny_when(matcher: FieldMatcher | AllOfMatcher | AnyOfMatcher | NotMatcher | AlwaysMatcher) -> Rule:
    return Rule(id="r-deny", effect="deny", when=matcher)


class TestFieldMatcherEvaluation:
    @pytest.fixture
    def evaluator(self) -> PolicyEvaluator:
        return PolicyEvaluator()

    @pytest.fixture
    def context(self) -> EvaluationContext:
        return EvaluationContext(
            subject={"id": "u1", "role": "admin", "score": 0.95},
            action="read",
            data={"tags": ["alpha", "beta"], "vendor_id": "acme"},
        )

    @pytest.mark.parametrize(
        ("kind", "field", "value", "expected"),
        [
            ("eq", "subject.role", "admin", True),
            ("eq", "subject.role", "user", False),
            ("ne", "subject.role", "user", True),
            ("gt", "subject.score", 0.9, True),
            ("gte", "subject.score", 0.95, True),
            ("lt", "subject.score", 1.0, True),
            ("lte", "subject.score", 0.95, True),
            ("in", "subject.role", ["admin", "owner"], True),
            ("in", "subject.role", ["viewer"], False),
            ("not_in", "subject.role", ["viewer"], True),
            ("contains", "tags", "alpha", True),
            ("contains", "tags", "gamma", False),
            ("starts_with", "vendor_id", "ac", True),
            ("ends_with", "vendor_id", "me", True),
            ("regex", "vendor_id", r"^[a-z]+$", True),
            ("regex", "vendor_id", r"^\d+$", False),
        ],
    )
    def test_operators(
        self,
        evaluator: PolicyEvaluator,
        context: EvaluationContext,
        kind: str,
        field: str,
        value: object,
        expected: bool,
    ) -> None:
        bundle = _bundle(
            Policy(
                id="p",
                default_effect="deny",
                rules=[_allow_when(FieldMatcher(kind=kind, field=field, value=value))],  # type: ignore[arg-type]
            )
        )
        result = evaluator.evaluate(bundle, context)
        assert (result.decision.kind == "allow") is expected

    def test_exists_for_present_field(self, evaluator: PolicyEvaluator, context: EvaluationContext) -> None:
        bundle = _bundle(
            Policy(
                id="p",
                default_effect="deny",
                rules=[_allow_when(FieldMatcher(kind="exists", field="subject.id"))],
            )
        )
        assert evaluator.evaluate(bundle, context).decision.kind == "allow"

    def test_missing_for_absent_field(self, evaluator: PolicyEvaluator, context: EvaluationContext) -> None:
        bundle = _bundle(
            Policy(
                id="p",
                default_effect="deny",
                rules=[_allow_when(FieldMatcher(kind="missing", field="subject.email"))],
            )
        )
        assert evaluator.evaluate(bundle, context).decision.kind == "allow"

    def test_eq_against_missing_field_is_false(
        self, evaluator: PolicyEvaluator, context: EvaluationContext
    ) -> None:
        bundle = _bundle(
            Policy(
                id="p",
                default_effect="deny",
                rules=[_allow_when(FieldMatcher(kind="eq", field="subject.email", value="anything"))],
            )
        )
        # No rule matched -> falls back to default_effect deny.
        assert evaluator.evaluate(bundle, context).decision.kind == "deny"

    def test_gt_on_incompatible_types_returns_false(self) -> None:
        evaluator = PolicyEvaluator()
        bundle = _bundle(
            Policy(
                id="p",
                default_effect="deny",
                rules=[_allow_when(FieldMatcher(kind="gt", field="subject.role", value=5))],
            )
        )
        ctx = EvaluationContext(subject={"role": "admin"})
        assert evaluator.evaluate(bundle, ctx).decision.kind == "deny"


class TestCompositeMatchers:
    def test_all_of(self) -> None:
        evaluator = PolicyEvaluator()
        bundle = _bundle(
            Policy(
                id="p",
                default_effect="deny",
                rules=[
                    _allow_when(
                        AllOfMatcher(
                            matchers=[
                                FieldMatcher(kind="eq", field="subject.role", value="admin"),
                                FieldMatcher(kind="gte", field="subject.score", value=0.9),
                            ]
                        )
                    )
                ],
            )
        )
        ok_ctx = EvaluationContext(subject={"role": "admin", "score": 0.95})
        no_score = EvaluationContext(subject={"role": "admin", "score": 0.5})
        assert evaluator.evaluate(bundle, ok_ctx).decision.kind == "allow"
        assert evaluator.evaluate(bundle, no_score).decision.kind == "deny"

    def test_any_of(self) -> None:
        evaluator = PolicyEvaluator()
        bundle = _bundle(
            Policy(
                id="p",
                default_effect="deny",
                rules=[
                    _allow_when(
                        AnyOfMatcher(
                            matchers=[
                                FieldMatcher(kind="eq", field="subject.role", value="admin"),
                                FieldMatcher(kind="eq", field="subject.role", value="owner"),
                            ]
                        )
                    )
                ],
            )
        )
        for role in ("admin", "owner"):
            ctx = EvaluationContext(subject={"role": role})
            assert evaluator.evaluate(bundle, ctx).decision.kind == "allow"
        no = EvaluationContext(subject={"role": "viewer"})
        assert evaluator.evaluate(bundle, no).decision.kind == "deny"

    def test_not(self) -> None:
        evaluator = PolicyEvaluator()
        bundle = _bundle(
            Policy(
                id="p",
                default_effect="deny",
                rules=[
                    _allow_when(
                        NotMatcher(matcher=FieldMatcher(kind="eq", field="subject.role", value="viewer"))
                    )
                ],
            )
        )
        ctx = EvaluationContext(subject={"role": "admin"})
        assert evaluator.evaluate(bundle, ctx).decision.kind == "allow"


class TestBundleCombination:
    def test_deny_trumps_allow_across_policies(self) -> None:
        """If any policy denies, the bundle denies — even if another would allow."""
        evaluator = PolicyEvaluator()
        bundle = _bundle(
            Policy(
                id="allow-admins",
                default_effect="deny",
                rules=[_allow_when(FieldMatcher(kind="eq", field="subject.role", value="admin"))],
            ),
            Policy(
                id="deny-suspended",
                default_effect="allow",
                rules=[_deny_when(FieldMatcher(kind="eq", field="subject.suspended", value=True))],
            ),
        )
        ctx = EvaluationContext(subject={"role": "admin", "suspended": True})
        result = evaluator.evaluate(bundle, ctx)
        assert result.decision.kind == "deny"
        assert result.decision.matched_policy_id == "deny-suspended"

    def test_no_rule_fires_uses_policy_default_effect(self) -> None:
        evaluator = PolicyEvaluator()
        bundle = _bundle(
            Policy(
                id="p",
                default_effect="deny",
                rules=[_allow_when(FieldMatcher(kind="eq", field="subject.role", value="admin"))],
            )
        )
        ctx = EvaluationContext(subject={"role": "viewer"})
        result = evaluator.evaluate(bundle, ctx)
        # Rule didn't fire; default_effect=deny is recorded with matched_rule_id=None.
        assert result.decision.kind == "deny"
        assert result.policy_decisions[0].matched_rule_id is None

    def test_first_matching_rule_wins_inside_policy(self) -> None:
        evaluator = PolicyEvaluator()
        bundle = _bundle(
            Policy(
                id="p",
                default_effect="deny",
                rules=[
                    Rule(
                        id="early",
                        effect="allow",
                        when=FieldMatcher(kind="eq", field="subject.role", value="admin"),
                    ),
                    Rule(
                        id="late",
                        effect="deny",
                        when=AlwaysMatcher(),
                    ),
                ],
            )
        )
        ctx = EvaluationContext(subject={"role": "admin"})
        result = evaluator.evaluate(bundle, ctx)
        assert result.decision.kind == "allow"
        assert result.decision.matched_rule_id == "early"

    def test_per_policy_decisions_recorded(self) -> None:
        evaluator = PolicyEvaluator()
        bundle = _bundle(
            Policy(id="a", default_effect="deny", rules=[_allow_when(AlwaysMatcher())]),
            Policy(id="b", default_effect="deny", rules=[_allow_when(AlwaysMatcher())]),
        )
        result = evaluator.evaluate(bundle, EvaluationContext())
        assert [d.matched_policy_id for d in result.policy_decisions] == ["a", "b"]


class TestRegexCache:
    def test_pattern_compiled_once_per_distinct_regex(self) -> None:
        evaluator = PolicyEvaluator()
        ctx = EvaluationContext(data={"v": "abc"})
        bundle = _bundle(
            Policy(
                id="p",
                default_effect="deny",
                rules=[_allow_when(FieldMatcher(kind="regex", field="v", value=r"^a"))],
            )
        )
        for _ in range(50):
            evaluator.evaluate(bundle, ctx)
        # The cache should contain exactly one compiled pattern.
        assert len(evaluator._regex_cache) == 1
