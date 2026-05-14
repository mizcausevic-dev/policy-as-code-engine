"""Unit tests for the Pydantic models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

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


class TestFieldMatcher:
    def test_eq_matcher(self) -> None:
        m = FieldMatcher(kind="eq", field="subject.role", value="admin")
        assert m.field == "subject.role"
        assert m.value == "admin"

    def test_in_matcher_requires_list(self) -> None:
        with pytest.raises(ValidationError):
            FieldMatcher(kind="in", field="x", value="notalist")

    def test_exists_does_not_require_value(self) -> None:
        m = FieldMatcher(kind="exists", field="subject.id")
        assert m.value is None

    def test_eq_requires_value(self) -> None:
        with pytest.raises(ValidationError):
            FieldMatcher(kind="eq", field="x")


class TestCompositeMatchers:
    def test_all_of_requires_children(self) -> None:
        with pytest.raises(ValidationError):
            AllOfMatcher(matchers=[])

    def test_any_of_accepts_list(self) -> None:
        m = AnyOfMatcher(
            matchers=[
                FieldMatcher(kind="eq", field="a", value=1),
                FieldMatcher(kind="eq", field="b", value=2),
            ]
        )
        assert len(m.matchers) == 2

    def test_not_wraps_one(self) -> None:
        inner = FieldMatcher(kind="eq", field="a", value=1)
        m = NotMatcher(matcher=inner)
        assert isinstance(m.matcher, FieldMatcher)


class TestRuleAndPolicy:
    def test_rule_requires_id_and_when(self) -> None:
        with pytest.raises(ValidationError):
            Rule.model_validate({"effect": "allow"})

    def test_policy_requires_at_least_one_rule(self) -> None:
        with pytest.raises(ValidationError):
            Policy(id="p", rules=[])

    def test_bundle_strict_extras_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyBundle.model_validate(
                {
                    "bundle_id": "b",
                    "policies": [
                        {
                            "id": "p",
                            "rules": [
                                {"id": "r", "effect": "allow", "when": {"kind": "always"}},
                            ],
                        }
                    ],
                    "unknown_field": True,
                }
            )

    def test_bundle_basic_shape_validates(self) -> None:
        bundle = PolicyBundle.model_validate(
            {
                "bundle_id": "b",
                "policies": [
                    {
                        "id": "p",
                        "rules": [{"id": "r", "effect": "allow", "when": {"kind": "always"}}],
                    }
                ],
            }
        )
        assert bundle.bundle_id == "b"
        assert isinstance(bundle.policies[0].rules[0].when, AlwaysMatcher)


class TestEvaluationContext:
    def test_lookup_walks_dotted_path(self) -> None:
        ctx = EvaluationContext(data={"vendor": {"name": "Acme"}})
        assert ctx.lookup("vendor.name") == "Acme"

    def test_lookup_returns_sentinel_on_missing(self) -> None:
        from policy_as_code_engine.models import _MISSING

        ctx = EvaluationContext(data={})
        assert ctx.lookup("nope.nada") is _MISSING

    def test_lookup_indexes_into_lists(self) -> None:
        ctx = EvaluationContext(data={"items": ["a", "b", "c"]})
        assert ctx.lookup("items.1") == "b"

    def test_lookup_merges_named_fields(self) -> None:
        ctx = EvaluationContext(
            subject={"id": "u1", "role": "admin"},
            action="read",
            resource={"id": "doc-42"},
        )
        assert ctx.lookup("subject.role") == "admin"
        assert ctx.lookup("action") == "read"
        assert ctx.lookup("resource.id") == "doc-42"
