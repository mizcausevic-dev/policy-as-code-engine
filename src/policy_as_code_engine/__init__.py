"""
policy-as-code-engine — declarative policy evaluation for Python services.

This package answers one question: *given this context object and these rules,
should the request be allowed?* It is deliberately small. Rules are JSON/YAML
documents; the engine walks them and produces a structured decision (allow /
deny / not-applicable) with the matching rule and the reason.

Designed to compose with the rest of the Kinetic Gain ecosystem:

    procurement-decision-api   -> drafts a Decision Card with conditions[]
    policy-as-code-engine      -> converts those conditions into a PolicyBundle,
                                  then evaluates them against live requests

Two surfaces:

    Library:  from policy_as_code_engine import PolicyEvaluator
    HTTP:     uvicorn policy_as_code_engine.app:app (optional `[api]` extra)
"""

from __future__ import annotations

from .evaluator import PolicyEvaluator
from .from_decision_card import policy_bundle_from_decision_card
from .models import (
    Decision,
    DecisionKind,
    EvaluationContext,
    EvaluationResult,
    Matcher,
    Policy,
    PolicyBundle,
    Rule,
)

__version__ = "0.1.0"

__all__ = [
    "Decision",
    "DecisionKind",
    "EvaluationContext",
    "EvaluationResult",
    "Matcher",
    "Policy",
    "PolicyBundle",
    "PolicyEvaluator",
    "Rule",
    "__version__",
    "policy_bundle_from_decision_card",
]
