# policy-as-code-engine

[![CI](https://github.com/mizcausevic-dev/policy-as-code-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/mizcausevic-dev/policy-as-code-engine/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Declarative policy-as-code evaluator for Python services.** JSON/YAML rules → first-match-wins evaluation → structured allow/deny decision with the matching rule and the reason. Cheap to embed; ships with a FastAPI surface; **pairs directly with [`procurement-decision-api`](https://github.com/mizcausevic-dev/procurement-decision-api)** so the same Decision Card that records a buyer's posture also becomes the runtime gate that enforces it.

---

## Why

Most policy engines either ask you to learn a DSL (Rego, Cedar) or hand you a dictionary-of-lambdas and call it a library. Neither is the right shape when the *source of truth* is a JSON document a human signed off on. This engine:

1. **Reads JSON/YAML bundles.** No DSL. The matcher tree is the policy.
2. **Returns *why*, not just *what*.** Every decision carries the matched policy + rule + reason. Operators get a real audit log on each evaluation.
3. **Bridges to the Kinetic Gain Protocol Suite.** A single endpoint turns an AI Procurement Decision Card into a runtime-enforceable `PolicyBundle` — approve, reject, or approve-with-conditions all map to concrete allow/deny logic.

---

## Install

```bash
pip install policy-as-code-engine
# with the FastAPI surface:
pip install "policy-as-code-engine[api]"
```

Python 3.11+. Runtime deps: `pydantic` + `PyYAML`.

---

## Library quickstart

```python
from policy_as_code_engine import (
    EvaluationContext,
    PolicyBundle,
    PolicyEvaluator,
)

bundle = PolicyBundle.model_validate({
    "bundle_id": "edu-gate",
    "policies": [{
        "id": "writes-require-admin",
        "default_effect": "deny",
        "rules": [
            {
                "id": "admin-writes",
                "effect": "allow",
                "when": {
                    "kind": "all_of",
                    "matchers": [
                        {"kind": "in", "field": "action", "value": ["create", "update", "delete"]},
                        {"kind": "eq", "field": "subject.role", "value": "admin"},
                    ],
                },
            },
        ],
    }],
})

ctx = EvaluationContext(
    subject={"id": "u-42", "role": "admin"},
    action="update",
    resource={"id": "doc-7"},
)

result = PolicyEvaluator().evaluate(bundle, ctx)
print(result.decision.kind)             # "allow"
print(result.decision.matched_rule_id)  # "admin-writes"
print(result.decision.reason)           # "matched rule 'admin-writes'"
```

`result.policy_decisions` carries every per-policy outcome — drop it straight into your audit log.

---

## Bundle DSL

A bundle is a small recursive structure. Matchers compose; rules ordered.

### Field matchers

| Kind            | Notes |
| --------------- | --- |
| `eq` / `ne`     | Strict equality. |
| `gt` / `gte` / `lt` / `lte` | Comparison; returns `false` on incompatible types (won't raise). |
| `in` / `not_in` | `value` must be a list. |
| `contains`      | Works against strings, lists, sets, dicts. |
| `exists` / `missing` | No `value`. Operates against the dotted-path resolver. |
| `regex`         | Compiled patterns are cached per-evaluator. |
| `starts_with` / `ends_with` | String-only. |

### Composite matchers

| Kind     | Children | Truth |
| -------- | -------- | --- |
| `all_of` | `matchers: [...]` | All children true. |
| `any_of` | `matchers: [...]` | At least one child true. |
| `not`    | `matcher: {...}`  | Inverts the child. |
| `always` | —                 | Always true. Useful as a final catch-all. |

### Dotted paths

The resolver looks at the merged context (`data` + `subject` + `action` + `resource`):

```
subject.role
resource.tags.0          # list index
data.conditions_satisfied.dpa-signed
```

Missing segments produce a `_MISSING` sentinel — `exists` / `missing` matchers see it; every other matcher returns `false`.

---

## FastAPI surface

```bash
pip install "policy-as-code-engine[api]"
python -m policy_as_code_engine     # binds 0.0.0.0:8089 by default
```

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/healthz` | Liveness probe. |
| GET | `/` | Service info. |
| POST | `/bundles` | Register a `PolicyBundle` in memory. |
| GET | `/bundles` | List registered bundle IDs. |
| GET | `/bundles/{bundle_id}` | Inspect a registered bundle. |
| POST | `/bundles/{bundle_id}/evaluate` | Evaluate a stored bundle against an `EvaluationContext`. |
| POST | `/evaluate` | One-shot. Bundle + context in, decision out. |
| POST | `/bundles/from-decision-card` | **The cross-ecosystem hook.** Turn a Kinetic Gain Procurement Decision Card into a `PolicyBundle` and register it. |

---

## The cross-ecosystem hook

The headline feature. An AI Procurement Decision Card is the buyer-side record that says "we evaluated this vendor and our position is X." This engine turns that human-authored artifact into a runtime gate, mechanically.

```bash
curl -X POST http://localhost:8089/bundles/from-decision-card \
  -H 'Content-Type: application/json' \
  -d @decision-card.json
```

Mapping:

| Decision Card status | Resulting bundle |
| --- | --- |
| `approved` | Single `allow-all` policy. |
| `rejected` · `rejected-with-remediation` · `withdrawn` · `expired` · `pending` | Single `deny-all` policy (fail safe). |
| `approved-with-conditions` | One policy *per* condition. Each policy `allow`s only when `conditions_satisfied.{condition_id}` is `true` in the evaluation context; `deny` otherwise. The bundle combiner does deny-trumps-allow, so **every** condition must be satisfied to allow. |

Wire your own satisfaction signal — DPA verifier, bias-audit freshness check, attestation timestamp — into the context, and the bundle does the rest.

```python
from policy_as_code_engine import (
    EvaluationContext,
    PolicyEvaluator,
    policy_bundle_from_decision_card,
)

card = {...}  # POST /decisions/draft output from procurement-decision-api
bundle = policy_bundle_from_decision_card(card)

ctx = EvaluationContext(
    subject={"id": "u-1"},
    action="enroll",
    data={
        "conditions_satisfied": {
            "dpa-signed":         True,
            "bias-audit-fresh":   True,
        }
    },
)

decision = PolicyEvaluator().evaluate(bundle, ctx).decision
```

---

## CLI

```bash
python -m policy_as_code_engine eval examples/example-bundle.yaml examples/example-context.json
```

Prints the full `EvaluationResult` as JSON. Exits non-zero on `deny`.

---

## How decisions combine

Inside a single policy: **first matching rule wins**, otherwise `default_effect`.

Across the bundle:

```
deny     -> deny      (any policy denies => bundle denies)
allow    -> allow     (otherwise, any allow => bundle allows)
neither  -> not_applicable
```

Per-policy decisions are always returned — useful for "we denied because of policy B, but A would have allowed" audit narratives.

---

## Tests

```bash
pip install -e ".[dev]"
ruff check src tests && ruff format --check src tests
mypy src
pytest -v
```

CI matrix runs Python 3.11 / 3.12 / 3.13.

---

## Related in this ecosystem

- **[procurement-decision-api](https://github.com/mizcausevic-dev/procurement-decision-api)** — drafts the Decision Cards that this engine enforces.
- **[ai-procurement-decision-spec](https://github.com/mizcausevic-dev/ai-procurement-decision-spec)** — the v0.1 schema.
- **[slo-budget-tracker](https://github.com/mizcausevic-dev/slo-budget-tracker)** — error-budget tracker that you can wire into the same FastAPI app.
- **[reliability-toolkit-rs](https://github.com/mizcausevic-dev/reliability-toolkit-rs)** — Rust async reliability primitives.
- More at [kineticgain.com](https://kineticgain.com/).

---

## License

MIT. See [LICENSE](LICENSE).
