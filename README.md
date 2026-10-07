# policy-as-code-engine

[![CI](https://github.com/mizcausevic-dev/policy-as-code-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/mizcausevic-dev/policy-as-code-engine/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Declarative policy-as-code evaluator for Python services.** JSON/YAML rules → first-match-wins evaluation → structured allow/deny decision with the matching rule and the reason. It can convert fields from a [`procurement-decision-api`](https://github.com/mizcausevic-dev/procurement-decision-api) Decision Card into a candidate runtime policy bundle. The caller must verify the card's authority and supply trustworthy condition signals before using that bundle to gate requests.

---

## Why

Most policy engines either ask you to learn a DSL (Rego, Cedar) or hand you a dictionary-of-lambdas and call it a library. Neither is the right shape when the *source of truth* is a JSON document a human signed off on. This engine:

1. **Reads JSON/YAML bundles.** No DSL. The matcher tree is the policy.
2. **Returns *why*, not just *what*.** Every decision carries the matched policy + rule + reason. The library does not persist an audit log; optional outbound audit events are best effort.
3. **Bridges to the Kinetic Gain Protocol Suite.** A single endpoint maps an AI Procurement Decision Card's status and conditions to a `PolicyBundle`. This conversion does not authenticate the card or independently verify the conditions.

---

## Install

```bash
pip install policy-as-code-engine
# with the FastAPI surface:
pip install "policy-as-code-engine[api]"
```

Python 3.11+. Runtime deps: `pydantic`, `PyYAML`, and `httpx`.

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

`result.policy_decisions` carries every per-policy outcome. Callers that need durable audit records must persist them in their own trusted system.

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

Missing segments produce a `_MISSING` sentinel — `exists` / `missing` matchers see it; every other matcher returns `false`. Escape a literal dot or backslash in a key with a backslash, for example `conditions_satisfied.risk\.review`.

---

## FastAPI surface

```bash
pip install "policy-as-code-engine[api]"
python -m policy_as_code_engine     # binds 127.0.0.1:8089 by default
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

An AI Procurement Decision Card records a buyer's posture toward a vendor. This bridge maps its status and condition IDs into policy rules. It accepts a version `0.1` card object only and rejects newer versions and unknown top-level or `decision` fields. It does not validate the full upstream schema. The current procurement API returns `{ "draft": ..., "documents_fetched": ..., "fetch_errors": ..., "suggested_status": ... }`. Its `draft` remains pending, and `suggested_status` is advisory. Pass the inner card only after human review, an authorized status change, and authority checks.

```bash
curl -X POST http://localhost:8089/bundles/from-decision-card \
  -H 'Content-Type: application/json' \
  -d @decision-card.json
```

Mapping:

| Decision Card status | Resulting bundle |
| --- | --- |
| `approved` | Single `allow-all` policy within this bundle. This is not general authorization for every action or resource. |
| `rejected` · `rejected-with-remediation` · `withdrawn` · `expired` · `pending` | Single `deny-all` policy (fail safe). |
| `approved-with-conditions` | One policy *per* condition. Each policy `allow`s only when `conditions_satisfied.{condition_id}` is the boolean `true` in the evaluation context; `deny` otherwise. The bundle combiner does deny-trumps-allow, so **every** condition must be satisfied to allow. |

The caller must derive satisfaction signals from trusted checks, such as a DPA verifier or an attestation freshness check. A caller that can freely set these booleans can bypass the conditions. The bridge rejects duplicate condition IDs and preserves literal dots and backslashes in IDs. The evaluator checks `decision.effective_from` and `decision.effective_until` against its own UTC clock on every evaluation. These optional fields must use timezone-qualified RFC 3339 timestamps such as `2026-10-07T12:00:00Z`; invalid or offset-free values are rejected at conversion.

```python
from policy_as_code_engine import (
    EvaluationContext,
    PolicyEvaluator,
    policy_bundle_from_decision_card,
)

draft_response = {...}  # parsed POST /decisions/draft response from procurement-decision-api
card = draft_response["draft"]  # review and authenticate before conversion
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

### Production boundary

The HTTP API has no authentication or authorization and keeps bundles only in process memory. It is intended for local evaluation and binds to `127.0.0.1` when started with `python -m policy_as_code_engine`. A deployment that exposes the ASGI app or sets `HOST=0.0.0.0` must add authenticated, authorized access and request limits at its boundary. The bridge does not verify signatures, issuer authority, publication state, vendor/resource identity, or later revocation. Decision Card `scope` is free text and is not applied as an action/resource rule. Callers must select a bundle for the intended vendor and resource, then combine its result with a separate action/resource authorization policy. An `approved` card must not be used as the sole allow rule for production requests. Registration overwrites a bundle with the same ID, and restarts erase registered bundles.

When `AUDIT_STREAM_URL` is configured, registration and allow/deny events are posted synchronously and best effort. Free-text reasons and bundle sources are excluded from these outbound events; IDs may still be sensitive in some deployments. Failed delivery is not retried or durably queued and can add up to the configured timeout to a request. Use a trusted local audit path and a separate persistence design when audit completeness matters.

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
ruff check src tests scripts && ruff format --check src tests scripts
mypy src scripts
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
