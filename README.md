# policy-as-code-engine

[![CI](https://github.com/mizcausevic-dev/policy-as-code-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/mizcausevic-dev/policy-as-code-engine/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Declarative policy-as-code evaluator for Python services.** JSON/YAML rules → first-match-wins evaluation → structured allow/deny decision with the matching rule and the reason. The HTTP bridge converts an operator-trusted, attested v0.1 Decision Card into a vendor-scoped `use` bundle after verifying its v2 signature against a pinned key. The operator must verify buyer authority and condition evidence separately.

---

## Why

The engine keeps policy rules in JSON/YAML and returns the reason for each decision. Its Decision Card bridge is designed for cards that have completed buyer review and an independent key-trust process. It:

1. **Reads JSON/YAML bundles.** No DSL. The matcher tree is the policy.
2. **Returns *why*, not just *what*.** Every decision carries the matched policy + rule + reason. The library does not persist an audit log; optional outbound audit events are best effort.
3. **Bridges to the Kinetic Gain Protocol Suite.** Positive card conversion verifies a buyer-key attestation; the caller must pin the buyer key independently. The HTTP adapter also keeps condition assertions behind the admin credential, with a seven-day maximum validity.

---

## Install

```bash
pip install policy-as-code-engine
# with the FastAPI surface:
pip install "policy-as-code-engine[api]"
```

Python 3.11+. Runtime deps: `pydantic`, `PyYAML`, `httpx`, `cryptography`, `rfc8785`, and `regex`. The last three provide Ed25519 verification, cross-language canonical JSON, and bounded regex matching.

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
| `regex`         | Patterns have a 256-character limit; input is limited to 4,096 characters and each match has a 20 ms timeout. Compiled patterns are cached with a 128-entry cap. |
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
conditions_satisfied.dpa-signed
```

Missing segments produce a `_MISSING` sentinel — `exists` / `missing` matchers see it; every other matcher returns `false`. Escape a literal dot or backslash in a key with a backslash, for example `conditions_satisfied.risk\.review`.

---

## FastAPI surface

```bash
pip install "policy-as-code-engine[api]"
python -m policy_as_code_engine     # binds 127.0.0.1:8089 by default
```

Before starting, configure **distinct** random values of at least 32 characters for `POLICY_ENGINE_ADMIN_TOKEN` and `POLICY_ENGINE_EVALUATE_TOKEN` through your secret manager. The service returns 503 on protected routes when either is absent, short, or reused. Send `Authorization: Bearer <token>` over TLS. The admin token can register, list, inspect, and evaluate bundles; the evaluator token can only call `POST /bundles/{bundle_id}/evaluate`. `/` and `/healthz` remain public. Restarting loses all bundles and condition assertions.

For positive Decision Cards, configure `POLICY_ENGINE_BUYER_KEYS_JSON` as a JSON map of trusted buyer ID to expected key URL to base64-encoded 32-byte Ed25519 public key. Pin these values from an independent buyer authority process; neither a card's `buyer.id` nor its attestation `key_url` establishes trust by itself. No real key or token is included in this README.

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/healthz` | Liveness probe. |
| GET | `/` | Service info. |
| POST | `/bundles` | Register a `PolicyBundle` in memory. |
| GET | `/bundles` | List registered bundle IDs. |
| GET | `/bundles/{bundle_id}` | Inspect a registered bundle. |
| POST | `/bundles/{bundle_id}/evaluate` | Evaluate a stored bundle against an `EvaluationContext`. |
| POST | `/evaluate` | One-shot. Bundle + context in, decision out. |
| POST | `/bundles/from-decision-card` | Verify and register a scoped v0.1 Decision Card bundle. Admin only. |
| PUT | `/bundles/{bundle_id}/conditions/{condition_id}` | Admin assertion of a condition state with expiry within seven days. |

POST and PUT bodies are capped at 128 KiB. Registration rejects a duplicate bundle ID with 409. Add an edge rate limit, TLS, and network access controls before exposing the ASGI app; the built-in bearer check has no per-client rate limit or tenant isolation.

---

## The cross-ecosystem hook

An AI Procurement Decision Card records a buyer's posture toward a vendor. The current procurement API returns `{ "draft": ..., "documents_fetched": ..., "fetch_errors": ..., "document_hashes": ..., "suggested_status": ... }`. Its `draft` remains pending; `suggested_status` is advisory. A buyer review/signing system must produce a final card and a v2 `hash-attestation-rs` attestation before positive HTTP registration. This repo does not supply that approval workflow.

The endpoint accepts an envelope with `card`, `attestation`, and `allowed_actions`. The card must be v0.1. For approved statuses, it must contain `buyer.id`, `subject.vendor_id`, and a timezone-qualified `decision.effective_until`. The HTTP bridge accepts only `allowed_actions: ["use"]` until the buyer card has a machine-readable signed operation scope. This local choice does not mean the buyer signed action authorization. The bridge rejects duplicate JSON object keys, non-finite numbers, unsupported card versions, and unknown top-level or relevant nested fields. It does not validate the full upstream schema.

```bash
curl -X POST http://localhost:8089/bundles/from-decision-card \
  -H "Authorization: Bearer $POLICY_ENGINE_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @approved-card-registration.json
```

The JSON envelope has this shape; values shown in angle brackets are placeholders:

```json
{
  "card": { "decision_card_version": "0.1", "decision_id": "<final-card-id>", "buyer": { "id": "<pinned-buyer-id>" }, "decision": { "status": "approved", "effective_until": "<RFC3339-time>" }, "subject": { "vendor_name": "<name>", "vendor_id": "<vendor-id>" } },
  "attestation": { "algorithm": "ed25519", "hash_profile": "jcs-rfc8785-v1", "signed_hash": "<sha256:...>", "signature": "<base64-signature>", "key_url": "<pinned-key-url>", "signed_at": "<RFC3339-time>" },
  "allowed_actions": ["use"]
}
```

The example omits other card fields; the actual final card and attestation must match exactly. The verifier checks RFC 8785 canonical hash and the Rust v2 domain-separated signature. Legacy signatures are rejected. A malformed or untrusted positive card cannot register. A trusted signature proves possession of the pinned key, not the signer's legal authority, the accuracy of the buyer's review, or that the card has not since been revoked.

Mapping:

| Decision Card status | Resulting bundle |
| --- | --- |
| `approved` | One policy that allows only the configured action(s) on `resource.vendor_id` matching the signed card's `subject.vendor_id`; otherwise denies. |
| `rejected` · `rejected-with-remediation` · `withdrawn` · `expired` · `pending` | Single `deny-all` policy (fail safe). |
| `approved-with-conditions` | One policy per condition. Every condition must have a current admin assertion of boolean `true` and the action/vendor scope must match; otherwise denies. Evaluation callers cannot supply `conditions_satisfied` to the HTTP API. |

The admin must derive condition assertions from evidence outside this service, then PUT `{ "satisfied": true, "valid_until": "<RFC3339-time-within-seven-days>" }` to the condition endpoint. An unset or expired assertion denies. Assertions and bundles disappear on restart. The bridge rejects duplicate condition IDs and preserves literal dots and backslashes in IDs. The evaluator checks card effective times against its own UTC clock on every evaluation; invalid or offset-free values are rejected at conversion.

The Python library requires `policy_bundle_from_decision_card(card, allowed_actions=["use"], attestation=attestation, trusted_key_url=key_url, trusted_public_key=public_key)` for positive cards. It verifies the v2 signature, but the calling process must map `buyer.id` to an independently trusted key and provide verified condition signals. The HTTP adapter handles the pinned-key mapping and replaces caller condition data with admin assertions. Decision Card conversion permits only `use`; applications author other operation rules separately.

Evaluate converted cards with `PolicyEvaluator.evaluate(bundle, context)` or the stored HTTP evaluation route. `evaluate_policy(policy, context)` deliberately returns deny for card-derived policies because it has no bundle time window or scope metadata.

### Production boundary

The API is a local/reference integration. Bearer roles, buyer-key checks, vendor/action binding, condition assertions, and request bounds protect its basic boundary, but it has no durable bundle/condition store, revocation feed, key-rotation workflow, tenant isolation, or built-in rate limiting. `decision.scope` remains free text and is **not** parsed into the action mapping. The evaluating service must derive `action` and `resource.vendor_id` from its own authenticated request, select the right bundle, and combine the result with its own subject/resource authorization. A card approval alone is not permission to run every operation. A buyer withdrawal after registration is not discovered automatically; operators must stop using the bundle and update the source of truth. Do not treat this reference API as standalone production authorization until those controls are designed and tested for the deployment.

When `AUDIT_STREAM_URL` is configured with the private sink base URL or exact `/events` endpoint, also set `AUDIT_STREAM_TOKEN` to the sink's separate bearer credential (at least 32 visible ASCII characters) from a secret store. The URL requires HTTPS except for numeric loopback HTTP addresses. Registration, condition assertion, and allow/deny events are posted synchronously and best effort. Invalid configuration prevents outbound delivery and logs a failure; HTTP errors are logged without the URL or token. Free-text reasons, condition descriptions, and bundle sources are excluded from these outbound events; IDs may still be sensitive in some deployments. Failed delivery is not retried or durably queued and can add up to the configured timeout to a request. Use a trusted local audit path and a separate persistence design when audit completeness matters.

### Opt-in synthetic pilot

The v0.2.1 source tree packages a separate `policy_as_code_engine.pilot_app:app` for **local synthetic drills**. It uses tenant-scoped, short-lived Ed25519 assertions; a local SQLite file for buyer-key/card/condition state and committed minimal receipts; per-evaluation card/key revocation checks; and a deny-all default. It has no generic bundle or one-shot evaluation route. The main reference API above does not invoke this pilot surface, and the published v0.2.0 package does not contain it. See [the synthetic pilot guide](docs/SYNTHETIC_PILOT.md) for configuration, tests, and limitations. A local SQLite file, fictional issuer, and loopback guard do not clear hosted customer-use gates.

### v0.2.1 changes

This version adds authenticated, redirect-safe, best-effort audit delivery and packages the opt-in synthetic pilot module. If you already set `AUDIT_STREAM_URL`, configure the sink to require a separate bearer credential and set `AUDIT_STREAM_TOKEN` before upgrading. Without a valid token, audit delivery fails and is logged, while policy evaluation continues because delivery is best effort. This version does not add hosted authorization, audit completeness, or a revocation feed to the reference API. A source version string alone does not establish PyPI availability; check the tagged workflow and published artifacts before making a release claim.

### Migrating from 0.1.1 to 0.2.0

This release intentionally breaks the permissive Decision Card path. Set separate admin and evaluator tokens before using protected HTTP routes. Wrap bridge requests as `{ "card": ..., "attestation": ..., "allowed_actions": ["use"] }`; an approved card needs a v2 Rust-compatible signature and an independently pinned buyer key. Add `buyer.id`, `subject.vendor_id`, and a timezone-qualified `decision.effective_until` to positive cards. Library callers must pass the attestation and trusted buyer key explicitly. The generated bundle now defaults to deny outside its vendor/action scope, and the HTTP evaluator rejects caller-supplied condition booleans. Admins assert condition state separately with a maximum seven-day validity. Bundle IDs cannot overwrite existing registrations; restart or create a new decision ID to replace one. Existing stored bundles are in memory only and are erased on restart, so migration requires explicit re-registration.

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

- **[procurement-decision-api](https://github.com/mizcausevic-dev/procurement-decision-api)** — drafts Decision Cards for buyer review; it does not issue signed approvals.
- **[ai-procurement-decision-spec](https://github.com/mizcausevic-dev/ai-procurement-decision-spec)** — the v0.1 schema.
- **[slo-budget-tracker](https://github.com/mizcausevic-dev/slo-budget-tracker)** — error-budget tracker that you can wire into the same FastAPI app.
- **[reliability-toolkit-rs](https://github.com/mizcausevic-dev/reliability-toolkit-rs)** — Rust async reliability primitives.
- More at [kineticgain.com](https://kineticgain.com/).

---

## License

MIT. See [LICENSE](LICENSE).
