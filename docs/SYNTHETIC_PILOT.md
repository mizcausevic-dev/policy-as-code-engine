# Local synthetic policy pilot

This source branch adds `policy_as_code_engine.pilot_app:app` as a separate,
opt-in FastAPI surface. The published v0.2.0 package and its existing HTTP API
are unchanged. **Use fictional buyers, vendors, cards, and assertions only.**
The pilot is not a customer authorization service or a hosted deployment.

## What it proves locally

- A short-lived Ed25519 assertion must name the configured issuer and audience,
  tenant, subject, and `admin` or `evaluate` role. Evaluation assertions must
  also name the exact `use` action and vendor. The service builds the policy
  context from that signed assertion, not from an evaluation request body.
- Buyer public keys are pinned to a tenant, buyer ID, key ID, and URL by a
  pilot administrator. A positive v0.1 Decision Card needs its exact v2
  attestation and a currently active key. The URL selects the enrolled key;
  it does not prove the buyer's organizational authority.
- SQLite holds keys, derived bundles, condition assertions, and minimal audit
  receipts on one local disk. Each state mutation and its receipt commit in one
  transaction. Evaluation inserts a receipt before returning an `allow`.
  Missing or unwritable state returns 503. A card or buyer-key revocation is
  checked again on the next evaluation, including after process restart.
- Positive results require **both** `POLICY_PILOT_ALLOW_SYNTHETIC=1` and
  `POLICY_PILOT_DENY_ALL=0`. The default is deny-all. The app's own entry point
  binds `127.0.0.1:8090`, and a non-loopback caller is rejected. Requests are
  capped at 128 KiB, 32 JSON nesting levels, and five seconds; responses
  request `Cache-Control: no-store`.

## Configuration

Install the repository with `pip install -e ".[dev]"`, then set these values
in the local process environment. Keep private signing keys outside the repo.
The service receives **public keys only**; an independent trusted caller mints
the signed assertions. Do not use the fictional keys in `tests/` for any real
identity or buyer enrollment.

| Variable | Purpose |
| --- | --- |
| `POLICY_PILOT_DB_PATH` | Absolute path to a local SQLite file in an existing private directory. It is created on startup. Do not place it on Cloud Run's ephemeral filesystem for a hosted claim. |
| `POLICY_PILOT_ISSUER` | Exact synthetic assertion issuer string. |
| `POLICY_PILOT_AUDIENCE` | Exact audience of this pilot service. |
| `POLICY_PILOT_ISSUER_PUBLIC_KEY_B64` | Base64 encoding of the issuer's 32-byte Ed25519 public key. |
| `POLICY_PILOT_ALLOW_SYNTHETIC` | Must equal `1` before any `allow` is possible. |
| `POLICY_PILOT_DENY_ALL` | Defaults to `1`; must equal `0` for a synthetic `allow`. Set to `1` first in a local rollback drill. |

The compact bearer assertion has a fixed `{"alg":"EdDSA","typ":"JWT"}`
header and claims `iss`, `aud`, `sub`, `tenant`, `role`, `iat`, `nbf`, and `exp`.
The `evaluate` role also needs signed `action="use"` and `vendor_id`. Maximum
lifetime is five minutes. The tenant is taken only from the verified assertion.
The issuer key and the process environment are operator trust boundaries, not
customer identity proof.

Run the app locally with:

```powershell
$env:PYTHONPATH = 'C:\Users\chaus\OneDrive\Documents\ChatGPT\buyer-side governance Kinetic Gain\policy-as-code-engine\src'
python -m policy_as_code_engine.pilot_app
```

The command requires the four mandatory variables above to use protected
routes. `GET /healthz` is liveness. `GET /readyz` checks the configured issuer,
database schema version, required tables and columns, and SQLite quick check;
it is **not** evidence that a hosted gateway, buyer
authority, egress policy, backup, or rollback exists.

## API surface

| Route | Role | Result |
| --- | --- | --- |
| `POST /v1/keys` | tenant admin | Enroll one synthetic buyer public key and receipt. |
| `POST /v1/keys/{key_id}/revoke` | tenant admin | Revoke key; next evaluation of its cards denies. |
| `POST /v1/cards` | tenant admin | Verify a signed positive v0.1 card, derive one scoped bundle, record hash and receipt. Duplicate tenant/bundle IDs are rejected. |
| `POST /v1/bundles/{bundle_id}/revoke` | tenant admin | Revoke the card bundle. |
| `PUT /v1/bundles/{bundle_id}/conditions/{condition_id}` | tenant admin | Record a condition assertion valid for at most seven days. |
| `POST /v1/bundles/{bundle_id}/evaluate` | tenant evaluator | Derive action and vendor from the signed assertion; return `allow` or `deny` plus a committed receipt ID. Request bodies are rejected. |
| `GET /v1/receipts` | tenant admin | Last 100 minimal receipts for that tenant only. |

The pilot has no generic `/bundles`, one-shot `/evaluate`, raw card read,
customer login, or remote fetch route. Its stored bundle descriptions can
contain the synthetic card's vendor text, so the database remains synthetic.

## Reproducible local drill

```powershell
Set-Location 'C:\Users\chaus\OneDrive\Documents\ChatGPT\buyer-side governance Kinetic Gain\policy-as-code-engine'
$env:PYTHONPATH = (Resolve-Path 'src').Path
python -m pytest -q tests/test_pilot_app.py
```

The tests generate temporary issuer and buyer keys and a temporary SQLite
file. They exercise default deny, scoped allow, a deny-all rollback switch,
wrong issuer audience, expired or tampered assertions, cross-tenant lookup,
wrong vendor, role separation, signed-card tampering, condition state,
old/new key overlap, key/card revocation across a restart, strict body limits,
headerless evaluation bodies, missing schema tables, and a known-positive audit
write failure. A 503 on the injected receipt write
failure is the expected fail-closed outcome.

## What remains blocked

This SQLite file is not a shared multi-instance store; it has no backed-up
restore, retention scheduler, migration playbook, or transactional delivery
outbox to another audit sink. The pilot issuer is a configured synthetic key,
not enrolled customer identity; it has no issuer rotation or replay prevention
for write assertions. Key enrollment is an operator assertion and does not
verify a buyer's real-world authority. The local loopback guard is not a
hosted gateway, distributed rate limit, or network egress policy. No remote
vendor fetching or customer traffic should be enabled from this pilot.

For hosted use, see the separate workspace release plan and the live release
gates. A real rollback needs an immutable deployed prior revision, a traffic
switch, and a database backup or compatible forward repair demonstrated on
the named deployment target. Setting a local deny-all flag is only a local
control drill.
