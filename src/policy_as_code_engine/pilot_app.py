"""Opt-in, loopback-only synthetic policy pilot.

This app deliberately has no generic bundle or one-shot evaluation routes. Its
SQLite file is local pilot state, not a shared hosted policy database.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import Field, ValidationError
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .card_attestation import CardAttestation
from .evaluator import PolicyEvaluator
from .from_decision_card import policy_bundle_from_decision_card
from .models import EvaluationContext, PolicyBundle, StrictModel

_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_TOKEN_BYTES = 4096
_MAX_TOKEN_AGE_SECONDS = 300
_MAX_CARD_DAYS = 30
_MAX_BODY_BYTES = 131_072
_MAX_JSON_DEPTH = 32
_SCHEMA_VERSION = 1
_SCHEMA_COLUMNS = {
    "buyer_keys": {"tenant_id", "key_id", "buyer_id", "key_url", "public_key", "active"},
    "cards": {
        "tenant_id",
        "bundle_id",
        "buyer_id",
        "key_id",
        "vendor_id",
        "card_hash",
        "bundle_json",
        "condition_ids_json",
        "active",
        "created_at",
    },
    "conditions": {"tenant_id", "bundle_id", "condition_id", "satisfied", "valid_until"},
    "receipts": {"receipt_id", "tenant_id", "event", "subject_ref", "outcome", "occurred_at"},
}


@dataclass(frozen=True)
class _Principal:
    tenant_id: str
    subject_id: str
    role: Literal["admin", "evaluate"]
    action: str | None
    vendor_id: str | None


class _KeyInput(StrictModel):
    key_id: str = Field(..., min_length=1, max_length=64)
    buyer_id: str = Field(..., min_length=1, max_length=128)
    key_url: str = Field(..., min_length=1, max_length=512)
    public_key_b64: str = Field(..., min_length=44, max_length=44)


class _CardInput(StrictModel):
    key_id: str = Field(..., min_length=1, max_length=64)
    card: dict[str, Any]
    attestation: CardAttestation


class _ConditionInput(StrictModel):
    satisfied: bool
    valid_until: datetime


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except RecursionError as err:
        raise ValueError("JSON nesting limit exceeded") from err
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    pending: list[tuple[Any, int]] = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > _MAX_JSON_DEPTH:
            raise ValueError("JSON nesting limit exceeded")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def _decode_segment(part: str) -> bytes:
    if not part or not _B64URL.fullmatch(part):
        raise ValueError("invalid token encoding")
    raw = base64.b64decode(part + "=" * (-len(part) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != part:
        raise ValueError("noncanonical token encoding")
    return raw


def _identity_config() -> tuple[str, str, bytes]:
    issuer = os.environ.get("POLICY_PILOT_ISSUER", "")
    audience = os.environ.get("POLICY_PILOT_AUDIENCE", "")
    encoded_key = os.environ.get("POLICY_PILOT_ISSUER_PUBLIC_KEY_B64", "")
    if not issuer or not audience or not encoded_key or len(issuer) > 256 or len(audience) > 256:
        raise HTTPException(503, "pilot identity is not configured")
    try:
        public_key = base64.b64decode(encoded_key, validate=True)
    except binascii.Error as err:
        raise HTTPException(503, "pilot identity is not configured") from err
    if len(public_key) != 32:
        raise HTTPException(503, "pilot identity is not configured")
    return issuer, audience, public_key


def _principal(request: Request) -> _Principal:
    issuer, audience, public_key = _identity_config()
    scheme, separator, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not separator or not token:
        raise HTTPException(401, "bearer assertion required", headers={"WWW-Authenticate": "Bearer"})
    if len(token) > _MAX_TOKEN_BYTES:
        raise HTTPException(403, "invalid pilot assertion")
    try:
        header_part, payload_part, signature_part = token.split(".")
        header = _json_object(_decode_segment(header_part))
        claims = _json_object(_decode_segment(payload_part))
        signature = _decode_segment(signature_part)
        if header != {"alg": "EdDSA", "typ": "JWT"} or len(signature) != 64:
            raise ValueError("unsupported assertion header")
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, f"{header_part}.{payload_part}".encode("ascii")
        )
        now = int(datetime.now(UTC).timestamp())
        issued = claims["iat"]
        not_before = claims["nbf"]
        expires = claims["exp"]
        if any(type(value) is not int for value in (issued, not_before, expires)):
            raise ValueError("invalid assertion time")
        if not (now - _MAX_TOKEN_AGE_SECONDS <= issued <= now):
            raise ValueError("invalid assertion issue time")
        if not (issued <= not_before <= now < expires <= issued + _MAX_TOKEN_AGE_SECONDS):
            raise ValueError("invalid assertion validity window")
        if claims["iss"] != issuer or claims["aud"] != audience:
            raise ValueError("wrong assertion issuer or audience")
        tenant = claims["tenant"]
        subject = claims["sub"]
        role = claims["role"]
        if not isinstance(tenant, str) or not _ID.fullmatch(tenant):
            raise ValueError("invalid tenant")
        if not isinstance(subject, str) or not 1 <= len(subject) <= 128:
            raise ValueError("invalid subject")
        if role not in {"admin", "evaluate"}:
            raise ValueError("invalid role")
        action = claims.get("action")
        vendor_id = claims.get("vendor_id")
        if role == "evaluate" and (
            action != "use" or not isinstance(vendor_id, str) or not 1 <= len(vendor_id) <= 128
        ):
            raise ValueError("evaluation scope missing")
        return _Principal(tenant, subject, role, action, vendor_id)
    except (
        ValueError,
        KeyError,
        UnicodeError,
        binascii.Error,
        InvalidSignature,
        TypeError,
        RecursionError,
    ) as err:
        raise HTTPException(403, "invalid pilot assertion") from err


def _admin(principal: Annotated[_Principal, Depends(_principal)]) -> _Principal:
    if principal.role != "admin":
        raise HTTPException(403, "pilot administrator role required")
    return principal


def _evaluator(principal: Annotated[_Principal, Depends(_principal)]) -> _Principal:
    if principal.role != "evaluate":
        raise HTTPException(403, "pilot evaluator role required")
    return principal


def _db_path() -> Path:
    configured = os.environ.get("POLICY_PILOT_DB_PATH", "")
    path = Path(configured)
    if not configured or not path.is_absolute() or not path.parent.is_dir():
        raise HTTPException(503, "pilot state is not configured")
    return path


def _open_db() -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(_db_path(), timeout=1.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=1000")
        connection.execute("PRAGMA synchronous=FULL")
        return connection
    except sqlite3.Error as err:
        raise HTTPException(503, "pilot state unavailable") from err


def _check_schema(connection: sqlite3.Connection, *, integrity: bool = False) -> None:
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version != _SCHEMA_VERSION:
        raise sqlite3.DatabaseError("unsupported pilot schema version")
    for table, expected_columns in _SCHEMA_COLUMNS.items():
        actual_columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
        if actual_columns != expected_columns:
            raise sqlite3.DatabaseError("pilot schema is incomplete")
    if integrity and connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
        raise sqlite3.DatabaseError("pilot database integrity check failed")


def _initialize() -> None:
    connection = _open_db()
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == _SCHEMA_VERSION:
            _check_schema(connection, integrity=True)
            return
        if (
            version != 0
            or connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1"
            ).fetchone()
        ):
            raise sqlite3.DatabaseError("unexpected existing pilot database")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS buyer_keys (
                tenant_id TEXT NOT NULL, key_id TEXT NOT NULL, buyer_id TEXT NOT NULL,
                key_url TEXT NOT NULL, public_key BLOB NOT NULL, active INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, key_id)
            );
            CREATE TABLE IF NOT EXISTS cards (
                tenant_id TEXT NOT NULL, bundle_id TEXT NOT NULL, buyer_id TEXT NOT NULL,
                key_id TEXT NOT NULL, vendor_id TEXT NOT NULL, card_hash TEXT NOT NULL,
                bundle_json TEXT NOT NULL, condition_ids_json TEXT NOT NULL,
                active INTEGER NOT NULL, created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, bundle_id),
                FOREIGN KEY (tenant_id, key_id) REFERENCES buyer_keys(tenant_id, key_id)
            );
            CREATE TABLE IF NOT EXISTS conditions (
                tenant_id TEXT NOT NULL, bundle_id TEXT NOT NULL, condition_id TEXT NOT NULL,
                satisfied INTEGER NOT NULL, valid_until TEXT NOT NULL,
                PRIMARY KEY (tenant_id, bundle_id, condition_id),
                FOREIGN KEY (tenant_id, bundle_id) REFERENCES cards(tenant_id, bundle_id)
            );
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, event TEXT NOT NULL,
                subject_ref TEXT NOT NULL, outcome TEXT NOT NULL, occurred_at TEXT NOT NULL
            );
            """
        )
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
        _check_schema(connection, integrity=True)
        connection.commit()
    except sqlite3.Error as err:
        raise HTTPException(503, "pilot state unavailable") from err
    finally:
        connection.close()


@contextmanager
def _transaction() -> Iterator[sqlite3.Connection]:
    connection = _open_db()
    try:
        _check_schema(connection)
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except sqlite3.Error as err:
        connection.rollback()
        raise HTTPException(503, "pilot state unavailable") from err
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _receipt(connection: sqlite3.Connection, tenant_id: str, event: str, subject: str, outcome: str) -> str:
    receipt_id = uuid.uuid4().hex
    subject_ref = hashlib.sha256(f"{tenant_id}\0{subject}".encode()).hexdigest()
    connection.execute(
        "INSERT INTO receipts VALUES (?, ?, ?, ?, ?, ?)",
        (receipt_id, tenant_id, event, subject_ref, outcome, datetime.now(UTC).isoformat()),
    )
    return receipt_id


def _key_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and bool(hostname)
        and parts.username is None
        and parts.password is None
        and not parts.query
        and not parts.fragment
    )


class _PilotRequestBoundary:
    """Bound and strictly decode local JSON before FastAPI sees it."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        body = bytearray()
        try:
            async with asyncio.timeout(5):
                while True:
                    message = await receive()
                    if message["type"] != "http.request":
                        return
                    body.extend(message.get("body", b""))
                    if len(body) > _MAX_BODY_BYTES:
                        await JSONResponse({"detail": "request body exceeds 128 KiB"}, status_code=413)(
                            scope, receive, send
                        )
                        return
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            await JSONResponse({"detail": "request body read timed out"}, status_code=408)(
                scope, receive, send
            )
            return
        if body:
            try:
                decoded = _json_object(bytes(body))
                rfc8785.dumps(decoded)
            except (UnicodeDecodeError, ValueError, RecursionError, rfc8785.CanonicalizationError):
                await JSONResponse({"detail": "invalid or ambiguous JSON body"}, status_code=400)(
                    scope, receive, send
                )
                return
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    if os.environ.get("POLICY_PILOT_DB_PATH"):
        _initialize()
    yield


app = FastAPI(
    title="policy-as-code-engine synthetic pilot",
    description="Opt-in loopback pilot; no customer authorization or hosted durability claim.",
    lifespan=_lifespan,
)
app.add_middleware(_PilotRequestBoundary)


@app.middleware("http")
async def _no_store(request: Request, call_next: Any) -> Any:
    client_host = request.client.host if request.client else ""
    if client_host != "testclient":
        try:
            if not ipaddress.ip_address(client_host).is_loopback:
                return JSONResponse({"detail": "local pilot only"}, status_code=403)
        except ValueError:
            return JSONResponse({"detail": "local pilot only"}, status_code=403)
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(RequestValidationError)
async def _invalid_request(_request: Request, _error: RequestValidationError) -> JSONResponse:
    return JSONResponse({"detail": "invalid request"}, status_code=422)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "alive", "mode": "synthetic-local-pilot"}


@app.get("/readyz")
def readyz() -> dict[str, Any]:
    _identity_config()
    connection = _open_db()
    try:
        _check_schema(connection, integrity=True)
    except sqlite3.Error as err:
        raise HTTPException(503, "pilot state unavailable") from err
    finally:
        connection.close()
    return {"status": "ready", "allow_enabled": _allow_enabled()}


def _allow_enabled() -> bool:
    return (
        os.environ.get("POLICY_PILOT_ALLOW_SYNTHETIC") == "1"
        and os.environ.get("POLICY_PILOT_DENY_ALL", "1") == "0"
    )


@app.post("/v1/keys", status_code=201)
def enroll_key(payload: _KeyInput, principal: Annotated[_Principal, Depends(_admin)]) -> dict[str, str]:
    if not _ID.fullmatch(payload.key_id) or not _key_url(payload.key_url):
        raise HTTPException(400, "invalid buyer key selector")
    try:
        key = base64.b64decode(payload.public_key_b64, validate=True)
    except binascii.Error as err:
        raise HTTPException(400, "invalid buyer public key") from err
    if len(key) != 32:
        raise HTTPException(400, "invalid buyer public key")
    with _transaction() as connection:
        existing = connection.execute(
            "SELECT 1 FROM buyer_keys WHERE tenant_id=? AND key_id=?",
            (principal.tenant_id, payload.key_id),
        ).fetchone()
        if existing:
            raise HTTPException(409, "buyer key already exists")
        connection.execute(
            "INSERT INTO buyer_keys VALUES (?, ?, ?, ?, ?, 1)",
            (principal.tenant_id, payload.key_id, payload.buyer_id, payload.key_url, key),
        )
        receipt_id = _receipt(connection, principal.tenant_id, "key_enrolled", payload.key_id, "active")
    return {"key_id": payload.key_id, "receipt_id": receipt_id}


@app.post("/v1/keys/{key_id}/revoke")
def revoke_key(key_id: str, principal: Annotated[_Principal, Depends(_admin)]) -> dict[str, str]:
    with _transaction() as connection:
        changed = connection.execute(
            "UPDATE buyer_keys SET active=0 WHERE tenant_id=? AND key_id=? AND active=1",
            (principal.tenant_id, key_id),
        ).rowcount
        if not changed:
            raise HTTPException(404, "buyer key not found")
        receipt_id = _receipt(connection, principal.tenant_id, "key_revoked", key_id, "revoked")
    return {"key_id": key_id, "receipt_id": receipt_id}


@app.post("/v1/cards", status_code=201)
def register_card(payload: _CardInput, principal: Annotated[_Principal, Depends(_admin)]) -> dict[str, str]:
    card = payload.card
    buyer = card.get("buyer")
    decision = card.get("decision")
    buyer_id = buyer.get("id") if isinstance(buyer, dict) else None
    card_status = decision.get("status") if isinstance(decision, dict) else None
    if card_status not in {"approved", "approved-with-conditions"} or not isinstance(buyer_id, str):
        raise HTTPException(400, "pilot requires a signed positive Decision Card")
    with _transaction() as connection:
        key = connection.execute(
            "SELECT * FROM buyer_keys WHERE tenant_id=? AND key_id=? AND active=1",
            (principal.tenant_id, payload.key_id),
        ).fetchone()
        if key is None or key["buyer_id"] != buyer_id:
            raise HTTPException(400, "no active buyer key binding")
        try:
            bundle = policy_bundle_from_decision_card(
                card,
                allowed_actions=["use"],
                attestation=payload.attestation,
                trusted_key_url=key["key_url"],
                trusted_public_key=key["public_key"],
            )
            scope = bundle.card_scope
            if scope is None or bundle.effective_until is None:
                raise ValueError("card has no positive runtime scope")
            now = datetime.now(UTC)
            signed_at = datetime.fromisoformat(payload.attestation.signed_at.replace("Z", "+00:00"))
            if bundle.effective_until <= now or bundle.effective_until > signed_at + timedelta(
                days=_MAX_CARD_DAYS
            ):
                raise ValueError("pilot approval lifetime is outside its bounds")
            digest = "sha256:" + hashlib.sha256(rfc8785.dumps(card)).hexdigest()
        except (ValueError, ValidationError, rfc8785.CanonicalizationError) as err:
            raise HTTPException(400, "invalid Decision Card or attestation") from err
        existing = connection.execute(
            "SELECT 1 FROM cards WHERE tenant_id=? AND bundle_id=?",
            (principal.tenant_id, bundle.bundle_id),
        ).fetchone()
        if existing:
            raise HTTPException(409, "Decision Card bundle already exists")
        connection.execute(
            "INSERT INTO cards VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (
                principal.tenant_id,
                bundle.bundle_id,
                buyer_id,
                payload.key_id,
                scope.vendor_id,
                digest,
                bundle.model_dump_json(),
                json.dumps(scope.condition_ids),
                datetime.now(UTC).isoformat(),
            ),
        )
        receipt_id = _receipt(connection, principal.tenant_id, "card_registered", bundle.bundle_id, "active")
    return {"bundle_id": bundle.bundle_id, "card_hash": digest, "receipt_id": receipt_id}


@app.post("/v1/bundles/{bundle_id}/revoke")
def revoke_card(bundle_id: str, principal: Annotated[_Principal, Depends(_admin)]) -> dict[str, str]:
    with _transaction() as connection:
        changed = connection.execute(
            "UPDATE cards SET active=0 WHERE tenant_id=? AND bundle_id=? AND active=1",
            (principal.tenant_id, bundle_id),
        ).rowcount
        if not changed:
            raise HTTPException(404, "bundle not found")
        receipt_id = _receipt(connection, principal.tenant_id, "card_revoked", bundle_id, "revoked")
    return {"bundle_id": bundle_id, "receipt_id": receipt_id}


@app.put("/v1/bundles/{bundle_id}/conditions/{condition_id}")
def assert_condition(
    bundle_id: str,
    condition_id: str,
    payload: _ConditionInput,
    principal: Annotated[_Principal, Depends(_admin)],
) -> dict[str, str]:
    now = datetime.now(UTC)
    if payload.valid_until.tzinfo is None or not now < payload.valid_until <= now + timedelta(days=7):
        raise HTTPException(400, "condition assertion must expire within seven days")
    with _transaction() as connection:
        card = connection.execute(
            "SELECT condition_ids_json, active FROM cards WHERE tenant_id=? AND bundle_id=?",
            (principal.tenant_id, bundle_id),
        ).fetchone()
        if card is None or not card["active"] or condition_id not in json.loads(card["condition_ids_json"]):
            raise HTTPException(404, "card condition not found")
        connection.execute(
            "INSERT INTO conditions VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(tenant_id, bundle_id, condition_id) DO UPDATE SET "
            "satisfied=excluded.satisfied, valid_until=excluded.valid_until",
            (
                principal.tenant_id,
                bundle_id,
                condition_id,
                int(payload.satisfied),
                payload.valid_until.isoformat(),
            ),
        )
        receipt_id = _receipt(connection, principal.tenant_id, "condition_asserted", bundle_id, "recorded")
    return {"bundle_id": bundle_id, "condition_id": condition_id, "receipt_id": receipt_id}


async def _empty_evaluation_body(request: Request) -> None:
    if (
        request.headers.get("content-length") not in {None, "0"}
        or request.headers.get("transfer-encoding")
        or await request.body()
    ):
        raise HTTPException(400, "evaluation context must come from the signed assertion")


@app.post("/v1/bundles/{bundle_id}/evaluate")
def evaluate(
    bundle_id: str,
    principal: Annotated[_Principal, Depends(_evaluator)],
    _body: Annotated[None, Depends(_empty_evaluation_body)],
) -> dict[str, str]:
    with _transaction() as connection:
        card = connection.execute(
            "SELECT cards.*, buyer_keys.active AS key_active, buyer_keys.buyer_id AS key_buyer_id "
            "FROM cards JOIN buyer_keys "
            "ON cards.tenant_id=buyer_keys.tenant_id AND cards.key_id=buyer_keys.key_id "
            "WHERE cards.tenant_id=? AND cards.bundle_id=?",
            (principal.tenant_id, bundle_id),
        ).fetchone()
        if card is None:
            raise HTTPException(404, "bundle not found")
        outcome = "deny"
        reason = "pilot_denied"
        if not card["active"] or not card["key_active"] or card["buyer_id"] != card["key_buyer_id"]:
            reason = "revoked"
        elif not _allow_enabled():
            reason = "deny_all"
        else:
            try:
                bundle = PolicyBundle.model_validate_json(card["bundle_json"])
                condition_ids = json.loads(card["condition_ids_json"])
                satisfied: dict[str, bool] = {}
                now = datetime.now(UTC)
                for condition_id in condition_ids:
                    row = connection.execute(
                        "SELECT satisfied, valid_until FROM conditions WHERE "
                        "tenant_id=? AND bundle_id=? AND condition_id=?",
                        (principal.tenant_id, bundle_id, condition_id),
                    ).fetchone()
                    satisfied[condition_id] = bool(
                        row and row["satisfied"] and datetime.fromisoformat(row["valid_until"]) > now
                    )
                context = EvaluationContext(
                    subject={"id": principal.subject_id},
                    action=principal.action,
                    resource={"vendor_id": principal.vendor_id},
                    data={"conditions_satisfied": satisfied},
                )
                decision = PolicyEvaluator().evaluate(bundle, context).decision.kind
                if decision == "allow":
                    outcome = "allow"
                    reason = "approved_scope"
                else:
                    reason = "out_of_scope_or_condition"
            except (ValueError, ValidationError, TypeError, KeyError) as err:
                raise HTTPException(503, "pilot policy state invalid") from err
        receipt_id = _receipt(connection, principal.tenant_id, "evaluation", bundle_id, outcome)
    return {"decision": outcome, "reason_code": reason, "receipt_id": receipt_id}


@app.get("/v1/receipts")
def list_receipts(principal: Annotated[_Principal, Depends(_admin)]) -> dict[str, list[dict[str, str]]]:
    connection = _open_db()
    try:
        _check_schema(connection)
        rows = connection.execute(
            "SELECT receipt_id, event, subject_ref, outcome, occurred_at FROM receipts "
            "WHERE tenant_id=? ORDER BY occurred_at DESC LIMIT 100",
            (principal.tenant_id,),
        ).fetchall()
    except sqlite3.Error as err:
        raise HTTPException(503, "pilot state unavailable") from err
    finally:
        connection.close()
    return {"receipts": [dict(row) for row in rows]}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("policy_as_code_engine.pilot_app:app", host="127.0.0.1", port=8090)
