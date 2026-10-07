"""
FastAPI app for local bundle registration and evaluation.

  GET  /                              service info
  GET  /healthz                       liveness probe
  POST /bundles                       register a PolicyBundle (in-memory)
  GET  /bundles/{bundle_id}           inspect a registered bundle
  POST /bundles/{bundle_id}/evaluate  evaluate it against a context
  POST /evaluate                      one-shot: bundle + context in, decision out
  POST /bundles/from-decision-card    build a bundle from a Decision Card

Bundles are held in process memory by default; restart-safe storage is a
caller responsibility. Wire a Redis / Postgres backend by replacing the
`_BundleStore` instance in `lifespan`.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any

import httpx
import rfc8785
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from pydantic import AwareDatetime, BaseModel, StrictBool, ValidationError
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import __version__, audit_stream
from .card_attestation import CardAttestation
from .evaluator import PolicyEvaluator
from .from_decision_card import policy_bundle_from_decision_card
from .models import EvaluationContext, EvaluationResult, PolicyBundle, StrictModel

MAX_BODY_READ_SECONDS = 10.0


class _BundleStore:
    """Thread-safe in-memory bundle store."""

    __slots__ = ("_bundles", "_conditions", "_lock")

    def __init__(self) -> None:
        self._bundles: dict[str, PolicyBundle] = {}
        self._conditions: dict[tuple[str, str], tuple[bool, datetime]] = {}
        self._lock = Lock()

    def put(self, bundle: PolicyBundle) -> None:
        with self._lock:
            if bundle.bundle_id in self._bundles:
                raise ValueError("bundle ID is already registered")
            if len(self._bundles) >= 256:
                raise OverflowError("bundle store is full")
            self._bundles[bundle.bundle_id] = bundle

    def set_condition(self, bundle_id: str, condition_id: str, satisfied: bool, until: datetime) -> None:
        with self._lock:
            self._conditions[(bundle_id, condition_id)] = (satisfied, until)

    def condition_snapshot(self, bundle_id: str, condition_ids: list[str]) -> dict[str, bool]:
        now = datetime.now(UTC)
        with self._lock:
            return {
                cid: True
                for cid in condition_ids
                if (entry := self._conditions.get((bundle_id, cid))) is not None
                and entry[0] is True
                and entry[1] > now
            }

    def get(self, bundle_id: str) -> PolicyBundle:
        with self._lock:
            try:
                return self._bundles[bundle_id]
            except KeyError as err:
                raise KeyError(bundle_id) from err

    def list_ids(self) -> list[str]:
        with self._lock:
            return list(self._bundles.keys())


class _OneShotRequest(BaseModel):
    bundle: PolicyBundle
    context: EvaluationContext


class _CardRegistrationRequest(StrictModel):
    card: dict[str, Any]
    attestation: CardAttestation | None = None
    allowed_actions: list[str] | None = None


class _ConditionAssertion(StrictModel):
    satisfied: StrictBool
    valid_until: AwareDatetime


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON object key")
        obj[key] = value
    return obj


def _reject_nonfinite_number(_value: str) -> None:
    raise ValueError("non-finite JSON number")


class _RequestBoundary:
    """Cap API payloads and preserve signed-card JSON semantics before parsing."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        body = bytearray()
        try:
            async with asyncio.timeout(MAX_BODY_READ_SECONDS):
                while True:
                    message = await receive()
                    if message["type"] != "http.request":
                        return
                    body.extend(message.get("body", b""))
                    if len(body) > 131_072:
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
        if scope["path"] == "/bundles/from-decision-card":
            try:
                parsed = json.loads(
                    body.decode("utf-8"),
                    object_pairs_hook=_reject_duplicate_keys,
                    parse_constant=_reject_nonfinite_number,
                )
                rfc8785.dumps(parsed)
            except (UnicodeDecodeError, ValueError, rfc8785.CanonicalizationError):
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


class _NoStore:
    """Prevent caching of protected policy material."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not (
            scope["path"].startswith("/bundles") or scope["path"] == "/evaluate"
        ):
            await self.app(scope, receive, send)
            return

        async def with_no_store(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, with_no_store)


def _trusted_buyer_key(buyer_id: str, key_url: str) -> bytes:
    """Read a pinned buyer key from operator configuration, never from a card."""
    try:
        mapping = json.loads(os.environ.get("POLICY_ENGINE_BUYER_KEYS_JSON", ""))
        public_key = mapping[buyer_id][key_url]
        if not isinstance(public_key, str):
            raise ValueError("invalid key")
        key_bytes = base64.b64decode(public_key, validate=True)
        if len(key_bytes) != 32:
            raise ValueError("invalid key length")
        return key_bytes
    except (ValueError, KeyError, TypeError, AttributeError) as err:
        raise HTTPException(status_code=503, detail="trusted buyer key is not configured") from err


def _put_bundle(bundle: PolicyBundle) -> None:
    try:
        _store().put(bundle)
    except ValueError as err:
        raise HTTPException(status_code=409, detail=str(err)) from err
    except OverflowError as err:
        raise HTTPException(status_code=503, detail=str(err)) from err


def _configured_tokens() -> tuple[str, str]:
    admin = os.environ.get("POLICY_ENGINE_ADMIN_TOKEN", "")
    evaluator = os.environ.get("POLICY_ENGINE_EVALUATE_TOKEN", "")
    if (
        not 32 <= len(admin) <= 256
        or not 32 <= len(evaluator) <= 256
        or not admin.isascii()
        or not evaluator.isascii()
        or secrets.compare_digest(admin, evaluator)
    ):
        raise HTTPException(status_code=503, detail="policy engine API credentials are not configured")
    return admin, evaluator


def _authorize(request: Request, *, admin_only: bool) -> None:
    admin, evaluator = _configured_tokens()
    scheme, separator, token = request.headers.get("authorization", "").partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=401, detail="bearer token required", headers={"WWW-Authenticate": "Bearer"}
        )
    if len(token) > 256 or not token.isascii():
        raise HTTPException(status_code=403, detail="token is not authorized for this operation")
    allowed = secrets.compare_digest(token, admin)
    if not admin_only:
        allowed = allowed or secrets.compare_digest(token, evaluator)
    if not allowed:
        raise HTTPException(status_code=403, detail="token is not authorized for this operation")


def _require_admin(request: Request) -> None:
    _authorize(request, admin_only=True)


def _require_evaluator(request: Request) -> None:
    _authorize(request, admin_only=False)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.store = _BundleStore()
    app.state.evaluator = PolicyEvaluator()
    # Shared httpx client for best-effort audit-stream emission. Always
    # created; the audit_stream module no-ops when AUDIT_STREAM_URL is unset.
    app.state.http_client = httpx.AsyncClient(
        headers={"User-Agent": f"policy-as-code-engine/{__version__} (+https://kineticgain.com)"},
        trust_env=False,
    )
    try:
        yield
    finally:
        await app.state.http_client.aclose()


app = FastAPI(
    title="policy-as-code-engine",
    version=__version__,
    description=(
        "Declarative policy-as-code evaluator. Pairs with procurement-decision-api: "
        "Decision Card fields can be converted into PolicyBundles via "
        "POST /bundles/from-decision-card."
    ),
    lifespan=_lifespan,
)
app.add_middleware(_RequestBoundary)
app.add_middleware(_NoStore)


@app.exception_handler(RequestValidationError)
async def _request_validation_error(_request: Request, _error: RequestValidationError) -> JSONResponse:
    return JSONResponse({"detail": "invalid request"}, status_code=422)


def _store() -> _BundleStore:
    """Typed accessor for app.state.store — keeps mypy strict happy."""
    store = app.state.store
    assert isinstance(store, _BundleStore)
    return store


def _evaluator() -> PolicyEvaluator:
    evaluator = app.state.evaluator
    assert isinstance(evaluator, PolicyEvaluator)
    return evaluator


def _with_trusted_conditions(bundle: PolicyBundle, context: EvaluationContext) -> EvaluationContext:
    scope = bundle.card_scope
    if scope is None:
        return context
    if "conditions_satisfied" in context.data:
        raise HTTPException(
            status_code=400,
            detail="Decision Card conditions must come from admin assertions, not evaluation input",
        )
    if not scope.condition_ids:
        return context
    data = {
        **context.data,
        "conditions_satisfied": _store().condition_snapshot(bundle.bundle_id, scope.condition_ids),
    }
    return context.model_copy(update={"data": data})


def _http_client() -> httpx.AsyncClient:
    """Shared httpx client used by audit_stream.emit (best-effort)."""
    client = app.state.http_client
    assert isinstance(client, httpx.AsyncClient)
    return client


@app.get("/", tags=["meta"])
async def root() -> dict[str, Any]:
    return {
        "name": "policy-as-code-engine",
        "version": __version__,
        "description": (
            "Evaluates declarative policy bundles against arbitrary request contexts. "
            "Bridges to the Kinetic Gain Protocol Suite via /bundles/from-decision-card."
        ),
        "endpoints": {
            "GET  /": "this page",
            "GET  /healthz": "liveness probe",
            "GET  /bundles": "list registered bundle IDs",
            "POST /bundles": "register a PolicyBundle",
            "GET  /bundles/{bundle_id}": "fetch a registered bundle",
            "POST /bundles/{bundle_id}/evaluate": "evaluate a stored bundle against a context",
            "POST /evaluate": "one-shot: bundle + context in, decision out",
            "POST /bundles/from-decision-card": "build a bundle from a Decision Card",
        },
    }


@app.get("/healthz", tags=["meta"])
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/bundles", tags=["bundles"], dependencies=[Depends(_require_admin)])
async def list_bundles() -> dict[str, list[str]]:
    return {"bundle_ids": _store().list_ids()}


@app.post("/bundles", tags=["bundles"], status_code=201, dependencies=[Depends(_require_admin)])
async def register_bundle(bundle: PolicyBundle) -> dict[str, str]:
    _put_bundle(bundle)
    await audit_stream.emit(
        _http_client(),
        kind="policy_bundle_registered",
        payload={
            "bundle_id": bundle.bundle_id,
            "policy_count": len(bundle.policies),
        },
    )
    return {"bundle_id": bundle.bundle_id, "status": "registered"}


@app.get("/bundles/{bundle_id}", tags=["bundles"], dependencies=[Depends(_require_admin)])
async def get_bundle(bundle_id: str) -> PolicyBundle:
    try:
        return _store().get(bundle_id)
    except KeyError as err:
        raise HTTPException(status_code=404, detail="unknown bundle") from err


@app.put(
    "/bundles/{bundle_id}/conditions/{condition_id}",
    tags=["bridge"],
    dependencies=[Depends(_require_admin)],
)
async def assert_condition(
    bundle_id: str, condition_id: str, assertion: _ConditionAssertion
) -> dict[str, str]:
    try:
        bundle = _store().get(bundle_id)
    except KeyError as err:
        raise HTTPException(status_code=404, detail="unknown bundle") from err
    if bundle.card_scope is None or condition_id not in bundle.card_scope.condition_ids:
        raise HTTPException(status_code=404, detail="unknown card condition")
    now = datetime.now(UTC)
    if assertion.valid_until <= now or assertion.valid_until > now + timedelta(days=7):
        raise HTTPException(status_code=400, detail="condition assertion must expire within seven days")
    _store().set_condition(bundle_id, condition_id, assertion.satisfied, assertion.valid_until)
    await audit_stream.emit(
        _http_client(),
        kind="policy_condition_asserted",
        payload={
            "bundle_id": bundle_id,
            "condition_id": condition_id,
            "satisfied": assertion.satisfied,
            "valid_until": assertion.valid_until.isoformat(),
        },
    )
    return {"bundle_id": bundle_id, "condition_id": condition_id, "status": "asserted"}


async def _emit_decision(bundle_id: str, result: EvaluationResult) -> None:
    """Emit request_allowed / request_denied; skip on not_applicable."""
    kind_map = {"allow": "request_allowed", "deny": "request_denied"}
    event_kind = kind_map.get(result.decision.kind)
    if event_kind is None:
        return
    await audit_stream.emit(
        _http_client(),
        kind=event_kind,
        payload={
            "bundle_id": bundle_id,
            "decision": result.decision.kind,
            "matched_policy_id": result.decision.matched_policy_id,
            "matched_rule_id": result.decision.matched_rule_id,
        },
    )


@app.post("/bundles/{bundle_id}/evaluate", tags=["evaluate"], dependencies=[Depends(_require_evaluator)])
async def evaluate_registered(bundle_id: str, context: EvaluationContext) -> EvaluationResult:
    try:
        bundle = _store().get(bundle_id)
    except KeyError as err:
        raise HTTPException(status_code=404, detail="unknown bundle") from err
    context = _with_trusted_conditions(bundle, context)
    result = _evaluator().evaluate(bundle, context)
    await _emit_decision(bundle.bundle_id, result)
    return result


@app.post("/evaluate", tags=["evaluate"], dependencies=[Depends(_require_admin)])
async def evaluate_oneshot(request: _OneShotRequest) -> EvaluationResult:
    context = _with_trusted_conditions(request.bundle, request.context)
    result = _evaluator().evaluate(request.bundle, context)
    await _emit_decision(request.bundle.bundle_id, result)
    return result


@app.post(
    "/bundles/from-decision-card", tags=["bridge"], status_code=201, dependencies=[Depends(_require_admin)]
)
async def bundle_from_decision_card(request: _CardRegistrationRequest) -> PolicyBundle:
    """
    Translate a Kinetic Gain Procurement Decision Card into a PolicyBundle
    and register it. This is the cross-ecosystem hook.
    """
    try:
        card = request.card
        decision = card.get("decision")
        card_status = decision.get("status") if isinstance(decision, dict) else None
        trusted_public_key: bytes | None = None
        trusted_key_url: str | None = None
        if isinstance(card_status, str) and card_status in {"approved", "approved-with-conditions"}:
            if request.attestation is None:
                raise ValueError("approved Decision Cards require a trusted buyer attestation")
            if request.allowed_actions != ["use"]:
                raise ValueError("the HTTP bridge only permits allowed_actions=['use']")
            buyer = card.get("buyer")
            buyer_id = buyer.get("id") if isinstance(buyer, dict) else None
            if not isinstance(buyer_id, str) or not buyer_id.strip():
                raise ValueError("approved Decision Cards require buyer.id")
            trusted_key_url = request.attestation.key_url
            trusted_public_key = _trusted_buyer_key(buyer_id, trusted_key_url)
        bundle = policy_bundle_from_decision_card(
            card,
            allowed_actions=request.allowed_actions,
            attestation=request.attestation,
            trusted_key_url=trusted_key_url,
            trusted_public_key=trusted_public_key,
        )
    except (ValueError, ValidationError) as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid Decision Card or attestation",
        ) from err
    _put_bundle(bundle)
    await audit_stream.emit(
        _http_client(),
        kind="policy_bundle_registered",
        payload={
            "bundle_id": bundle.bundle_id,
            "policy_count": len(bundle.policies),
        },
    )
    return bundle
