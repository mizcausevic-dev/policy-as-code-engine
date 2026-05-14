"""
FastAPI app — five endpoints.

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

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from threading import Lock
from typing import Any

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, ValidationError

from . import __version__
from .evaluator import PolicyEvaluator
from .from_decision_card import policy_bundle_from_decision_card
from .models import EvaluationContext, EvaluationResult, PolicyBundle


class _BundleStore:
    """Thread-safe in-memory bundle store."""

    __slots__ = ("_bundles", "_lock")

    def __init__(self) -> None:
        self._bundles: dict[str, PolicyBundle] = {}
        self._lock = Lock()

    def put(self, bundle: PolicyBundle) -> None:
        with self._lock:
            self._bundles[bundle.bundle_id] = bundle

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


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.store = _BundleStore()
    app.state.evaluator = PolicyEvaluator()
    try:
        yield
    finally:
        pass


app = FastAPI(
    title="policy-as-code-engine",
    version=__version__,
    description=(
        "Declarative policy-as-code evaluator. Pairs with procurement-decision-api: "
        "drafted Decision Cards become enforceable PolicyBundles via "
        "POST /bundles/from-decision-card."
    ),
    lifespan=_lifespan,
)


def _store() -> _BundleStore:
    """Typed accessor for app.state.store — keeps mypy strict happy."""
    store = app.state.store
    assert isinstance(store, _BundleStore)
    return store


def _evaluator() -> PolicyEvaluator:
    evaluator = app.state.evaluator
    assert isinstance(evaluator, PolicyEvaluator)
    return evaluator


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


@app.get("/bundles", tags=["bundles"])
async def list_bundles() -> dict[str, list[str]]:
    return {"bundle_ids": _store().list_ids()}


@app.post("/bundles", tags=["bundles"], status_code=201)
async def register_bundle(bundle: PolicyBundle) -> dict[str, str]:
    _store().put(bundle)
    return {"bundle_id": bundle.bundle_id, "status": "registered"}


@app.get("/bundles/{bundle_id}", tags=["bundles"])
async def get_bundle(bundle_id: str) -> PolicyBundle:
    try:
        return _store().get(bundle_id)
    except KeyError as err:
        raise HTTPException(status_code=404, detail=f"unknown bundle: {bundle_id!r}") from err


@app.post("/bundles/{bundle_id}/evaluate", tags=["evaluate"])
async def evaluate_registered(bundle_id: str, context: EvaluationContext) -> EvaluationResult:
    try:
        bundle = _store().get(bundle_id)
    except KeyError as err:
        raise HTTPException(status_code=404, detail=f"unknown bundle: {bundle_id!r}") from err
    return _evaluator().evaluate(bundle, context)


@app.post("/evaluate", tags=["evaluate"])
async def evaluate_oneshot(request: _OneShotRequest) -> EvaluationResult:
    return _evaluator().evaluate(request.bundle, request.context)


@app.post("/bundles/from-decision-card", tags=["bridge"], status_code=201)
async def bundle_from_decision_card(card: dict[str, Any]) -> PolicyBundle:
    """
    Translate a Kinetic Gain Procurement Decision Card into a PolicyBundle
    and register it. This is the cross-ecosystem hook.
    """
    try:
        bundle = policy_bundle_from_decision_card(card)
    except (ValueError, ValidationError) as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err
    _store().put(bundle)
    return bundle
