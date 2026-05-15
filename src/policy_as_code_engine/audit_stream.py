"""
Optional audit-stream-py integration.

When the `AUDIT_STREAM_URL` env var is set, this module fires governance
events at `{AUDIT_STREAM_URL}/events` for the moments the service produces.
Best-effort: a failed POST is logged, not raised — audit-stream outages
must never block policy registration or evaluation.

Event kinds this service emits:
    policy_bundle_registered    on POST /bundles (any successful registration,
                                including the from-decision-card bridge)
    request_allowed             on POST /bundles/{id}/evaluate when the bundle
                                decision is "allow"
    request_denied              on the same endpoint when the bundle decision
                                is "deny"

Same opt-in pattern as procurement-decision-api.audit_stream and
aeo-validator-service.audit_stream. Identical config envvars.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

DEFAULT_TIMEOUT_S = 2.5


def is_enabled() -> bool:
    """True when AUDIT_STREAM_URL is set to a non-empty value."""
    return bool(os.environ.get("AUDIT_STREAM_URL", "").strip())


def base_url() -> str | None:
    """Stripped audit-stream base URL, or None when disabled."""
    raw = os.environ.get("AUDIT_STREAM_URL", "").strip()
    if not raw:
        return None
    return raw.rstrip("/")


def timeout_s() -> float:
    """Configured per-call timeout. Defaults to 2.5s."""
    raw = os.environ.get("AUDIT_STREAM_TIMEOUT_S", "").strip()
    if not raw:
        return DEFAULT_TIMEOUT_S
    try:
        return max(0.1, float(raw))
    except ValueError:
        return DEFAULT_TIMEOUT_S


async def emit(
    client: httpx.AsyncClient,
    *,
    kind: str,
    payload: dict[str, Any],
) -> None:
    """Fire one event. Silent no-op when AUDIT_STREAM_URL is unset."""
    url = base_url()
    if url is None:
        return

    body = {
        "kind": kind,
        "source": "policy-as-code-engine",
        "payload": payload,
    }
    try:
        response = await client.post(
            f"{url}/events",
            json=body,
            timeout=timeout_s(),
        )
        response.raise_for_status()
    except (httpx.HTTPError, OSError) as err:
        print(
            f"audit-stream emit failed (kind={kind}): {type(err).__name__}: {err}",
            flush=True,
        )
