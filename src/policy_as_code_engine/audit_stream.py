"""
Optional audit-stream-py integration.

When `AUDIT_STREAM_URL` is set to the sink base URL (or its `/events`
endpoint), this module fires governance events at the normalized endpoint.
`AUDIT_STREAM_TOKEN` supplies the sink's bearer credential.
Best-effort: a failed POST is logged, not raised — audit-stream outages
must never block policy registration or evaluation.

Event kinds this service emits:
    policy_bundle_registered    on POST /bundles (any successful registration,
                                including the from-decision-card bridge)
    request_allowed             on POST /bundles/{id}/evaluate when the bundle
                                decision is "allow"
    request_denied              on the same endpoint when the bundle decision
                                is "deny"
    policy_condition_asserted   on a successful admin condition assertion

The sink contract is aligned with procurement-decision-api.audit_stream.
"""

from __future__ import annotations

import math
import os
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

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


def events_url() -> str | None:
    """Normalize a sink base or exact `/events` URL without forwarding URL credentials."""
    raw = base_url()
    if raw is None:
        return None
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    path = parsed.path.rstrip("/")
    if not path.endswith("/events"):
        path += "/events"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def audit_token() -> str | None:
    """Return only a token accepted by the sink's configured-token syntax."""
    token = os.environ.get("AUDIT_STREAM_TOKEN", "")
    return token if re.fullmatch(r"[!-~]{32,}", token) else None


def timeout_s() -> float:
    """Configured per-call timeout. Defaults to 2.5s."""
    raw = os.environ.get("AUDIT_STREAM_TIMEOUT_S", "").strip()
    if not raw:
        return DEFAULT_TIMEOUT_S
    try:
        parsed = float(raw)
        return min(10.0, max(0.1, parsed)) if math.isfinite(parsed) else DEFAULT_TIMEOUT_S
    except ValueError:
        return DEFAULT_TIMEOUT_S


async def emit(
    client: httpx.AsyncClient,
    *,
    kind: str,
    payload: dict[str, Any],
) -> None:
    """Fire one event. Silent no-op when AUDIT_STREAM_URL is unset."""
    if not is_enabled():
        return
    url = events_url()
    token = audit_token()
    if url is None or token is None:
        print(f"audit-stream emit failed (kind={kind}): InvalidConfiguration", flush=True)
        return

    body = {
        "kind": kind,
        "source": "policy-as-code-engine",
        "payload": payload,
    }
    try:
        response = await client.post(
            url,
            json=body,
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout_s(),
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as err:
        print(
            f"audit-stream emit failed (kind={kind}): HTTPStatusError status={err.response.status_code}",
            flush=True,
        )
    except (httpx.HTTPError, OSError) as err:
        print(
            f"audit-stream emit failed (kind={kind}): {type(err).__name__}",
            flush=True,
        )
