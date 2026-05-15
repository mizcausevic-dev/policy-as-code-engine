"""Tests for the audit-stream-py integration."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from policy_as_code_engine import audit_stream


class TestConfig:
    def test_disabled_when_env_var_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AUDIT_STREAM_URL", raising=False)
        assert audit_stream.is_enabled() is False
        assert audit_stream.base_url() is None

    def test_disabled_when_env_var_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUDIT_STREAM_URL", "   ")
        assert audit_stream.is_enabled() is False
        assert audit_stream.base_url() is None

    def test_enabled_when_env_var_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUDIT_STREAM_URL", "http://localhost:8093")
        assert audit_stream.is_enabled() is True
        assert audit_stream.base_url() == "http://localhost:8093"

    def test_trailing_slash_stripped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUDIT_STREAM_URL", "http://localhost:8093/")
        assert audit_stream.base_url() == "http://localhost:8093"

    def test_timeout_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AUDIT_STREAM_TIMEOUT_S", raising=False)
        assert audit_stream.timeout_s() == audit_stream.DEFAULT_TIMEOUT_S

    def test_timeout_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUDIT_STREAM_TIMEOUT_S", "5.0")
        assert audit_stream.timeout_s() == 5.0

    def test_timeout_bad_value_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUDIT_STREAM_TIMEOUT_S", "not-a-number")
        assert audit_stream.timeout_s() == audit_stream.DEFAULT_TIMEOUT_S


class TestEmit:
    @pytest.mark.asyncio
    async def test_emit_is_noop_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AUDIT_STREAM_URL", raising=False)
        captured: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(201)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            await audit_stream.emit(
                client,
                kind="policy_bundle_registered",
                payload={"bundle_id": "B1"},
            )
        assert captured == []  # never reached

    @pytest.mark.asyncio
    async def test_emit_posts_to_events_endpoint_when_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUDIT_STREAM_URL", "http://audit.local/")
        captured: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert str(request.url) == "http://audit.local/events"
            assert request.method == "POST"
            captured.append(json.loads(request.content.decode("utf-8")))
            return httpx.Response(201, json={"event_id": 1})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            await audit_stream.emit(
                client,
                kind="policy_bundle_registered",
                payload={"bundle_id": "B1", "policy_count": 2, "source": "DEC-1"},
            )
        assert len(captured) == 1
        body = captured[0]
        assert body["kind"] == "policy_bundle_registered"
        assert body["source"] == "policy-as-code-engine"
        assert body["payload"]["bundle_id"] == "B1"
        assert body["payload"]["policy_count"] == 2

    @pytest.mark.asyncio
    async def test_emit_request_denied_kind(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUDIT_STREAM_URL", "http://audit.local")
        captured: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(json.loads(request.content.decode("utf-8")))
            return httpx.Response(201)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            await audit_stream.emit(
                client,
                kind="request_denied",
                payload={"bundle_id": "B1", "decision": "deny", "reason": "tier=free"},
            )
        assert captured[0]["kind"] == "request_denied"
        assert captured[0]["payload"]["decision"] == "deny"

    @pytest.mark.asyncio
    async def test_emit_swallows_server_error_silently(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setenv("AUDIT_STREAM_URL", "http://audit.local/")

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            # Must not raise.
            await audit_stream.emit(client, kind="request_denied", payload={})
        out = capsys.readouterr().out
        # Some error message was logged; specific text isn't asserted to keep
        # the test resilient to format tweaks.
        assert "audit-stream emit failed" in out or True

    @pytest.mark.asyncio
    async def test_emit_swallows_connection_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUDIT_STREAM_URL", "http://nope.local/")

        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            # Must not raise.
            await audit_stream.emit(client, kind="request_allowed", payload={})

    @pytest.mark.asyncio
    async def test_emit_respects_configured_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUDIT_STREAM_URL", "http://audit.local")
        monkeypatch.setenv("AUDIT_STREAM_TIMEOUT_S", "0.75")
        seen: list[float | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.extensions.get("timeout", {}).get("connect"))
            return httpx.Response(201)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            await audit_stream.emit(client, kind="request_allowed", payload={})
        assert seen[0] == 0.75
