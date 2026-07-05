"""Tests for HTTP client factory and context-manager helpers."""

import asyncio

import pytest

import eve_auth_manager.helpers.http_session_factory as http_session_factory


def test_config_http_client_passes_user_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Synchronous client factory should pass the User-Agent header through."""
    created: dict[str, object] = {}

    class FakeClient:
        def __init__(self, *, headers: dict[str, str]) -> None:
            created["headers"] = headers

    monkeypatch.setattr(http_session_factory, "Client", FakeClient)

    client = http_session_factory.config_http_client("custom-agent")

    assert isinstance(client, FakeClient)
    assert created["headers"] == {"User-Agent": "custom-agent"}


def test_config_async_http_client_passes_user_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async client factory should pass the User-Agent header through."""
    created: dict[str, object] = {}

    class FakeAsyncClient:
        def __init__(self, *, headers: dict[str, str]) -> None:
            created["headers"] = headers

    monkeypatch.setattr(http_session_factory, "AsyncClient", FakeAsyncClient)

    client = asyncio.run(http_session_factory.config_async_http_client("custom-agent"))

    assert isinstance(client, FakeAsyncClient)
    assert created["headers"] == {"User-Agent": "custom-agent"}


def test_client_manager_yields_client_and_closes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Synchronous client manager should always close the created client."""
    events: list[str] = []

    class FakeClient:
        def close(self) -> None:
            events.append("close")

    fake_client = FakeClient()
    monkeypatch.setattr(
        http_session_factory,
        "config_http_client",
        lambda user_agent: events.append(f"config:{user_agent}") or fake_client,
    )

    with http_session_factory.client_manager("custom-agent") as client:
        events.append("yield")
        assert client is fake_client

    assert events == ["config:custom-agent", "yield", "close"]


def test_client_manager_closes_client_after_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Synchronous client manager should close the client even on error."""
    events: list[str] = []

    class FakeClient:
        def close(self) -> None:
            events.append("close")

    fake_client = FakeClient()
    monkeypatch.setattr(
        http_session_factory,
        "config_http_client",
        lambda user_agent: fake_client,
    )

    with pytest.raises(RuntimeError, match="boom"):
        with http_session_factory.client_manager() as client:
            assert client is fake_client
            raise RuntimeError("boom")

    assert events == ["close"]


def test_async_client_manager_yields_client_and_closes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async client manager should always close the created async client."""
    events: list[str] = []

    class FakeAsyncClient:
        async def aclose(self) -> None:
            events.append("aclose")

    fake_client = FakeAsyncClient()

    async def fake_config(user_agent: str) -> FakeAsyncClient:
        events.append(f"config:{user_agent}")
        return fake_client

    monkeypatch.setattr(http_session_factory, "config_async_http_client", fake_config)

    async def runner() -> None:
        async with http_session_factory.async_client_manager("custom-agent") as client:
            events.append("yield")
            assert client is fake_client

    asyncio.run(runner())
    assert events == ["config:custom-agent", "yield", "aclose"]


def test_async_client_manager_closes_client_after_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async client manager should close the client even on error."""
    events: list[str] = []

    class FakeAsyncClient:
        async def aclose(self) -> None:
            events.append("aclose")

    fake_client = FakeAsyncClient()

    async def fake_config(user_agent: str) -> FakeAsyncClient:
        return fake_client

    monkeypatch.setattr(http_session_factory, "config_async_http_client", fake_config)

    async def runner() -> None:
        async with http_session_factory.async_client_manager() as client:
            assert client is fake_client
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        asyncio.run(runner())

    assert events == ["aclose"]
