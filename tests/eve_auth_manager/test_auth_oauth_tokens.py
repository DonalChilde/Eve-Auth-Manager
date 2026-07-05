"""Tests for low-level OAuth token helpers."""

import asyncio
from types import SimpleNamespace

import pytest

import eve_auth_manager.auth.oauth_tokens as oauth_tokens


class FakeHTTPError(Exception):
    """Test double for HTTP client errors."""


class FakeResponse:
    """Synchronous response double."""

    def __init__(
        self, payload, *, status_code: int = 200, error: Exception | None = None
    ):
        self._payload = payload
        self.status_code = status_code
        self._error = error

    def raise_for_status(self) -> None:
        if self._error is not None:
            raise self._error

    def json(self):
        return self._payload


class FakeSession:
    """Synchronous session double that records post calls."""

    def __init__(self, response: FakeResponse):
        self.response = response
        self.calls: list[dict[str, object]] = []

    def post(
        self, url: str, *, headers: dict[str, str], data: dict[str, str]
    ) -> FakeResponse:
        self.calls.append({"url": url, "headers": headers, "data": data})
        return self.response


class FakeAsyncResponse:
    """Asynchronous response double."""

    def __init__(
        self, payload, *, status_code: int = 200, error: Exception | None = None
    ):
        self._payload = payload
        self.status_code = status_code
        self._error = error

    def raise_for_status(self) -> None:
        if self._error is not None:
            raise self._error

    async def json(self):
        return self._payload


class FakeAsyncSession:
    """Asynchronous session double that records post calls."""

    def __init__(self, response: FakeAsyncResponse):
        self.response = response
        self.calls: list[dict[str, object]] = []

    async def post(
        self, url: str, *, headers: dict[str, str], data: dict[str, str]
    ) -> FakeAsyncResponse:
        self.calls.append({"url": url, "headers": headers, "data": data})
        return self.response


def test_oauth_token_exceptions_preserve_message() -> None:
    """Custom exception wrappers should pass messages through unchanged."""
    assert str(oauth_tokens.TokenValidationError("validation")) == "validation"
    assert str(oauth_tokens.NewTokenRequestError("new")) == "new"
    assert str(oauth_tokens.TokenRefreshError("refresh")) == "refresh"
    assert str(oauth_tokens.TokenRevocationError("revoke")) == "revoke"
    assert str(oauth_tokens.DecodeTokenError("decode")) == "decode"


def test_request_token_posts_expected_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """Token request should submit the authorization-code form payload."""
    monkeypatch.setattr(oauth_tokens, "HTTPError", FakeHTTPError)
    response = FakeResponse({"access_token": "token"})
    session = FakeSession(response)

    result = oauth_tokens.request_token(
        client_id="client-id",
        authorization_code="auth-code",
        code_verifier="verifier",
        token_endpoint="https://issuer.example/token",
        session=session,  # type: ignore[arg-type]
    )

    assert result == {"access_token": "token"}
    assert session.calls == [
        {
            "url": "https://issuer.example/token",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "data": {
                "grant_type": "authorization_code",
                "code": "auth-code",
                "client_id": "client-id",
                "code_verifier": "verifier",
            },
        }
    ]


@pytest.mark.parametrize(
    ("error", "pattern"),
    [
        (FakeHTTPError("boom"), "HTTP error during token request: boom"),
        (RuntimeError("boom"), "Unexpected error during token request: boom"),
    ],
)
def test_request_token_wraps_errors(
    monkeypatch: pytest.MonkeyPatch, error: Exception, pattern: str
) -> None:
    """Token request should map HTTP and unexpected failures to domain errors."""
    monkeypatch.setattr(oauth_tokens, "HTTPError", FakeHTTPError)
    session = FakeSession(FakeResponse({}, error=error))

    with pytest.raises(oauth_tokens.NewTokenRequestError, match=pattern):
        oauth_tokens.request_token(
            client_id="client-id",
            authorization_code="auth-code",
            code_verifier="verifier",
            token_endpoint="https://issuer.example/token",
            session=session,  # type: ignore[arg-type]
        )


def test_refresh_token_posts_expected_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """Token refresh should submit the refresh-token form payload."""
    monkeypatch.setattr(oauth_tokens, "HTTPError", FakeHTTPError)
    response = FakeResponse({"access_token": "token"})
    session = FakeSession(response)

    result = oauth_tokens.refresh_token(
        refresh_token="refresh-token",
        client_id="client-id",
        token_endpoint="https://issuer.example/token",
        session=session,  # type: ignore[arg-type]
    )

    assert result == {"access_token": "token"}
    assert session.calls[0]["data"] == {
        "client_id": "client-id",
        "grant_type": "refresh_token",
        "refresh_token": "refresh-token",
    }


@pytest.mark.parametrize(
    ("error", "pattern"),
    [
        (FakeHTTPError("boom"), "HTTP error during token refresh: boom"),
        (RuntimeError("boom"), "Unexpected error during token refresh: boom"),
    ],
)
def test_refresh_token_wraps_errors(
    monkeypatch: pytest.MonkeyPatch, error: Exception, pattern: str
) -> None:
    """Token refresh should map HTTP and unexpected failures to domain errors."""
    monkeypatch.setattr(oauth_tokens, "HTTPError", FakeHTTPError)
    session = FakeSession(FakeResponse({}, error=error))

    with pytest.raises(oauth_tokens.TokenRefreshError, match=pattern):
        oauth_tokens.refresh_token(
            refresh_token="refresh-token",
            client_id="client-id",
            token_endpoint="https://issuer.example/token",
            session=session,  # type: ignore[arg-type]
        )


def test_revoke_refresh_token_posts_expected_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Token revocation should submit the revocation form payload."""
    monkeypatch.setattr(oauth_tokens, "HTTPError", FakeHTTPError)
    response = FakeResponse({"revoked": True})
    session = FakeSession(response)

    result = oauth_tokens.revoke_refresh_token(
        refresh_token="refresh-token",
        revocation_endpoint="https://issuer.example/revoke",
        client_id="client-id",
        session=session,  # type: ignore[arg-type]
    )

    assert result == {"revoked": True}
    assert session.calls[0]["data"] == {
        "token": "refresh-token",
        "token_type_hint": "refresh_token",
        "client_id": "client-id",
    }


@pytest.mark.parametrize(
    ("error", "pattern"),
    [
        (FakeHTTPError("boom"), "HTTP error during token revocation: boom"),
        (RuntimeError("boom"), "Unexpected error during token revocation: boom"),
    ],
)
def test_revoke_refresh_token_wraps_errors(
    monkeypatch: pytest.MonkeyPatch, error: Exception, pattern: str
) -> None:
    """Token revocation should map HTTP and unexpected failures to domain errors."""
    monkeypatch.setattr(oauth_tokens, "HTTPError", FakeHTTPError)
    session = FakeSession(FakeResponse({}, error=error))

    with pytest.raises(oauth_tokens.TokenRevocationError, match=pattern):
        oauth_tokens.revoke_refresh_token(
            refresh_token="refresh-token",
            revocation_endpoint="https://issuer.example/revoke",
            client_id="client-id",
            session=session,  # type: ignore[arg-type]
        )


def test_async_request_token_requires_session() -> None:
    """Async token request should reject a missing session."""
    with pytest.raises(ValueError, match="session must be initialized"):
        asyncio.run(
            oauth_tokens.async_request_token(
                client_id="client-id",
                authorization_code="auth-code",
                code_verifier="verifier",
                token_endpoint="https://issuer.example/token",
                session=None,  # type: ignore[arg-type]
            )
        )


def test_async_request_token_posts_expected_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async token request should submit the authorization-code payload."""
    monkeypatch.setattr(oauth_tokens, "HTTPError", FakeHTTPError)
    session = FakeAsyncSession(FakeAsyncResponse({"access_token": "token"}))

    result = asyncio.run(
        oauth_tokens.async_request_token(
            client_id="client-id",
            authorization_code="auth-code",
            code_verifier="verifier",
            token_endpoint="https://issuer.example/token",
            session=session,  # type: ignore[arg-type]
        )
    )

    assert result == {"access_token": "token"}
    assert session.calls[0]["data"] == {
        "grant_type": "authorization_code",
        "code": "auth-code",
        "client_id": "client-id",
        "code_verifier": "verifier",
    }


@pytest.mark.parametrize(
    ("error", "pattern"),
    [
        (FakeHTTPError("boom"), "HTTP error during async token request: boom"),
        (RuntimeError("boom"), "Unexpected error during async token request: boom"),
    ],
)
def test_async_request_token_wraps_errors(
    monkeypatch: pytest.MonkeyPatch, error: Exception, pattern: str
) -> None:
    """Async token request should map HTTP and unexpected failures."""
    monkeypatch.setattr(oauth_tokens, "HTTPError", FakeHTTPError)
    session = FakeAsyncSession(FakeAsyncResponse({}, error=error))

    with pytest.raises(oauth_tokens.NewTokenRequestError, match=pattern):
        asyncio.run(
            oauth_tokens.async_request_token(
                client_id="client-id",
                authorization_code="auth-code",
                code_verifier="verifier",
                token_endpoint="https://issuer.example/token",
                session=session,  # type: ignore[arg-type]
            )
        )


def test_async_refresh_token_requires_session() -> None:
    """Async refresh should reject a missing session."""
    with pytest.raises(ValueError, match="session must be initialized"):
        asyncio.run(
            oauth_tokens.async_refresh_token(
                refresh_token="refresh-token",
                client_id="client-id",
                token_endpoint="https://issuer.example/token",
                session=None,  # type: ignore[arg-type]
            )
        )


def test_async_refresh_token_posts_expected_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async refresh should submit the refresh-token payload."""
    monkeypatch.setattr(oauth_tokens, "HTTPError", FakeHTTPError)
    session = FakeAsyncSession(FakeAsyncResponse({"access_token": "token"}))

    result = asyncio.run(
        oauth_tokens.async_refresh_token(
            refresh_token="refresh-token",
            client_id="client-id",
            token_endpoint="https://issuer.example/token",
            session=session,  # type: ignore[arg-type]
        )
    )

    assert result == {"access_token": "token"}
    assert session.calls[0]["data"] == {
        "client_id": "client-id",
        "grant_type": "refresh_token",
        "refresh_token": "refresh-token",
    }


@pytest.mark.parametrize(
    ("error", "pattern"),
    [
        (FakeHTTPError("boom"), "HTTP error during async token refresh: boom"),
        (RuntimeError("boom"), "Unexpected error during async token refresh: boom"),
    ],
)
def test_async_refresh_token_wraps_errors(
    monkeypatch: pytest.MonkeyPatch, error: Exception, pattern: str
) -> None:
    """Async refresh should map HTTP and unexpected failures."""
    monkeypatch.setattr(oauth_tokens, "HTTPError", FakeHTTPError)
    session = FakeAsyncSession(FakeAsyncResponse({}, error=error))

    with pytest.raises(oauth_tokens.TokenRefreshError, match=pattern):
        asyncio.run(
            oauth_tokens.async_refresh_token(
                refresh_token="refresh-token",
                client_id="client-id",
                token_endpoint="https://issuer.example/token",
                session=session,  # type: ignore[arg-type]
            )
        )


def test_async_revoke_refresh_token_posts_payload_and_accepts_non_200(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async revocation should submit payload and only log on HTTP 200."""
    monkeypatch.setattr(oauth_tokens, "HTTPError", FakeHTTPError)
    session = FakeAsyncSession(FakeAsyncResponse({}, status_code=204))

    result = asyncio.run(
        oauth_tokens.async_revoke_refresh_token(
            refresh_token="refresh-token",
            revocation_endpoint="https://issuer.example/revoke",
            client_id="client-id",
            session=session,  # type: ignore[arg-type]
        )
    )

    assert result is None
    assert session.calls[0]["data"] == {
        "token": "refresh-token",
        "token_type_hint": "refresh_token",
        "client_id": "client-id",
    }


def test_async_revoke_refresh_token_logs_success_on_http_200(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async revocation should log a success message on HTTP 200."""
    monkeypatch.setattr(oauth_tokens, "HTTPError", FakeHTTPError)
    messages: list[str] = []
    monkeypatch.setattr(
        oauth_tokens.logger, "info", lambda message: messages.append(message)
    )
    session = FakeAsyncSession(FakeAsyncResponse({}, status_code=200))

    asyncio.run(
        oauth_tokens.async_revoke_refresh_token(
            refresh_token="refresh-token",
            revocation_endpoint="https://issuer.example/revoke",
            client_id="client-id",
            session=session,  # type: ignore[arg-type]
        )
    )

    assert messages == ["Token revoked successfully"]


@pytest.mark.parametrize(
    ("error", "pattern"),
    [
        (FakeHTTPError("boom"), "HTTP error during async token revocation: boom"),
        (RuntimeError("boom"), "Unexpected error during async token revocation: boom"),
    ],
)
def test_async_revoke_refresh_token_wraps_errors(
    monkeypatch: pytest.MonkeyPatch, error: Exception, pattern: str
) -> None:
    """Async revocation should map HTTP and unexpected failures."""
    monkeypatch.setattr(oauth_tokens, "HTTPError", FakeHTTPError)
    session = FakeAsyncSession(FakeAsyncResponse({}, error=error))

    with pytest.raises(oauth_tokens.TokenRevocationError, match=pattern):
        asyncio.run(
            oauth_tokens.async_revoke_refresh_token(
                refresh_token="refresh-token",
                revocation_endpoint="https://issuer.example/revoke",
                client_id="client-id",
                session=session,  # type: ignore[arg-type]
            )
        )


def test_validate_jwt_token_uses_existing_jwks_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JWT validation should reuse a provided JWKS client."""
    calls: dict[str, object] = {}

    def get_signing_key(kid: str) -> SimpleNamespace:
        calls["kid"] = kid
        return SimpleNamespace(key="signing-key")

    def fake_decode(**kwargs):
        calls["decode"] = kwargs
        return {"sub": "CHARACTER:EVE:7"}

    jwks_client = SimpleNamespace(get_signing_key=get_signing_key)
    monkeypatch.setattr(
        oauth_tokens,
        "get_unverified_header",
        lambda token: {"kid": "kid-1", "alg": "RS256"},
    )
    monkeypatch.setattr(oauth_tokens, "decode", fake_decode)

    result = oauth_tokens.validate_jwt_token(
        access_token="jwt-token",
        jwks_client=jwks_client,  # type: ignore[arg-type]
        audience="audience",
        issuers=["https://issuer.example"],
    )

    assert result == {"sub": "CHARACTER:EVE:7"}
    assert calls["kid"] == "kid-1"
    assert calls["decode"] == {
        "jwt": "jwt-token",
        "key": "signing-key",
        "algorithms": ["RS256"],
        "audience": "audience",
        "issuer": ["https://issuer.example"],
        "options": {"verify_aud": True, "verify_iss": True},
    }


def test_validate_jwt_token_builds_jwks_client_and_warns_without_user_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JWT validation should build a client and warn when user-agent is absent."""
    warnings: list[str] = []
    created: dict[str, object] = {}

    class FakePyJWKClient:
        def __init__(self, url: str, headers: dict[str, str]) -> None:
            created["url"] = url
            created["headers"] = headers

        def get_signing_key(self, kid: str) -> SimpleNamespace:
            created["kid"] = kid
            return SimpleNamespace(key="signing-key")

    monkeypatch.setattr(oauth_tokens, "PyJWKClient", FakePyJWKClient)
    monkeypatch.setattr(
        oauth_tokens,
        "get_unverified_header",
        lambda token: {"kid": "kid-1", "alg": "RS256"},
    )
    monkeypatch.setattr(
        oauth_tokens.logger, "warning", lambda message: warnings.append(message)
    )
    monkeypatch.setattr(
        oauth_tokens, "decode", lambda **kwargs: {"sub": "CHARACTER:EVE:8"}
    )

    result = oauth_tokens.validate_jwt_token(
        access_token="jwt-token",
        jwks_client=None,
        audience="audience",
        issuers=["https://issuer.example"],
        jwks_uri="https://issuer.example/jwks",
    )

    assert result == {"sub": "CHARACTER:EVE:8"}
    assert created == {
        "url": "https://issuer.example/jwks",
        "headers": {"User-Agent": "Token validation without User-Agent"},
        "kid": "kid-1",
    }
    assert warnings == [
        "User-Agent is empty when fetching JWKS keys with PyJWKClient. It's recommended to provide a User-Agent string when fetching JWKS keys."
    ]


def test_validate_jwt_token_builds_jwks_client_with_user_agent_without_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JWT validation should skip the warning when a user-agent is supplied."""
    warnings: list[str] = []
    created: dict[str, object] = {}

    class FakePyJWKClient:
        def __init__(self, url: str, headers: dict[str, str]) -> None:
            created["url"] = url
            created["headers"] = headers

        def get_signing_key(self, kid: str) -> SimpleNamespace:
            created["kid"] = kid
            return SimpleNamespace(key="signing-key")

    monkeypatch.setattr(oauth_tokens, "PyJWKClient", FakePyJWKClient)
    monkeypatch.setattr(
        oauth_tokens,
        "get_unverified_header",
        lambda token: {"kid": "kid-2", "alg": "RS256"},
    )
    monkeypatch.setattr(
        oauth_tokens.logger, "warning", lambda message: warnings.append(message)
    )
    monkeypatch.setattr(
        oauth_tokens, "decode", lambda **kwargs: {"sub": "CHARACTER:EVE:9"}
    )

    result = oauth_tokens.validate_jwt_token(
        access_token="jwt-token",
        jwks_client=None,
        audience="audience",
        issuers=["https://issuer.example"],
        user_agent="custom-agent",
        jwks_uri="https://issuer.example/jwks",
    )

    assert result == {"sub": "CHARACTER:EVE:9"}
    assert created == {
        "url": "https://issuer.example/jwks",
        "headers": {"User-Agent": "custom-agent"},
        "kid": "kid-2",
    }
    assert warnings == []


def test_validate_jwt_token_requires_jwks_uri_when_building_client() -> None:
    """JWT validation should require a JWKS URI when no client is provided."""
    with pytest.raises(ValueError, match="jwks_uri must be provided"):
        oauth_tokens.validate_jwt_token(
            access_token="jwt-token",
            jwks_client=None,
            audience="audience",
            issuers=["https://issuer.example"],
        )


def test_validate_jwt_token_wraps_expired_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Expired JWTs should map to DecodeTokenError with a clear message."""
    monkeypatch.setattr(
        oauth_tokens,
        "get_unverified_header",
        lambda token: {"kid": "kid-1", "alg": "RS256"},
    )
    jwks_client = SimpleNamespace(
        get_signing_key=lambda kid: SimpleNamespace(key="signing-key")
    )
    monkeypatch.setattr(
        oauth_tokens,
        "decode",
        lambda **kwargs: (_ for _ in ()).throw(
            oauth_tokens.ExpiredSignatureError("expired")
        ),
    )

    with pytest.raises(
        oauth_tokens.DecodeTokenError, match=r"Token has expired\. expired"
    ):
        oauth_tokens.validate_jwt_token(
            access_token="jwt-token",
            jwks_client=jwks_client,  # type: ignore[arg-type]
            audience="audience",
            issuers=["https://issuer.example"],
        )


def test_validate_jwt_token_wraps_other_decode_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected decode failures should map to DecodeTokenError."""
    monkeypatch.setattr(
        oauth_tokens,
        "get_unverified_header",
        lambda token: {"kid": "kid-1", "alg": "RS256"},
    )
    jwks_client = SimpleNamespace(
        get_signing_key=lambda kid: SimpleNamespace(key="signing-key")
    )
    monkeypatch.setattr(
        oauth_tokens,
        "decode",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("bad token")),
    )

    with pytest.raises(
        oauth_tokens.DecodeTokenError,
        match=r"Invalid token or other error: bad token",
    ):
        oauth_tokens.validate_jwt_token(
            access_token="jwt-token",
            jwks_client=jwks_client,  # type: ignore[arg-type]
            audience="audience",
            issuers=["https://issuer.example"],
        )
