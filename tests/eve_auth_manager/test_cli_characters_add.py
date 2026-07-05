"""Tests for the characters add CLI command."""

from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
import typer

import eve_auth_manager.cli.characters.add as add_module
from eve_auth_manager.cli.characters.add import add
from eve_auth_manager.models import AuthorizedCharacter, OauthToken
from eve_auth_manager.settings import EveAuthManagerSettings


def _make_context(tmp_path: Path) -> SimpleNamespace:
    """Build a minimal context object with configured settings."""
    settings = EveAuthManagerSettings(
        auth_db_path=tmp_path / "auth.db",
        logging_directory=tmp_path / "logs",
    )
    return SimpleNamespace(obj={"eve-auth-manager-settings": settings})


def _make_character(*, cred_id: UUID, character_id: int) -> AuthorizedCharacter:
    """Create an authorized character value for mocked token flow results."""
    return AuthorizedCharacter(
        character_id=character_id,
        cred_id=cred_id,
        character_name="Jane Capsuleer",
        expires_at=4_600,
        oauth_token=OauthToken(
            token_data={
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "expires_in": 3_600,
                "token_type": "Bearer",
            }
        ),
    )


def test_add_requires_credential_selector(tmp_path: Path) -> None:
    """Add should require either a credential ID or credential name."""
    ctx = _make_context(tmp_path)

    with pytest.raises(typer.Exit) as exc_info:
        add(ctx, 77, quiet=True)  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 1


def test_add_exits_cleanly_when_character_is_already_authorized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Add should stop before OAuth work when the character already exists."""
    ctx = _make_context(tmp_path)
    cred_id = UUID("88888888-8888-8888-8888-888888888888")

    class FakeManager:
        oauth_metadata = SimpleNamespace(
            authorization_endpoint="https://login.eveonline.com/authorize"
        )

        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> object:
            return SimpleNamespace(
                cred_id=cred_id,
                clientId="client-id",
                callbackUrl="http://localhost/callback",
                scopes=["scope.one"],
            )

        def get_all_character_ids(self, credential_id: UUID) -> dict[int, str]:
            assert credential_id == cred_id
            return {77: "Jane Capsuleer"}

    monkeypatch.setattr(add_module, "SqliteAuthManager", lambda path: FakeManager())
    monkeypatch.setattr(
        add_module,
        "generate_request_params",
        lambda **kwargs: pytest.fail("generate_request_params should not be called"),
    )

    with pytest.raises(typer.Exit) as exc_info:
        add(ctx, 77, cred_id=cred_id, quiet=True)  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 0


def test_add_completes_successful_authorization_flow(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Add should request, validate, and store a new authorized character."""
    ctx = _make_context(tmp_path)
    cred_id = UUID("99999999-9999-9999-9999-999999999999")
    calls: dict[str, object] = {}
    session = object()
    jwks_client = object()
    oauth_metadata = SimpleNamespace(
        authorization_endpoint="https://login.eveonline.com/authorize"
    )
    validated_token = SimpleNamespace(character_id=42, character_name="Jane Capsuleer")

    class FakeManager:
        def __init__(self) -> None:
            self.oauth_metadata = oauth_metadata
            self.session = session
            self.jwks_client = jwks_client

        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> object:
            calls["get_credential"] = {"cred_id": cred_id, "cred_name": cred_name}
            return SimpleNamespace(
                cred_id=cred_id,
                clientId="client-id",
                callbackUrl="http://localhost/callback",
                scopes=["scope.one", "scope.two"],
            )

        def get_all_character_ids(self, credential_id: UUID) -> dict[int, str]:
            calls["get_all_character_ids"] = credential_id
            return {}

        def add_character(
            self, *, cred_id: UUID, character: AuthorizedCharacter
        ) -> None:
            calls["add_character"] = {"cred_id": cred_id, "character": character}

    request_params = SimpleNamespace(
        redirect_url="https://login.eveonline.com/authorize?foo=bar",
        state="expected-state",
        code_verifier="verifier-value",
    )
    oauth_token = OauthToken(
        token_data={
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 3_600,
            "token_type": "Bearer",
        }
    )
    character_token = _make_character(cred_id=cred_id, character_id=42)

    monkeypatch.setattr(add_module, "SqliteAuthManager", lambda path: FakeManager())
    monkeypatch.setattr(
        add_module,
        "generate_request_params",
        lambda **kwargs: (
            calls.__setitem__("request_params_kwargs", kwargs) or request_params
        ),
    )
    monkeypatch.setattr(
        add_module,
        "start_web_server_and_listen_for_code",
        lambda **kwargs: calls.__setitem__("listen_kwargs", kwargs) or "auth-code",
    )
    monkeypatch.setattr(
        add_module.token_tools,
        "request_new_token",
        lambda **kwargs: (
            calls.__setitem__("request_new_token_kwargs", kwargs) or oauth_token
        ),
    )
    monkeypatch.setattr(
        add_module.token_tools,
        "validate_token",
        lambda **kwargs: (
            calls.__setitem__("validate_token_kwargs", kwargs) or validated_token
        ),
    )
    monkeypatch.setattr(
        add_module.token_tools,
        "create_character_token",
        lambda **kwargs: (
            calls.__setitem__("create_character_token_kwargs", kwargs)
            or character_token
        ),
    )

    add(
        ctx,
        42,
        cred_id=cred_id,
        browser_auto_open=False,
        server_timeout=45,
        quiet=True,
    )  # type: ignore[arg-type]

    assert calls["get_credential"] == {"cred_id": cred_id, "cred_name": None}
    assert calls["get_all_character_ids"] == cred_id
    assert calls["request_params_kwargs"] == {
        "client_id": "client-id",
        "callback_url": "http://localhost/callback",
        "authorization_endpoint": "https://login.eveonline.com/authorize",
        "scopes": ["scope.one", "scope.two"],
    }
    assert calls["listen_kwargs"] == {
        "redirect_url": "http://localhost/callback",
        "expected_state": "expected-state",
        "timeout_seconds": 45,
    }
    assert calls["request_new_token_kwargs"] == {
        "session": session,
        "client_id": "client-id",
        "authorization_code": "auth-code",
        "code_verifier": "verifier-value",
        "oauth_metadata": oauth_metadata,
    }
    assert calls["validate_token_kwargs"] == {
        "access_token": "access-token",
        "jwks_client": jwks_client,
        "oauth_metadata": oauth_metadata,
    }
    assert calls["create_character_token_kwargs"] == {
        "cred_id": cred_id,
        "oauth_token": oauth_token,
        "validated_token": validated_token,
    }
    assert calls["add_character"] == {
        "cred_id": cred_id,
        "character": character_token,
    }


def test_add_exits_when_authorization_code_is_not_received(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Add should fail when the local callback server does not receive a code."""
    ctx = _make_context(tmp_path)
    cred_id = UUID("15151515-1515-1515-1515-151515151515")

    class FakeManager:
        oauth_metadata = SimpleNamespace(
            authorization_endpoint="https://login.eveonline.com/authorize"
        )

        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> object:
            return SimpleNamespace(
                cred_id=cred_id,
                clientId="client-id",
                callbackUrl="http://localhost/callback",
                scopes=["scope.one"],
            )

        def get_all_character_ids(self, credential_id: UUID) -> dict[int, str]:
            assert credential_id == cred_id
            return {}

    request_params = SimpleNamespace(
        redirect_url="https://login.eveonline.com/authorize?foo=bar",
        state="expected-state",
        code_verifier="verifier-value",
    )

    monkeypatch.setattr(add_module, "SqliteAuthManager", lambda path: FakeManager())
    monkeypatch.setattr(
        add_module, "generate_request_params", lambda **kwargs: request_params
    )
    monkeypatch.setattr(
        add_module,
        "start_web_server_and_listen_for_code",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        add_module.token_tools,
        "request_new_token",
        lambda **kwargs: pytest.fail("request_new_token should not be called"),
    )

    with pytest.raises(typer.Exit) as exc_info:
        add(ctx, 42, cred_id=cred_id, browser_auto_open=False, quiet=True)  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 1


def test_add_exits_when_validated_character_does_not_match_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Add should fail when the returned token belongs to a different character."""
    ctx = _make_context(tmp_path)
    cred_id = UUID("16161616-1616-1616-1616-161616161616")

    class FakeManager:
        oauth_metadata = SimpleNamespace(
            authorization_endpoint="https://login.eveonline.com/authorize"
        )
        session = object()
        jwks_client = object()

        def __enter__(self) -> "FakeManager":
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def get_credential(
            self, *, cred_id: UUID | None = None, cred_name: str | None = None
        ) -> object:
            return SimpleNamespace(
                cred_id=cred_id,
                clientId="client-id",
                callbackUrl="http://localhost/callback",
                scopes=["scope.one"],
            )

        def get_all_character_ids(self, credential_id: UUID) -> dict[int, str]:
            assert credential_id == cred_id
            return {}

        def add_character(
            self, *, cred_id: UUID, character: AuthorizedCharacter
        ) -> None:
            pytest.fail("add_character should not be called")

    request_params = SimpleNamespace(
        redirect_url="https://login.eveonline.com/authorize?foo=bar",
        state="expected-state",
        code_verifier="verifier-value",
    )
    oauth_token = OauthToken(
        token_data={
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 3_600,
            "token_type": "Bearer",
        }
    )
    mismatched_character = _make_character(cred_id=cred_id, character_id=999)

    monkeypatch.setattr(add_module, "SqliteAuthManager", lambda path: FakeManager())
    monkeypatch.setattr(
        add_module, "generate_request_params", lambda **kwargs: request_params
    )
    monkeypatch.setattr(
        add_module,
        "start_web_server_and_listen_for_code",
        lambda **kwargs: "auth-code",
    )
    monkeypatch.setattr(
        add_module.token_tools,
        "request_new_token",
        lambda **kwargs: oauth_token,
    )
    monkeypatch.setattr(
        add_module.token_tools,
        "validate_token",
        lambda **kwargs: SimpleNamespace(
            character_id=999, character_name="Other Character"
        ),
    )
    monkeypatch.setattr(
        add_module.token_tools,
        "create_character_token",
        lambda **kwargs: mismatched_character,
    )

    with pytest.raises(typer.Exit) as exc_info:
        add(ctx, 42, cred_id=cred_id, browser_auto_open=False, quiet=True)  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 1
