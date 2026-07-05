"""Tests for OAuth authorization request and callback helpers."""

import runpy
import socket
import sys
import threading
import time
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen

import pytest

import eve_auth_manager.auth.request_authentication_code as auth_code_module
from eve_auth_manager.auth.request_authentication_code import (
    AuthenticationRequestParams,
    generate_request_params,
    generate_url,
    start_web_server_and_listen_for_code,
)


def _get_free_port() -> int:
    """Reserve and return an ephemeral loopback port for a test server."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _dispatch_callback(url: str, results: list[object]) -> None:
    """Send an HTTP callback request once the test server becomes available."""
    deadline = time.monotonic() + 2
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=1) as response:
                results.append(response.status)
                results.append(response.read().decode("utf-8"))
                return
        except HTTPError as exc:
            results.append(exc.code)
            results.append(exc.read().decode("utf-8"))
            return
        except URLError as exc:
            last_error = exc
            time.sleep(0.01)
    results.append(last_error or RuntimeError("callback request did not complete"))


def test_generate_url_builds_expected_authorization_query() -> None:
    """Authorization URL builder should include the expected OAuth parameters."""
    url = generate_url(
        code_challenge="challenge-value",
        client_id="client-id",
        callback_url="http://localhost/callback",
        authorization_endpoint="https://login.eveonline.com/authorize",
        scopes=["scope.one", "scope.two"],
        state="state-value",
    )

    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert parsed.netloc == "login.eveonline.com"
    assert parsed.path == "/authorize"
    assert query == {
        "response_type": ["code"],
        "client_id": ["client-id"],
        "redirect_uri": ["http://localhost/callback"],
        "scope": ["scope.one scope.two"],
        "state": ["state-value"],
        "code_challenge": ["challenge-value"],
        "code_challenge_method": ["S256"],
    }


def test_generate_request_params_uses_generated_pkce_and_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Request params should compose PKCE, state, and redirect URL correctly."""
    monkeypatch.setattr(
        auth_code_module,
        "generate_code_challenge_and_verifier",
        lambda: SimpleNamespace(
            code_challenge="challenge-value",
            code_verifier="verifier-value",
        ),
    )
    monkeypatch.setattr(
        auth_code_module,
        "generate_secure_random_string",
        lambda length: "state-value",
    )

    result = generate_request_params(
        client_id="client-id",
        callback_url="http://localhost/callback",
        authorization_endpoint="https://login.eveonline.com/authorize",
        scopes=["scope.one", "scope.two"],
    )

    assert result == AuthenticationRequestParams(
        redirect_url=(
            "https://login.eveonline.com/authorize?"
            "response_type=code&client_id=client-id&"
            "redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&"
            "scope=scope.one+scope.two&state=state-value&"
            "code_challenge=challenge-value&code_challenge_method=S256"
        ),
        state="state-value",
        code_verifier="verifier-value",
        code_challenge="challenge-value",
    )


def test_start_web_server_and_listen_for_code_requires_hostname() -> None:
    """Callback server helper should reject redirect URLs without a hostname."""
    with pytest.raises(ValueError, match="redirect_url must include a hostname"):
        start_web_server_and_listen_for_code("/callback", "expected-state")


def test_start_web_server_and_listen_for_code_returns_authorization_code() -> None:
    """Callback server should return the authorization code from a valid callback."""
    port = _get_free_port()
    redirect_url = f"http://127.0.0.1:{port}/callback"
    callback_url = f"{redirect_url}?code=auth-code&state=expected-state"
    results: list[object] = []
    sender = threading.Thread(
        target=_dispatch_callback,
        args=(callback_url, results),
        daemon=True,
    )

    sender.start()
    code = start_web_server_and_listen_for_code(
        redirect_url=redirect_url,
        expected_state="expected-state",
        timeout_seconds=1,
    )
    sender.join(timeout=2)

    assert code == "auth-code"
    assert results[0] == 200
    assert "Authorization Complete" in str(results[1])


def test_start_web_server_and_listen_for_code_surfaces_oauth_error() -> None:
    """Callback server should convert OAuth error callbacks into ValueError."""
    port = _get_free_port()
    redirect_url = f"http://127.0.0.1:{port}/callback"
    callback_url = (
        f"{redirect_url}?error=access_denied&"
        "error_description=user+canceled&state=expected-state"
    )
    results: list[object] = []
    sender = threading.Thread(
        target=_dispatch_callback,
        args=(callback_url, results),
        daemon=True,
    )

    sender.start()
    with pytest.raises(
        ValueError,
        match=r"OAuth authorization failed: access_denied \(user canceled\)",
    ):
        start_web_server_and_listen_for_code(
            redirect_url=redirect_url,
            expected_state="expected-state",
            timeout_seconds=1,
        )
    sender.join(timeout=2)

    assert results[0] == 400
    assert "Authorization Failed" in str(results[1])


def test_start_web_server_and_listen_for_code_rejects_state_mismatch() -> None:
    """Callback server should reject callbacks with the wrong CSRF state."""
    port = _get_free_port()
    redirect_url = f"http://127.0.0.1:{port}/callback"
    callback_url = f"{redirect_url}?code=auth-code&state=wrong-state"
    results: list[object] = []
    sender = threading.Thread(
        target=_dispatch_callback,
        args=(callback_url, results),
        daemon=True,
    )

    sender.start()
    with pytest.raises(ValueError, match="State mismatch in OAuth callback"):
        start_web_server_and_listen_for_code(
            redirect_url=redirect_url,
            expected_state="expected-state",
            timeout_seconds=1,
        )
    sender.join(timeout=2)

    assert results[0] == 400
    assert "State mismatch" in str(results[1])


def test_start_web_server_and_listen_for_code_rejects_missing_code() -> None:
    """Callback server should reject callbacks that omit the authorization code."""
    port = _get_free_port()
    redirect_url = f"http://127.0.0.1:{port}/callback"
    callback_url = f"{redirect_url}?state=expected-state"
    results: list[object] = []
    sender = threading.Thread(
        target=_dispatch_callback,
        args=(callback_url, results),
        daemon=True,
    )

    sender.start()
    with pytest.raises(
        ValueError, match="Missing authorization code in callback query parameters"
    ):
        start_web_server_and_listen_for_code(
            redirect_url=redirect_url,
            expected_state="expected-state",
            timeout_seconds=1,
        )
    sender.join(timeout=2)

    assert results[0] == 400
    assert "Missing authorization code" in str(results[1])


def test_start_web_server_and_listen_for_code_times_out() -> None:
    """Callback server should raise TimeoutError when no callback arrives."""
    port = _get_free_port()
    redirect_url = f"http://127.0.0.1:{port}/callback"

    with pytest.raises(TimeoutError, match="Timed out after 0.05 seconds"):
        start_web_server_and_listen_for_code(
            redirect_url=redirect_url,
            expected_state="expected-state",
            timeout_seconds=0.05,
        )


def test_request_authentication_code_main_guard_raises() -> None:
    """Module main guard should currently raise until the example is rewritten."""
    module_name = "eve_auth_manager.auth.request_authentication_code"
    existing_module = sys.modules.pop(module_name, None)
    try:
        with pytest.raises(NotImplementedError, match="Waiting for rewrite"):
            runpy.run_module(module_name, run_name="__main__")
    finally:
        if existing_module is not None:
            sys.modules[module_name] = existing_module
