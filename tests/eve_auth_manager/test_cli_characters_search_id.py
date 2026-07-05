"""Tests for the character search CLI command."""

import json
from pathlib import Path

import pytest
import typer

import eve_auth_manager.cli.characters.search_id as search_module
from eve_auth_manager.cli.characters.search_id import search


def test_search_plain_stdout_writes_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Search should emit plain JSON to stdout when requested."""
    expected = {"inventory_types": [{"id": 34, "name": "Tritanium"}]}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, list[dict[str, object]]]:
            return expected

    class FakeSession:
        def post(self, *, url: str, json: list[str]) -> FakeResponse:
            assert url == search_module.SEARCH_ENDPOINT
            assert json == ["Tritanium"]
            return FakeResponse()

    class FakeClientManager:
        def __enter__(self) -> FakeSession:
            return FakeSession()

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

    monkeypatch.setattr(search_module, "client_manager", lambda: FakeClientManager())

    search(["Tritanium"], plain=True, quiet=True)  # type: ignore[arg-type]

    assert json.loads(capsys.readouterr().out) == expected


def test_search_writes_results_to_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Search should write JSON results to the requested file path."""
    expected = {"characters": [{"id": 123, "name": "Jane Capsuleer"}]}
    output_path = tmp_path / "search-results.json"

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, list[dict[str, object]]]:
            return expected

    class FakeSession:
        def post(self, *, url: str, json: list[str]) -> FakeResponse:
            assert url == search_module.SEARCH_ENDPOINT
            assert json == ["Jane Capsuleer"]
            return FakeResponse()

    class FakeClientManager:
        def __enter__(self) -> FakeSession:
            return FakeSession()

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

    monkeypatch.setattr(search_module, "client_manager", lambda: FakeClientManager())

    search(["Jane Capsuleer"], file_path=output_path, quiet=True)  # type: ignore[arg-type]

    assert json.loads(output_path.read_text(encoding="utf-8")) == expected


def test_search_exits_cleanly_when_no_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Search should exit successfully when ESI returns no matches."""

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {}

    class FakeSession:
        def post(self, *, url: str, json: list[str]) -> FakeResponse:
            assert url == search_module.SEARCH_ENDPOINT
            assert json == ["Missing Name"]
            return FakeResponse()

    class FakeClientManager:
        def __enter__(self) -> FakeSession:
            return FakeSession()

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

    monkeypatch.setattr(search_module, "client_manager", lambda: FakeClientManager())

    with pytest.raises(typer.Exit) as exc_info:
        search(["Missing Name"], quiet=True)  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 0
