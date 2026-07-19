"""Tests for the character search CLI command."""

import json
from pathlib import Path

import pytest
import typer

import pfmsoft.eve_auth_manager.cli.characters.search_id as search_module
from pfmsoft.eve_auth_manager.cli.characters.search_id import search


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


def test_search_rich_stdout_prints_results_and_status_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Search should print the search status and rich results when not plain."""
    expected = {"characters": [{"id": 123, "name": "Jane Capsuleer"}]}
    printed: list[object] = []
    console_kwargs: list[dict[str, object]] = []

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

    class FakeConsole:
        def __init__(self, **kwargs: object) -> None:
            console_kwargs.append(dict(kwargs))

        def print(self, message: object) -> None:
            printed.append(message)

    monkeypatch.setattr(search_module, "client_manager", lambda: FakeClientManager())
    monkeypatch.setattr(search_module, "Console", FakeConsole)

    search(["Jane Capsuleer"], plain=False, quiet=False)  # type: ignore[arg-type]

    assert console_kwargs == [{"stderr": True}]
    assert printed == [
        "Searching for the following names: Jane Capsuleer",
        expected,
    ]


def test_search_writes_results_to_file_reports_output_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Search should report the saved output path when writing to a file."""
    expected = {"characters": [{"id": 123, "name": "Jane Capsuleer"}]}
    output_path = tmp_path / "search-results.json"
    printed: list[object] = []
    save_calls: dict[str, object] = {}

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

    class FakeConsole:
        def __init__(self, **kwargs: object) -> None:
            return None

        def print(self, message: object) -> None:
            printed.append(message)

    def fake_save_text_file(**kwargs: object) -> Path:
        save_calls.update(kwargs)
        output_path.write_text(kwargs["text"], encoding="utf-8")
        return output_path

    monkeypatch.setattr(search_module, "client_manager", lambda: FakeClientManager())
    monkeypatch.setattr(search_module, "Console", FakeConsole)
    monkeypatch.setattr(search_module, "save_text_file", fake_save_text_file)

    search(
        ["Jane Capsuleer"],
        file_path=output_path,
        indent=2,
        overwrite=True,
        quiet=False,
    )  # type: ignore[arg-type]

    assert save_calls == {
        "text": json.dumps(expected, indent=2),
        "output_directory": tmp_path,
        "file_name": "search-results.json",
        "overwrite": True,
    }
    assert printed == [
        "Searching for the following names: Jane Capsuleer",
        f"Output written to {output_path}",
    ]
