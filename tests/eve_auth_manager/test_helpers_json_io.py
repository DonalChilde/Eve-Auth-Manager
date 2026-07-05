"""Tests for JSON and JSONL helper functions."""

from pathlib import Path

import pytest

from eve_auth_manager.helpers.json_io import (
    json_dump_bytes,
    json_dumps,
    json_dumps_path,
    json_load_path,
    json_loads,
    jsonl_dump_bytes,
    jsonl_dump_path,
    jsonl_dumps,
    jsonl_load_bytes,
    jsonl_load_bytes_indexed,
    jsonl_load_path,
    jsonl_load_path_indexed,
    jsonl_loads,
    jsonl_loads_indexed,
)


def test_json_loads_and_dump_helpers_round_trip_values(tmp_path: Path) -> None:
    """JSON helpers should serialize and deserialize standard Python values."""
    payload = {"name": "Jane", "count": 2, "items": [1, 2, 3]}
    json_path = tmp_path / "payload.json"

    assert json_loads('{"hello":"world"}') == {"hello": "world"}
    assert json_loads(b'{"value": 3}') == {"value": 3}
    assert json_dumps(payload) == '{"name":"Jane","count":2,"items":[1,2,3]}'
    assert json_dump_bytes(payload) == b'{"name":"Jane","count":2,"items":[1,2,3]}'

    written = json_dumps_path(payload, filepath=json_path)

    assert written == len(json_path.read_text(encoding="utf-8"))
    assert json_path.read_text(encoding="utf-8").endswith("\n")
    assert json_load_path(json_path) == payload


def test_json_dumps_path_respects_overwrite_flag(tmp_path: Path) -> None:
    """JSON file dumping should reject existing files unless overwrite is enabled."""
    json_path = tmp_path / "payload.json"
    json_path.write_text('{"existing":true}\n', encoding="utf-8")

    with pytest.raises(FileExistsError):
        json_dumps_path({"replacement": True}, filepath=json_path)

    written = json_dumps_path({"replacement": True}, filepath=json_path, overwrite=True)

    assert written == len('{"replacement":true}\n')
    assert json_load_path(json_path) == {"replacement": True}


def test_jsonl_load_helpers_skip_blank_lines_and_preserve_indexes(
    tmp_path: Path,
) -> None:
    """JSONL loaders should ignore blank lines while keeping original line numbers."""
    jsonl_text = '{"a":1}\n\n{"b":2}\n'
    jsonl_bytes = jsonl_text.encode("utf-8")
    jsonl_path = tmp_path / "records.jsonl"
    jsonl_path.write_text(jsonl_text, encoding="utf-8")

    assert list(jsonl_loads(jsonl_text)) == [{"a": 1}, {"b": 2}]
    assert list(jsonl_loads_indexed(jsonl_text)) == [(1, {"a": 1}), (3, {"b": 2})]
    assert list(jsonl_load_bytes(jsonl_bytes)) == [{"a": 1}, {"b": 2}]
    assert list(jsonl_load_bytes_indexed(jsonl_bytes)) == [
        (1, {"a": 1}),
        (3, {"b": 2}),
    ]
    assert list(jsonl_load_path(jsonl_path)) == [{"a": 1}, {"b": 2}]
    assert list(jsonl_load_path_indexed(jsonl_path)) == [
        (1, {"a": 1}),
        (3, {"b": 2}),
    ]


def test_jsonl_dump_helpers_write_expected_output(tmp_path: Path) -> None:
    """JSONL dump helpers should serialize one object per line."""
    records = [{"a": 1}, {"b": 2}]
    jsonl_path = tmp_path / "records.jsonl"

    written = jsonl_dump_path(iter(records), filepath=jsonl_path)

    assert written == len('{"a":1}\n{"b":2}\n')
    assert jsonl_path.read_text(encoding="utf-8") == '{"a":1}\n{"b":2}\n'
    assert jsonl_dumps(iter(records)) == '{"a":1}\n{"b":2}'
    assert jsonl_dump_bytes(iter(records)) == b'{"a":1}\n{"b":2}'


def test_jsonl_dump_path_supports_append_and_overwrite(tmp_path: Path) -> None:
    """JSONL file dumping should support append and overwrite modes."""
    jsonl_path = tmp_path / "records.jsonl"
    jsonl_path.write_text('{"seed":0}\n', encoding="utf-8")

    appended = jsonl_dump_path(iter([{"a": 1}]), filepath=jsonl_path, append=True)
    assert appended == len('{"a":1}\n')
    assert jsonl_path.read_text(encoding="utf-8") == '{"seed":0}\n{"a":1}\n'

    overwritten = jsonl_dump_path(
        iter([{"fresh": True}]),
        filepath=jsonl_path,
        overwrite=True,
    )
    assert overwritten == len('{"fresh":true}\n')
    assert jsonl_path.read_text(encoding="utf-8") == '{"fresh":true}\n'


def test_jsonl_dump_helpers_reject_indent_and_conflicting_modes(tmp_path: Path) -> None:
    """JSONL dump helpers should reject unsupported indent and conflicting modes."""
    jsonl_path = tmp_path / "records.jsonl"

    with pytest.raises(ValueError, match="indent is not supported for JSONL files"):
        jsonl_dump_path(iter([{"a": 1}]), filepath=jsonl_path, indent=2)

    with pytest.raises(ValueError, match="overwrite and append are mutually exclusive"):
        jsonl_dump_path(
            iter([{"a": 1}]),
            filepath=jsonl_path,
            overwrite=True,
            append=True,
        )

    with pytest.raises(ValueError, match="indent is not supported for JSONL files"):
        jsonl_dumps(iter([{"a": 1}]), indent=2)

    with pytest.raises(ValueError, match="indent is not supported for JSONL files"):
        jsonl_dump_bytes(iter([{"a": 1}]), indent=2)
