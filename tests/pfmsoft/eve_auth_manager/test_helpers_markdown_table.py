"""Tests for markdown table rendering helpers."""

import runpy
import sys

import pytest

from pfmsoft.eve_auth_manager.helpers.markdown_table import (
    Align,
    MarkdownTable,
    _escape,
    _format_cell,
    _pad,
    _separator_cell,
)


def test_escape_and_format_cell_handle_special_characters() -> None:
    """Cell escaping should protect pipes and replace embedded newlines."""
    assert _escape("left|right\nnext", "<br>") == "left\\|right<br>next"
    assert _format_cell(None, " ") == ""
    assert _format_cell("left|right\nnext", "<br>") == "left\\|right<br>next"


@pytest.mark.parametrize(
    ("width", "align", "expected"),
    [
        (1, Align.LEFT, "---"),
        (5, Align.LEFT, "-----"),
        (4, Align.RIGHT, "---:"),
        (5, Align.CENTER, ":---:"),
    ],
)
def test_separator_cell_respects_alignment(
    width: int, align: Align, expected: str
) -> None:
    """Separator cells should follow markdown alignment syntax."""
    assert _separator_cell(width, align) == expected


@pytest.mark.parametrize(
    ("cell", "width", "align", "expected"),
    [
        ("x", 3, Align.LEFT, "x  "),
        ("x", 3, Align.RIGHT, "  x"),
        ("x", 3, Align.CENTER, " x "),
    ],
)
def test_pad_respects_alignment(
    cell: str, width: int, align: Align, expected: str
) -> None:
    """Padding should place cell text according to the requested alignment."""
    assert _pad(cell, width, align) == expected


def test_markdown_table_validates_alignment_and_row_lengths() -> None:
    """Table builder should reject mismatched alignments and row widths."""
    with pytest.raises(ValueError, match="align length 1 != headers length 2"):
        MarkdownTable(headers=["A", "B"], align=[Align.LEFT])

    table = MarkdownTable(headers=["A", "B"])

    with pytest.raises(ValueError, match="row length 1 != headers length 2"):
        table.add_row(["only-one"])


def test_markdown_table_add_row_dict_validates_missing_and_extra_keys() -> None:
    """Dict-based rows should validate keys and support defaults."""
    table = MarkdownTable(headers=["Name", "Qty", "Notes"])

    with pytest.raises(ValueError, match="unexpected keys"):
        table.add_row_dict({"Name": "Widget", "Qty": 1, "Extra": True})

    with pytest.raises(ValueError, match="missing keys"):
        table.add_row_dict({"Name": "Widget", "Qty": 1})

    table.add_row_dict({"Name": "Widget", "Qty": 1}, default="-")

    assert table.rows == [["Widget", 1, "-"]]


def test_markdown_table_render_handles_alignment_and_newline_replacement() -> None:
    """Rendered markdown should include escaped cells, alignment, and padding."""
    table = MarkdownTable(
        headers=["Name", "Qty", "Notes"],
        align=[Align.LEFT, Align.RIGHT, Align.CENTER],
        newline_replacement="<br>",
    )
    table.add_row(["Widget|Deluxe", 12, "in\nstock"])
    table.add_row_dict({"Qty": 3, "Name": "Gadget", "Notes": "backordered"})

    rendered = table.render()

    assert rendered.splitlines()[0].startswith("| Name")
    assert "Widget\\|Deluxe" in rendered
    assert "in<br>stock" in rendered
    assert ":---------:" in rendered
    assert "| Gadget" in rendered
    assert "|   3 |" in rendered or "| 3 |" in rendered


def test_markdown_table_render_supports_header_only_tables() -> None:
    """Rendering without rows should still produce a valid markdown table."""
    table = MarkdownTable(headers=["Name", "Qty"])

    rendered = table.render()

    assert rendered == "| Name | Qty |\n| ---- | --- |"


def test_markdown_table_module_main_renders_demo_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The module demo block should render the sample tables without warning noise."""
    previous_module = sys.modules.pop(
        "pfmsoft.eve_auth_manager.helpers.markdown_table", None
    )

    try:
        runpy.run_module(
            "pfmsoft.eve_auth_manager.helpers.markdown_table", run_name="__main__"
        )
    finally:
        if previous_module is not None:
            sys.modules["pfmsoft.eve_auth_manager.helpers.markdown_table"] = (
                previous_module
            )

    captured = capsys.readouterr()
    assert "-- default (space) --" in captured.out
    assert "-- html <br> --" in captured.out
    assert "-- dict-based rows --" in captured.out
    assert "Gadget \\| Deluxe" in captured.out
