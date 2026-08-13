"""Small shared Rich primitives with hostile-data containment."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..errors import UnavailableError
from ..safety import clean

MAX_RENDERED_ROWS = 100


def obj(value: object, label: str = "record") -> dict[str, Any]:
    if not isinstance(value, dict):
        raise UnavailableError(f"EIP API returned an invalid {label}")
    return value


def items(value: object, label: str = "items") -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise UnavailableError(f"EIP API returned invalid {label}")
    result: list[dict[str, Any]] = []
    for entry in value:
        result.append(obj(entry, label.rstrip("s")))
    return result


def bounded_items(
    value: object, label: str = "items", *, limit: int = MAX_RENDERED_ROWS
) -> tuple[list[dict[str, Any]], int]:
    """Return a bounded render page and the number of response rows omitted."""
    rows = items(value, label)
    return rows[:limit], max(0, len(rows) - limit)


def response_rows_omitted(console: Console, count: int) -> None:
    if count:
        console.print(Text(f"{count:,} additional response row(s) omitted", style="dim"))


def text(value: object, *, limit: int = 400, style: str | None = None) -> Text:
    return Text(clean(value, limit=limit), style=style)


def prose(value: object, *, limit: int = 2_000) -> Text:
    return Text(clean(value, limit=limit, multiline=True))


def heading(value: object, *, style: str = "bold cyan") -> Text:
    return text(value, limit=300, style=style)


def value_or_dash(value: object, *, limit: int = 300) -> Text:
    if value is None or value == "":
        return Text(" - ", style="dim")
    return text(value, limit=limit)


def number(value: object) -> str:
    if value is None:
        return " - "
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        return f"{value:,.4g}"
    return clean(value, limit=80)


def date_value(value: object) -> str:
    if not isinstance(value, str) or not value:
        return " - "
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return clean(value, limit=80)
    if parsed.hour == parsed.minute == parsed.second == 0:
        return parsed.date().isoformat()
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def narrow(console: Console, *, below: int = 110) -> bool:
    """Return whether a horizontal record table would be cramped."""

    return console.size.width < below


def kv_table(rows: Iterable[tuple[str, object]], *, title: str | None = None) -> Table:
    table = Table(title=title, show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold", no_wrap=True)
    table.add_column(overflow="fold")
    for label, value in rows:
        table.add_row(Text(label), value if isinstance(value, Text) else value_or_dash(value))
    return table


def page_footer(console: Console, page: Mapping[str, Any]) -> None:
    cursor = page.get("next_cursor")
    if isinstance(cursor, str) and cursor:
        console.print(
            Text(
                "More results are available; repeat the unchanged query with --cursor.", style="dim"
            )
        )
        console.print(Text("Next cursor:", style="dim"))
        console.print(text(cursor, limit=10_000, style="dim"))


def section_title(console: Console, title: str, *, count: int | None = None) -> None:
    label = title if count is None else f"{title} ({count:,})"
    console.print()
    console.print(heading(label))


def collection(value: object) -> tuple[list[dict[str, Any]], int, bool]:
    record = obj(value, "collection")
    rows = items(record.get("items", []))
    total = record.get("total")
    if not isinstance(total, int):
        total = len(rows)
    truncated = record.get("truncated") is True
    return rows, total, truncated


def omitted(console: Console, shown: int, total: int, truncated: bool = False) -> None:
    hidden = max(0, total - shown)
    if hidden or truncated:
        detail = f"{hidden:,} additional item(s) omitted" if hidden else "API collection truncated"
        console.print(Text(detail, style="dim"))
