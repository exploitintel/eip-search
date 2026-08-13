"""Vendor, package, CWE, and author directory presentation."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .common import (
    bounded_items,
    heading,
    kv_table,
    narrow,
    number,
    obj,
    page_footer,
    prose,
    response_rows_omitted,
    text,
)

_DIRECTORY_COLUMNS: dict[str, tuple[tuple[str, str], ...]] = {
    "vendors": (
        ("Vendor", "vendor"),
        ("Vulnerabilities", "vulnerability_count"),
        ("Products", "product_count"),
    ),
    "products": (
        ("Vendor", "vendor"),
        ("Product", "product"),
        ("Vulnerabilities", "vulnerability_count"),
    ),
    "ecosystems": (
        ("Ecosystem", "ecosystem"),
        ("Vulnerabilities", "vulnerability_count"),
        ("Packages", "package_count"),
    ),
    "packages": (
        ("Ecosystem", "ecosystem"),
        ("Package", "package_name"),
        ("Vulnerabilities", "vulnerability_count"),
    ),
    "weaknesses": (
        ("CWE", "cwe_id"),
        ("Type", "record_type"),
        ("Name", "name"),
        ("Status", "status"),
        ("Vulnerabilities", "vulnerability_count"),
    ),
    "authors": (
        ("ID", "public_id"),
        ("Source", "source_scope"),
        ("Name", "display_name"),
        ("Roles", "roles"),
        ("PoCs", "poc_count"),
        ("Vulnerabilities", "vulnerability_count"),
    ),
}


def render_directory(console: Console, data: dict[str, Any], kind: str) -> None:
    columns = _DIRECTORY_COLUMNS[kind]
    console.print(heading(kind.replace("_", " ").title()))
    rows, hidden = bounded_items(data.get("items", []))
    if narrow(console):
        for row in rows:
            values: list[tuple[str, object]] = []
            for label, key in columns:
                value = row.get(key)
                if isinstance(value, list):
                    value = ", ".join(str(item) for item in value)
                if key.endswith("count") or key == "public_id":
                    value = number(value)
                values.append((label, value))
            console.print()
            console.print(kv_table(values))
        response_rows_omitted(console, hidden)
        page_footer(console, data)
        return
    table = Table(show_lines=False)
    for label, _key in columns:
        table.add_column(label, overflow="fold", no_wrap=label in {"ID", "CWE", "PoCs"})
    for row in rows:
        cells: list[Text] = []
        for _label, key in columns:
            value = row.get(key)
            if isinstance(value, list):
                value = ", ".join(str(item) for item in value)
            if key.endswith("count") or key == "public_id":
                value = number(value)
            cells.append(text(value, limit=280))
        table.add_row(*cells)
    console.print(table)
    response_rows_omitted(console, hidden)
    page_footer(console, data)


def render_weakness(console: Console, data: dict[str, Any]) -> None:
    record = obj(data, "CWE record")
    console.print(heading(f"{record.get('cwe_id', 'CWE')} - {record.get('name', '')}"))
    console.print(
        kv_table(
            [
                ("Type", record.get("record_type")),
                ("Status", record.get("status")),
                ("Abstraction", record.get("abstraction")),
                ("Vulnerabilities", number(record.get("vulnerability_count"))),
            ]
        )
    )
    console.print()
    console.print(prose(record.get("description"), limit=6_000))
    provenance = record.get("provenance")
    if isinstance(provenance, dict):
        console.print(
            Text.assemble(
                Text("Source: ", style="dim"), text(provenance.get("source"), style="dim")
            )
        )


def render_author(console: Console, data: dict[str, Any]) -> None:
    record = obj(data, "author")
    console.print(heading(record.get("display_name") or "Exploit contributor"))
    roles = record.get("roles")
    console.print(
        kv_table(
            [
                ("Public ID", number(record.get("public_id"))),
                ("Source", record.get("source_scope")),
                ("Source identity", record.get("external_id")),
                (
                    "Roles",
                    ", ".join(str(value) for value in roles) if isinstance(roles, list) else roles,
                ),
                ("PoCs", number(record.get("poc_count"))),
                ("Vulnerabilities", number(record.get("vulnerability_count"))),
                ("Profile", record.get("profile_url")),
            ]
        )
    )
