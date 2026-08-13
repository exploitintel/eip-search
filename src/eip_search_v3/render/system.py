"""Corpus state and statistics presentation."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .common import (
    bounded_items,
    date_value,
    heading,
    items,
    kv_table,
    number,
    obj,
    response_rows_omitted,
    section_title,
    text,
)


def render_readiness(console: Console, data: dict[str, Any]) -> None:
    status = data.get("status")
    style = "bold green" if status == "ready" else "bold red"
    console.print(heading("EIP corpus readiness"))
    console.print(text(status or "unknown", style=style))
    console.print(
        kv_table(
            [
                ("Read model", data.get("read_model_version")),
                ("API policy", data.get("api_policy_revision")),
                ("Built", date_value(data.get("built_at"))),
                ("Source checkpoint", data.get("source_checkpoint_sha256")),
                ("Database read-only", str(data.get("database_read_only"))),
                ("Code search", data.get("code_search_status")),
                ("Code checkpoint", data.get("code_search_checkpoint_sha256")),
                ("Code artifacts", number(data.get("code_search_artifact_count"))),
                ("Code files", number(data.get("code_search_file_count"))),
            ]
        )
    )


def render_statistics(console: Console, data: dict[str, Any]) -> None:
    console.print(heading("EIP corpus statistics"))
    labels = [
        ("Vulnerabilities", "vulnerabilities"),
        ("With artifacts", "with_artifacts"),
        ("With PoCs", "with_pocs"),
        ("CISA KEV", "cisa_kev"),
        ("Ransomware", "ransomware"),
        ("With Nuclei", "with_nuclei"),
    ]
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column(justify="right")
    for label, key in labels:
        table.add_row(Text(label), text(number(data.get(key))))
    console.print(table)


def _series(console: Console, value: object, title: str) -> None:
    rows, hidden = bounded_items(value, title)
    section_title(console, title)
    for series in rows:
        points = items(series.get("points", []), "trend points")
        latest = points[-1] if points else {}
        console.print(
            Text.assemble(
                text(series.get("label") or series.get("key"), style="bold"),
                "  ",
                text(latest.get("period"), style="dim"),
                "  ",
                text(number(latest.get("count"))),
                "  ",
                text(f"({len(points)} points)", style="dim"),
            )
        )
    response_rows_omitted(console, hidden)


def render_trends(console: Console, data: dict[str, Any], selected: str) -> None:
    record = obj(data, "statistics trends")
    console.print(heading("EIP corpus trends"))
    console.print(Text(f"As of {date_value(record.get('as_of'))}", style="dim"))
    mapping = {
        "cve-published": ("cve_published", "CVE publications"),
        "cwe": ("cve_weaknesses", "CWE series"),
        "catalog-additions": ("catalog_additions", "Catalog additions"),
        "poc-supply": ("poc_supply", "PoC supply"),
    }
    keys = mapping if selected == "all" else {selected: mapping[selected]}
    for _name, (field, label) in keys.items():
        value = record.get(field)
        if field == "cve_published" and isinstance(value, dict):
            value = [value]
        _series(console, value or [], label)
