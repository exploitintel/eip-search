from __future__ import annotations

from io import StringIO

import pytest
from rich.console import Console

from eip_search_v3.errors import UnavailableError
from eip_search_v3.render import (
    render_analysis,
    render_code_search,
    render_directory,
    render_file,
    render_file_list,
    render_labs,
    render_poc_page,
    render_statistics,
    render_trends,
    render_vulnerability,
    render_vulnerability_page,
)
from eip_search_v3.render.common import number


def rendered(renderer, payload, *, width: int = 80, **kwargs) -> str:
    output = StringIO()
    console = Console(file=output, width=width, color_system=None, force_terminal=False)
    renderer(console, payload, **kwargs)
    return output.getvalue()


@pytest.mark.parametrize("width", [80, 120, 180])
def test_search_presentations_are_legible_at_supported_widths(api_data, width: int) -> None:
    vuln_page = {
        "items": [
            {
                "identifier": "CVE-2026-1000",
                "title": "A deliberately long source-native vulnerability title " * 3,
                "published_at": "2026-01-01T00:00:00Z",
                "cvss_score": 9.8,
                "epss_score": 0.8,
                "poc_count": 1,
                "cisa_kev": True,
                "known_ransomware": False,
                "nuclei_count": 1,
            }
        ]
    }
    poc_page = {"items": [api_data["poc"]]}
    vuln_output = rendered(render_vulnerability_page, vuln_page, width=width)
    poc_output = rendered(render_poc_page, poc_page, width=width)
    assert "CVE-2026-1000" in vuln_output
    assert "owner/[bold]repo[/bold]" in poc_output
    assert "\x1b" not in vuln_output + poc_output
    if width == 80:
        assert "┏" not in vuln_output + poc_output


def test_dense_vulnerability_and_analysis_are_semantically_rendered(api_data) -> None:
    output = rendered(
        render_vulnerability,
        api_data["vuln"],
        width=120,
        sections=(
            "exploitation",
            "affected",
            "pocs",
            "artifacts",
            "related-artifacts",
            "nuclei",
            "labs",
            "references",
            "writeups",
            "research",
            "weaknesses",
            "lifecycle",
        ),
        section_limit=10,
    )
    assert "Example / Server · 1.0 to < 2.0 (affected)" in output
    assert "CISA SSVC  exploitation=active · automatable=yes" in output
    assert "https://example.test/advisory · advisory" in output
    assert "fixed-source-record" not in output
    assert "repository-poc" in output
    assert "Docker labs" in output

    analysis = rendered(render_analysis, api_data["analysis"], width=80)
    assert "undetermined" in analysis
    assert "No current stored analysis" not in analysis
    missing = rendered(render_analysis, None, width=80)
    assert "No current stored analysis" in missing
    assert "safe" not in missing.lower()


def test_code_and_lab_output_preserve_meaning(api_data) -> None:
    code = rendered(
        render_code_search,
        {
            "total": 1,
            "items": [
                {
                    "public_id": 123,
                    "title": "Example",
                    "source": "exploitdb",
                    "path": "poc.py",
                    "match_line": 5,
                    "match_location": "content",
                    "snippet_role": "matched-content",
                    "snippet_character_truncated": False,
                    "snippet_start_line": 4,
                    "snippet_end_line": 6,
                    "snippet": "a\nb\nc",
                    "file_type": "python",
                    "vulnerability_ids": ["CVE-2026-1000"],
                }
            ],
        },
    )
    assert "content match" in code
    assert "context near line 5" in code
    assert "lines 4-6" in code
    assert "Untrusted source excerpt" in code
    assert "textual relevance" in code
    assert "quality" in code

    without_line = rendered(
        render_code_search,
        {
            "total": 1,
            "items": [
                {
                    "public_id": True,
                    "title": "Example",
                    "source": "repository-inventory",
                    "path": "README.md",
                    "snippet_start_line": 1,
                    "snippet_end_line": 1,
                    "snippet": "example",
                    "match_location": "path",
                    "snippet_role": "file-context",
                    "snippet_character_truncated": True,
                    "vulnerability_ids": [],
                }
            ],
            "scope": {"kind": "vulnerability", "vulnerability_id": "CVE-2026-1000"},
        },
    )
    assert "Scope: PoCs associated with CVE-2026-1000" in without_line
    assert "Unassigned repository match" in without_line
    assert "Excerpt only; no public PoC unit is assigned" in without_line
    assert "path match" in without_line
    assert "file context" in without_line
    assert "character-truncated" in without_line

    labs = rendered(
        render_labs,
        {
            "statistics": {"total": 1, "cve_linked": 1, "analyzed": 1},
            "items": [api_data["lab"]],
        },
        include_analysis=True,
    )
    assert "Stored model interpretation" in labs
    assert "not proof" in labs
    assert "CVE association assessments" in labs
    assert "Stored operator-risk interpretation" in labs


def test_broken_response_shapes_fail_clearly() -> None:
    with pytest.raises(UnavailableError, match="invalid items"):
        rendered(render_vulnerability_page, {"items": "not-a-list"})


def test_missing_optional_number_renders_as_absent() -> None:
    assert number(None) == " - "


def test_statistics_treats_api_values_as_literal_text() -> None:
    output = rendered(render_statistics, {"vulnerabilities": "[/bold]"})
    assert "[/bold]" in output


def test_source_and_code_search_strip_terminal_control_sequences() -> None:
    hostile = "safe\x1b]52;c;cHdu\x07\x1b[2J\x07end"
    file_output = rendered(render_file, {"path": "poc.py", "content": hostile})
    search_output = rendered(
        render_code_search,
        {
            "total": 1,
            "items": [
                {
                    "public_id": 1,
                    "path": "poc.py",
                    "snippet": hostile,
                    "snippet_start_line": 1,
                    "snippet_end_line": 1,
                }
            ],
        },
    )
    assert "\x1b" not in file_output + search_output
    assert "\x07" not in file_output + search_output


@pytest.mark.parametrize(
    "renderer,payload,kwargs",
    [
        (
            render_vulnerability_page,
            {"items": [{"identifier": f"CVE-2026-{index:04d}"} for index in range(101)]},
            {},
        ),
        (
            render_poc_page,
            {"items": [{"public_id": index, "title": "row"} for index in range(101)]},
            {},
        ),
        (
            render_code_search,
            {
                "items": [
                    {
                        "public_id": index,
                        "path": "poc.py",
                        "snippet": "row",
                        "snippet_start_line": 1,
                        "snippet_end_line": 1,
                    }
                    for index in range(101)
                ]
            },
            {},
        ),
        (
            render_directory,
            {"items": [{"vendor": f"vendor-{index}"} for index in range(101)]},
            {"kind": "vendors"},
        ),
        (
            render_labs,
            {"items": [{"public_id": index, "owner": {"title": "lab"}} for index in range(101)]},
            {},
        ),
        (
            render_file_list,
            {"items": [{"path": f"file-{index}"} for index in range(201)]},
            {},
        ),
        (
            render_trends,
            {
                "cve_weaknesses": [
                    {"label": f"series-{index}", "points": []} for index in range(101)
                ]
            },
            {"selected": "cwe"},
        ),
    ],
)
def test_every_collection_renderer_has_an_independent_row_bound(renderer, payload, kwargs) -> None:
    output = rendered(renderer, payload, **kwargs)
    assert "additional response row(s) omitted" in output
