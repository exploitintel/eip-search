"""First-class Docker lab catalog presentation."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.text import Text

from .common import (
    bounded_items,
    heading,
    kv_table,
    number,
    obj,
    page_footer,
    prose,
    response_rows_omitted,
    section_title,
    text,
)


def _evidence(value: object) -> str:
    if not isinstance(value, list):
        return ""
    citations = []
    for entry in value[:8]:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path") or "file"
        start = entry.get("line_start")
        end = entry.get("line_end")
        span = f":{start}" if start else ""
        if start and end and start != end:
            span += f"-{end}"
        citations.append(f"{path}{span}")
    return ", ".join(citations)


def _described_claim(console: Console, label: str, value: object) -> None:
    if not isinstance(value, dict):
        return
    description = value.get("description") or value.get("text")
    if description:
        console.print(
            Text.assemble(text(label, style="bold"), "  ", prose(description, limit=2_500))
        )
    evidence = _evidence(value.get("evidence"))
    if evidence:
        console.print(text(f"Evidence: {evidence}", style="dim"))


def _analysis(console: Console, value: object) -> None:
    if not isinstance(value, dict):
        return
    environment = value.get("environment_summary")
    if isinstance(environment, dict):
        _described_claim(console, "Environment", environment)
    assessment = value.get("lab_assessment")
    if isinstance(assessment, dict):
        classification = assessment.get("classification") or "unclassified"
        _described_claim(console, f"Lab assessment · {classification}", assessment)
    prerequisites = value.get("prerequisites")
    if isinstance(prerequisites, list) and prerequisites:
        console.print(Text("Prerequisites described by the stored analysis", style="bold"))
        for prerequisite in prerequisites[:20]:
            _described_claim(console, "•", prerequisite)
    components = value.get("components")
    if isinstance(components, list) and components:
        console.print(Text("Components", style="bold"))
        for component in components[:20]:
            if not isinstance(component, dict):
                continue
            console.print(
                Text.assemble(
                    "• ",
                    text(component.get("name"), style="bold"),
                    " - ",
                    prose(component.get("description"), limit=1_500),
                )
            )
            evidence = _evidence(component.get("evidence"))
            if evidence:
                console.print(text(f"  Evidence: {evidence}", style="dim"))
    path = value.get("exercise_path")
    if isinstance(path, list) and path:
        console.print(Text("Exercise path described by the stored analysis", style="bold"))
        for step in path[:20]:
            if not isinstance(step, dict):
                continue
            console.print(
                Text.assemble(
                    text(step.get("step"), style="bold"),
                    ". ",
                    prose(step.get("description"), limit=1_500),
                )
            )
            evidence = _evidence(step.get("evidence"))
            if evidence:
                console.print(text(f"   Evidence: {evidence}", style="dim"))
    assessments = value.get("cve_assessments")
    if isinstance(assessments, list) and assessments:
        console.print(Text("CVE association assessments", style="bold"))
        for assessment in assessments[:20]:
            if not isinstance(assessment, dict):
                continue
            label = (
                f"{assessment.get('cve_id', 'CVE')} · {assessment.get('verdict', 'undetermined')}"
            )
            _described_claim(console, label, assessment)
    safety_verdict = value.get("safety_verdict")
    safety_reason = value.get("safety_reason")
    indicators = value.get("suspicious_indicators")
    if safety_verdict or safety_reason or indicators:
        console.print(Text("Stored operator-risk interpretation", style="bold"))
        if safety_verdict:
            console.print(text(f"Review field: {safety_verdict}"))
        _described_claim(console, "Review basis", safety_reason)
        if isinstance(indicators, list):
            for indicator in indicators[:20]:
                if isinstance(indicator, dict):
                    label = str(indicator.get("category") or "Indicator")
                    _described_claim(console, label, indicator)
                else:
                    console.print(Text.assemble("• ", prose(indicator, limit=1_500)))
    limitations = value.get("limitations")
    if isinstance(limitations, list) and limitations:
        console.print(Text("Analysis limitations", style="bold"))
        for limitation in limitations[:20]:
            console.print(Text.assemble("• ", prose(limitation, limit=1_500)))


def render_labs(console: Console, data: dict[str, Any], *, include_analysis: bool = False) -> None:
    record = obj(data, "lab search page")
    statistics = record.get("statistics") if isinstance(record.get("statistics"), dict) else {}
    console.print(heading("Docker labs"))
    console.print(
        kv_table(
            [
                ("Total", number(statistics.get("total"))),
                ("CVE-linked", number(statistics.get("cve_linked"))),
                ("Analyzed", number(statistics.get("analyzed"))),
                ("Screenshots", number(statistics.get("screenshots"))),
                ("Compose units", number(statistics.get("compose_units"))),
            ]
        )
    )
    rows, hidden = bounded_items(record.get("items", []))
    for lab in rows:
        owner = lab.get("owner") if isinstance(lab.get("owner"), dict) else {}
        console.print()
        console.print(
            Text.assemble(
                text(lab.get("public_id"), style="bold cyan"),
                "  ",
                text(
                    owner.get("title") or owner.get("native_id") or "Docker lab",
                    limit=800,
                    style="bold",
                ),
            )
        )
        cves = lab.get("cve_ids")
        cve_text = (
            ", ".join(str(value) for value in cves)
            if isinstance(cves, list) and cves
            else "unlinked"
        )
        console.print(
            kv_table(
                [
                    (
                        "Source",
                        f"{owner.get('source', ' - ')} · "
                        f"{owner.get('provider_host') or owner.get('provider_type') or ' - '}",
                    ),
                    ("Source URL", owner.get("url")),
                    ("Source date", owner.get("published_at")),
                    ("CVEs", cve_text),
                    ("Shape", lab.get("shape")),
                    ("Anchor", lab.get("anchor_kind")),
                    ("Services", number(lab.get("service_count"))),
                    ("Compose manifests", number(lab.get("compose_manifest_count"))),
                    ("Dockerfiles", number(lab.get("dockerfile_count"))),
                    (
                        "Analysis",
                        f"{lab.get('analysis_status', 'unknown')} · "
                        f"{lab.get('analysis_model') or 'no current model result'}",
                    ),
                    ("Screenshot", "available" if lab.get("screenshot") else "not supplied"),
                    (
                        "Evidence omissions",
                        "present" if lab.get("evidence_omissions_present") else "none reported",
                    ),
                ]
            )
        )
        if include_analysis and isinstance(lab.get("analysis"), dict):
            section_title(console, "Stored lab analysis")
            _analysis(console, lab.get("analysis"))
            console.print(
                Text(
                    "Stored model interpretation is not proof that this lab is runnable, "
                    "vulnerable, complete, or safe.",
                    style="dim",
                )
            )
        elif include_analysis:
            console.print(Text("No current stored lab analysis is available.", style="yellow"))
    response_rows_omitted(console, hidden)
    page_footer(console, record)
