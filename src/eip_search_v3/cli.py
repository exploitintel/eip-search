"""Command tree for the first-class EIP v3 terminal client."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.text import Text
from typer.core import TyperCommand, TyperGroup

from . import __version__
from .client import EipClient
from .config import Settings
from .errors import CliError, InputError, LocalFileError
from .render import (
    render_analysis,
    render_artifact,
    render_author,
    render_code_search,
    render_directory,
    render_file,
    render_file_list,
    render_labs,
    render_nuclei,
    render_poc_detail,
    render_poc_page,
    render_readiness,
    render_statistics,
    render_trends,
    render_vulnerability,
    render_vulnerability_page,
    render_weakness,
)
from .render.vulnerability import ALL_SECTIONS, DEFAULT_SECTIONS
from .safety import clean


class Severity(StrEnum):
    critical = "CRITICAL"
    high = "HIGH"
    medium = "MEDIUM"
    low = "LOW"
    none = "NONE"


class VulnSort(StrEnum):
    published = "published"
    cvss = "cvss"
    epss = "epss"


class PocSource(StrEnum):
    exploitdb = "exploitdb"
    metasploit = "metasploit"
    repository_inventory = "repository-inventory"


class AuthorSource(StrEnum):
    exploitdb = "exploitdb"
    metasploit = "metasploit"
    github = "github"
    gitlab = "gitlab"
    generic = "generic"


class CatalogKind(StrEnum):
    exploitdb_exploit = "exploitdb-exploit"
    metasploit_exploit = "metasploit-exploit"
    metasploit_auxiliary = "metasploit-auxiliary"
    repository_poc = "repository-poc"
    repository_candidate = "repository-candidate"


class Association(StrEnum):
    all = "all"
    linked = "linked"
    unlinked = "unlinked"


class LabKind(StrEnum):
    all = "all"
    compose = "compose"
    dockerfile = "dockerfile"


class AnalysisAvailability(StrEnum):
    all = "all"
    available = "available"
    pending = "pending"


class Trend(StrEnum):
    none = "none"
    cve_published = "cve-published"
    cwe = "cwe"
    catalog_additions = "catalog-additions"
    poc_supply = "poc-supply"
    all = "all"


class StixMapping(StrEnum):
    v1 = "v1"
    v2 = "v2"


@dataclass(slots=True)
class Runtime:
    api_base_url: str | None
    timeout_seconds: float | None
    console: Console
    error_console: Console
    _client: EipClient | None = None

    @property
    def client(self) -> EipClient:
        if self._client is None:
            settings = Settings.load(
                base_url=self.api_base_url,
                timeout_seconds=self.timeout_seconds,
            )
            self._client = EipClient(settings)
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()


_HELP_BANNER = "EIP // EXPLOIT INTEL\nVulnerability and exploit intelligence"
_PAGE_LIMIT_HELP = "Maximum records in this bounded page."
_CURSOR_HELP = "Opaque next-page cursor from the same query."
_JSON_HELP = "Emit one JSON document to stdout."
_ROOT_COMMAND_ORDER = (
    "vuln",
    "exploit",
    "code",
    "lab",
    "vendor",
    "product",
    "ecosystem",
    "package",
    "cwe",
    "author",
    "artifact",
    "stats",
    "doctor",
    "stix",
)


class EipHelpGroup(TyperGroup):
    """Add restrained branding and friendly no-command help."""

    def parse_args(self, ctx: Any, args: list[str]) -> list[str]:
        if not args and self.no_args_is_help and not ctx.resilient_parsing:
            typer.echo(ctx.get_help())
            raise typer.Exit()
        return super().parse_args(ctx, args)

    def format_help(self, ctx: Any, formatter: Any) -> None:
        if ctx.parent is None:
            formatter.write(_HELP_BANNER + "\n")
            formatter.write_paragraph()
        super().format_help(ctx, formatter)

    def list_commands(self, ctx: Any) -> list[str]:
        commands = super().list_commands(ctx)
        if ctx.parent is not None:
            return commands
        order = {name: position for position, name in enumerate(_ROOT_COMMAND_ORDER)}
        return sorted(commands, key=lambda name: order.get(name, len(order)))


class EipHelpCommand(TyperCommand):
    """Show complete leaf-command guidance when required input is absent."""

    def parse_args(self, ctx: Any, args: list[str]) -> list[str]:
        if not args and self.no_args_is_help and not ctx.resilient_parsing:
            typer.echo(ctx.get_help())
            raise typer.Exit()
        return super().parse_args(ctx, args)


def _command_group(summary: str, *examples: str) -> typer.Typer:
    example_lines = "\n".join(f"  {example}" for example in examples)
    return typer.Typer(
        help=f"{summary}\n\n\b\nExamples:\n{example_lines}",
        no_args_is_help=True,
        rich_markup_mode=None,
        cls=EipHelpGroup,
    )


app = typer.Typer(
    name="eip-search",
    help=(
        "Search the Exploit Intelligence Platform v3 corpus.\n\n\b\n"
        "Examples:\n"
        "  eip-search apache\n"
        "  eip-search CVE-2024-3400\n"
        "  eip-search code 'subprocess.run('"
    ),
    no_args_is_help=True,
    add_completion=True,
    rich_markup_mode=None,
    cls=EipHelpGroup,
)
vuln_app = _command_group(
    "Search and inspect vulnerabilities.",
    "eip-search vuln search apache",
    "eip-search vuln show CVE-2024-3400",
)
exploit_app = _command_group(
    "Search and inspect exploit and PoC artifacts.",
    "eip-search exploit search CVE-2024-3400",
    "eip-search exploit show 8700882207674114",
)
lab_app = _command_group(
    "Search Docker and Compose labs.",
    "eip-search lab search CVE-2024 --kind compose",
    "eip-search lab screenshot 43471308592392 --output lab.png",
)
cwe_app = _command_group(
    "Browse the official CWE catalog.",
    "eip-search cwe list injection",
    "eip-search cwe show CWE-78",
)
author_app = _command_group(
    "Browse exploit contributors and repository owners.",
    "eip-search author list exploitintel --source github",
    "eip-search author show 8195520625892450",
)
stix_app = _command_group(
    "Export API-owned STIX 2.1 bundles.",
    "eip-search stix vuln CVE-2024-3400 --mapping v2",
    "eip-search stix exploit 8700882207674114",
)

app.add_typer(vuln_app, name="vuln")
app.add_typer(exploit_app, name="exploit")
app.add_typer(lab_app, name="lab")
app.add_typer(cwe_app, name="cwe")
app.add_typer(author_app, name="author")
app.add_typer(stix_app, name="stix")

_IDENTIFIER_RE = re.compile(
    r"^(?:CVE-\d{4}-\d{4,}|GHSA-[23456789CFGHJMPQRVWX]{4}(?:-[23456789CFGHJMPQRVWX]{4}){2})$",
    re.IGNORECASE,
)
_CODE_TERM_RE = re.compile(r"\w", re.UNICODE)
_ROOT_COMMANDS = set(_ROOT_COMMAND_ORDER)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"eip-search {__version__}")
        raise typer.Exit()


@app.callback()
def root(
    ctx: typer.Context,
    api_base_url: Annotated[
        str | None,
        typer.Option("--api-base-url", help="Override EIP_API_BASE_URL."),
    ] = None,
    timeout: Annotated[
        float | None,
        typer.Option("--timeout", min=1.0, max=900.0, help="Request timeout in seconds."),
    ] = None,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable terminal color and styling."),
    ] = False,
    version: Annotated[
        bool,
        typer.Option(
            "--version", "-V", callback=_version, is_eager=True, help="Show version and exit."
        ),
    ] = False,
) -> None:
    del version
    color_system = None if no_color or os.environ.get("NO_COLOR") is not None else "auto"
    runtime = Runtime(
        api_base_url=api_base_url,
        timeout_seconds=timeout,
        console=Console(color_system=color_system),
        error_console=Console(stderr=True, color_system=color_system),
    )
    ctx.obj = runtime
    ctx.call_on_close(runtime.close)


def _runtime(ctx: typer.Context) -> Runtime:
    if not isinstance(ctx.obj, Runtime):
        raise RuntimeError("CLI runtime was not initialized")
    return ctx.obj


def _json(payload: object) -> None:
    try:
        encoded = json.dumps(payload, ensure_ascii=True, allow_nan=False, indent=2)
    except (TypeError, ValueError) as exc:
        raise CliError(f"Cannot serialize API response as JSON: {exc}", 4) from None
    sys.stdout.write(encoded + "\n")


def _execute(
    ctx: typer.Context,
    request: Callable[[EipClient], dict[str, Any]],
    render: Callable[[Console, dict[str, Any]], None],
    *,
    output_json: bool,
) -> None:
    runtime = _runtime(ctx)
    try:
        payload = request(runtime.client)
        if output_json:
            _json(payload)
        else:
            render(runtime.console, payload)
    except CliError as exc:
        runtime.error_console.print(
            Text(f"Error: {clean(exc.message, limit=1_000)}", style="bold red")
        )
        if exc.retry_after is not None:
            runtime.error_console.print(Text(f"Retry-After: {exc.retry_after}s", style="dim"))
        raise typer.Exit(exc.exit_code) from None


def _params(**values: object) -> list[tuple[str, object]]:
    result: list[tuple[str, object]] = []
    for name, value in values.items():
        if value is None or value is False or value == "":
            continue
        if isinstance(value, list):
            result.extend(
                (name, item.value if isinstance(item, StrEnum) else item) for item in value
            )
        elif isinstance(value, StrEnum):
            result.append((name, value.value))
        elif isinstance(value, date):
            result.append((name, value.isoformat()))
        else:
            result.append((name, value))
    return result


def _require_public_id(value: int) -> int:
    if not 1 <= value <= 9_000_000_000_000_000:
        raise InputError("public ID is outside the supported range")
    return value


def _iso_date(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError:
        raise typer.BadParameter("expected an ISO date in YYYY-MM-DD form") from None


def _code_query(value: str) -> str:
    if not 2 <= len(value) <= 200:
        raise typer.BadParameter("must contain between 2 and 200 characters")
    if not any(_CODE_TERM_RE.search(chunk) for chunk in value.split()):
        raise typer.BadParameter("must contain at least one letter, digit, or underscore")
    return value


def _identifier(value: str) -> str:
    normalized = value.strip().upper()
    if normalized.startswith("CVE-") and not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
        raise typer.BadParameter("a CVE identifier is CVE-<4-digit year>-<4 or more digits>")
    if normalized.startswith("GHSA-") and not _IDENTIFIER_RE.fullmatch(normalized):
        raise typer.BadParameter("a GHSA identifier is GHSA-xxxx-xxxx-xxxx")
    return normalized


@vuln_app.command("search")
def vuln_search(
    ctx: typer.Context,
    query: Annotated[
        str | None, typer.Argument(help="Full-text vulnerability query.")
    ] = None,
    severity: Annotated[
        list[Severity] | None,
        typer.Option("--severity", "-s", help="Repeat to include CVSS severities."),
    ] = None,
    cwe: Annotated[str | None, typer.Option("--cwe", help="Exact CWE identifier.")] = None,
    vendor: Annotated[
        str | None, typer.Option("--vendor", help="Source-native vendor name.")
    ] = None,
    product: Annotated[
        str | None, typer.Option("--product", help="Source-native product name.")
    ] = None,
    ecosystem: Annotated[
        str | None, typer.Option("--ecosystem", help="Exact package ecosystem.")
    ] = None,
    package: Annotated[
        str | None, typer.Option("--package", help="Exact package in the selected ecosystem.")
    ] = None,
    cisa_kev: Annotated[
        bool, typer.Option("--cisa-kev", help="Require CISA Known Exploited Vulnerabilities.")
    ] = False,
    ransomware: Annotated[
        bool, typer.Option("--ransomware", help="Require source-backed ransomware evidence.")
    ] = False,
    nuclei: Annotated[
        bool, typer.Option("--nuclei", help="Require at least one linked Nuclei template.")
    ] = False,
    with_artifacts: Annotated[
        bool,
        typer.Option(
            "--with-artifacts", help="Require artifact_count > 0; this is broader than PoCs."
        ),
    ] = False,
    sort: Annotated[VulnSort, typer.Option("--sort", help="API-owned result ordering.")] = (
        VulnSort.published
    ),
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, max=100, help=_PAGE_LIMIT_HELP)
    ] = 25,
    cursor: Annotated[str | None, typer.Option("--cursor", help=_CURSOR_HELP)] = None,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Search vulnerabilities using API-owned filters and ordering.

    Example: eip-search vuln search apache --severity HIGH
    """
    if package is not None and ecosystem is None:
        raise typer.BadParameter("--package requires --ecosystem")
    params = _params(
        q=query,
        severity=severity,
        cwe=cwe,
        vendor=vendor,
        product=product,
        ecosystem=ecosystem,
        package=package,
        cisa_kev=cisa_kev,
        ransomware=ransomware,
        nuclei=nuclei,
        with_artifacts=with_artifacts,
        sort=sort,
        limit=limit,
        cursor=cursor,
    )
    _execute(
        ctx,
        lambda client: client.search_vulnerabilities(params),
        render_vulnerability_page,
        output_json=output_json,
    )


@vuln_app.command("show")
def vuln_show(
    ctx: typer.Context,
    identifier: Annotated[
        str,
        typer.Argument(
            metavar="IDENTIFIER",
            callback=_identifier,
            help="CVE, GHSA, or supported alternate identifier.",
        ),
    ],
    section: Annotated[
        list[str] | None,
        typer.Option(
            "--section",
            help=f"Repeat to select sections: {', '.join(ALL_SECTIONS)}.",
        ),
    ] = None,
    all_sections: Annotated[
        bool, typer.Option("--all", help="Render every detail section.")
    ] = False,
    section_limit: Annotated[
        int,
        typer.Option(
            "--section-limit", min=1, max=50, help="Maximum records rendered per section."
        ),
    ] = 10,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Show one vulnerability and selected detail sections.

    Example: eip-search vuln show CVE-2024-3400
    """
    if section and all_sections:
        raise typer.BadParameter("--section and --all cannot be used together")
    selected = tuple(section or (ALL_SECTIONS if all_sections else DEFAULT_SECTIONS))
    unknown = sorted(set(selected) - set(ALL_SECTIONS))
    if unknown:
        raise typer.BadParameter(f"unknown section(s): {', '.join(unknown)}")
    _execute(
        ctx,
        lambda client: client.vulnerability(identifier),
        lambda console, payload: render_vulnerability(
            console, payload, sections=selected, section_limit=section_limit
        ),
        output_json=output_json,
    )


@vuln_app.command("nuclei")
def vuln_nuclei(
    ctx: typer.Context,
    identifier: Annotated[
        str,
        typer.Argument(
            metavar="IDENTIFIER",
            callback=_identifier,
            help="CVE or supported vulnerability identifier.",
        ),
    ],
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, max=50, help="Maximum templates rendered.")
    ] = 20,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Show Nuclei templates linked to one vulnerability.

    Example: eip-search vuln nuclei CVE-2024-3400
    """
    def render(console: Console, payload: dict[str, Any]) -> None:
        render_nuclei(console, payload.get("nuclei_templates"), limit=limit)

    def request(client: EipClient) -> dict[str, Any]:
        payload = client.vulnerability(identifier)
        if output_json:
            return {
                "identifier": payload.get("identifier"),
                "nuclei_templates": payload.get("nuclei_templates"),
            }
        return payload

    _execute(ctx, request, render, output_json=output_json)


@exploit_app.command("search")
def exploit_search(
    ctx: typer.Context,
    query: Annotated[
        str | None,
        typer.Argument(help="Metadata substring or exact linked CVE."),
    ] = None,
    source: Annotated[
        PocSource | None, typer.Option("--source", help="Exact artifact source lane.")
    ] = None,
    catalog_kind: Annotated[
        CatalogKind | None, typer.Option("--catalog-kind", help="Exact catalog kind.")
    ] = None,
    association: Annotated[
        Association,
        typer.Option("--association", help="Include all, CVE-linked, or unlinked artifacts."),
    ] = Association.all,
    language: Annotated[
        str | None, typer.Option("--language", "-l", help="Source-native language label.")
    ] = None,
    source_date_from: Annotated[
        str | None,
        typer.Option(
            "--source-date-from", callback=_iso_date, help="Earliest source date, YYYY-MM-DD."
        ),
    ] = None,
    source_date_to: Annotated[
        str | None,
        typer.Option(
            "--source-date-to", callback=_iso_date, help="Latest source date, YYYY-MM-DD."
        ),
    ] = None,
    author_id: Annotated[
        int | None,
        typer.Option(
            "--author-id", min=1, max=9_000_000_000_000_000, help="Exact author public ID."
        ),
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, max=100, help=_PAGE_LIMIT_HELP)
    ] = 25,
    cursor: Annotated[str | None, typer.Option("--cursor", help=_CURSOR_HELP)] = None,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Search catalogued and repository exploit artifacts.

    Example: eip-search exploit search CVE-2024-3400
    """
    if source_date_from and source_date_to and source_date_from > source_date_to:
        raise typer.BadParameter("--source-date-from must not be after --source-date-to")
    params = _params(
        q=query,
        source=source,
        catalog_kind=catalog_kind,
        association=association,
        language=language,
        source_date_from=source_date_from,
        source_date_to=source_date_to,
        author_id=author_id,
        limit=limit,
        cursor=cursor,
    )
    _execute(
        ctx, lambda client: client.search_pocs(params), render_poc_page, output_json=output_json
    )


@exploit_app.command("show")
def exploit_show(
    ctx: typer.Context,
    identity: Annotated[
        str,
        typer.Argument(
            metavar="IDENTITY", help="Stable numeric public ID or API artifact ID."
        ),
    ],
    no_analysis: Annotated[
        bool, typer.Option("--no-analysis", help="Omit stored model interpretation.")
    ] = False,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Show one exploit artifact with files and optional analysis.

    Example: eip-search exploit show 8700882207674114
    """
    _execute(
        ctx,
        lambda client: client.poc(identity),
        lambda console, payload: render_poc_detail(
            console, payload, include_analysis=not no_analysis
        ),
        output_json=output_json,
    )


@exploit_app.command("analysis")
def exploit_analysis(
    ctx: typer.Context,
    identity: Annotated[
        str,
        typer.Argument(
            metavar="IDENTITY", help="Stable numeric public ID or API artifact ID."
        ),
    ],
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Show stored technical and backdoor analysis for an artifact.

    Example: eip-search exploit analysis 8700882207674114
    """
    def request(client: EipClient) -> dict[str, Any]:
        payload = client.poc(identity)
        return {"artifact_id": payload.get("artifact_id"), "analysis": payload.get("analysis")}

    _execute(
        ctx,
        request,
        lambda console, payload: render_analysis(console, payload.get("analysis")),
        output_json=output_json,
    )


@exploit_app.command("files")
def exploit_files(
    ctx: typer.Context,
    identity: Annotated[
        str,
        typer.Argument(
            metavar="IDENTITY", help="Stable numeric public ID or API artifact ID."
        ),
    ],
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """List safely readable files for one exploit artifact.

    Example: eip-search exploit files 8700882207674114
    """
    _execute(
        ctx, lambda client: client.poc_files(identity), render_file_list, output_json=output_json
    )


@exploit_app.command("view")
def exploit_view(
    ctx: typer.Context,
    identity: Annotated[
        str,
        typer.Argument(
            metavar="IDENTITY", help="Stable numeric public ID or API artifact ID."
        ),
    ],
    path: Annotated[
        str, typer.Argument(metavar="PATH", help="Exact path returned by `exploit files`.")
    ],
    language: Annotated[
        str | None, typer.Option("--language", help="Override syntax-highlighting language.")
    ] = None,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """View one safely readable source file without executing it.

    Example: eip-search exploit view 8700882207674114 README.md
    """
    _execute(
        ctx,
        lambda client: client.poc_file(identity, path),
        lambda console, payload: render_file(console, payload, language=language),
        output_json=output_json,
    )


@exploit_app.command("download")
def exploit_download(
    ctx: typer.Context,
    identity: Annotated[
        str,
        typer.Argument(
            metavar="IDENTITY", help="Stable numeric public ID or API artifact ID."
        ),
    ],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Destination ZIP path.")
    ] = None,
    force: Annotated[
        bool, typer.Option("--force", help="Replace an existing destination file.")
    ] = False,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Download a protected archive without extracting or executing it.

    Example: eip-search exploit download 8700882207674114 --output poc.zip
    """
    def render(console: Console, payload: dict[str, Any]) -> None:
        console.print(
            Text(
                clean(f"Saved {payload['path']} ({payload['size']:,} bytes)", limit=2_000),
                style="bold green",
            )
        )
        console.print(Text(f"SHA-256: {payload['sha256']}", style="dim"))
        console.print(Text("Archive password: eip", style="bold yellow"))
        console.print(Text("The archive was not extracted or executed.", style="dim"))

    _execute(
        ctx,
        lambda client: client.download_poc(identity, output, force=force),
        render,
        output_json=output_json,
    )


@app.command("code", cls=EipHelpCommand, no_args_is_help=True)
def code_search(
    ctx: typer.Context,
    query: Annotated[
        str,
        typer.Argument(
            metavar="QUERY",
            callback=_code_query,
            help="Source-code FTS text, 2 to 200 characters.",
        ),
    ],
    source: Annotated[
        PocSource | None, typer.Option("--source", help="Restrict to one source lane.")
    ] = None,
    public_id: Annotated[
        int | None,
        typer.Option(
            "--public-id",
            min=1,
            max=9_000_000_000_000_000,
            help="Search only the PoC with this stable public ID.",
        ),
    ] = None,
    vulnerability_id: Annotated[
        str | None,
        typer.Option(
            "--vulnerability",
            metavar="IDENTIFIER",
            help="Search only PoCs associated with this vulnerability identifier.",
        ),
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, max=50, help=_PAGE_LIMIT_HELP)
    ] = 25,
    cursor: Annotated[str | None, typer.Option("--cursor", help=_CURSOR_HELP)] = None,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Search safely readable PoC files by token terms.

    Each whitespace-separated chunk containing a letter, digit, or `_`
    is required as an FTS phrase; punctuation-only chunks are ignored. Results
    are ordered by textual relevance, not exploit quality.

    Example: eip-search code 'subprocess.run(' --vulnerability CVE-2024-3400
    """
    if public_id is not None and vulnerability_id is not None:
        raise typer.BadParameter("--public-id and --vulnerability cannot be used together")
    normalized_vulnerability = vulnerability_id.strip() if vulnerability_id is not None else None
    if normalized_vulnerability is not None and not 1 <= len(normalized_vulnerability) <= 512:
        raise typer.BadParameter("--vulnerability must contain between 1 and 512 characters")
    if normalized_vulnerability is not None and any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        for character in normalized_vulnerability
    ):
        raise typer.BadParameter("--vulnerability contains invalid control characters")
    body: dict[str, Any] = {"q": query, "limit": limit}
    if source is not None:
        body["source"] = source.value
    if public_id is not None:
        body["public_id"] = public_id
    if normalized_vulnerability is not None:
        body["vulnerability_id"] = normalized_vulnerability
    if cursor:
        body["cursor"] = cursor
    _execute(
        ctx, lambda client: client.code_search(body), render_code_search, output_json=output_json
    )


@lab_app.command("search")
def lab_search(
    ctx: typer.Context,
    query: Annotated[
        str | None,
        typer.Argument(help="Metadata substring or exact linked CVE."),
    ] = None,
    kind: Annotated[
        LabKind, typer.Option("--kind", help="Restrict the lab definition kind.")
    ] = LabKind.all,
    association: Annotated[
        Association,
        typer.Option("--association", help="Include all, CVE-linked, or unlinked labs."),
    ] = Association.all,
    analysis: Annotated[
        AnalysisAvailability, typer.Option("--analysis", help="Filter stored analysis presence.")
    ] = AnalysisAvailability.all,
    include_analysis: Annotated[
        bool,
        typer.Option("--include-analysis", help="Render stored analysis; requires limit <= 10."),
    ] = False,
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, max=100, help=_PAGE_LIMIT_HELP)
    ] = 10,
    cursor: Annotated[str | None, typer.Option("--cursor", help=_CURSOR_HELP)] = None,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Search first-class Docker and Compose lab units.

    Example: eip-search lab search CVE-2024 --kind compose
    """
    if include_analysis and limit > 10:
        raise typer.BadParameter("--include-analysis requires --limit 10 or lower")
    params = _params(
        q=query, kind=kind, association=association, analysis=analysis, limit=limit, cursor=cursor
    )
    _execute(
        ctx,
        lambda client: client.search_labs(params),
        lambda console, payload: render_labs(console, payload, include_analysis=include_analysis),
        output_json=output_json,
    )


@lab_app.command("screenshot")
def lab_screenshot(
    ctx: typer.Context,
    public_id: Annotated[
        int, typer.Argument(metavar="PUBLIC-ID", help="Stable numeric lab public ID.")
    ],
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Destination image path.")
    ],
    force: Annotated[
        bool, typer.Option("--force", help="Replace an existing destination file.")
    ] = False,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Download a lab screenshot when one is available.

    Example: eip-search lab screenshot 43471308592392 --output lab.png
    """
    _execute(
        ctx,
        lambda client: client.download_screenshot(
            _require_public_id(public_id), output, force=force
        ),
        lambda console, payload: console.print(
            Text(
                clean(f"Saved {payload['path']} ({payload['size']:,} bytes)", limit=2_000),
                style="bold green",
            )
        ),
        output_json=output_json,
    )


def _directory_command(
    ctx: typer.Context,
    name: str,
    *,
    query: str | None,
    limit: int,
    cursor: str | None,
    output_json: bool,
    parent: tuple[str, str] | None = None,
) -> None:
    values: dict[str, object] = {"q": query, "limit": limit, "cursor": cursor}
    if parent:
        values[parent[0]] = parent[1]
    params = _params(**values)
    _execute(
        ctx,
        lambda client: client.directory(name, params),
        lambda console, payload: render_directory(console, payload, name),
        output_json=output_json,
    )


@app.command("vendor")
def vendor_list(
    ctx: typer.Context,
    query: Annotated[
        str | None, typer.Argument(help="Optional vendor-name substring.")
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, max=100, help=_PAGE_LIMIT_HELP)
    ] = 25,
    cursor: Annotated[str | None, typer.Option("--cursor", help=_CURSOR_HELP)] = None,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """List source-native vendors.

    Example: eip-search vendor Microsoft
    """
    _directory_command(
        ctx, "vendors", query=query, limit=limit, cursor=cursor, output_json=output_json
    )


@app.command("product", cls=EipHelpCommand, no_args_is_help=True)
def product_list(
    ctx: typer.Context,
    vendor: Annotated[str, typer.Option("--vendor", help="Exact source-native vendor name.")],
    query: Annotated[
        str | None, typer.Argument(help="Optional product-name substring.")
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, max=100, help=_PAGE_LIMIT_HELP)
    ] = 25,
    cursor: Annotated[str | None, typer.Option("--cursor", help=_CURSOR_HELP)] = None,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """List one vendor's products.

    Example: eip-search product --vendor Microsoft Windows
    """
    _directory_command(
        ctx,
        "products",
        query=query,
        limit=limit,
        cursor=cursor,
        output_json=output_json,
        parent=("vendor", vendor),
    )


@app.command("ecosystem")
def ecosystem_list(
    ctx: typer.Context,
    query: Annotated[
        str | None, typer.Argument(help="Optional ecosystem-name substring.")
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, max=100, help=_PAGE_LIMIT_HELP)
    ] = 25,
    cursor: Annotated[str | None, typer.Option("--cursor", help=_CURSOR_HELP)] = None,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """List package ecosystems.

    Example: eip-search ecosystem PyPI
    """
    _directory_command(
        ctx, "ecosystems", query=query, limit=limit, cursor=cursor, output_json=output_json
    )


@app.command("package", cls=EipHelpCommand, no_args_is_help=True)
def package_list(
    ctx: typer.Context,
    ecosystem: Annotated[str, typer.Option("--ecosystem", help="Exact package ecosystem.")],
    query: Annotated[
        str | None, typer.Argument(help="Optional package-name substring.")
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, max=100, help=_PAGE_LIMIT_HELP)
    ] = 25,
    cursor: Annotated[str | None, typer.Option("--cursor", help=_CURSOR_HELP)] = None,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """List packages in an ecosystem.

    Example: eip-search package --ecosystem PyPI Django
    """
    _directory_command(
        ctx,
        "packages",
        query=query,
        limit=limit,
        cursor=cursor,
        output_json=output_json,
        parent=("ecosystem", ecosystem),
    )


@cwe_app.command("list")
def cwe_list(
    ctx: typer.Context,
    query: Annotated[
        str | None, typer.Argument(help="Optional CWE ID or name substring.")
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, max=100, help=_PAGE_LIMIT_HELP)
    ] = 25,
    cursor: Annotated[str | None, typer.Option("--cursor", help=_CURSOR_HELP)] = None,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """List official CWE catalog entries used by vulnerabilities.

    Example: eip-search cwe list injection
    """
    _directory_command(
        ctx, "weaknesses", query=query, limit=limit, cursor=cursor, output_json=output_json
    )


@cwe_app.command("show")
def cwe_show(
    ctx: typer.Context,
    cwe_id: Annotated[
        str,
        typer.Argument(metavar="CWE-ID", help="Exact CWE identifier, such as CWE-78."),
    ],
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Show one official CWE catalog entry.

    Example: eip-search cwe show CWE-78
    """
    _execute(
        ctx,
        lambda client: client.weakness(cwe_id.upper()),
        render_weakness,
        output_json=output_json,
    )


@author_app.command("list")
def author_list(
    ctx: typer.Context,
    query: Annotated[
        str | None,
        typer.Argument(help="Optional contributor-name substring."),
    ] = None,
    source: Annotated[
        AuthorSource | None, typer.Option("--source", help="Exact contributor source scope.")
    ] = None,
    role: Annotated[
        str | None, typer.Option("--role", help="Contributor role: author or owner.")
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, max=100, help=_PAGE_LIMIT_HELP)
    ] = 25,
    cursor: Annotated[str | None, typer.Option("--cursor", help=_CURSOR_HELP)] = None,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """List source-scoped exploit contributors and repository owners.

    Example: eip-search author list exploitintel --source github
    """
    if role not in {None, "author", "owner"}:
        raise typer.BadParameter("role must be author or owner")
    params = _params(q=query, source_scope=source, role=role, limit=limit, cursor=cursor)
    _execute(
        ctx,
        lambda client: client.directory("authors", params),
        lambda console, payload: render_directory(console, payload, "authors"),
        output_json=output_json,
    )


@author_app.command("show")
def author_show(
    ctx: typer.Context,
    public_id: Annotated[
        int, typer.Argument(metavar="PUBLIC-ID", help="Stable numeric author public ID.")
    ],
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Show one source-scoped contributor identity.

    Example: eip-search author show 8195520625892450
    """
    _execute(
        ctx,
        lambda client: client.author(_require_public_id(public_id)),
        render_author,
        output_json=output_json,
    )


@author_app.command("exploits")
def author_exploits(
    ctx: typer.Context,
    public_id: Annotated[
        int, typer.Argument(metavar="PUBLIC-ID", help="Stable numeric author public ID.")
    ],
    limit: Annotated[
        int, typer.Option("--limit", "-n", min=1, max=100, help=_PAGE_LIMIT_HELP)
    ] = 25,
    cursor: Annotated[str | None, typer.Option("--cursor", help=_CURSOR_HELP)] = None,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """List exploit artifacts linked to one contributor identity.

    Example: eip-search author exploits 8195520625892450
    """
    params = _params(author_id=_require_public_id(public_id), limit=limit, cursor=cursor)
    _execute(
        ctx, lambda client: client.search_pocs(params), render_poc_page, output_json=output_json
    )


@app.command("artifact", cls=EipHelpCommand, no_args_is_help=True)
def artifact_show(
    ctx: typer.Context,
    identity: Annotated[
        str, typer.Argument(metavar="ARTIFACT-ID", help="Exact API artifact identity.")
    ],
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Show linked-artifact metadata.

    Example: eip-search artifact 4134af29-1554-5627-9c62-16de2390ed0a
    """
    _execute(
        ctx,
        lambda client: client.artifact(identity),
        render_artifact,
        output_json=output_json,
    )


@app.command("stats")
def stats(
    ctx: typer.Context,
    trends: Annotated[
        Trend, typer.Option("--trends", help="Include one bounded trend series or all series.")
    ] = Trend.none,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Show current corpus totals and optional trend series.

    Example: eip-search stats --trends all
    """
    def request(client: EipClient) -> dict[str, Any]:
        totals = client.statistics()
        if trends == Trend.none:
            return totals
        trend_payload = client.statistics_trends()
        if trends != Trend.all:
            field = {
                Trend.cve_published: "cve_published",
                Trend.cwe: "cve_weaknesses",
                Trend.catalog_additions: "catalog_additions",
                Trend.poc_supply: "poc_supply",
            }[trends]
            trend_payload = {
                key: value
                for key, value in trend_payload.items()
                if key in {"as_of", field}
            }
        return {"statistics": totals, "trends": trend_payload}

    def render(console: Console, payload: dict[str, Any]) -> None:
        if trends == Trend.none:
            render_statistics(console, payload)
            return
        render_statistics(console, payload["statistics"])
        render_trends(console, payload["trends"], trends.value)

    _execute(ctx, request, render, output_json=output_json)


@app.command("doctor")
def doctor(
    ctx: typer.Context,
    output_json: Annotated[bool, typer.Option("--json", "-j", help=_JSON_HELP)] = False,
) -> None:
    """Check API and code-search readiness.

    Example: eip-search doctor
    """
    runtime = _runtime(ctx)
    try:
        payload = runtime.client.readiness()
        if output_json:
            _json(payload)
        else:
            render_readiness(runtime.console, payload)
        if payload.get("status") != "ready" or payload.get("code_search_status") != "ready":
            raise typer.Exit(4)
    except CliError as exc:
        runtime.error_console.print(
            Text(f"Error: {clean(exc.message, limit=1_000)}", style="bold red")
        )
        raise typer.Exit(exc.exit_code) from None


def _save_json(payload: dict[str, Any], output: Path, *, force: bool) -> dict[str, Any]:
    destination = output.expanduser()
    encoded = (
        json.dumps(payload, ensure_ascii=False, allow_nan=False, indent=2).encode("utf-8") + b"\n"
    )
    temporary: Path | None = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and not force:
            raise LocalFileError(f"Refusing to overwrite {destination}; pass --force")
        descriptor, raw_path = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".part", dir=destination.parent
        )
        temporary = Path(raw_path)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            os.replace(temporary, destination)
        else:
            try:
                os.link(temporary, destination)
            except FileExistsError:
                raise LocalFileError(f"Refusing to overwrite {destination}; pass --force") from None
            temporary.unlink()
        temporary = None
    except OSError as exc:
        raise LocalFileError(f"Cannot write {destination}: {exc}") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {"path": str(destination), "size": len(encoded)}


def _stix_command(
    ctx: typer.Context,
    request: Callable[[EipClient], dict[str, Any]],
    *,
    output: Path | None,
    force: bool,
) -> None:
    runtime = _runtime(ctx)
    try:
        payload = request(runtime.client)
        if output is None:
            _json(payload)
        else:
            result = _save_json(payload, output, force=force)
            runtime.console.print(
                Text(
                    clean(f"Saved {result['path']} ({result['size']:,} bytes)", limit=2_000),
                    style="bold green",
                )
            )
    except CliError as exc:
        runtime.error_console.print(
            Text(f"Error: {clean(exc.message, limit=1_000)}", style="bold red")
        )
        raise typer.Exit(exc.exit_code) from None


@stix_app.command("vuln")
def stix_vuln(
    ctx: typer.Context,
    identifier: Annotated[
        str,
        typer.Argument(
            metavar="IDENTIFIER",
            callback=_identifier,
            help="CVE or supported vulnerability identifier.",
        ),
    ],
    mapping: Annotated[
        StixMapping, typer.Option("--mapping", help="API-owned STIX mapping version.")
    ] = StixMapping.v1,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the bundle to this JSON file.")
    ] = None,
    force: Annotated[
        bool, typer.Option("--force", help="Replace an existing output file.")
    ] = False,
) -> None:
    """Export an API-owned STIX 2.1 bundle for one vulnerability.

    Example: eip-search stix vuln CVE-2024-3400 --mapping v2
    """
    _stix_command(
        ctx,
        lambda client: client.stix_vulnerability(identifier, mapping=mapping.value),
        output=output,
        force=force,
    )


@stix_app.command("exploit")
def stix_exploit(
    ctx: typer.Context,
    public_id: Annotated[
        int, typer.Argument(metavar="PUBLIC-ID", help="Stable numeric exploit public ID.")
    ],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the bundle to this JSON file.")
    ] = None,
    force: Annotated[
        bool, typer.Option("--force", help="Replace an existing output file.")
    ] = False,
) -> None:
    """Export an API-owned STIX 2.1 bundle for one exploit.

    Example: eip-search stix exploit 8700882207674114
    """
    _stix_command(
        ctx,
        lambda client: client.stix_exploit(_require_public_id(public_id)),
        output=output,
        force=force,
    )


def _route_bare_argument(argv: list[str]) -> list[str]:
    if not argv:
        return argv
    value_options = {"--api-base-url", "--timeout"}
    flag_options = {"--no-color"}
    index = 0
    while index < len(argv):
        value = argv[index]
        if value in flag_options:
            index += 1
        elif value in value_options:
            index += 2
        elif any(value.startswith(option + "=") for option in value_options):
            index += 1
        else:
            break
    if index >= len(argv):
        return argv
    candidate = argv[index]
    if candidate.startswith("-") or candidate in _ROOT_COMMANDS:
        return argv
    command = ["vuln", "show"] if _IDENTIFIER_RE.fullmatch(candidate) else ["vuln", "search"]
    return argv[:index] + command + argv[index:]


def entrypoint() -> None:
    sys.argv[1:] = _route_bare_argument(sys.argv[1:])
    try:
        app()
    except (SystemExit, KeyboardInterrupt):
        raise
    except Exception:
        typer.echo("Error: eip-search encountered an unexpected internal error.", err=True)
        raise SystemExit(1) from None
