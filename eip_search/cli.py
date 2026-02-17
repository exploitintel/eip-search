"""eip-search CLI — modern searchsploit replacement powered by the Exploit Intelligence Platform."""

from __future__ import annotations

import json
import re
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.status import Status

from eip_search import __version__
from eip_search.client import APIError

console = Console()
err_console = Console(stderr=True)

_app = typer.Typer(
    name="eip-search",
    help="Search exploits, vulnerabilities, and threat intelligence from the Exploit Intelligence Platform.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=True,
)

# Known subcommands for argv routing
_SUBCOMMANDS = {"search", "info", "view", "download", "triage", "nuclei", "stats"}


def app():
    """Entry point that auto-routes bare queries to 'search' subcommand."""
    args = sys.argv[1:]

    # Handle --version before typer (no_args_is_help blocks callback)
    if args and args[0] in ("--version", "-V"):
        console.print(f"eip-search {__version__}")
        raise SystemExit(0)

    # If the first non-option arg isn't a known subcommand, prepend "search"
    if args and not args[0].startswith("-") and args[0] not in _SUBCOMMANDS:
        # e.g. eip-search "apache httpd" → eip-search search "apache httpd"
        sys.argv = [sys.argv[0], "search"] + args

    _app()

# ---------------------------------------------------------------------------
# Regex patterns for auto-CVE routing
# ---------------------------------------------------------------------------
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_EIP_RE = re.compile(r"^EIP-\d{4}-\d+$", re.IGNORECASE)


def _is_vuln_id(query: str) -> bool:
    """Return True if query looks like a CVE-ID or EIP-ID."""
    q = query.strip()
    return bool(_CVE_RE.match(q) or _EIP_RE.match(q))


def _normalize_vuln_id(raw: str) -> str:
    """Normalize a CVE/EIP ID to uppercase with ASCII hyphens."""
    return raw.strip().upper().replace("\u2010", "-").replace("\u2013", "-").replace("\u2014", "-")


def _api_call(func, *args, spinner_text: str = "Querying API...", **kwargs):
    """Wrap an API call with a rich spinner and error handling."""
    with Status(spinner_text, console=err_console, spinner="dots"):
        try:
            return func(*args, **kwargs)
        except APIError as exc:
            from eip_search.display import print_error
            if exc.status_code == 404:
                print_error(f"Not found: {exc.message}")
            elif exc.status_code == 429:
                print_error(f"Rate limited. {exc.message}")
            else:
                print_error(exc.message)
            raise typer.Exit(1)
        except Exception as exc:
            from eip_search.display import print_error
            print_error(f"Connection error: {exc}")
            raise typer.Exit(1)


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  DEFAULT COMMAND: search (or auto-route to info for CVE IDs)            ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

@_app.command()
def search(
    query: Optional[str] = typer.Argument(None, help="Search query, CVE-ID, or EIP-ID"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter: critical, high, medium, low"),
    has_exploits: bool = typer.Option(False, "--has-exploits", "-e", help="Only CVEs with public exploits"),
    kev: bool = typer.Option(False, "--kev", "-k", help="Only CISA Known Exploited Vulnerabilities"),
    has_nuclei: bool = typer.Option(False, "--has-nuclei", help="Only CVEs with Nuclei templates"),
    vendor: Optional[str] = typer.Option(None, "--vendor", "-v", help="Filter by vendor name"),
    product: Optional[str] = typer.Option(None, "--product", "-p", help="Filter by product name"),
    ecosystem: Optional[str] = typer.Option(None, "--ecosystem", help="Filter by ecosystem (npm, pip, maven, go)"),
    cwe: Optional[str] = typer.Option(None, "--cwe", help="Filter by CWE ID (e.g. 79 or CWE-79)"),
    year: Optional[int] = typer.Option(None, "--year", "-y", help="Filter by CVE year"),
    min_cvss: Optional[float] = typer.Option(None, "--min-cvss", help="Minimum CVSS score (0-10)"),
    min_epss: Optional[float] = typer.Option(None, "--min-epss", help="Minimum EPSS score (0-1)"),
    date_from: Optional[str] = typer.Option(None, "--date-from", help="Start date (YYYY-MM-DD)"),
    date_to: Optional[str] = typer.Option(None, "--date-to", help="End date (YYYY-MM-DD)"),
    sort: Optional[str] = typer.Option(None, "--sort", help="Sort: newest, oldest, cvss_desc, epss_desc, relevance"),
    page: int = typer.Option(1, "--page", help="Page number"),
    per_page: Optional[int] = typer.Option(None, "--per-page", "-n", help="Results per page (max 100)"),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
) -> None:
    """Search vulnerabilities and exploits.

    \b
    Examples:
      eip-search search "apache httpd" --has-exploits
      eip-search search "fortinet" --severity critical --kev
      eip-search search --vendor paloalto --min-epss 0.5 --sort epss_desc
      eip-search search --cwe 89 --has-exploits --sort cvss_desc
    """
    has_filters = any([
        severity, has_exploits, kev, has_nuclei, vendor, product,
        ecosystem, cwe, year, min_cvss, min_epss, date_from, date_to,
    ])
    if not query and not has_filters:
        from eip_search.display import print_error
        print_error("Provide a search query or at least one filter.")
        raise typer.Exit(1)

    # Auto-route CVE/EIP IDs to the detail view
    if query and _is_vuln_id(query):
        _do_info(_normalize_vuln_id(query), show_all=False, output_json=output_json)
        return

    _do_search(
        q=query, severity=severity, has_exploits=has_exploits, kev=kev,
        has_nuclei=has_nuclei, vendor=vendor, product=product, ecosystem=ecosystem,
        cwe=cwe, year=year, min_cvss=min_cvss, min_epss=min_epss,
        date_from=date_from, date_to=date_to, sort=sort, page=page,
        per_page=per_page, output_json=output_json,
    )


@_app.callback()
def main() -> None:
    """Search exploits, vulnerabilities, and threat intelligence from the Exploit Intelligence Platform.

    \b
    Quick usage (bare query auto-routes to search):
      eip-search "apache httpd"
      eip-search CVE-2024-3400

    \b
    Search with filters:
      eip-search search "fortinet" --severity critical --has-exploits --kev
      eip-search search --vendor paloalto --min-epss 0.5

    \b
    Other commands:
      eip-search info CVE-2024-3400      Full intelligence brief
      eip-search triage --vendor apache   Risk-based triage
      eip-search nuclei CVE-2024-27198   Nuclei templates + dorks
      eip-search view 77423              View exploit source code
      eip-search download 77423          Download exploit ZIP
      eip-search stats                   Platform statistics
    """
    pass


def _do_search(*, q, severity, has_exploits, kev, has_nuclei, vendor, product,
               ecosystem, cwe, year, min_cvss, min_epss, date_from, date_to,
               sort, page, per_page, output_json):
    """Execute a search and display results."""
    from eip_search import client
    from eip_search.config import get_config

    params = {
        "q": q,
        "severity": severity,
        "is_kev": kev or None,
        "has_exploits": has_exploits or None,
        "has_nuclei": has_nuclei or None,
        "vendor": vendor,
        "product": product,
        "ecosystem": ecosystem,
        "cwe": cwe,
        "year": year,
        "min_cvss": min_cvss,
        "min_epss": min_epss,
        "date_from": date_from,
        "date_to": date_to,
        "sort": sort or "newest",
        "page": page,
        "per_page": per_page or get_config().per_page,
    }

    result = _api_call(client.search_vulns, params, spinner_text="Searching...")

    if output_json:
        _json_out({
            "total": result.total,
            "page": result.page,
            "per_page": result.per_page,
            "total_pages": result.total_pages,
            "items": [_vuln_summary_dict(v) for v in result.items],
        })
    else:
        from eip_search.display import print_search_results
        print_search_results(result)


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  INFO COMMAND                                                           ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

@_app.command()
def info(
    vuln_id: str = typer.Argument(..., help="CVE-ID (e.g. CVE-2024-3400) or EIP-ID"),
    show_all: bool = typer.Option(False, "--all", "-a", help="Show all exploits including trickest"),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
) -> None:
    """Show full intelligence brief for a vulnerability."""
    _do_info(_normalize_vuln_id(vuln_id), show_all=show_all, output_json=output_json)


def _do_info(vuln_id: str, *, show_all: bool = False, output_json: bool = False):
    from eip_search import client

    vuln = _api_call(client.get_vuln_detail, vuln_id, spinner_text=f"Fetching {vuln_id}...")

    if output_json:
        _json_out(_vuln_detail_dict(vuln))
    else:
        from eip_search.display import print_vuln_detail
        print_vuln_detail(vuln, show_all=show_all)


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  VIEW COMMAND                                                           ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

@_app.command()
def view(
    exploit_id: int = typer.Argument(..., help="Exploit ID"),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="Specific file path to view"),
) -> None:
    """View exploit source code with syntax highlighting."""
    from eip_search import client
    from eip_search.display import print_code, print_exploit_files

    files = _api_call(client.list_exploit_files, exploit_id, spinner_text=f"Listing files for exploit {exploit_id}...")

    if not files:
        from eip_search.display import print_error
        print_error(f"No code files found for exploit {exploit_id}")
        raise typer.Exit(1)

    # If --file specified, use it directly
    if file:
        target_path = file
    elif len(files) == 1:
        target_path = files[0].path
    else:
        # Auto-select: prefer main code files, fall back to first
        target_path = _pick_main_file(files)
        if target_path is None:
            print_exploit_files(files, exploit_id)
            console.print("[dim]Tip: use --file <path> to view a specific file[/dim]")
            raise typer.Exit()

    content = _api_call(
        client.get_exploit_code, exploit_id, target_path,
        spinner_text=f"Fetching {target_path}...",
    )
    print_code(content, target_path)


def _pick_main_file(files) -> str | None:
    """Auto-select the most likely 'main' exploit file."""
    # Priority: exploit.*, main.*, poc.*, then largest code file
    code_exts = {".py", ".rb", ".go", ".c", ".cpp", ".java", ".js", ".pl", ".php", ".sh", ".ps1"}
    code_files = [f for f in files if any(f.path.endswith(ext) for ext in code_exts)]

    for pattern in ("exploit", "poc", "main", "scan", "vuln", "rce"):
        for f in code_files:
            if pattern in f.path.lower():
                return f.path

    # Fall back to largest code file
    if code_files:
        return max(code_files, key=lambda f: f.size).path

    # If no code files, return the largest file that isn't README
    non_readme = [f for f in files if "readme" not in f.path.lower()]
    if non_readme:
        return max(non_readme, key=lambda f: f.size).path

    return files[0].path if files else None


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  DOWNLOAD COMMAND                                                       ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

@_app.command()
def download(
    exploit_id: int = typer.Argument(..., help="Exploit ID to download"),
    extract: bool = typer.Option(False, "--extract", "-x", help="Extract the ZIP after downloading"),
    output_dir: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory (default: current dir)"),
) -> None:
    """Download exploit code as a password-protected ZIP.

    \b
    Downloaded ZIPs are encrypted with password "eip" (as a safety measure
    to prevent antivirus from quarantining exploit code).

    \b
    Use --extract / -x to automatically unzip after downloading.

    \b
    Examples:
      eip-search download 77423
      eip-search download 77423 --extract
      eip-search download 77423 -x -o /tmp/exploits
    """
    import zipfile
    from pathlib import Path
    from eip_search import client

    dest = Path(output_dir) if output_dir else Path.cwd()
    if not dest.exists():
        dest.mkdir(parents=True, exist_ok=True)

    out_path = _api_call(
        client.download_exploit, exploit_id,
        spinner_text=f"Downloading exploit {exploit_id}...",
        output_dir=dest,
    )

    console.print(f"\n[bold green]Downloaded:[/bold green] {out_path}")
    console.print("[dim]ZIP password: [bold]eip[/bold] (exploit archives are password-protected to prevent AV quarantine)[/dim]")

    if extract:
        extract_dir = dest / out_path.stem
        try:
            with zipfile.ZipFile(out_path, "r") as zf:
                # Validate all paths BEFORE extracting (prevent zip-slip attacks)
                resolved_target = extract_dir.resolve()
                for member in zf.namelist():
                    member_path = (extract_dir / member).resolve()
                    if not str(member_path).startswith(str(resolved_target)):
                        from eip_search.display import print_error
                        print_error(f"Blocked zip-slip path traversal: {member}")
                        raise typer.Exit(1)

                zf.extractall(path=extract_dir, pwd=b"eip")
            console.print(f"[bold green]Extracted:[/bold green]  {extract_dir}/")

            # List extracted files
            extracted = sorted(extract_dir.rglob("*"))
            files = [f for f in extracted if f.is_file()]
            if files:
                console.print(f"[dim]Files ({len(files)}):[/dim]")
                for f in files[:15]:
                    rel = f.relative_to(extract_dir)
                    console.print(f"  [dim]-[/dim] {rel}")
                if len(files) > 15:
                    console.print(f"  [dim]... and {len(files) - 15} more[/dim]")
        except zipfile.BadZipFile:
            from eip_search.display import print_error
            print_error("Downloaded file is not a valid ZIP archive")
        except typer.Exit:
            raise
        except Exception as exc:
            from eip_search.display import print_error
            print_error(f"Extraction failed: {exc}")

    else:
        console.print("[dim]Tip: use --extract / -x to unzip automatically[/dim]")

    console.print()


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  TRIAGE COMMAND                                                         ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

@_app.command()
def triage(
    vendor: Optional[str] = typer.Option(None, "--vendor", "-v", help="Filter by vendor"),
    product: Optional[str] = typer.Option(None, "--product", "-p", help="Filter by product"),
    ecosystem: Optional[str] = typer.Option(None, "--ecosystem", help="Filter by ecosystem"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter: critical, high, medium, low"),
    min_epss: float = typer.Option(0.5, "--min-epss", help="Minimum EPSS score (default: 0.5)"),
    min_cvss: Optional[float] = typer.Option(None, "--min-cvss", help="Minimum CVSS score"),
    kev: bool = typer.Option(False, "--kev", "-k", help="Only CISA KEV entries"),
    page: int = typer.Option(1, "--page", help="Page number"),
    per_page: Optional[int] = typer.Option(None, "--per-page", "-n", help="Results per page (max 100)"),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
) -> None:
    """Risk-based triage: what should you worry about right now?

    \b
    Defaults to showing vulnerabilities with public exploits and EPSS >= 0.5,
    sorted by exploitation probability (EPSS descending).

    \b
    Examples:
      eip-search triage
      eip-search triage --vendor fortinet --severity critical
      eip-search triage --ecosystem npm --min-epss 0.3
      eip-search triage --kev
    """
    from eip_search import client
    from eip_search.config import get_config

    params = {
        "has_exploits": True,
        "is_kev": kev or None,
        "vendor": vendor,
        "product": product,
        "ecosystem": ecosystem,
        "severity": severity,
        "min_epss": min_epss,
        "min_cvss": min_cvss,
        "sort": "epss_desc",
        "page": page,
        "per_page": per_page or get_config().per_page,
    }

    result = _api_call(client.search_vulns, params, spinner_text="Running triage...")

    if output_json:
        _json_out({
            "total": result.total,
            "page": result.page,
            "per_page": result.per_page,
            "total_pages": result.total_pages,
            "items": [_vuln_summary_dict(v) for v in result.items],
        })
    else:
        from eip_search.display import print_search_results
        # Show a triage-specific header
        console.print("\n[bold red]TRIAGE[/bold red] [dim]— vulnerabilities with exploits, sorted by exploitation risk[/dim]")
        filters_desc: list[str] = []
        if vendor:
            filters_desc.append(f"vendor={vendor}")
        if product:
            filters_desc.append(f"product={product}")
        if ecosystem:
            filters_desc.append(f"ecosystem={ecosystem}")
        if severity:
            filters_desc.append(f"severity={severity}")
        if kev:
            filters_desc.append("KEV only")
        filters_desc.append(f"EPSS>={min_epss}")
        if min_cvss:
            filters_desc.append(f"CVSS>={min_cvss}")
        console.print(f"[dim]Filters: {', '.join(filters_desc)}[/dim]")
        print_search_results(result)


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  NUCLEI COMMAND                                                         ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

@_app.command()
def nuclei(
    vuln_id: str = typer.Argument(..., help="CVE-ID to show Nuclei templates for"),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
) -> None:
    """Show Nuclei scanner templates and recon dorks for a CVE.

    \b
    Displays template metadata, tags, verification status, and
    ready-to-paste Shodan/FOFA/Google queries.

    \b
    Examples:
      eip-search nuclei CVE-2024-27198
    """
    from eip_search import client

    vid = _normalize_vuln_id(vuln_id)
    vuln = _api_call(client.get_vuln_detail, vid, spinner_text=f"Fetching {vid}...")

    if output_json:
        templates = []
        for t in vuln.nuclei_templates:
            templates.append({
                "template_id": t.template_id,
                "name": t.name,
                "severity": t.severity,
                "verified": t.verified,
                "author": t.author,
                "tags": t.tags,
                "shodan_query": t.shodan_query,
                "fofa_query": t.fofa_query,
                "google_query": t.google_query,
            })
        _json_out({"cve_id": vuln.display_id, "nuclei_templates": templates})
    else:
        from eip_search.display import print_nuclei_for_vuln
        print_nuclei_for_vuln(vuln)


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  STATS COMMAND                                                          ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

@_app.command()
def stats(
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
) -> None:
    """Show platform-wide statistics."""
    from eip_search import client

    data = _api_call(client.get_stats, spinner_text="Fetching stats...")

    if output_json:
        _json_out({
            "total_vulns": data.total_vulns,
            "published": data.published,
            "with_cvss": data.with_cvss,
            "with_epss": data.with_epss,
            "kev_total": data.kev_total,
            "critical_count": data.critical_count,
            "with_nuclei": data.with_nuclei,
            "total_with_exploits": data.total_with_exploits,
            "total_exploits": data.total_exploits,
            "total_vendors": data.total_vendors,
            "total_authors": data.total_authors,
            "last_updated": data.last_updated,
        })
    else:
        from eip_search.display import print_stats
        print_stats(data)


# ---------------------------------------------------------------------------
# JSON output helpers
# ---------------------------------------------------------------------------

def _json_out(data: dict) -> None:
    """Write JSON to stdout."""
    console.print_json(json.dumps(data, default=str))


def _vuln_summary_dict(v) -> dict:
    return {
        "cve_id": v.cve_id,
        "eip_id": v.eip_id,
        "title": v.title,
        "severity_label": v.severity_label,
        "cvss_v3_score": v.cvss_v3_score,
        "epss_score": v.epss_score,
        "is_kev": v.is_kev,
        "has_nuclei_template": v.has_nuclei_template,
        "exploit_count": v.exploit_count,
        "cwe_ids": v.cwe_ids,
        "cve_published_at": v.cve_published_at,
    }


def _vuln_detail_dict(v) -> dict:
    return {
        "cve_id": v.cve_id,
        "eip_id": v.eip_id,
        "title": v.title,
        "description": v.description,
        "severity_label": v.severity_label,
        "cvss_v3_score": v.cvss_v3_score,
        "cvss_v3_vector": v.cvss_v3_vector,
        "epss_score": v.epss_score,
        "epss_percentile": v.epss_percentile,
        "attack_vector": v.attack_vector,
        "vuln_type": v.vuln_type,
        "cwe_ids": v.cwe_ids,
        "is_kev": v.is_kev,
        "kev_added_at": v.kev_added_at,
        "has_nuclei_template": v.has_nuclei_template,
        "cve_published_at": v.cve_published_at,
        "exploit_count": len(v.exploits),
        "exploits": [
            {
                "id": e.id,
                "source": e.source,
                "source_id": e.source_id,
                "source_url": e.source_url,
                "language": e.language,
                "github_stars": e.github_stars,
                "verified": e.verified,
                "exploit_rank": e.exploit_rank,
                "llm_classification": e.llm_classification,
                "has_code": e.has_code,
            }
            for e in v.exploits
        ],
        "affected_products": [
            {"vendor": p.vendor, "product": p.product, "version_start": p.version_start,
             "version_end": p.version_end, "ecosystem": p.ecosystem}
            for p in v.affected_products
        ],
        "nuclei_templates": [
            {"template_id": t.template_id, "name": t.name, "severity": t.severity,
             "verified": t.verified, "shodan_query": t.shodan_query,
             "fofa_query": t.fofa_query, "google_query": t.google_query}
            for t in v.nuclei_templates
        ],
        "alt_identifiers": [
            {"type": a.id_type, "value": a.id_value}
            for a in v.alt_identifiers
        ],
    }
