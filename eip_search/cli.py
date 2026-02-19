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
_SUBCOMMANDS = {
    "search", "info", "view", "download", "generate", "triage", "nuclei", "exploits",
    "stats", "authors", "author", "cwes", "cwe", "vendors", "products", "lookup",
}


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
      eip-search info CVE-2024-3400          Full intelligence brief
      eip-search exploits "fortinet" -c      Browse exploits directly
      eip-search triage --vendor apache      Risk-based triage
      eip-search nuclei CVE-2024-27198      Nuclei templates + dorks
      eip-search view CVE-2024-3400         View exploit code (picks best)
      eip-search download CVE-2024-3400 -x  Download exploit ZIP
      eip-search stats                      Platform statistics
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
    show_all: bool = typer.Option(False, "--all", "-a", help="Show all exploits including low-quality sources"),
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
# ║  CVE → EXPLOIT PICKER (shared by view/download)                        ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def _resolve_exploit_id(target: str, *, code_only: bool = False) -> int:
    """Resolve a target to an integer exploit ID.

    If *target* is a plain integer, return it directly.  If it looks like a
    CVE/EIP ID, fetch the vulnerability, rank its exploits, and present an
    interactive picker.  *code_only* filters to exploits with downloadable code.
    """
    # Plain integer → use directly
    try:
        return int(target)
    except ValueError:
        pass

    if not _is_vuln_id(target):
        from eip_search.display import print_error
        print_error(f"'{target}' is not a valid exploit ID or CVE ID.")
        raise typer.Exit(1)

    from eip_search import client
    from eip_search.ranking import rank_exploits
    from eip_search.display import print_exploit_picker

    vuln_id = _normalize_vuln_id(target)
    vuln = _api_call(client.get_vuln_detail, vuln_id, spinner_text=f"Fetching {vuln_id}...")

    candidates = vuln.exploits
    if code_only:
        candidates = [e for e in candidates if e.has_code]

    if not candidates:
        from eip_search.display import print_error
        label = "with downloadable code " if code_only else ""
        print_error(f"No exploits {label}found for {vuln_id}")
        raise typer.Exit(1)

    # Rank and filter out trojans/suspicious for the picker
    ranked = rank_exploits(list(candidates))
    safe = [e for e in ranked if not e.is_suspicious]
    if not safe:
        safe = ranked  # fall back to all if everything is suspicious

    if len(safe) == 1:
        return safe[0].id

    print_exploit_picker(safe, vuln_id, code_only=code_only)

    choice = None
    while choice is None:
        raw = console.input(f"  Select [bold][1-{len(safe)}, default=1][/bold]: ").strip()
        if raw == "":
            choice = 1
        else:
            try:
                choice = int(raw)
                if choice < 1 or choice > len(safe):
                    console.print(f"  [red]Enter a number between 1 and {len(safe)}[/red]")
                    choice = None
            except ValueError:
                console.print(f"  [red]Enter a number between 1 and {len(safe)}[/red]")

    return safe[choice - 1].id


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  VIEW COMMAND                                                           ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

@_app.command()
def view(
    target: str = typer.Argument(..., help="Exploit ID or CVE-ID (e.g. 77423 or CVE-2024-3400)"),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="Specific file path to view"),
) -> None:
    """View exploit source code with syntax highlighting.

    \b
    Accepts an exploit ID or a CVE ID.  When given a CVE, shows an
    interactive picker to choose which exploit to view.

    \b
    Examples:
      eip-search view 77423
      eip-search view CVE-2024-3400
      eip-search view 77423 --file exploit.py
    """
    from eip_search import client
    from eip_search.display import print_code, print_exploit_files

    exploit_id = _resolve_exploit_id(target)

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
    target: str = typer.Argument(..., help="Exploit ID or CVE-ID (e.g. 77423 or CVE-2024-3400)"),
    extract: bool = typer.Option(False, "--extract", "-x", help="Extract the ZIP after downloading"),
    output_dir: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory (default: current dir)"),
) -> None:
    """Download exploit code as a password-protected ZIP.

    \b
    Accepts an exploit ID or a CVE ID.  When given a CVE, shows an
    interactive picker to choose which exploit to download.

    \b
    Downloaded ZIPs are encrypted with password "eip" (as a safety measure
    to prevent antivirus from quarantining exploit code).

    \b
    Use --extract / -x to automatically unzip after downloading.

    \b
    Examples:
      eip-search download CVE-2024-3400 -x
      eip-search download 77423
      eip-search download 77423 --extract
      eip-search download 77423 -x -o /tmp/exploits
    """
    import zipfile
    from pathlib import Path
    from eip_search import client

    exploit_id = _resolve_exploit_id(target, code_only=True)

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
                # Create destination directory before validation/extraction
                extract_dir.mkdir(parents=True, exist_ok=True)

                # Basic zip-bomb limits (exploit archives should be small)
                infos = zf.infolist()
                max_files = 5000
                max_total_uncompressed = 250 * 1024 * 1024  # 250 MB

                if len(infos) > max_files:
                    from eip_search.display import print_error
                    print_error(f"Archive contains too many files ({len(infos)} > {max_files}) — aborting")
                    raise typer.Exit(1)

                total_uncompressed = sum(i.file_size for i in infos)
                if total_uncompressed > max_total_uncompressed:
                    from eip_search.display import print_error
                    print_error(
                        f"Archive expands to {total_uncompressed / (1024*1024):.1f} MB "
                        f"({max_total_uncompressed / (1024*1024):.0f} MB limit) — aborting"
                    )
                    raise typer.Exit(1)

                # Validate all paths BEFORE extracting (prevent zip-slip attacks)
                resolved_target = extract_dir.resolve()
                for info in infos:
                    member = info.filename
                    member_path = (extract_dir / member).resolve()
                    try:
                        member_path.relative_to(resolved_target)
                    except ValueError:
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
# ║  GENERATE COMMAND                                                       ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

@_app.command()
def generate(
    vuln_id: str = typer.Argument(..., help="CVE-ID (e.g. CVE-2024-3400) or EIP-ID"),
    check: bool = typer.Option(False, "--check", help="Check feasibility only (no Ollama needed)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save generated exploit to file"),
    no_vision: bool = typer.Option(False, "--no-vision", help="Skip screenshot analysis (faster, text only)"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override code generation model"),
    vision_model: Optional[str] = typer.Option(None, "--vision-model", help="Override vision model"),
) -> None:
    """Generate a proof-of-concept exploit using a local LLM.

    \b
    Requires Ollama running locally (https://ollama.com).
    Fetches CVE intelligence from the API, optionally analyzes writeup
    screenshots with a vision model, then generates a minimal Python PoC.

    \b
    Use --check to see the feasibility score without generating anything
    (no Ollama required).

    \b
    Configure models in ~/.eip-search.toml:
      [generate]
      ollama_url = "http://127.0.0.1:11434"
      code_model = "kimi-k2:1t-cloud"
      vision_model = "qwen3-vl:235b-instruct-cloud"

    \b
    Examples:
      eip-search generate CVE-2026-2686 --check
      eip-search generate CVE-2026-2686
      eip-search generate CVE-2026-2686 --no-vision
      eip-search generate CVE-2026-2686 -m glm-5:cloud -o exploit.py
    """
    from pathlib import Path

    from rich.markup import escape
    from rich.status import Status

    from eip_search import client
    from eip_search.config import get_config
    from eip_search.display import print_code, print_error
    from eip_search.generate import (
        OllamaError,
        build_prompt,
        check_ollama,
        classify_feasibility,
        describe_images,
        generate_code,
        wrap_output,
    )

    cfg = get_config()
    ollama_url = cfg.ollama_url
    code_model_name = model or cfg.code_model
    vision_model_name = vision_model or cfg.vision_model
    vid = _normalize_vuln_id(vuln_id)

    # -- Fetch CVE intelligence + feasibility gate (before touching Ollama) --
    vuln = _api_call(client.get_vuln_detail, vid, spinner_text=f"Fetching {vid}...")

    feas = classify_feasibility(vuln)
    tier_color = {"excellent": "green", "good": "cyan", "possible": "yellow", "difficult": "red"}.get(feas["tier"], "white")
    console.print()
    console.print(f"  [bold]{escape(vuln.display_id)}[/bold] — {escape(vuln.title or 'Unknown')}")
    console.print(
        f"  CVSS {vuln.cvss_v3_score or '?'} | {feas['attack_type']} | {feas['complexity']} | "
        f"Feasibility: [{tier_color}]{feas['tier'].upper()} ({feas['score']})[/{tier_color}]"
    )

    console.print(f"  [dim]Reasons: {', '.join(feas['reasons'])}[/dim]")

    # Count available images
    writeup_for_check = None
    for e in vuln.exploits:
        if e.llm_classification == "writeup":
            writeup_for_check = e
            break
    if not writeup_for_check and vuln.exploits:
        writeup_for_check = vuln.exploits[0]

    if writeup_for_check:
        all_files_check = _api_call(
            client.list_exploit_files, writeup_for_check.id,
            spinner_text="Listing files...",
        )
        img_count = sum(1 for f in all_files_check if f.file_type == "image")
        txt_count = sum(1 for f in all_files_check if f.file_type != "image")
        console.print(f"  [dim]Files: {txt_count} text, {img_count} screenshots[/dim]")
    else:
        all_files_check = []
        console.print("  [dim]No exploit files found[/dim]")

    if check:
        console.print()
        raise typer.Exit(0)

    if feas["tier"] == "difficult":
        console.print(
            "\n  [red]Feasibility too low for automated PoC generation.[/red]"
        )
        raise typer.Exit(1)

    if feas["tier"] == "possible":
        console.print(
            f"\n  [yellow]Low feasibility — generated PoC may be incomplete or generic.[/yellow]"
        )

    # -- Check Ollama (only after feasibility passes) --
    try:
        available = check_ollama(ollama_url)
    except OllamaError as exc:
        print_error(str(exc))
        raise typer.Exit(1)

    if code_model_name not in available:
        print_error(
            f"Code model '{code_model_name}' not found in Ollama.\n"
            f"Available: {', '.join(available) or '(none)'}\n"
            f"Pull it with: ollama pull {code_model_name}"
        )
        raise typer.Exit(1)

    if not no_vision and vision_model_name not in available:
        err_console.print(
            f"[yellow]Vision model '{vision_model_name}' not available — "
            f"falling back to text-only mode[/yellow]"
        )
        no_vision = True

    # -- Gather exploit context: writeup text, existing code, images --
    writeup_text = None
    existing_code = None
    source_exploit = None

    # Prefer writeup exploits for text + images
    for e in vuln.exploits:
        if e.llm_classification == "writeup":
            source_exploit = e
            break

    # Also look for exploits with actual code
    code_exploit = None
    for e in vuln.exploits:
        if e.has_code and e.llm_classification not in ("trojan", "suspicious"):
            code_exploit = e
            break

    if not source_exploit:
        source_exploit = code_exploit or (vuln.exploits[0] if vuln.exploits else None)

    # Fetch writeup text from the source exploit
    if source_exploit:
        files = _api_call(
            client.list_exploit_files, source_exploit.id,
            spinner_text="Listing exploit files...",
        )
        text_files = [f for f in files if f.file_type != "image"]
        if text_files:
            writeup_text = _api_call(
                client.get_exploit_code, source_exploit.id, text_files[0].path,
                spinner_text="Fetching writeup text...",
            )
            if writeup_text:
                console.print(f"  Writeup: {len(writeup_text)} chars from exploit {source_exploit.id}")

    # Fetch existing exploit code (if different from writeup source)
    if code_exploit and code_exploit.id != (source_exploit.id if source_exploit else None):
        code_files = _api_call(
            client.list_exploit_files, code_exploit.id,
            spinner_text="Listing code files...",
        )
        code_text_files = [f for f in code_files if f.file_type != "image"]
        if code_text_files:
            existing_code = _api_call(
                client.get_exploit_code, code_exploit.id, code_text_files[0].path,
                spinner_text="Fetching existing exploit code...",
            )
            if existing_code:
                console.print(f"  Existing code: {len(existing_code)} chars from exploit {code_exploit.id}")
    elif code_exploit and not writeup_text:
        # Source exploit IS the code exploit and we already fetched its text
        # but it wasn't labeled as writeup — treat it as existing code
        if writeup_text:
            existing_code = writeup_text
            writeup_text = None
            console.print(f"  [dim](treating as existing code to rewrite)[/dim]")

    # -- Vision stage --
    image_descs: list[dict] = []
    if not no_vision and source_exploit:
        all_files = _api_call(
            client.list_exploit_files, source_exploit.id,
            spinner_text="Listing exploit files...",
        )
        image_files = [f for f in all_files if f.file_type == "image"]

        if image_files:
            console.print(f"\n  Analyzing {len(image_files)} screenshot{'s' if len(image_files) != 1 else ''}...")

            eid_for_images = source_exploit.id

            def _on_image_progress(filename: str, desc: str, elapsed: float):
                preview = desc[:100].replace("\n", " ")
                if "no actionable" in desc.lower():
                    console.print(f"    [dim]{escape(filename)}: skipped (no actionable details)[/dim]")
                else:
                    console.print(f"    {escape(filename)}: {escape(preview)}... ({elapsed:.1f}s)")

            def _fetch_image(filename: str) -> bytes:
                return client.get_exploit_image(eid_for_images, filename)

            image_descs = describe_images(
                image_files,
                fetch_fn=_fetch_image,
                ollama_url=ollama_url,
                model=vision_model_name,
                on_progress=_on_image_progress,
            )

            useful = sum(1 for d in image_descs if "no actionable" not in d["description"].lower())
            console.print(f"  [dim]{useful} useful / {len(image_descs)} total screenshots described[/dim]")
        else:
            console.print("  [dim]No screenshots found for this exploit[/dim]")

    # -- Build prompt + generate --
    prompt = build_prompt(vuln, writeup_text, image_descs, existing_code)
    console.print(f"\n  Prompt: {len(prompt)} chars")

    with Status(f"Generating PoC with {code_model_name}...", console=err_console, spinner="dots"):
        try:
            raw_code, elapsed = generate_code(prompt, ollama_url, code_model_name)
        except Exception as exc:
            print_error(f"Code generation failed: {exc}")
            raise typer.Exit(1)

    final_code = wrap_output(raw_code, vuln)
    lines = len(final_code.strip().split("\n"))

    console.print(f"  Generated {lines} lines in {elapsed:.1f}s\n")
    print_code(final_code, "exploit.py")

    # -- Save to file --
    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(final_code, encoding="utf-8")
        console.print(f"\n[bold green]Saved:[/bold green] {out_path}")
    else:
        safe_name = vid.replace("-", "_") + ".py"
        console.print(f"\n[dim]Tip: use -o {safe_name} to save to file[/dim]")

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
# ║  EXPLOITS COMMAND                                                       ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

@_app.command()
def exploits(
    query: Optional[str] = typer.Argument(None, help="CVE ID, vendor, or product to filter by"),
    source: Optional[str] = typer.Option(None, "--source", help="Source: github, metasploit, exploitdb, nomisec"),
    language: Optional[str] = typer.Option(None, "--language", "-l", help="Language: python, ruby, go, c, etc."),
    classification: Optional[str] = typer.Option(None, "--classification", help="LLM class: working_poc, scanner, trojan"),
    attack_type: Optional[str] = typer.Option(None, "--attack-type", help="Attack: RCE, SQLi, XSS, DoS, LPE, auth_bypass"),
    complexity: Optional[str] = typer.Option(None, "--complexity", help="Complexity: trivial, simple, moderate, complex"),
    reliability: Optional[str] = typer.Option(None, "--reliability", help="Reliability: reliable, unreliable, untested"),
    author: Optional[str] = typer.Option(None, "--author", help="Filter by author name"),
    min_stars: Optional[int] = typer.Option(None, "--min-stars", help="Minimum GitHub stars"),
    has_code: bool = typer.Option(False, "--has-code", "-c", help="Only exploits with downloadable code"),
    cve: Optional[str] = typer.Option(None, "--cve", help="Filter by CVE ID"),
    vendor: Optional[str] = typer.Option(None, "--vendor", "-v", help="Filter by vendor name"),
    product: Optional[str] = typer.Option(None, "--product", "-p", help="Filter by product name"),
    sort: Optional[str] = typer.Option(None, "--sort", help="Sort: newest, stars_desc"),
    page: int = typer.Option(1, "--page", help="Page number"),
    per_page: Optional[int] = typer.Option(None, "--per-page", "-n", help="Results per page (max 25)"),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
) -> None:
    """Browse and search exploits directly.

    \b
    Search exploits by source, language, attack type, author, and more.
    The positional query is auto-detected: CVE IDs map to --cve, other
    text maps to --vendor.

    \b
    Examples:
      eip-search exploits --source metasploit --attack-type RCE
      eip-search exploits "fortinet" --language python --has-code
      eip-search exploits --cve CVE-2024-3400
      eip-search exploits --author "Chocapikk" --sort stars_desc
    """
    from eip_search import client
    from eip_search.config import get_config

    # Auto-detect positional query: CVE ID → --cve, otherwise → --vendor
    if query and not cve and not vendor:
        if _is_vuln_id(query):
            cve = _normalize_vuln_id(query)
        else:
            vendor = query

    has_filters = any([
        source, language, classification, attack_type, complexity, reliability,
        author, min_stars, has_code, cve, vendor, product,
    ])
    if not has_filters:
        from eip_search.display import print_error
        print_error("Provide a query or at least one filter. Try: eip-search exploits --help")
        raise typer.Exit(1)

    params = {
        "source": source,
        "language": language,
        "llm_classification": classification,
        "attack_type": attack_type,
        "complexity": complexity,
        "reliability": reliability,
        "author": author,
        "min_stars": min_stars,
        "has_code": has_code or None,
        "cve": cve,
        "vendor": vendor,
        "product": product,
        "sort": sort or "newest",
        "page": page,
        "per_page": per_page or min(get_config().per_page, 25),
    }

    result = _api_call(client.browse_exploits, params, spinner_text="Searching exploits...")

    if output_json:
        _json_out({
            "total": result.total,
            "page": result.page,
            "per_page": result.per_page,
            "total_pages": result.total_pages,
            "items": [_exploit_with_cve_dict(e) for e in result.items],
        })
    else:
        from eip_search.display import print_exploit_results
        print_exploit_results(result)


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


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  AUTHORS COMMANDS                                                       ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

@_app.command()
def authors(
    page: int = typer.Option(1, "--page", help="Page number"),
    per_page: Optional[int] = typer.Option(None, "--per-page", "-n", help="Results per page (max 50)"),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
) -> None:
    """List top exploit authors ranked by exploit count.

    \b
    Examples:
      eip-search authors
      eip-search authors --page 2 -n 20
    """
    from eip_search import client

    params = {"page": page, "per_page": per_page or 25}
    data = _api_call(client.list_authors, params, spinner_text="Fetching authors...")

    if output_json:
        _json_out(data)
    else:
        from eip_search.display import print_authors_list
        print_authors_list(data)


@_app.command()
def author(
    name: str = typer.Argument(..., help="Author name (e.g. 'Metasploit', 'Chocapikk')"),
    page: int = typer.Option(1, "--page", help="Page number for exploits"),
    per_page: Optional[int] = typer.Option(None, "--per-page", "-n", help="Exploits per page"),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
) -> None:
    """Show an exploit author's profile and their exploits.

    \b
    Examples:
      eip-search author Metasploit
      eip-search author "Chocapikk" --page 2
    """
    from eip_search import client

    params = {"page": page, "per_page": per_page or 25}
    data = _api_call(client.get_author, name, spinner_text=f"Fetching author {name}...", params=params)

    if output_json:
        _json_out(data)
    else:
        from eip_search.display import print_author_detail
        print_author_detail(data)


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  CWE COMMANDS                                                           ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

@_app.command()
def cwes(
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
) -> None:
    """List CWE categories ranked by vulnerability count.

    \b
    Examples:
      eip-search cwes
      eip-search cwes --json
    """
    from eip_search import client

    data = _api_call(client.list_cwes, spinner_text="Fetching CWEs...")

    if output_json:
        _json_out(data)
    else:
        from eip_search.display import print_cwe_list
        print_cwe_list(data)


@_app.command()
def cwe(
    cwe_id: str = typer.Argument(..., help="CWE identifier (e.g. '79' or 'CWE-79')"),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
) -> None:
    """Show details for a specific CWE.

    \b
    Accepts both numeric ('79') and prefixed ('CWE-79') format.

    \b
    Examples:
      eip-search cwe 79
      eip-search cwe CWE-89
    """
    from eip_search import client

    normalized = cwe_id.strip()
    if normalized.isdigit():
        normalized = f"CWE-{normalized}"

    data = _api_call(client.get_cwe, normalized, spinner_text=f"Fetching {normalized}...")

    if output_json:
        _json_out(data)
    else:
        from eip_search.display import print_cwe_detail
        print_cwe_detail(data)


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  VENDOR / PRODUCT COMMANDS                                              ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

@_app.command()
def vendors(
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
) -> None:
    """List top vendors ranked by vulnerability count.

    \b
    Examples:
      eip-search vendors
      eip-search vendors --json
    """
    from eip_search import client

    data = _api_call(client.list_vendors, spinner_text="Fetching vendors...")

    if output_json:
        _json_out(data)
    else:
        from eip_search.display import print_vendors_list
        print_vendors_list(data)


@_app.command()
def products(
    vendor: str = typer.Argument(..., help="Vendor name (e.g. 'apache', 'microsoft')"),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
) -> None:
    """List products for a vendor with vulnerability counts.

    \b
    Use this to discover exact product names for filtering.
    Product names follow CPE conventions (e.g. 'http_server' not 'apache httpd').

    \b
    Examples:
      eip-search products apache
      eip-search products microsoft --json
    """
    from eip_search import client

    data = _api_call(client.list_vendor_products, vendor, spinner_text=f"Fetching products for {vendor}...")

    if output_json:
        _json_out(data)
    else:
        from eip_search.display import print_products_list
        print_products_list(data)


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  LOOKUP COMMAND                                                         ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

@_app.command()
def lookup(
    alt_id: str = typer.Argument(..., help="Alternate ID (e.g. 'EDB-45961', 'GHSA-jfh8-c2jp-5v3q')"),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON"),
) -> None:
    """Resolve an ExploitDB or GHSA identifier to its CVE.

    \b
    Examples:
      eip-search lookup EDB-45961
      eip-search lookup GHSA-jfh8-c2jp-5v3q
    """
    from eip_search import client

    data = _api_call(client.lookup_alt_id, alt_id, spinner_text=f"Looking up {alt_id}...")

    if output_json:
        _json_out(data)
    else:
        from eip_search.display import print_lookup_result
        print_lookup_result(data)


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


def _exploit_with_cve_dict(e) -> dict:
    return {
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
        "cve_id": e.cve_id,
        "cve_title": e.cve_title,
        "severity_label": e.severity_label,
        "cvss_v3_score": e.cvss_v3_score,
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
