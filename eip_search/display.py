"""Rich terminal output formatters for eip-search."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from eip_search.models import (
    Exploit,
    ExploitBrowseResult,
    ExploitFile,
    ExploitWithCVE,
    NucleiTemplate,
    SearchResult,
    Stats,
    VulnDetail,
    VulnSummary,
)
from eip_search.ranking import ExploitGroups, group_exploits

console = Console()

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "bold bright_red",
    "medium": "bold yellow",
    "low": "bold blue",
}


def _severity_badge(label: str | None) -> Text:
    if not label:
        return Text("--", style="dim")
    style = _SEVERITY_COLORS.get(label, "dim")
    return Text(label.upper(), style=style)


def _format_cvss(score: float | None) -> Text:
    if score is None:
        return Text("--", style="dim")
    if score >= 9.0:
        style = "bold red"
    elif score >= 7.0:
        style = "bold bright_red"
    elif score >= 4.0:
        style = "bold yellow"
    else:
        style = "bold blue"
    return Text(f"{score:.1f}", style=style)


def _format_epss(score: float | None) -> Text:
    if score is None:
        return Text("--", style="dim")
    pct = score * 100
    if pct >= 90:
        style = "bold red"
    elif pct >= 50:
        style = "bold yellow"
    else:
        style = "dim"
    return Text(f"{pct:.1f}%", style=style)


def _format_kev(is_kev: bool) -> Text:
    if is_kev:
        return Text("KEV", style="bold red")
    return Text("", style="dim")


def _format_exploits(count: int) -> Text:
    if count == 0:
        return Text("0", style="dim")
    return Text(str(count), style="bold green")


# ---------------------------------------------------------------------------
# Search results table
# ---------------------------------------------------------------------------

def print_search_results(result: SearchResult) -> None:
    """Print a paginated search results table."""
    if result.total == 0:
        console.print("\n[dim]No results found.[/dim]\n")
        return

    table = Table(
        show_header=True,
        header_style="bold",
        border_style="dim",
        pad_edge=False,
        expand=True,
    )
    table.add_column("CVE", style="bold cyan", no_wrap=True, min_width=16)
    table.add_column("Sev", justify="center", no_wrap=True, width=10)
    table.add_column("CVSS", justify="right", no_wrap=True, width=5)
    table.add_column("EPSS", justify="right", no_wrap=True, width=6)
    table.add_column("Exp", justify="right", no_wrap=True, width=4)
    table.add_column("", no_wrap=True, width=3)  # KEV flag
    table.add_column("Title", ratio=1)

    for v in result.items:
        table.add_row(
            Text(v.display_id, style="bold cyan"),
            _severity_badge(v.severity_label),
            _format_cvss(v.cvss_v3_score),
            _format_epss(v.epss_score),
            _format_exploits(v.exploit_count),
            _format_kev(v.is_kev),
            Text(v.title or "", overflow="ellipsis", no_wrap=True),
        )

    console.print()
    console.print(table)
    console.print(
        f"\n[dim]Page {result.page}/{result.total_pages} "
        f"({result.total:,} total results)[/dim]\n"
    )


# ---------------------------------------------------------------------------
# Exploit browse results table
# ---------------------------------------------------------------------------

def print_exploit_results(result: ExploitBrowseResult) -> None:
    """Print a paginated exploit browse results table."""
    if result.total == 0:
        console.print("\n[dim]No exploits found.[/dim]\n")
        return

    table = Table(
        show_header=True,
        header_style="bold",
        border_style="dim",
        pad_edge=False,
        expand=True,
    )
    table.add_column("ID", style="dim cyan", no_wrap=True, width=8)
    table.add_column("CVE", style="bold cyan", no_wrap=True, min_width=16)
    table.add_column("Sev", justify="center", no_wrap=True, width=10)
    table.add_column("Source", no_wrap=True, width=11)
    table.add_column("Lang", no_wrap=True, width=8)
    table.add_column("\u2605", justify="right", no_wrap=True, width=5)
    table.add_column("Name", ratio=1)

    src_styles = {
        "metasploit": "bold magenta",
        "exploitdb": "bold green",
        "nomisec": "cyan",
        "github": "cyan",
        "writeup": "dim",
        "ghsa": "blue",
    }

    for e in result.items:
        stars_text = Text(str(e.github_stars), style="yellow") if e.github_stars else Text("", style="dim")
        name = e.display_name
        if len(name) > 40:
            name = name[:37] + "..."
        table.add_row(
            Text(str(e.id), style="dim cyan"),
            Text(e.cve_id or "", style="bold cyan"),
            _severity_badge(e.severity_label),
            Text(e.source, style=src_styles.get(e.source, "dim")),
            Text(e.language or "", style="dim"),
            stars_text,
            Text(name, overflow="ellipsis", no_wrap=True),
        )

    console.print()
    console.print(table)
    console.print(
        f"\n[dim]Page {result.page}/{result.total_pages} "
        f"({result.total:,} total results)[/dim]"
    )
    console.print("[dim]Tip: eip-search view <id> | eip-search download <id> -x[/dim]\n")


# ---------------------------------------------------------------------------
# Exploit picker (interactive selection for download/view by CVE)
# ---------------------------------------------------------------------------

def print_exploit_picker(exploits: list[Exploit], vuln_id: str, *, code_only: bool = False) -> None:
    """Print a numbered list of exploits for interactive selection."""
    label = "with code " if code_only else ""
    console.print(f"\n  [bold]Exploits {label}for {vuln_id}:[/bold]\n")

    src_styles = {
        "metasploit": "bold magenta",
        "exploitdb": "bold green",
        "nomisec": "cyan",
        "github": "cyan",
        "writeup": "dim",
        "ghsa": "blue",
    }

    for i, e in enumerate(exploits, 1):
        line = Text("  ")
        line.append(f"[{i}]", style="bold")
        line.append("  ")
        line.append(f"#{e.id:<7}", style="dim cyan")
        line.append(" ")

        if e.github_stars is not None and e.source in ("github", "nomisec") and e.github_stars > 0:
            line.append(f"\u2605 {e.github_stars:<5}", style="yellow")
            line.append(" ")
        else:
            line.append("       ")

        line.append(f"{e.source:<12}", style=src_styles.get(e.source, "dim"))
        lang = e.language or ""
        line.append(f"{lang:<10}", style="dim")

        name = e.display_name
        if len(name) > 45:
            name = name[:42] + "..."
        line.append(escape(name))

        console.print(line)

        # Metadata line
        details: list[str] = []
        if e.exploit_rank:
            details.append(f"Rank: {e.exploit_rank}")
        if e.llm_classification:
            details.append(e.llm_classification)
        if e.verified:
            details.append("\u2713 verified")
        if details:
            console.print(f"         {'':>7}       [dim]{'  '.join(details)}[/dim]")

    console.print()


# ---------------------------------------------------------------------------
# Vulnerability detail panel
# ---------------------------------------------------------------------------

def print_vuln_detail(vuln: VulnDetail, *, show_all: bool = False) -> None:
    """Print a full intelligence brief for a vulnerability."""
    # --- Header ---
    sev = (vuln.severity_label or "unknown").upper()
    sev_style = _SEVERITY_COLORS.get(vuln.severity_label or "", "dim")
    header = Text()
    header.append(vuln.display_id, style="bold cyan")
    header.append("  ")
    header.append(sev, style=sev_style)
    if vuln.is_kev:
        header.append("  ")
        header.append("KEV", style="bold red")
    if vuln.has_nuclei_template:
        header.append("  ")
        header.append("NUCLEI", style="bold magenta")

    console.print()
    console.print(Panel(header, border_style="bold cyan", expand=False))

    if vuln.title:
        console.print(f"  [bold]{escape(vuln.title)}[/bold]")

    # --- Scores row ---
    scores = Text("  ")
    scores.append("CVSS: ")
    scores.append_text(_format_cvss(vuln.cvss_v3_score))
    if vuln.cvss_v3_vector:
        scores.append(f"  ({vuln.cvss_v3_vector})", style="dim")
    console.print(scores)

    epss_line = Text("  EPSS: ")
    epss_line.append_text(_format_epss(vuln.epss_score))
    if vuln.epss_percentile is not None:
        pctl = vuln.epss_percentile * 100
        epss_line.append(f"  ({pctl:.1f}th percentile)", style="dim")
    console.print(epss_line)

    # --- Metadata ---
    meta_parts: list[str] = []
    if vuln.attack_vector:
        meta_parts.append(f"Attack Vector: {escape(vuln.attack_vector)}")
    if vuln.vuln_type:
        meta_parts.append(f"Type: {escape(vuln.vuln_type)}")
    if vuln.cwe_ids:
        meta_parts.append(f"CWE: {escape(', '.join(vuln.cwe_ids))}")
    if vuln.cve_published_at:
        meta_parts.append(f"Published: {vuln.cve_published_at[:10]}")
    if vuln.is_kev and vuln.kev_added_at:
        meta_parts.append(f"KEV added: {vuln.kev_added_at[:10]}")
    if meta_parts:
        console.print(f"  [dim]{' | '.join(meta_parts)}[/dim]")

    # --- Description ---
    if vuln.description:
        desc = vuln.description[:500]
        if len(vuln.description) > 500:
            desc += "..."
        console.print()
        console.print(Padding(Text(desc, style=""), (0, 2)))

    # --- Affected products ---
    if vuln.affected_products:
        console.print()
        console.print("  [bold]Affected Products[/bold]")
        for p in vuln.affected_products[:10]:
            parts = []
            if p.vendor:
                parts.append(p.vendor)
            if p.product:
                parts.append(p.product)
            name = "/".join(parts) if parts else "unknown"
            version = ""
            if p.version_start or p.version_end:
                vs = p.version_start or "*"
                ve = p.version_end or "*"
                version = f"  {vs} - {ve}"
            eco = f"  [{p.ecosystem}]" if p.ecosystem else ""
            console.print(f"    [dim]-[/dim] {escape(name)}{escape(version)}{escape(eco)}")
        if len(vuln.affected_products) > 10:
            console.print(f"    [dim]... and {len(vuln.affected_products) - 10} more[/dim]")

    # --- Exploits (grouped) ---
    if vuln.exploits:
        groups = group_exploits(vuln.exploits, show_all=show_all)
        _print_exploit_groups(groups)
    else:
        console.print("\n  [dim]No exploits found.[/dim]")

    # --- Nuclei templates ---
    if vuln.nuclei_templates:
        _print_nuclei_templates(vuln.nuclei_templates)

    # --- Alt identifiers ---
    if vuln.alt_identifiers:
        console.print()
        console.print("  [bold]Also Known As[/bold]")
        for alt in vuln.alt_identifiers:
            console.print(f"    [dim]-[/dim] {escape(alt.id_type)}: {escape(alt.id_value)}")

    # --- References ---
    if vuln.references:
        console.print()
        console.print("  [bold]References[/bold]")
        for ref in vuln.references[:8]:
            rtype = f"[{ref.ref_type}] " if ref.ref_type else ""
            console.print(f"    [dim]-[/dim] {escape(rtype)}[link={ref.url}]{escape(ref.url[:80])}[/link]")
        if len(vuln.references) > 8:
            console.print(f"    [dim]... and {len(vuln.references) - 8} more[/dim]")

    console.print()


# ---------------------------------------------------------------------------
# Exploit group display
# ---------------------------------------------------------------------------

def _print_exploit_groups(groups: ExploitGroups) -> None:
    """Print grouped and ranked exploits."""
    console.print()
    total = groups.total_count
    console.print(f"  [bold]Exploits ({total})[/bold]")

    if groups.modules:
        console.print()
        console.print("    [bold magenta]MODULES[/bold magenta]")
        for e in groups.modules:
            _print_exploit_line(e, indent=6)

    if groups.verified:
        console.print()
        console.print("    [bold green]VERIFIED[/bold green]")
        for e in groups.verified:
            _print_exploit_line(e, indent=6)

    if groups.pocs:
        console.print()
        console.print("    [bold]PROOF OF CONCEPT[/bold]")
        for e in groups.pocs:
            _print_exploit_line(e, indent=6)

    if groups.other_hidden > 0:
        console.print(f"    [dim]... and {groups.other_hidden} more PoCs (use --all to show)[/dim]")

    if groups.suspicious:
        console.print()
        console.print("    [bold red]SUSPICIOUS[/bold red]")
        for e in groups.suspicious:
            _print_exploit_line(e, indent=6, suspicious=True)

    if total > 0:
        console.print()
        console.print("    [dim]Tip: eip-search view <id> | eip-search download <id> -x[/dim]")


def _print_exploit_line(exploit: Exploit, *, indent: int = 4, suspicious: bool = False) -> None:
    """Print a single exploit line."""
    pad = " " * indent
    line = Text(pad)

    # Exploit ID (needed for view/download commands)
    id_str = f"#{exploit.id}"
    line.append(f"{id_str:<8}", style="dim cyan")

    # Stars (for GitHub/nomisec)
    if exploit.github_stars is not None and exploit.source in ("github", "nomisec"):
        stars = exploit.github_stars
        line.append(f"\u2605 {stars:<5}", style="yellow" if stars > 0 else "dim")
        line.append(" ")
    else:
        line.append("       ")

    # Source badge
    src_styles = {
        "metasploit": "bold magenta",
        "exploitdb": "bold green",
        "nomisec": "cyan",
        "github": "cyan",
        "writeup": "dim",
        "ghsa": "blue",
    }
    line.append(f"{exploit.source:<12}", style=src_styles.get(exploit.source, "dim"))

    # Language
    lang = exploit.language or ""
    if lang:
        line.append(f"{lang:<10}", style="dim")
    else:
        line.append(" " * 10)

    # Display name
    name = exploit.display_name
    if len(name) > 55:
        name = name[:52] + "..."
    line.append(escape(name))

    console.print(line)

    # Second line: metadata
    meta = Text(pad + " " * 8 + "       ")
    details: list[str] = []

    if exploit.exploit_rank:
        details.append(f"Rank: {exploit.exploit_rank}")
    if exploit.llm_classification:
        details.append(f"LLM: {exploit.llm_classification}")
    if exploit.verified:
        details.append("\u2713 verified")
    if exploit.has_code:
        details.append("has code")

    if suspicious and exploit.llm_classification in ("trojan", "suspicious"):
        warning = "\u26a0 " + ("TROJAN" if exploit.llm_classification == "trojan" else "SUSPICIOUS")
        warning += " \u2014 flagged by AI analysis"
        console.print(f"{pad}{' ' * 8}       [bold red]{warning}[/bold red]")
    elif details:
        meta.append("  ".join(details), style="dim")
        console.print(meta)


# ---------------------------------------------------------------------------
# Nuclei templates display
# ---------------------------------------------------------------------------

def _print_nuclei_templates(templates: list[NucleiTemplate]) -> None:
    """Print Nuclei template info with dorks."""
    console.print()
    console.print(f"  [bold magenta]Nuclei Templates ({len(templates)})[/bold magenta]")

    for t in templates:
        console.print()
        name_line = Text("    ")
        name_line.append(t.template_id, style="bold")
        if t.verified:
            name_line.append("  \u2713 verified", style="green")
        if t.severity:
            sev_style = _SEVERITY_COLORS.get(t.severity, "dim")
            name_line.append(f"  {t.severity}", style=sev_style)
        console.print(name_line)

        if t.name:
            console.print(f"    {escape(t.name)}")
        if t.author:
            console.print(f"    [dim]Author: {escape(t.author)}[/dim]")
        if t.tags:
            console.print(f"    [dim]Tags: {escape(', '.join(t.tags))}[/dim]")

        # Dorks
        has_dorks = t.shodan_query or t.fofa_query or t.google_query
        if has_dorks:
            console.print()
            console.print("    [bold]Recon Queries:[/bold]")
            if t.shodan_query:
                console.print(f"      [yellow]Shodan:[/yellow]  {escape(t.shodan_query)}")
            if t.fofa_query:
                console.print(f"      [yellow]FOFA:[/yellow]    {escape(t.fofa_query)}")
            if t.google_query:
                console.print(f"      [yellow]Google:[/yellow]  {escape(t.google_query)}")

        console.print()
        console.print(f"    [dim]Run:[/dim]  nuclei -t {escape(t.template_id)} -u https://target.com")


# ---------------------------------------------------------------------------
# Nuclei standalone display (for `nuclei` subcommand)
# ---------------------------------------------------------------------------

def print_nuclei_for_vuln(vuln: VulnDetail) -> None:
    """Print Nuclei template info specifically for the nuclei subcommand."""
    if not vuln.nuclei_templates:
        console.print(f"\n[dim]No Nuclei templates found for {vuln.display_id}.[/dim]\n")
        return

    header = Text()
    header.append(vuln.display_id, style="bold cyan")
    header.append("  ")
    header.append("Nuclei Templates", style="bold magenta")
    console.print()
    console.print(Panel(header, border_style="bold magenta", expand=False))

    if vuln.title:
        console.print(f"  [bold]{escape(vuln.title)}[/bold]")

    _print_nuclei_templates(vuln.nuclei_templates)
    console.print()


# ---------------------------------------------------------------------------
# Exploit code viewer
# ---------------------------------------------------------------------------

def print_exploit_files(files: list[ExploitFile], exploit_id: int) -> None:
    """Print file listing for an exploit."""
    if not files:
        console.print(f"\n[dim]No code files found for exploit {exploit_id}.[/dim]\n")
        return

    console.print(f"\n  [bold]Files in exploit {exploit_id}[/bold]\n")
    table = Table(show_header=True, header_style="bold", border_style="dim", pad_edge=False)
    table.add_column("#", justify="right", style="dim", width=3)
    table.add_column("Size", justify="right", width=10)
    table.add_column("Path", ratio=1)

    for i, f in enumerate(files, 1):
        size_str = _human_size(f.size)
        table.add_row(str(i), size_str, f.path)

    console.print(Padding(table, (0, 2)))
    console.print()


def print_code(content: str, file_path: str) -> None:
    """Print syntax-highlighted source code."""
    # Guess language from extension
    ext = file_path.rsplit(".", 1)[-1] if "." in file_path else ""
    lang_map = {
        "py": "python", "rb": "ruby", "js": "javascript", "ts": "typescript",
        "go": "go", "rs": "rust", "c": "c", "cpp": "cpp", "h": "c",
        "java": "java", "sh": "bash", "bash": "bash", "zsh": "bash",
        "pl": "perl", "php": "php", "ps1": "powershell", "psm1": "powershell",
        "yml": "yaml", "yaml": "yaml", "json": "json", "xml": "xml",
        "html": "html", "css": "css", "sql": "sql", "md": "markdown",
        "txt": "text", "cfg": "ini", "conf": "ini", "toml": "toml",
        "dockerfile": "dockerfile", "lua": "lua", "r": "r",
    }
    # Handle special filenames
    basename = file_path.rsplit("/", 1)[-1].lower()
    if basename in ("dockerfile", "makefile", "rakefile", "gemfile"):
        lang = basename
    elif basename.endswith(".rb"):
        lang = "ruby"
    else:
        lang = lang_map.get(ext.lower(), "text")

    console.print()
    console.print(f"  [bold]{escape(file_path)}[/bold]")
    console.print()
    syntax = Syntax(
        content,
        lang,
        theme="monokai",
        line_numbers=True,
        word_wrap=False,
    )
    console.print(Padding(syntax, (0, 2)))
    console.print()


# ---------------------------------------------------------------------------
# Stats display
# ---------------------------------------------------------------------------

def print_stats(stats: Stats) -> None:
    """Print platform statistics."""
    console.print()
    console.print(Panel(
        Text("Exploit Intelligence Platform", style="bold cyan"),
        border_style="bold cyan",
        expand=False,
    ))
    console.print()

    table = Table(show_header=False, border_style="dim", pad_edge=True, expand=False)
    table.add_column("Metric", style="bold", min_width=28)
    table.add_column("Value", justify="right", min_width=12)

    table.add_row("Total Vulnerabilities", f"{stats.total_vulns:,}")
    table.add_row("Published", f"{stats.published:,}")
    table.add_row("With CVSS Scores", f"{stats.with_cvss:,}")
    table.add_row("With EPSS Scores", f"{stats.with_epss:,}")
    table.add_row("Critical Severity", f"[red]{stats.critical_count:,}[/red]")
    table.add_row("CISA KEV Entries", f"[red]{stats.kev_total:,}[/red]")
    table.add_row("", "")
    table.add_row("Vulns with Exploits", f"[green]{stats.total_with_exploits:,}[/green]")
    table.add_row("Total Exploits", f"[green]{stats.total_exploits:,}[/green]")
    table.add_row("With Nuclei Templates", f"[magenta]{stats.with_nuclei:,}[/magenta]")
    table.add_row("", "")
    table.add_row("Vendors Tracked", f"{stats.total_vendors:,}")
    table.add_row("Exploit Authors", f"{stats.total_authors:,}")

    if stats.last_updated:
        table.add_row("", "")
        table.add_row("Last Updated", stats.last_updated[:19].replace("T", " "))

    console.print(Padding(table, (0, 2)))
    console.print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _human_size(size: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            if unit == "B":
                return f"{size} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024  # type: ignore[assignment]
    return f"{size:.1f} GB"


def print_error(message: str) -> None:
    """Print an error message."""
    console.print(f"\n[bold red]Error:[/bold red] {escape(message)}\n")


# ---------------------------------------------------------------------------
# Authors
# ---------------------------------------------------------------------------

def print_authors_list(data: dict) -> None:
    """Print paginated author listing."""
    total = data.get("total", 0)
    page = data.get("page", 1)
    total_pages = data.get("total_pages", 0)
    items = data.get("items", [])

    if not items:
        console.print("\n[dim]No authors found.[/dim]\n")
        return

    table = Table(box=None, padding=(0, 2))
    table.add_column("Name", style="bold")
    table.add_column("Exploits", justify="right")
    table.add_column("Handle", style="dim")

    for a in items:
        handle = f"@{a['handle']}" if a.get("handle") else ""
        table.add_row(escape(a["name"]), f"{a['exploit_count']:,}", handle)

    console.print()
    console.print(Padding(table, (0, 2)))
    console.print(f"\n  [dim]Page {page}/{total_pages} ({total:,} total authors)[/dim]\n")


def print_author_detail(data: dict) -> None:
    """Print author profile with their exploits."""
    name = data.get("name", "?")
    handle = data.get("handle")
    count = data.get("exploit_count", 0)
    since = (data.get("first_seen_at") or "?")[:10]
    exploits = data.get("exploits", [])
    total = data.get("total", count)
    page = data.get("page", 1)
    total_pages = data.get("total_pages", 1)

    header = Text(f" {name}", style="bold")
    if handle:
        header.append(f"  @{handle}", style="dim")
    console.print()
    console.print(Panel(header, expand=False))
    console.print(f"  Exploits: {count:,}  |  Active since: {since}")
    console.print()

    if not exploits:
        console.print("  [dim]No exploits to display.[/dim]\n")
        return

    table = Table(box=None, padding=(0, 1))
    table.add_column("ID", style="dim", justify="right")
    table.add_column("CVE")
    table.add_column("Sev", justify="center")
    table.add_column("Source", style="dim")
    table.add_column("Name")

    for e in exploits:
        cve = e.get("cve_id") or e.get("cve_title") or ""
        sev = _severity_badge(e.get("severity_label"))
        src = e.get("source", "")
        name_str = e.get("source_id") or f"exploit-{e.get('id', '?')}"
        table.add_row(str(e.get("id", "")), cve, sev, src, escape(name_str))

    console.print(Padding(table, (0, 2)))
    if total_pages > 1:
        console.print(f"\n  [dim]Page {page}/{total_pages} ({total:,} total exploits)[/dim]")
    console.print()


# ---------------------------------------------------------------------------
# CWEs
# ---------------------------------------------------------------------------

def print_cwe_list(data: dict) -> None:
    """Print CWE category listing."""
    total = data.get("total", 0)
    items = data.get("items", [])

    if not items:
        console.print("\n[dim]No CWE data available.[/dim]\n")
        return

    table = Table(box=None, padding=(0, 2))
    table.add_column("CWE", style="bold", justify="right")
    table.add_column("Vulns", justify="right")
    table.add_column("Name")

    for c in items:
        label = c.get("short_label") or c.get("name", "?")
        if len(label) > 60:
            label = label[:57] + "..."
        table.add_row(c["cwe_id"], f"{c['vuln_count']:,}", escape(label))

    console.print()
    console.print(Padding(table, (0, 2)))
    console.print(f"\n  [dim]{total} CWE categories with vulnerabilities[/dim]\n")


def print_cwe_detail(data: dict) -> None:
    """Print CWE detail."""
    cwe_id = data.get("cwe_id", "?")
    name = data.get("name", "?")
    vuln_count = data.get("vuln_count", 0)

    header = Text(f" {cwe_id}", style="bold")
    header.append(f"  {name}", style="")
    console.print()
    console.print(Panel(header, expand=False))

    meta = []
    if data.get("short_label"):
        meta.append(f"Short label: {data['short_label']}")
    if data.get("likelihood"):
        meta.append(f"Exploit likelihood: {data['likelihood']}")
    meta.append(f"Vulnerabilities: {vuln_count:,}")
    for m in meta:
        console.print(f"  {m}")

    parent = data.get("parent_cwe")
    if parent:
        console.print(f"  Parent: {parent['cwe_id']} ({parent['name']})")

    desc = data.get("description")
    if desc:
        console.print()
        console.print(Padding(Text(desc), (0, 2)))

    console.print()


# ---------------------------------------------------------------------------
# Vendors / Products
# ---------------------------------------------------------------------------

def print_vendors_list(data: dict) -> None:
    """Print vendor listing."""
    total = data.get("total", 0)
    items = data.get("items", [])

    if not items:
        console.print("\n[dim]No vendor data available.[/dim]\n")
        return

    table = Table(box=None, padding=(0, 2))
    table.add_column("Vendor", style="bold")
    table.add_column("Vulns", justify="right")

    for v in items:
        table.add_row(escape(v["vendor"]), f"{v['vuln_count']:,}")

    console.print()
    console.print(Padding(table, (0, 2)))
    console.print(f"\n  [dim]{total} vendors tracked[/dim]\n")


def print_products_list(data: dict) -> None:
    """Print product listing for a vendor."""
    vendor = data.get("vendor", "?")
    total = data.get("total", 0)
    items = data.get("items", [])

    if not items:
        console.print(f"\n[dim]No products found for vendor '{escape(vendor)}'.[/dim]\n")
        return

    table = Table(box=None, padding=(0, 2))
    table.add_column("Product", style="bold")
    table.add_column("Vulns", justify="right")

    for p in items:
        table.add_row(escape(p["product"]), f"{p['vuln_count']:,}")

    console.print()
    console.print(Padding(table, (0, 2)))
    console.print(f"\n  [dim]{total} products for {escape(vendor)}[/dim]")
    console.print(f"  [dim]Use: eip-search search --vendor {escape(vendor)} --product <name>[/dim]\n")


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------

def print_lookup_result(data: dict) -> None:
    """Print alt-ID lookup result."""
    alt_id = data.get("alt_id", "?")
    cve = data.get("cve_id") or data.get("eip_id", "?")
    title = data.get("title") or "No title"
    sev = _severity_badge(data.get("severity_label"))
    cvss = data.get("cvss_v3_score")
    cvss_str = f"CVSS {cvss:.1f}" if cvss is not None else ""

    console.print()
    console.print(f"  [bold]{escape(alt_id)}[/bold] [dim]\u2192[/dim] [bold cyan]{escape(cve)}[/bold cyan]")
    console.print(f"  {escape(title)}  ", end="")
    console.print(sev, end="")
    if cvss_str:
        console.print(f"  {cvss_str}", end="")
    console.print("\n")
