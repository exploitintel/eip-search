"""Data models for EIP API responses."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Exploit:
    """A single exploit/PoC entry."""

    id: int
    source: str
    source_url: str | None = None
    source_id: str | None = None
    language: str | None = None
    exploit_type: str | None = None
    quality_tier: str | None = None
    verified: bool | None = None
    author_name: str | None = None
    platform: str | None = None
    exploit_rank: str | None = None
    github_stars: int | None = None
    github_forks: int | None = None
    has_code: bool = False
    llm_classification: str | None = None
    llm_analysis: dict | None = None
    description: str | None = None

    # Computed by ranking algorithm
    rank_score: float = 0.0

    @classmethod
    def from_dict(cls, data: dict) -> Exploit:
        return cls(
            id=data.get("id", 0),
            source=data.get("source", ""),
            source_url=data.get("source_url"),
            source_id=data.get("source_id"),
            language=data.get("language"),
            exploit_type=data.get("exploit_type"),
            quality_tier=data.get("quality_tier"),
            verified=data.get("verified"),
            author_name=data.get("author_name"),
            platform=data.get("platform"),
            exploit_rank=data.get("exploit_rank"),
            github_stars=data.get("github_stars"),
            github_forks=data.get("github_forks"),
            has_code=data.get("has_code", False),
            llm_classification=data.get("llm_classification"),
            llm_analysis=data.get("llm_analysis"),
            description=data.get("description"),
        )

    @property
    def display_name(self) -> str:
        """Human-friendly name for display."""
        if self.source == "metasploit" and self.source_id:
            return self.source_id.split("/")[-1]
        if self.source == "exploitdb" and self.source_id:
            return self.source_id
        if self.source_id:
            return self.source_id
        return f"exploit-{self.id}"

    @property
    def is_suspicious(self) -> bool:
        return self.llm_classification in ("trojan", "suspicious")


@dataclass
class AffectedProduct:
    """An affected product entry."""

    vendor: str | None = None
    product: str | None = None
    version_start: str | None = None
    version_end: str | None = None
    cpe: str | None = None
    ecosystem: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> AffectedProduct:
        return cls(
            vendor=data.get("vendor"),
            product=data.get("product"),
            version_start=data.get("version_start"),
            version_end=data.get("version_end"),
            cpe=data.get("cpe"),
            ecosystem=data.get("ecosystem"),
        )


@dataclass
class VulnReference:
    """An external reference URL."""

    url: str
    ref_type: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> VulnReference:
        return cls(url=data.get("url", ""), ref_type=data.get("type"))


@dataclass
class AltIdentifier:
    """An alternate identifier (GHSA, EDB, etc.)."""

    id_type: str
    id_value: str

    @classmethod
    def from_dict(cls, data: dict) -> AltIdentifier:
        return cls(
            id_type=data.get("type", ""),
            id_value=data.get("value", ""),
        )


@dataclass
class NucleiTemplate:
    """A Nuclei scanner template."""

    template_id: str
    name: str
    severity: str | None = None
    verified: bool = False
    author: str | None = None
    tags: list[str] = field(default_factory=list)
    shodan_query: str | None = None
    fofa_query: str | None = None
    google_query: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> NucleiTemplate:
        return cls(
            template_id=data.get("template_id", ""),
            name=data.get("name", ""),
            severity=data.get("severity"),
            verified=data.get("verified", False),
            author=data.get("author"),
            tags=data.get("tags") or [],
            shodan_query=data.get("shodan_query"),
            fofa_query=data.get("fofa_query"),
            google_query=data.get("google_query"),
        )


@dataclass
class VulnSummary:
    """Vulnerability as returned in search results (compact)."""

    cve_id: str | None
    eip_id: str
    title: str | None
    severity_label: str | None
    cvss_v3_score: float | None
    epss_score: float | None
    is_kev: bool
    is_vulncheck_kev: bool = False
    is_exploited_wild: bool = False
    ransomware_use: str | None = None
    has_nuclei_template: bool = False
    exploit_count: int = 0
    cwe_ids: list[str] = field(default_factory=list)
    cve_published_at: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> VulnSummary:
        return cls(
            cve_id=data.get("cve_id"),
            eip_id=data.get("eip_id", ""),
            title=data.get("title"),
            severity_label=data.get("severity_label"),
            cvss_v3_score=data.get("cvss_v3_score"),
            epss_score=data.get("epss_score"),
            is_kev=data.get("is_kev", False),
            is_vulncheck_kev=data.get("is_vulncheck_kev", False),
            is_exploited_wild=data.get("is_exploited_wild", False),
            ransomware_use=data.get("ransomware_use"),
            has_nuclei_template=data.get("has_nuclei_template", False),
            exploit_count=data.get("exploit_count", 0),
            cwe_ids=data.get("cwe_ids") or [],
            cve_published_at=data.get("cve_published_at"),
        )

    @property
    def display_id(self) -> str:
        return self.cve_id or self.eip_id


@dataclass
class VulnDetail:
    """Full vulnerability detail from the API."""

    id: int
    cve_id: str | None
    eip_id: str
    status: str
    title: str | None
    description: str | None
    cvss_v3_score: float | None
    cvss_v3_vector: str | None
    epss_score: float | None
    epss_percentile: float | None
    severity_label: str | None
    attack_vector: str | None
    vuln_type: str | None
    cwe_ids: list[str] = field(default_factory=list)
    is_kev: bool = False
    kev_added_at: str | None = None
    is_vulncheck_kev: bool = False
    vulncheck_kev_added_at: str | None = None
    ransomware_use: str | None = None
    is_exploited_wild: bool = False
    wild_reported_at: str | None = None
    is_euvd_exploited: bool = False
    euvd_id: str | None = None
    has_nuclei_template: bool = False
    cve_published_at: str | None = None
    created_at: str | None = None
    exploits: list[Exploit] = field(default_factory=list)
    affected_products: list[AffectedProduct] = field(default_factory=list)
    references: list[VulnReference] = field(default_factory=list)
    alt_identifiers: list[AltIdentifier] = field(default_factory=list)
    nuclei_templates: list[NucleiTemplate] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> VulnDetail:
        return cls(
            id=data.get("id", 0),
            cve_id=data.get("cve_id"),
            eip_id=data.get("eip_id", ""),
            status=data.get("status", ""),
            title=data.get("title"),
            description=data.get("description"),
            cvss_v3_score=data.get("cvss_v3_score"),
            cvss_v3_vector=data.get("cvss_v3_vector"),
            epss_score=data.get("epss_score"),
            epss_percentile=data.get("epss_percentile"),
            severity_label=data.get("severity_label"),
            attack_vector=data.get("attack_vector"),
            vuln_type=data.get("vuln_type"),
            cwe_ids=data.get("cwe_ids") or [],
            is_kev=data.get("is_kev", False),
            kev_added_at=data.get("kev_added_at"),
            is_vulncheck_kev=data.get("is_vulncheck_kev", False),
            vulncheck_kev_added_at=data.get("vulncheck_kev_added_at"),
            ransomware_use=data.get("ransomware_use"),
            is_exploited_wild=data.get("is_exploited_wild", False),
            wild_reported_at=data.get("wild_reported_at"),
            is_euvd_exploited=data.get("is_euvd_exploited", False),
            euvd_id=data.get("euvd_id"),
            has_nuclei_template=data.get("has_nuclei_template", False),
            cve_published_at=data.get("cve_published_at"),
            created_at=data.get("created_at"),
            exploits=[Exploit.from_dict(e) for e in data.get("exploits", [])],
            affected_products=[AffectedProduct.from_dict(p) for p in data.get("affected_products", [])],
            references=[VulnReference.from_dict(r) for r in data.get("references", [])],
            alt_identifiers=[AltIdentifier.from_dict(a) for a in data.get("alt_identifiers", [])],
            nuclei_templates=[NucleiTemplate.from_dict(n) for n in data.get("nuclei_templates", [])],
        )

    @property
    def display_id(self) -> str:
        return self.cve_id or self.eip_id


@dataclass
class SearchResult:
    """Paginated search result set."""

    total: int
    page: int
    per_page: int
    total_pages: int
    items: list[VulnSummary]

    @classmethod
    def from_dict(cls, data: dict) -> SearchResult:
        return cls(
            total=data.get("total", 0),
            page=data.get("page", 1),
            per_page=data.get("per_page", 20),
            total_pages=data.get("total_pages", 0),
            items=[VulnSummary.from_dict(v) for v in data.get("items", [])],
        )


@dataclass
class ExploitWithCVE(Exploit):
    """An exploit with parent CVE context, returned by the exploit browse API."""

    cve_id: str | None = None
    cve_title: str | None = None
    severity_label: str | None = None
    cvss_v3_score: float | None = None

    @classmethod
    def from_dict(cls, data: dict) -> ExploitWithCVE:
        return cls(
            id=data.get("id", 0),
            source=data.get("source", ""),
            source_url=data.get("source_url"),
            source_id=data.get("source_id"),
            language=data.get("language"),
            exploit_type=data.get("exploit_type"),
            quality_tier=data.get("quality_tier"),
            verified=data.get("verified"),
            author_name=data.get("author_name"),
            platform=data.get("platform"),
            exploit_rank=data.get("exploit_rank"),
            github_stars=data.get("github_stars"),
            github_forks=data.get("github_forks"),
            has_code=data.get("has_code", False),
            llm_classification=data.get("llm_classification"),
            llm_analysis=data.get("llm_analysis"),
            description=data.get("description"),
            cve_id=data.get("cve_id"),
            cve_title=data.get("cve_title"),
            severity_label=data.get("severity_label"),
            cvss_v3_score=data.get("cvss_v3_score"),
        )


@dataclass
class ExploitBrowseResult:
    """Paginated exploit browse result set."""

    total: int
    page: int
    per_page: int
    total_pages: int
    items: list[ExploitWithCVE]

    @classmethod
    def from_dict(cls, data: dict) -> ExploitBrowseResult:
        return cls(
            total=data.get("total", 0),
            page=data.get("page", 1),
            per_page=data.get("per_page", 10),
            total_pages=data.get("total_pages", 0),
            items=[ExploitWithCVE.from_dict(e) for e in data.get("items", [])],
        )


@dataclass
class ExploitFile:
    """A file inside an exploit archive."""

    name: str
    path: str
    size: int
    file_type: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> ExploitFile:
        return cls(
            name=data.get("name", ""),
            path=data.get("path", ""),
            size=data.get("size", 0),
            file_type=data.get("type"),
        )


@dataclass
class Stats:
    """Platform-wide statistics."""

    total_vulns: int = 0
    published: int = 0
    with_title: int = 0
    with_cvss: int = 0
    with_epss: int = 0
    kev_total: int = 0
    vulncheck_kev_total: int = 0
    wild_total: int = 0
    ransomware_total: int = 0
    any_exploited_total: int = 0
    critical_count: int = 0
    with_nuclei: int = 0
    total_with_exploits: int = 0
    total_exploits: int = 0
    total_vendors: int = 0
    total_authors: int = 0
    last_updated: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> Stats:
        return cls(
            total_vulns=data.get("total_vulns", 0),
            published=data.get("published", 0),
            with_title=data.get("with_title", 0),
            with_cvss=data.get("with_cvss", 0),
            with_epss=data.get("with_epss", 0),
            kev_total=data.get("kev_total", 0),
            vulncheck_kev_total=data.get("vulncheck_kev_total", 0),
            wild_total=data.get("wild_total", 0),
            ransomware_total=data.get("ransomware_total", 0),
            any_exploited_total=data.get("any_exploited_total", 0),
            critical_count=data.get("critical_count", 0),
            with_nuclei=data.get("with_nuclei", 0),
            total_with_exploits=data.get("total_with_exploits", 0),
            total_exploits=data.get("total_exploits", 0),
            total_vendors=data.get("total_vendors", 0),
            total_authors=data.get("total_authors", 0),
            last_updated=data.get("last_updated"),
        )
