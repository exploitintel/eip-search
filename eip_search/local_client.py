"""Offline SQLite client for eip-search — queries a local EIP database.

Provides the same API surface as the HTTP ``client`` module so that CLI
commands can transparently switch between online and offline mode.

The SQLite database is created by the ``export_sqlite.py`` script on the
ingestion server and distributed as a gzipped download.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from eip_search.client import APIError
from eip_search.models import (
    AffectedProduct,
    AltIdentifier,
    Exploit,
    ExploitBrowseResult,
    ExploitWithCVE,
    NucleiTemplate,
    SearchResult,
    Stats,
    VulnDetail,
    VulnReference,
    VulnSummary,
)

DEFAULT_DB_PATH = Path.home() / ".eip" / "eip.db"
DEFAULT_DB_URL = "https://repo.exploit-intel.com/data/eip.db.gz"


class LocalClient:
    """SQLite-backed client matching the HTTP client module's function signatures."""

    def __init__(self, db_path: str | Path | None = None):
        self._db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        if not self._db_path.exists():
            raise FileNotFoundError(
                f"EIP database not found: {self._db_path}\n"
                f"Download it with: eip-search update-db"
            )
        self._conn: sqlite3.Connection | None = None

    @property
    def db_path(self) -> Path:
        return self._db_path

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA query_only = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA cache_size = -64000")  # 64 MB
        return self._conn

    # ── Search vulnerabilities ────────────────────────────────────────

    def search_vulns(self, params: dict[str, Any]) -> SearchResult:
        """Search vulnerabilities with filters (mirrors /api/v1/vulns)."""
        conn = self._get_conn()
        clean = {k: v for k, v in params.items() if v is not None}

        q = clean.get("q")
        page = int(clean.get("page", 1))
        per_page = min(int(clean.get("per_page", 20)), 100)
        offset = (page - 1) * per_page

        conditions: list[str] = []
        binds: list[Any] = []
        joins: list[str] = []
        use_fts = False

        if q:
            joins.append("JOIN vulns_fts ON vulns_fts.rowid = v.id")
            conditions.append("vulns_fts MATCH ?")
            binds.append(_fts_escape(q))
            use_fts = True

        if clean.get("severity"):
            conditions.append("v.severity_label = ?")
            binds.append(clean["severity"].lower())

        if clean.get("is_kev"):
            conditions.append("v.is_kev = 1")

        if clean.get("any_exploited"):
            conditions.append(
                "(v.is_kev = 1 OR v.is_vulncheck_kev = 1 OR v.is_exploited_wild = 1)"
            )

        if clean.get("ransomware"):
            conditions.append("v.ransomware_use IS NOT NULL")

        if clean.get("has_exploits"):
            conditions.append("v.exploit_count > 0")

        if clean.get("has_nuclei"):
            conditions.append("v.has_nuclei_template = 1")

        need_ap = any(k in clean for k in ("vendor", "product", "ecosystem"))
        if need_ap:
            joins.append(
                "JOIN affected_products ap ON ap.vulnerability_id = v.id"
            )
            if clean.get("vendor"):
                conditions.append("ap.vendor = ?")
                binds.append(clean["vendor"].lower())
            if clean.get("product"):
                conditions.append("ap.product = ?")
                binds.append(clean["product"].lower())
            if clean.get("ecosystem"):
                conditions.append("ap.ecosystem = ?")
                binds.append(clean["ecosystem"].lower())

        if clean.get("cwe"):
            cwe_val = str(clean["cwe"]).strip()
            if not cwe_val.upper().startswith("CWE-"):
                cwe_val = f"CWE-{cwe_val}"
            conditions.append("v.cwe_ids LIKE ?")
            binds.append(f'%"{cwe_val.upper()}"%')

        if clean.get("year"):
            conditions.append("v.cve_id LIKE ?")
            binds.append(f"CVE-{int(clean['year'])}-%")

        if clean.get("min_cvss") is not None:
            conditions.append("v.cvss_v3_score >= ?")
            binds.append(float(clean["min_cvss"]))

        if clean.get("min_epss") is not None:
            conditions.append("v.epss_score >= ?")
            binds.append(float(clean["min_epss"]))

        if clean.get("date_from"):
            conditions.append("v.cve_published_at >= ?")
            binds.append(clean["date_from"])
        if clean.get("date_to"):
            conditions.append("v.cve_published_at <= ?")
            binds.append(clean["date_to"] + "T23:59:59")

        join_sql = " ".join(joins)
        where_sql = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        # Sort
        sort_key = clean.get("sort", "newest")
        if sort_key == "relevance" and use_fts:
            order_sql = "ORDER BY vulns_fts.rank, v.id DESC"
        elif sort_key == "oldest":
            order_sql = "ORDER BY v.cve_published_at ASC, v.id ASC"
        elif sort_key == "cvss_desc":
            order_sql = "ORDER BY v.cvss_v3_score DESC, v.id DESC"
        elif sort_key == "epss_desc":
            order_sql = "ORDER BY v.epss_score DESC, v.id DESC"
        else:  # newest (default)
            order_sql = "ORDER BY v.cve_published_at DESC, v.id DESC"

        count_sql = (
            f"SELECT COUNT(DISTINCT v.id) FROM vulnerabilities v "
            f"{join_sql} {where_sql}"
        )
        total = conn.execute(count_sql, binds).fetchone()[0]
        total_pages = max(1, -(-total // per_page))

        data_sql = f"""
            SELECT v.id, v.cve_id, v.eip_id, v.title, v.severity_label,
                   v.cvss_v3_score, v.epss_score, v.is_kev, v.is_vulncheck_kev,
                   v.is_exploited_wild, v.ransomware_use, v.has_nuclei_template,
                   v.exploit_count, v.cwe_ids, v.cve_published_at
            FROM vulnerabilities v {join_sql} {where_sql}
            GROUP BY v.id
            {order_sql} LIMIT ? OFFSET ?
        """
        rows = conn.execute(data_sql, binds + [per_page, offset]).fetchall()
        items = [_row_to_vuln_summary(r) for r in rows]

        return SearchResult(
            total=total, page=page, per_page=per_page,
            total_pages=total_pages, items=items,
        )

    # ── Browse exploits ───────────────────────────────────────────────

    def browse_exploits(self, params: dict[str, Any]) -> ExploitBrowseResult:
        """Browse exploits with filters (mirrors /api/v1/exploits)."""
        conn = self._get_conn()
        clean = {k: v for k, v in params.items() if v is not None}

        page = int(clean.get("page", 1))
        per_page = min(int(clean.get("per_page", 10)), 25)
        offset = (page - 1) * per_page

        conditions: list[str] = []
        binds: list[Any] = []
        joins: list[str] = ["JOIN vulnerabilities v ON v.id = e.vulnerability_id"]

        if clean.get("source"):
            conditions.append("e.source = ?")
            binds.append(clean["source"])

        if clean.get("language"):
            conditions.append("e.language = ?")
            binds.append(clean["language"].lower())

        if clean.get("llm_classification"):
            conditions.append("e.llm_classification = ?")
            binds.append(clean["llm_classification"])

        if clean.get("attack_type"):
            conditions.append("e.llm_attack_type = ?")
            binds.append(clean["attack_type"])

        if clean.get("complexity"):
            conditions.append("e.llm_complexity = ?")
            binds.append(clean["complexity"])

        if clean.get("reliability"):
            conditions.append("e.llm_reliability = ?")
            binds.append(clean["reliability"])

        if clean.get("author"):
            conditions.append("e.author_name = ?")
            binds.append(clean["author"])

        if clean.get("min_stars") is not None:
            conditions.append("e.github_stars >= ?")
            binds.append(int(clean["min_stars"]))

        if clean.get("has_code"):
            conditions.append("e.has_code = 1")

        if clean.get("cve"):
            conditions.append("v.cve_id = ?")
            binds.append(clean["cve"].upper())

        need_ap = any(k in clean for k in ("vendor", "product"))
        if need_ap:
            joins.append(
                "JOIN affected_products ap ON ap.vulnerability_id = v.id"
            )
            if clean.get("vendor"):
                conditions.append("ap.vendor = ?")
                binds.append(clean["vendor"].lower())
            if clean.get("product"):
                conditions.append("ap.product = ?")
                binds.append(clean["product"].lower())

        if clean.get("requires_auth") is not None:
            conditions.append("e.llm_requires_auth = ?")
            binds.append(1 if clean["requires_auth"] else 0)

        join_sql = " ".join(joins)
        where_sql = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        sort_key = clean.get("sort", "newest")
        if sort_key == "stars_desc":
            order_sql = "ORDER BY e.github_stars DESC, e.id DESC"
        else:
            order_sql = "ORDER BY e.id DESC"

        count_sql = (
            f"SELECT COUNT(DISTINCT e.id) FROM exploits e "
            f"{join_sql} {where_sql}"
        )
        total = conn.execute(count_sql, binds).fetchone()[0]
        total_pages = max(1, -(-total // per_page))

        data_sql = f"""
            SELECT e.id, e.source, e.source_url, e.source_id,
                   e.language, e.exploit_type, e.quality_tier, e.verified,
                   e.author_name, e.exploit_rank, e.github_stars,
                   e.has_code, e.llm_classification,
                   v.cve_id, v.title AS cve_title,
                   v.severity_label, v.cvss_v3_score
            FROM exploits e {join_sql} {where_sql}
            GROUP BY e.id
            {order_sql} LIMIT ? OFFSET ?
        """
        rows = conn.execute(data_sql, binds + [per_page, offset]).fetchall()

        items = [
            ExploitWithCVE(
                id=r["id"],
                source=r["source"] or "",
                source_url=r["source_url"],
                source_id=r["source_id"],
                language=r["language"],
                exploit_type=r["exploit_type"],
                quality_tier=r["quality_tier"],
                verified=bool(r["verified"]),
                author_name=r["author_name"],
                exploit_rank=r["exploit_rank"],
                github_stars=r["github_stars"],
                has_code=bool(r["has_code"]),
                llm_classification=r["llm_classification"],
                cve_id=r["cve_id"],
                cve_title=r["cve_title"],
                severity_label=r["severity_label"],
                cvss_v3_score=r["cvss_v3_score"],
            )
            for r in rows
        ]

        return ExploitBrowseResult(
            total=total, page=page, per_page=per_page,
            total_pages=total_pages, items=items,
        )

    # ── Vulnerability detail ──────────────────────────────────────────

    def get_vuln_detail(self, vuln_id: str) -> VulnDetail:
        """Get full vulnerability detail by CVE-ID or EIP-ID."""
        conn = self._get_conn()
        vid = vuln_id.strip().upper()

        row = conn.execute(
            "SELECT * FROM vulnerabilities WHERE cve_id = ? OR eip_id = ?",
            (vid, vid),
        ).fetchone()

        if row is None:
            raise APIError(404, f"Vulnerability not found: {vuln_id}")

        v_id = row["id"]
        cwe_ids = json.loads(row["cwe_ids"]) if row["cwe_ids"] else []

        # Exploits
        expl_rows = conn.execute(
            """SELECT id, source, source_url, source_id, author_name, language,
                      exploit_type, quality_tier, verified, exploit_rank,
                      github_stars, has_code, llm_classification,
                      llm_attack_type, llm_complexity, llm_reliability,
                      llm_requires_auth
               FROM exploits WHERE vulnerability_id = ?
               ORDER BY id""",
            (v_id,),
        ).fetchall()

        exploits = []
        for e in expl_rows:
            llm_analysis = None
            if any(e[k] for k in ("llm_attack_type", "llm_complexity", "llm_reliability")):
                llm_analysis = {}
                if e["llm_attack_type"]:
                    llm_analysis["attack_type"] = e["llm_attack_type"]
                if e["llm_complexity"]:
                    llm_analysis["complexity"] = e["llm_complexity"]
                if e["llm_reliability"]:
                    llm_analysis["reliability"] = e["llm_reliability"]
                if e["llm_requires_auth"] is not None:
                    llm_analysis["requires_auth"] = bool(e["llm_requires_auth"])
            exploits.append(Exploit(
                id=e["id"],
                source=e["source"] or "",
                source_url=e["source_url"],
                source_id=e["source_id"],
                language=e["language"],
                exploit_type=e["exploit_type"],
                quality_tier=e["quality_tier"],
                verified=bool(e["verified"]),
                author_name=e["author_name"],
                exploit_rank=e["exploit_rank"],
                github_stars=e["github_stars"],
                has_code=bool(e["has_code"]),
                llm_classification=e["llm_classification"],
                llm_analysis=llm_analysis,
            ))

        # Affected products
        ap_rows = conn.execute(
            "SELECT vendor, product, version_start, version_end, cpe, ecosystem "
            "FROM affected_products WHERE vulnerability_id = ?",
            (v_id,),
        ).fetchall()
        affected_products = [
            AffectedProduct(
                vendor=a["vendor"], product=a["product"],
                version_start=a["version_start"], version_end=a["version_end"],
                cpe=a["cpe"], ecosystem=a["ecosystem"],
            )
            for a in ap_rows
        ]

        # References
        ref_rows = conn.execute(
            "SELECT url, ref_type FROM refs WHERE vulnerability_id = ?",
            (v_id,),
        ).fetchall()
        references = [
            VulnReference(url=r["url"], ref_type=r["ref_type"])
            for r in ref_rows
        ]

        # Alt identifiers
        alt_rows = conn.execute(
            "SELECT id_type, id_value FROM alt_ids WHERE vulnerability_id = ?",
            (v_id,),
        ).fetchall()
        alt_identifiers = [
            AltIdentifier(id_type=a["id_type"], id_value=a["id_value"])
            for a in alt_rows
        ]

        # Nuclei templates
        nuc_rows = conn.execute(
            "SELECT template_id, name, severity, verified, author, tags, "
            "       shodan_query, fofa_query, google_query "
            "FROM nuclei_templates WHERE vulnerability_id = ?",
            (v_id,),
        ).fetchall()
        nuclei_templates = [
            NucleiTemplate(
                template_id=n["template_id"] or "",
                name=n["name"] or "",
                severity=n["severity"],
                verified=bool(n["verified"]),
                author=n["author"],
                tags=json.loads(n["tags"]) if n["tags"] else [],
                shodan_query=n["shodan_query"],
                fofa_query=n["fofa_query"],
                google_query=n["google_query"],
            )
            for n in nuc_rows
        ]

        return VulnDetail(
            id=v_id,
            cve_id=row["cve_id"],
            eip_id=row["eip_id"] or "",
            status="published",
            title=row["title"],
            description=row["description"],
            cvss_v3_score=row["cvss_v3_score"],
            cvss_v3_vector=row["cvss_v3_vector"],
            epss_score=row["epss_score"],
            epss_percentile=row["epss_percentile"],
            severity_label=row["severity_label"],
            attack_vector=row["attack_vector"],
            vuln_type=None,
            cwe_ids=cwe_ids,
            is_kev=bool(row["is_kev"]),
            kev_added_at=row["kev_added_at"],
            is_vulncheck_kev=bool(row["is_vulncheck_kev"]),
            is_exploited_wild=bool(row["is_exploited_wild"]),
            wild_reported_at=row["wild_reported_at"],
            ransomware_use=row["ransomware_use"],
            has_nuclei_template=bool(row["has_nuclei_template"]),
            cve_published_at=row["cve_published_at"],
            exploits=exploits,
            affected_products=affected_products,
            references=references,
            alt_identifiers=alt_identifiers,
            nuclei_templates=nuclei_templates,
        )

    # ── Stats ─────────────────────────────────────────────────────────

    def get_stats(self) -> Stats:
        """Get platform-wide statistics from the local database."""
        conn = self._get_conn()

        def _c(sql: str) -> int:
            return conn.execute(sql).fetchone()[0]

        row = conn.execute(
            "SELECT value FROM metadata WHERE key = 'exported_at'"
        ).fetchone()
        last_updated = row[0] if row else None

        return Stats(
            total_vulns=_c("SELECT COUNT(*) FROM vulnerabilities"),
            published=_c("SELECT COUNT(*) FROM vulnerabilities WHERE cve_id IS NOT NULL"),
            with_title=_c("SELECT COUNT(*) FROM vulnerabilities WHERE title IS NOT NULL"),
            with_cvss=_c("SELECT COUNT(*) FROM vulnerabilities WHERE cvss_v3_score IS NOT NULL"),
            with_epss=_c("SELECT COUNT(*) FROM vulnerabilities WHERE epss_score IS NOT NULL"),
            kev_total=_c("SELECT COUNT(*) FROM vulnerabilities WHERE is_kev = 1"),
            vulncheck_kev_total=_c("SELECT COUNT(*) FROM vulnerabilities WHERE is_vulncheck_kev = 1"),
            wild_total=_c("SELECT COUNT(*) FROM vulnerabilities WHERE is_exploited_wild = 1"),
            ransomware_total=_c("SELECT COUNT(*) FROM vulnerabilities WHERE ransomware_use IS NOT NULL"),
            any_exploited_total=_c(
                "SELECT COUNT(*) FROM vulnerabilities "
                "WHERE is_kev = 1 OR is_vulncheck_kev = 1 OR is_exploited_wild = 1"
            ),
            critical_count=_c("SELECT COUNT(*) FROM vulnerabilities WHERE severity_label = 'critical'"),
            with_nuclei=_c("SELECT COUNT(*) FROM vulnerabilities WHERE has_nuclei_template = 1"),
            total_with_exploits=_c("SELECT COUNT(*) FROM vulnerabilities WHERE exploit_count > 0"),
            total_exploits=_c("SELECT COUNT(*) FROM exploits WHERE source != 'writeup'"),
            total_vendors=_c("SELECT COUNT(DISTINCT vendor) FROM affected_products WHERE vendor IS NOT NULL"),
            total_authors=_c("SELECT COUNT(DISTINCT author_name) FROM exploits WHERE author_name IS NOT NULL"),
            last_updated=last_updated,
        )

    # ── Authors ───────────────────────────────────────────────────────

    def list_authors(self, params: dict[str, Any]) -> dict:
        """List exploit authors ranked by exploit count."""
        conn = self._get_conn()
        page = int(params.get("page", 1))
        per_page = min(int(params.get("per_page", 25)), 50)
        offset = (page - 1) * per_page

        total = conn.execute(
            "SELECT COUNT(DISTINCT author_name) FROM exploits "
            "WHERE author_name IS NOT NULL AND source != 'writeup'"
        ).fetchone()[0]
        total_pages = max(1, -(-total // per_page))

        rows = conn.execute(
            "SELECT author_name, COUNT(*) AS exploit_count "
            "FROM exploits WHERE author_name IS NOT NULL AND source != 'writeup' "
            "GROUP BY author_name ORDER BY exploit_count DESC "
            "LIMIT ? OFFSET ?",
            (per_page, offset),
        ).fetchall()

        items = [
            {"name": r["author_name"], "handle": None, "exploit_count": r["exploit_count"]}
            for r in rows
        ]
        return {
            "total": total, "page": page, "per_page": per_page,
            "total_pages": total_pages, "items": items,
        }

    def get_author(self, name: str, params: dict[str, Any] | None = None) -> dict:
        """Get author profile with their exploits."""
        conn = self._get_conn()
        params = params or {}
        page = int(params.get("page", 1))
        per_page = min(int(params.get("per_page", 25)), 50)
        offset = (page - 1) * per_page

        exploit_count = conn.execute(
            "SELECT COUNT(*) FROM exploits "
            "WHERE author_name = ? AND source != 'writeup'",
            (name,),
        ).fetchone()[0]

        if exploit_count == 0:
            raise APIError(404, f"Author not found: {name}")

        total_pages = max(1, -(-exploit_count // per_page))

        first_row = conn.execute(
            "SELECT MIN(date_published) FROM exploits WHERE author_name = ?",
            (name,),
        ).fetchone()
        first_seen = first_row[0] if first_row else None

        rows = conn.execute(
            """SELECT e.id, e.source, e.source_id, e.source_url,
                      v.cve_id, v.severity_label
               FROM exploits e
               JOIN vulnerabilities v ON v.id = e.vulnerability_id
               WHERE e.author_name = ? AND e.source != 'writeup'
               ORDER BY e.id DESC LIMIT ? OFFSET ?""",
            (name, per_page, offset),
        ).fetchall()

        exploits = [
            {
                "id": r["id"], "source": r["source"], "source_id": r["source_id"],
                "source_url": r["source_url"], "cve_id": r["cve_id"],
                "severity_label": r["severity_label"],
            }
            for r in rows
        ]

        return {
            "name": name, "handle": None, "exploit_count": exploit_count,
            "first_seen_at": first_seen, "total": exploit_count,
            "page": page, "total_pages": total_pages, "exploits": exploits,
        }

    # ── CWEs ──────────────────────────────────────────────────────────

    def list_cwes(self) -> dict:
        """List CWE categories ranked by vulnerability count."""
        conn = self._get_conn()

        rows = conn.execute("""
            SELECT j.value AS cwe_id, COUNT(DISTINCT v.id) AS vuln_count
            FROM vulnerabilities v, json_each(v.cwe_ids) j
            WHERE v.cwe_ids IS NOT NULL
            GROUP BY j.value
            ORDER BY vuln_count DESC
        """).fetchall()

        items = []
        for r in rows:
            cwe_id = r["cwe_id"]
            cat = conn.execute(
                "SELECT name, short_label FROM cwe_catalog WHERE cwe_id = ?",
                (cwe_id,),
            ).fetchone()
            items.append({
                "cwe_id": cwe_id,
                "name": cat["name"] if cat else cwe_id,
                "short_label": cat["short_label"] if cat else None,
                "vuln_count": r["vuln_count"],
            })

        return {"total": len(items), "items": items}

    def get_cwe(self, cwe_id: str) -> dict:
        """Get CWE detail by ID (e.g. 'CWE-79' or '79')."""
        conn = self._get_conn()
        cwe_id = cwe_id.strip().upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        row = conn.execute(
            "SELECT * FROM cwe_catalog WHERE cwe_id = ?", (cwe_id,)
        ).fetchone()

        if row is None:
            raise APIError(404, f"CWE not found: {cwe_id}")

        vuln_count = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE cwe_ids LIKE ?",
            (f'%"{cwe_id}"%',),
        ).fetchone()[0]

        parent = None
        if row["parent_cwe"]:
            p = conn.execute(
                "SELECT cwe_id, name FROM cwe_catalog WHERE cwe_id = ?",
                (row["parent_cwe"],),
            ).fetchone()
            if p:
                parent = {"cwe_id": p["cwe_id"], "name": p["name"]}

        return {
            "cwe_id": row["cwe_id"],
            "name": row["name"],
            "short_label": row["short_label"],
            "description": row["description"],
            "likelihood": row["likelihood"],
            "parent_cwe": parent,
            "vuln_count": vuln_count,
        }

    # ── Vendors / Products ────────────────────────────────────────────

    def list_vendors(self) -> dict:
        """List vendors ranked by vulnerability count."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT vendor, COUNT(DISTINCT vulnerability_id) AS vuln_count "
            "FROM affected_products WHERE vendor IS NOT NULL "
            "GROUP BY vendor ORDER BY vuln_count DESC LIMIT 200"
        ).fetchall()

        items = [{"vendor": r["vendor"], "vuln_count": r["vuln_count"]} for r in rows]
        return {"total": len(items), "items": items}

    def list_vendor_products(self, vendor: str) -> dict:
        """List products for a specific vendor."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT product, COUNT(DISTINCT vulnerability_id) AS vuln_count "
            "FROM affected_products WHERE vendor = ? AND product IS NOT NULL "
            "GROUP BY product ORDER BY vuln_count DESC",
            (vendor.lower(),),
        ).fetchall()

        if not rows:
            raise APIError(404, f"Vendor not found: {vendor}")

        items = [{"product": r["product"], "vuln_count": r["vuln_count"]} for r in rows]
        return {"vendor": vendor, "total": len(items), "items": items}

    # ── Lookup ────────────────────────────────────────────────────────

    def lookup_alt_id(self, alt_id: str) -> dict:
        """Resolve an alternate ID (EDB-XXXXX, GHSA-XXXXX) to its CVE."""
        conn = self._get_conn()
        aid = alt_id.strip()

        # Parse type from prefix
        aid_upper = aid.upper()
        if aid_upper.startswith("EDB-"):
            id_type, id_value = "EDB", aid_upper
        elif aid_upper.startswith("GHSA-"):
            id_type, id_value = "GHSA", aid  # GHSA IDs are lowercase
        else:
            id_type, id_value = None, aid

        if id_type:
            row = conn.execute(
                "SELECT a.vulnerability_id, v.cve_id, v.eip_id, v.title, "
                "       v.severity_label, v.cvss_v3_score "
                "FROM alt_ids a JOIN vulnerabilities v ON v.id = a.vulnerability_id "
                "WHERE a.id_type = ? AND a.id_value = ?",
                (id_type, id_value),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT a.vulnerability_id, v.cve_id, v.eip_id, v.title, "
                "       v.severity_label, v.cvss_v3_score "
                "FROM alt_ids a JOIN vulnerabilities v ON v.id = a.vulnerability_id "
                "WHERE a.id_value = ?",
                (id_value,),
            ).fetchone()

        if row is None:
            raise APIError(404, f"Identifier not found: {alt_id}")

        return {
            "alt_id": alt_id,
            "cve_id": row["cve_id"],
            "eip_id": row["eip_id"],
            "title": row["title"],
            "severity_label": row["severity_label"],
            "cvss_v3_score": row["cvss_v3_score"],
        }

    # ── Exploit analysis ─────────────────────────────────────────────

    def get_exploit_analysis(self, exploit_id: int) -> ExploitWithCVE:
        """Get a single exploit with its LLM analysis and CVE context."""
        conn = self._get_conn()
        row = conn.execute(
            """SELECT e.id, e.source, e.source_url, e.source_id, e.author_name,
                      e.language, e.exploit_type, e.quality_tier, e.verified,
                      e.exploit_rank, e.github_stars, e.has_code,
                      e.llm_classification, e.llm_attack_type, e.llm_complexity,
                      e.llm_reliability, e.llm_requires_auth, e.llm_analysis_json,
                      v.cve_id, v.title AS cve_title,
                      v.severity_label, v.cvss_v3_score
               FROM exploits e
               JOIN vulnerabilities v ON v.id = e.vulnerability_id
               WHERE e.id = ?""",
            (exploit_id,),
        ).fetchone()

        if row is None:
            raise APIError(404, f"Exploit not found: {exploit_id}")

        # Build llm_analysis dict — prefer full JSON blob, fall back to columns
        llm_analysis = None
        if row["llm_analysis_json"]:
            try:
                llm_analysis = json.loads(row["llm_analysis_json"])
            except (json.JSONDecodeError, TypeError):
                llm_analysis = None

        if llm_analysis is None:
            if any(row[k] for k in ("llm_attack_type", "llm_complexity", "llm_reliability")):
                llm_analysis = {}
                if row["llm_attack_type"]:
                    llm_analysis["attack_type"] = row["llm_attack_type"]
                if row["llm_complexity"]:
                    llm_analysis["complexity"] = row["llm_complexity"]
                if row["llm_reliability"]:
                    llm_analysis["reliability"] = row["llm_reliability"]
                if row["llm_requires_auth"] is not None:
                    llm_analysis["requires_auth"] = bool(row["llm_requires_auth"])

        return ExploitWithCVE(
            id=row["id"],
            source=row["source"] or "",
            source_url=row["source_url"],
            source_id=row["source_id"],
            author_name=row["author_name"],
            language=row["language"],
            exploit_type=row["exploit_type"],
            quality_tier=row["quality_tier"],
            verified=bool(row["verified"]),
            exploit_rank=row["exploit_rank"],
            github_stars=row["github_stars"],
            has_code=bool(row["has_code"]),
            llm_classification=row["llm_classification"],
            llm_analysis=llm_analysis,
            cve_id=row["cve_id"],
            cve_title=row["cve_title"],
            severity_label=row["severity_label"],
            cvss_v3_score=row["cvss_v3_score"],
        )

    # ── Online-only stubs ─────────────────────────────────────────────

    def list_exploit_files(self, exploit_id: int) -> list:
        raise APIError(
            501,
            "Exploit file browsing is not available offline. "
            "Remove --offline to use the API.",
        )

    def get_exploit_code(self, exploit_id: int, file_path: str) -> str:
        raise APIError(
            501,
            "Exploit code viewing is not available offline. "
            "Remove --offline to use the API.",
        )

    def download_exploit(self, exploit_id: int, output_dir=None):
        raise APIError(
            501,
            "Exploit downloads are not available offline. "
            "Remove --offline to use the API.",
        )


# ── Helpers ───────────────────────────────────────────────────────────


def _fts_escape(query: str) -> str:
    """Prepare a user query for FTS5 MATCH.

    Wraps each token in quotes to handle special FTS5 characters safely.
    CVE/EIP IDs are searched as exact phrases.
    """
    q = query.strip()
    if not q:
        return '""'
    # CVE/EIP IDs → phrase search
    if q.upper().startswith(("CVE-", "EIP-")):
        return f'"{q}"'
    # Quote each word to prevent FTS5 syntax errors
    tokens = q.split()
    return " ".join(f'"{t}"' for t in tokens if t)


def _row_to_vuln_summary(r: sqlite3.Row) -> VulnSummary:
    """Convert a SQLite row to a VulnSummary dataclass."""
    cwe_ids = json.loads(r["cwe_ids"]) if r["cwe_ids"] else []
    return VulnSummary(
        cve_id=r["cve_id"],
        eip_id=r["eip_id"] or "",
        title=r["title"],
        severity_label=r["severity_label"],
        cvss_v3_score=r["cvss_v3_score"],
        epss_score=r["epss_score"],
        is_kev=bool(r["is_kev"]),
        is_vulncheck_kev=bool(r["is_vulncheck_kev"]),
        is_exploited_wild=bool(r["is_exploited_wild"]),
        ransomware_use=r["ransomware_use"],
        has_nuclei_template=bool(r["has_nuclei_template"]),
        exploit_count=r["exploit_count"] or 0,
        cwe_ids=cwe_ids,
        cve_published_at=r["cve_published_at"],
    )
