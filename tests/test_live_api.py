from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

import pytest

from eip_search_v3.client import EipClient
from eip_search_v3.config import Settings
from eip_search_v3.errors import InputError, NotFoundError

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def live() -> EipClient:
    base_url = os.environ.get("EIP_SEARCH_TEST_API_BASE_URL")
    if not base_url:
        pytest.skip("EIP_SEARCH_TEST_API_BASE_URL is not configured")
    client = EipClient(Settings.load(base_url=base_url, timeout_seconds=30, env={}))
    yield client
    client.close()


def params(**values: object) -> list[tuple[str, object]]:
    return [(key, value) for key, value in values.items() if value is not None]


def rows(page: dict) -> list[dict]:
    value = page.get("items")
    assert isinstance(value, list)
    return value


def test_readiness_and_zero_code_search(live: EipClient) -> None:
    ready = live.readiness()
    assert ready["status"] == "ready"
    assert ready["code_search_status"] == "ready"
    result = live.code_search({"q": "eip-search-definitely-no-match-9f1aa73c", "limit": 5})
    assert result["total"] == 0
    assert result["items"] == []


@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"])
def test_vulnerability_severity_filter(live: EipClient, severity: str) -> None:
    found = rows(live.search_vulnerabilities(params(severity=severity, limit=5)))
    assert found, f"expected at least one {severity} record in the review corpus"
    assert all(row["cvss_severity"] == severity for row in found)


@pytest.mark.parametrize(
    ("predicate", "field"),
    [("cisa_kev", "cisa_kev"), ("ransomware", "known_ransomware")],
)
def test_vulnerability_boolean_filters(live: EipClient, predicate: str, field: str) -> None:
    found = rows(live.search_vulnerabilities(params(**{predicate: True}, limit=5)))
    assert found and all(row[field] is True for row in found)


def test_vulnerability_nuclei_artifact_and_cwe_filters(live: EipClient) -> None:
    nuclei = rows(live.search_vulnerabilities(params(nuclei=True, limit=5)))
    artifacts = rows(live.search_vulnerabilities(params(with_artifacts=True, limit=5)))
    weaknesses = rows(live.search_vulnerabilities(params(cwe="CWE-79", limit=5)))
    assert nuclei and all(row["nuclei_count"] > 0 for row in nuclei)
    assert artifacts and all(row["artifact_count"] > 0 for row in artifacts)
    assert weaknesses and all("CWE-79" in row["cwe_ids"] for row in weaknesses)


def test_vulnerability_query_product_without_vendor_and_limit(live: EipClient) -> None:
    queried = rows(live.search_vulnerabilities(params(q="apache", limit=3)))
    assert len(queried) == 3
    assert all(
        "apache" in json.dumps(live.vulnerability(row["identifier"]), ensure_ascii=False).lower()
        for row in queried
    )
    by_product = rows(live.search_vulnerabilities(params(product="Windows", limit=2)))
    assert by_product
    for summary in by_product:
        claims = rows(live.vulnerability(summary["identifier"])["affected"])
        assert any(claim["data"].get("product") == "Windows" for claim in claims)


@pytest.mark.parametrize("sort", ["published", "cvss", "epss"])
def test_vulnerability_sorts_and_cursor(live: EipClient, sort: str) -> None:
    first = live.search_vulnerabilities(params(sort=sort, limit=5))
    first_rows = rows(first)
    assert len(first_rows) == 5 and first.get("next_cursor")
    second_rows = rows(
        live.search_vulnerabilities(params(sort=sort, limit=5, cursor=first["next_cursor"]))
    )
    assert {row["entity_id"] for row in first_rows}.isdisjoint(
        row["entity_id"] for row in second_rows
    )
    field = {"published": "published_at", "cvss": "cvss_score", "epss": "epss_score"}[sort]
    values = [row[field] for row in first_rows + second_rows if row.get(field) is not None]
    if sort == "published":
        values = [datetime.fromisoformat(value.replace("Z", "+00:00")) for value in values]
    assert values == sorted(values, reverse=True)
    with pytest.raises(InputError):
        live.search_vulnerabilities(params(sort=sort, limit=4, cursor=first["next_cursor"]))


@pytest.mark.parametrize(
    ("filters", "expected"),
    [
        ({"vendor": "Microsoft", "product": "Windows"}, ("Microsoft", "Windows", None, None)),
        ({"ecosystem": "PyPI", "package": "Django"}, (None, None, "PyPI", "Django")),
    ],
)
def test_vulnerability_product_and_package_pairs(live: EipClient, filters, expected) -> None:
    found = rows(live.search_vulnerabilities(params(**filters, limit=2)))
    assert found
    for summary in found:
        detail = live.vulnerability(summary["identifier"])
        claims = rows(detail["affected"])
        tuples = {
            (
                claim["data"].get("vendor"),
                claim["data"].get("product"),
                claim["data"].get("ecosystem"),
                claim["data"].get("package_name"),
            )
            for claim in claims
        }
        assert expected in tuples


@pytest.mark.parametrize("source", ["exploitdb", "metasploit", "repository-inventory"])
def test_poc_source_filter(live: EipClient, source: str) -> None:
    found = rows(live.search_pocs(params(source=source, limit=5)))
    assert found and all(row["source"] == source for row in found)


@pytest.mark.parametrize(
    "kind",
    [
        "exploitdb-exploit",
        "metasploit-exploit",
        "metasploit-auxiliary",
        "repository-poc",
        "repository-candidate",
    ],
)
def test_poc_catalog_kind_filter(live: EipClient, kind: str) -> None:
    found = rows(live.search_pocs(params(catalog_kind=kind, limit=5)))
    assert found and all(row["catalog_kind"] == kind for row in found)


@pytest.mark.parametrize("association", ["linked", "unlinked"])
def test_poc_association_filter(live: EipClient, association: str) -> None:
    found = rows(live.search_pocs(params(association=association, limit=5)))
    assert found
    expected = association == "linked"
    assert all(bool(row["vulnerability_ids"]) is expected for row in found)


def test_poc_language_author_date_and_cursor(live: EipClient) -> None:
    by_language = rows(live.search_pocs(params(language="Python", limit=5)))
    assert by_language and all(row["language"] == "Python" for row in by_language)
    by_author = rows(live.search_pocs(params(author_id=8195520625892450, limit=5)))
    assert by_author and all(
        any(author["public_id"] == 8195520625892450 for author in row["contributors"])
        for row in by_author
    )
    by_date = rows(live.search_pocs(params(source_date_from="2026-01-01", limit=5)))
    assert by_date and all(row["published_at"] >= "2026-01-01" for row in by_date)
    before_date = rows(live.search_pocs(params(source_date_to="2010-01-01", limit=5)))
    assert before_date and all(row["published_at"] <= "2010-01-01T23:59:59Z" for row in before_date)
    by_query = rows(live.search_pocs(params(q="CVE-2024-3400", limit=3)))
    assert by_query and all("CVE-2024-3400" in row["vulnerability_ids"] for row in by_query)
    first = live.search_pocs(params(source="repository-inventory", limit=3))
    second = live.search_pocs(
        params(source="repository-inventory", limit=3, cursor=first["next_cursor"])
    )
    assert {row["artifact_id"] for row in rows(first)}.isdisjoint(
        row["artifact_id"] for row in rows(second)
    )


def test_code_search_sources_and_spans(live: EipClient) -> None:
    for source in ("exploitdb", "metasploit", "repository-inventory"):
        found = rows(live.code_search({"q": "http", "source": source, "limit": 3}))
        assert found
        assert all(row["source"] == source for row in found)
        for row in found:
            match_line = row["match_line"]
            if match_line is None:
                assert row["match_location"] == "path"
                assert row["snippet_role"] == "file-context"
            else:
                assert row["snippet_start_line"] <= match_line <= row["snippet_end_line"]


def test_code_search_exact_scopes_hold_against_authoritative_membership(
    live: EipClient,
) -> None:
    unscoped = rows(live.code_search({"q": "http", "limit": 50}))
    assigned = [row for row in unscoped if isinstance(row.get("public_id"), int)]
    assert assigned

    public_id = assigned[0]["public_id"]
    public_scope = live.code_search({"q": "http", "public_id": public_id, "limit": 50})
    assert public_scope["scope"] == {"kind": "public-poc", "public_id": public_id}
    assert rows(public_scope) and all(row["public_id"] == public_id for row in rows(public_scope))

    for candidate in assigned:
        for identifier in candidate["vulnerability_ids"]:
            pocs = live.vulnerability(identifier)["pocs"]
            if pocs["truncated"] or pocs["total"] != len(pocs["items"]):
                continue
            authoritative_ids = {
                item["public_id"]
                for item in pocs["items"]
                if isinstance(item.get("public_id"), int)
            }
            if candidate["public_id"] not in authoritative_ids:
                continue
            scoped = live.code_search({"q": "http", "vulnerability_id": identifier, "limit": 1})
            scoped_rows = rows(scoped)
            if not scoped_rows:
                continue
            assert scoped["scope"] == {
                "kind": "vulnerability",
                "vulnerability_id": identifier,
            }
            assert all(row["public_id"] in authoritative_ids for row in scoped_rows)
            nonmember = next(
                (row["public_id"] for row in assigned if row["public_id"] not in authoritative_ids),
                None,
            )
            assert nonmember is not None and all(
                row["public_id"] != nonmember for row in scoped_rows
            )
            if scoped["next_cursor"]:
                next_page = live.code_search(
                    {
                        "q": "http",
                        "vulnerability_id": identifier,
                        "limit": 1,
                        "cursor": scoped["next_cursor"],
                    }
                )
                assert all(row["public_id"] in authoritative_ids for row in rows(next_page))
                with pytest.raises(InputError):
                    live.code_search(
                        {
                            "q": "http",
                            "public_id": public_id,
                            "limit": 1,
                            "cursor": scoped["next_cursor"],
                        }
                    )
            return
    pytest.fail("no complete vulnerability membership with a scoped code hit was found")


def test_code_search_cursor_is_query_bound(live: EipClient) -> None:
    first = live.code_search({"q": "http", "source": "exploitdb", "limit": 2})
    second = live.code_search(
        {
            "q": "http",
            "source": "exploitdb",
            "limit": 2,
            "cursor": first["next_cursor"],
        }
    )

    def identities(page: dict) -> set[tuple[str, str]]:
        return {(row["artifact_id"], row["path"]) for row in rows(page)}

    assert identities(first).isdisjoint(identities(second))
    with pytest.raises(InputError):
        live.code_search(
            {
                "q": "http",
                "source": "metasploit",
                "limit": 2,
                "cursor": first["next_cursor"],
            }
        )


@pytest.mark.parametrize("association", ["linked", "unlinked"])
def test_lab_association_filter(live: EipClient, association: str) -> None:
    found = rows(live.search_labs(params(association=association, limit=5)))
    assert found
    expected = association == "linked"
    assert all(bool(row["cve_ids"]) is expected for row in found)


@pytest.mark.parametrize("analysis", ["available", "pending"])
def test_lab_analysis_filter(live: EipClient, analysis: str) -> None:
    found = rows(live.search_labs(params(analysis=analysis, limit=5)))
    assert found
    assert all(
        (row["analysis_status"] == "available") is (analysis == "available") for row in found
    )


@pytest.mark.parametrize("kind", ["compose", "dockerfile"])
def test_lab_kind_filter(live: EipClient, kind: str) -> None:
    found = rows(live.search_labs(params(kind=kind, limit=5)))
    assert found
    key = "compose_manifest_count" if kind == "compose" else "dockerfile_count"
    assert all(row[key] > 0 for row in found)


def test_lab_query_limit_and_cursor(live: EipClient) -> None:
    first = live.search_labs(params(q="CVE-2024", limit=2))
    assert len(rows(first)) == 2
    for row in rows(first):
        searchable = " ".join(
            [
                *(str(value) for value in row["owner"].values() if value is not None),
                *row["cve_ids"],
                *row["anchor_directories"],
                *row["compose_manifest_paths"],
            ]
        )
        assert "cve-2024" in searchable.lower()
    second = live.search_labs(params(q="CVE-2024", limit=2, cursor=first["next_cursor"]))
    assert {row["lab_unit_id"] for row in rows(first)}.isdisjoint(
        row["lab_unit_id"] for row in rows(second)
    )


def test_directories_and_scoped_identifiers(live: EipClient) -> None:
    vendors = rows(live.directory("vendors", params(q="Microsoft", limit=5)))
    products = rows(live.directory("products", params(vendor="Microsoft", q="Windows", limit=5)))
    ecosystems = rows(live.directory("ecosystems", params(q="PyPI", limit=5)))
    packages = rows(live.directory("packages", params(ecosystem="PyPI", q="Django", limit=5)))
    authors = rows(
        live.directory(
            "authors", params(q="exploitintel", source_scope="github", role="owner", limit=5)
        )
    )
    assert vendors and all("microsoft" in row["vendor"].lower() for row in vendors)
    assert products and all(row["vendor"] == "Microsoft" for row in products)
    assert ecosystems and all("pypi" in row["ecosystem"].lower() for row in ecosystems)
    assert packages and all(row["ecosystem"] == "PyPI" for row in packages)
    assert authors and all(
        row["source_scope"] == "github" and "owner" in row["roles"] for row in authors
    )
    weaknesses = rows(live.directory("weaknesses", params(q="injection", limit=5)))
    assert weaknesses and all(
        "injection" in f"{row['name']} {row.get('description', '')}".lower() for row in weaknesses
    )
    assert live.weakness("CWE-79")["cwe_id"] == "CWE-79"
    assert live.author(8195520625892450)["display_name"] == "exploitintel"


def test_directory_cursor_is_query_bound(live: EipClient) -> None:
    first = live.directory("vendors", params(q="Microsoft", limit=2))
    second = live.directory("vendors", params(q="Microsoft", limit=2, cursor=first["next_cursor"]))
    assert {row["vendor"] for row in rows(first)}.isdisjoint(row["vendor"] for row in rows(second))
    with pytest.raises(InputError):
        live.directory("vendors", params(q="Adobe", limit=2, cursor=first["next_cursor"]))


def test_identity_resolution_and_absent_records(live: EipClient) -> None:
    cve = live.vulnerability("CVE-2024-3400")
    ghsa = live.vulnerability("GHSA-V475-XHC9-WFXG")
    assert cve["entity_id"] == ghsa["entity_id"]
    exploit = live.poc("8700882207674114")
    assert exploit["public_id"] == 8700882207674114
    assert live.artifact(exploit["artifact_id"])["artifact_id"] == exploit["artifact_id"]
    with pytest.raises(NotFoundError):
        live.vulnerability("CVE-2099-999999")


def test_statistics_stix_and_protected_content(live: EipClient, tmp_path: Path) -> None:
    statistics = live.statistics()
    trends = live.statistics_trends()
    assert statistics["vulnerabilities"] > statistics["with_pocs"] > 0
    assert trends["as_of"]
    vulnerability_bundle = live.stix_vulnerability("CVE-2024-3400", mapping="v2")
    exploit_bundle = live.stix_exploit(2078504146162010)
    assert vulnerability_bundle["type"] == exploit_bundle["type"] == "bundle"
    assert vulnerability_bundle["objects"] and exploit_bundle["objects"]

    file_page = live.poc_files("8700882207674114")
    assert any(row["path"] == "README.md" and row["viewable"] for row in rows(file_page))
    source = live.poc_file("8700882207674114", "README.md")
    assert source["path"] == "README.md" and source["sha256"].startswith("sha256:")
    archive = live.download_poc("8700882207674114", tmp_path / "poc.zip")
    assert Path(archive["path"]).read_bytes().startswith(b"PK")
    assert archive["password"] == "eip"


def test_lab_screenshot_download(live: EipClient, tmp_path: Path) -> None:
    image = live.download_screenshot(43471308592392, tmp_path / "lab.png")
    assert image["media_type"] == "image/png"
    assert Path(image["path"]).read_bytes().startswith(b"\x89PNG")
