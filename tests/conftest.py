from __future__ import annotations

from typing import Any

import pytest


def collection(items: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    rows = items or []
    return {"items": rows, "total": len(rows), "truncated": False}


@pytest.fixture
def api_data() -> dict[str, Any]:
    analysis = {
        "model": "model:cloud",
        "technical_analyzed_at": "2026-01-02T03:04:05Z",
        "backdoor_reviewed_at": "2026-01-02T03:05:05Z",
        "technical": {
            "classification": "exploit",
            "confidence": 0.9,
            "language": ["Python"],
            "requires_auth": "no",
            "attack_types": ["command injection"],
            "target_software": ["Example"],
            "summary": "Observed documented request behavior.",
            "classification_reason": {
                "text": "The source sends the documented request.",
                "citations": [{"path": "poc.py", "line_start": 1, "line_end": 2}],
            },
            "behavior": [
                {
                    "text": "Sends one request.",
                    "citations": [{"path": "poc.py", "line_start": 2, "line_end": 2}],
                }
            ],
            "prerequisites": [],
            "limitations": ["Only supplied files were reviewed."],
        },
        "backdoor_review": {
            "verdict": "undetermined",
            "summary": "Review remained uncertain.",
            "findings": [
                {
                    "category": "obfuscation",
                    "text": "Unreadable payload.",
                    "citations": [{"path": "poc.py", "line_start": 3, "line_end": 3}],
                }
            ],
            "observables": [
                {"type": "domain", "value": "example.test", "context": "hard-coded target"}
            ],
            "confidence_rationale": "Visible content was incomplete.",
            "limitations": ["Binary omitted."],
        },
    }
    poc = {
        "public_id": 123,
        "artifact_id": "artifact-1",
        "title": "owner/[bold]repo[/bold]\x1b[31m",
        "native_id": "github:1",
        "source": "repository-inventory",
        "catalog_kind": "repository-poc",
        "url": "https://example.test/repo",
        "published_at": "2026-01-01T00:00:00Z",
        "language": "Python",
        "stars": 5,
        "file_count": 2,
        "byte_count": 20,
        "contributors": [{"display_name": "owner", "role": "owner"}],
        "vulnerability_ids": ["CVE-2026-1000"],
        "vulnerability_ids_truncated": False,
        "analysis": analysis,
    }
    lab = {
        "public_id": 456,
        "owner": {
            "title": "owner/lab",
            "source": "repository-inventory",
            "provider_host": "github.com",
            "url": "https://example.test/lab",
            "published_at": "2026-01-01T00:00:00Z",
        },
        "cve_ids": ["CVE-2026-1000"],
        "shape": "compose_with_builds",
        "anchor_kind": "compose_project",
        "service_count": 2,
        "compose_manifest_count": 1,
        "dockerfile_count": 1,
        "analysis_status": "available",
        "analysis_model": "model:cloud",
        "screenshot": {"media_type": "image/png"},
        "evidence_omissions_present": False,
        "analysis": {
            "environment_summary": {
                "description": "One containerized target service.",
                "evidence": [{"path": "Dockerfile", "line_start": 1, "line_end": 2}],
            },
            "lab_assessment": {
                "classification": "vulnerability_lab",
                "description": "The supplied files describe a research lab.",
                "evidence": [{"path": "README.md", "line_start": 1, "line_end": 1}],
            },
            "prerequisites": [
                {
                    "description": "Container tooling is described upstream.",
                    "evidence": [{"path": "README.md", "line_start": 1, "line_end": 1}],
                }
            ],
            "components": [
                {
                    "name": "web",
                    "description": "Target service",
                    "evidence": [{"path": "Dockerfile", "line_start": 1, "line_end": 2}],
                }
            ],
            "exercise_path": [
                {
                    "step": 1,
                    "description": "Read the supplied instructions.",
                    "evidence": [{"path": "README.md", "line_start": 1, "line_end": 1}],
                }
            ],
            "cve_assessments": [
                {
                    "cve_id": "CVE-2026-1000",
                    "verdict": "supported",
                    "description": "The CVE is named in the supplied lab.",
                    "evidence": [{"path": "README.md", "line_start": 1, "line_end": 1}],
                }
            ],
            "safety_verdict": "undetermined",
            "safety_reason": {
                "description": "The stored review did not execute the lab.",
                "evidence": [{"path": "Dockerfile", "line_start": 1, "line_end": 2}],
            },
            "suspicious_indicators": [
                {
                    "category": "network",
                    "description": "One external host is referenced.",
                    "evidence": [{"path": "Dockerfile", "line_start": 2, "line_end": 2}],
                }
            ],
            "limitations": ["Not executed."],
        },
    }
    vuln = {
        "identifier": "CVE-2026-1000",
        "identifiers": ["CVE-2026-1000", "GHSA-2345-6789-CFGH"],
        "title": {
            "value": "Example command injection",
            "provenance": {"source": "cvelistV5", "provider": "example"},
        },
        "description": {"value": "A source-backed vulnerability description."},
        "published": {"value": "2026-01-01T00:00:00Z"},
        "tracked_since": {"value": "2026-01-02T00:00:00Z"},
        "cvss": {"score": 9.8, "severity": "CRITICAL", "version": "3.1"},
        "epss": {"score": 0.8, "percentile": 0.9},
        "cwe_ids": ["CWE-78"],
        "withdrawn": False,
        "rejected": False,
        "exploitation": {
            "cisa_kev": {"listed": True, "added_at": "2026-01-03T00:00:00Z"},
            "vulncheck_kev": {"listed": False},
            "reported_exploitation": {"observed": True},
            "known_ransomware": {"observed": False},
            "catalogued_exploit_count": 1,
            "curated_repository_poc_count": 1,
            "repository_candidate_count": 0,
            "nuclei_template_count": 1,
            "ssvc": {
                "exploitation": "active",
                "automatable": "yes",
                "technical_impact": "total",
            },
        },
        "affected": collection(
            [
                {
                    "source": "cvelistV5",
                    "provider": "example",
                    "data": {
                        "vendor": "Example",
                        "product": "Server",
                        "versions": {
                            "versions": [
                                {"version": "1.0", "lessThan": "2.0", "status": "affected"}
                            ]
                        },
                    },
                }
            ]
        ),
        "pocs": collection([poc]),
        "artifacts": collection(
            [{**poc, "kind": "repository", "published_at": "2026-01-01T00:00:00Z"}]
        ),
        "related_artifacts": collection([]),
        "nuclei_templates": collection(
            [
                {
                    "template_id": "CVE-2026-1000",
                    "name": "Example check",
                    "severity": "critical",
                    "authors": ["author"],
                    "tags": ["cve"],
                    "description": "Template description.",
                    "reconnaissance": [{"service": "Shodan", "query": "product:example"}],
                }
            ]
        ),
        "docker_labs": collection([lab]),
        "references": collection(
            [
                {
                    "source": "cvelistV5",
                    "provider": "example",
                    "data": {"url": "https://example.test/advisory", "tags": ["advisory"]},
                }
            ]
        ),
        "writeups": collection([]),
        "research_resources": collection(
            [
                {
                    "title": "Technical research",
                    "url": "https://example.test/research",
                    "summary": "Research summary.",
                }
            ]
        ),
        "weaknesses": collection(
            [{"source": "cvelistV5", "provider": "example", "data": {"cwe_id": "CWE-78"}}]
        ),
        "lifecycle": collection(
            [
                {
                    "source": "nvd",
                    "provider": "NVD",
                    "data": {
                        "state": "published",
                        "published_at": "2026-01-01T00:00:00Z",
                        "modified_at": "2026-01-02T00:00:00Z",
                        "reasons": [],
                    },
                }
            ]
        ),
    }
    return {"analysis": analysis, "poc": poc, "lab": lab, "vuln": vuln}


@pytest.fixture
def fake_client_class(api_data):
    data = api_data

    class FakeClient:
        instances: list[FakeClient] = []

        def __init__(self, _settings) -> None:
            self.calls: list[tuple[str, object]] = []
            self.closed = False
            self.__class__.instances.append(self)

        def close(self) -> None:
            self.closed = True

        def readiness(self):
            return {
                "status": "ready",
                "read_model_version": "view-v1",
                "api_policy_revision": "policy-v1",
                "built_at": "2026-01-01T00:00:00Z",
                "source_checkpoint_sha256": "sha256:source",
                "database_read_only": True,
                "code_search_status": "ready",
                "code_search_checkpoint_sha256": "sha256:code",
                "code_search_artifact_count": 10,
                "code_search_file_count": 20,
            }

        def statistics(self):
            return {
                "vulnerabilities": 100,
                "with_artifacts": 80,
                "with_pocs": 50,
                "cisa_kev": 10,
                "ransomware": 2,
                "with_nuclei": 20,
            }

        def statistics_trends(self):
            series = [{"key": "all", "label": "All", "points": [{"period": "2026 Q1", "count": 1}]}]
            return {
                "as_of": "2026-01-01T00:00:00Z",
                "cve_published": series[0],
                "cve_weaknesses": series,
                "catalog_additions": series,
                "poc_supply": series,
            }

        def search_vulnerabilities(self, params):
            self.calls.append(("vulnerabilities", list(params)))
            return {
                "items": [
                    {
                        "identifier": "CVE-2026-1000",
                        "title": "Example command injection",
                        "published_at": "2026-01-01T00:00:00Z",
                        "cvss_score": 9.8,
                        "epss_score": 0.8,
                        "poc_count": 1,
                        "cisa_kev": True,
                        "known_ransomware": False,
                        "nuclei_count": 1,
                    }
                ],
                "next_cursor": "opaque-cursor",
            }

        def vulnerability(self, identifier):
            self.calls.append(("vulnerability", identifier))
            return data["vuln"]

        def search_pocs(self, params):
            self.calls.append(("pocs", list(params)))
            return {"items": [data["poc"]], "next_cursor": "opaque-cursor"}

        def poc(self, identity):
            self.calls.append(("poc", identity))
            return {
                **data["poc"],
                "vulnerabilities": collection(
                    [
                        {
                            "identifier": "CVE-2026-1000",
                            "association_providers": ["source"],
                            "associations": [{"provider": "source", "pointer": "pointer"}],
                        }
                    ]
                ),
                "docker_labs": collection([data["lab"]]),
            }

        def poc_files(self, identity):
            return {
                "artifact_id": identity,
                "items": [
                    {
                        "path": "poc.py",
                        "size": 20,
                        "viewable": True,
                        "sha256": "sha256:file",
                    }
                ],
            }

        def poc_file(self, identity, path):
            return {
                "artifact_id": identity,
                "path": path,
                "sha256": "sha256:file",
                "content": "print('[bold]safe[/bold]')\x1b[31m",
            }

        def download_poc(self, identity, output, *, force=False):
            return {
                "path": str(output or "poc.zip"),
                "size": 20,
                "sha256": "sha256:archive",
                "password": "eip",
            }

        def code_search(self, body):
            self.calls.append(("code", body))
            return {
                "total": 1,
                "items": [
                    {
                        "public_id": 123,
                        "artifact_id": "artifact-1",
                        "title": "Example",
                        "source": "repository-inventory",
                        "path": "poc.py",
                        "match_line": 2,
                        "match_location": "content",
                        "snippet_role": "matched-content",
                        "snippet_character_truncated": False,
                        "snippet_start_line": 1,
                        "snippet_end_line": 3,
                        "snippet": "one\ntwo\nthree",
                        "file_type": "python",
                        "vulnerability_ids": ["CVE-2026-1000"],
                    }
                ],
                "next_cursor": None,
                "scope": (
                    {"kind": "public-poc", "public_id": body["public_id"]}
                    if "public_id" in body
                    else (
                        {
                            "kind": "vulnerability",
                            "vulnerability_id": body["vulnerability_id"],
                        }
                        if "vulnerability_id" in body
                        else None
                    )
                ),
            }

        def search_labs(self, params):
            self.calls.append(("labs", list(params)))
            return {
                "statistics": {
                    "total": 1,
                    "cve_linked": 1,
                    "analyzed": 1,
                    "screenshots": 1,
                    "compose_units": 1,
                },
                "items": [data["lab"]],
                "next_cursor": None,
            }

        def download_screenshot(self, public_id, output, *, force=False):
            return {"path": str(output), "size": 10, "sha256": "sha256:image"}

        def directory(self, name, params=()):
            self.calls.append((name, list(params)))
            rows = {
                "vendors": [{"vendor": "Example", "vulnerability_count": 2, "product_count": 1}],
                "products": [{"vendor": "Example", "product": "Server", "vulnerability_count": 2}],
                "ecosystems": [{"ecosystem": "PyPI", "vulnerability_count": 2, "package_count": 1}],
                "packages": [
                    {"ecosystem": "PyPI", "package_name": "example", "vulnerability_count": 2}
                ],
                "weaknesses": [
                    {
                        "cwe_id": "CWE-78",
                        "record_type": "Weakness",
                        "name": "OS Command Injection",
                        "status": "Stable",
                        "vulnerability_count": 2,
                    }
                ],
                "authors": [
                    {
                        "public_id": 789,
                        "source_scope": "github",
                        "display_name": "owner",
                        "roles": ["owner"],
                        "poc_count": 1,
                        "vulnerability_count": 1,
                    }
                ],
            }
            return {"items": rows[name], "next_cursor": None}

        def weakness(self, cwe_id):
            return {
                "cwe_id": cwe_id,
                "name": "OS Command Injection",
                "record_type": "Weakness",
                "status": "Stable",
                "abstraction": "Base",
                "vulnerability_count": 2,
                "description": "Improper neutralization of OS commands.",
                "provenance": {"source": "MITRE CWE"},
            }

        def author(self, public_id):
            return {
                "public_id": public_id,
                "display_name": "owner",
                "source_scope": "github",
                "external_id": "1",
                "roles": ["owner"],
                "poc_count": 1,
                "vulnerability_count": 1,
                "profile_url": "https://example.test/owner",
            }

        def artifact(self, identity):
            return {
                **data["poc"],
                "artifact_id": identity,
                "kind": "repository",
                "provider_host": "github.com",
                "description": "Repository metadata.",
                "vulnerabilities": collection([{"identifier": "CVE-2026-1000"}]),
            }

        def stix_vulnerability(self, identifier, *, mapping):
            return {"type": "bundle", "id": f"bundle--{identifier}-{mapping}", "objects": []}

        def stix_exploit(self, public_id):
            return {"type": "bundle", "id": f"bundle--{public_id}", "objects": []}

    return FakeClient
