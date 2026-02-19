"""Exploit PoC generation using local Ollama with optional vision pipeline."""

from __future__ import annotations

import base64
import re
import textwrap
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from eip_search.models import ExploitFile, VulnDetail

VISION_PROMPT = """\
You are analyzing a screenshot from a vulnerability writeup. Your job is to
extract ONLY the technical details needed to reproduce the exploit.

Focus on and extract (if visible):
- Full HTTP requests: method, path, headers, POST body, query parameters
- Injection payloads and the exact parameter they go into
- Vulnerable endpoints (URLs, CGI paths, API routes)
- Commands executed and their output (especially shells, reverse connections)
- Response content that confirms successful exploitation
- Credentials, tokens, session IDs used in the attack
- Error messages that reveal code paths or versions

Ignore and skip:
- UI layout, window decorations, toolbar descriptions
- Color schemes, fonts, styling
- General descriptions of what Burp Suite or terminals look like
- Speculation about what might be happening

Output a concise technical extraction. Use exact values from the image.
If you cannot read a value clearly, say so rather than guessing.
If the image shows nothing useful for exploit reproduction, say "No actionable details."
"""


class OllamaError(Exception):
    """Raised when Ollama is unreachable or returns an error."""


def check_ollama(ollama_url: str) -> list[str]:
    """Verify Ollama is reachable and return list of available model names."""
    try:
        r = httpx.get(f"{ollama_url}/api/tags", timeout=5)
        r.raise_for_status()
        return [m["name"] for m in r.json().get("models", [])]
    except httpx.ConnectError:
        raise OllamaError(
            f"Cannot connect to Ollama at {ollama_url}\n"
            f"Install Ollama from https://ollama.com and start it, then pull a model:\n"
            f"  ollama pull kimi-k2:1t-cloud"
        )
    except Exception as e:
        raise OllamaError(f"Ollama health check failed: {e}")


# ---------------------------------------------------------------------------
# Vision pipeline (stage 1)
# ---------------------------------------------------------------------------

def describe_image(
    image_bytes: bytes,
    ollama_url: str,
    model: str,
) -> tuple[str, float]:
    """Send image bytes to a vision model via Ollama /api/chat.

    Returns (description_text, elapsed_seconds).
    """
    b64 = base64.b64encode(image_bytes).decode()
    start = time.monotonic()
    r = httpx.post(f"{ollama_url}/api/chat", json={
        "model": model,
        "messages": [{"role": "user", "content": VISION_PROMPT, "images": [b64]}],
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 2048},
    }, timeout=300)
    r.raise_for_status()
    elapsed = time.monotonic() - start
    content = r.json().get("message", {}).get("content", "")
    return content, elapsed


def describe_images(
    image_files: list[ExploitFile],
    fetch_fn,
    ollama_url: str,
    model: str,
    max_images: int = 8,
    on_progress=None,
) -> list[dict[str, Any]]:
    """Describe a list of exploit image files via the vision model.

    *fetch_fn(filename)* should return raw bytes for a given image filename.
    *on_progress(filename, description, elapsed)* is called after each image.

    Returns list of {"filename", "description", "elapsed"} dicts.
    """
    descriptions: list[dict[str, Any]] = []

    for img in image_files[:max_images]:
        try:
            raw = fetch_fn(img.name)
        except Exception:
            continue

        try:
            desc, elapsed = describe_image(raw, ollama_url, model)
        except Exception:
            continue

        entry = {
            "filename": img.name,
            "description": desc,
            "elapsed": round(elapsed, 1),
        }
        descriptions.append(entry)

        if on_progress:
            on_progress(img.name, desc, elapsed)

    return descriptions


# ---------------------------------------------------------------------------
# Prompt building
# ---------------------------------------------------------------------------

def build_prompt(
    vuln: VulnDetail,
    writeup_text: str | None = None,
    image_descriptions: list[dict[str, Any]] | None = None,
) -> str:
    """Build the PoC generation prompt from vuln detail + optional context."""
    cve = vuln.cve_id or vuln.eip_id
    title = vuln.title or "Unknown"
    desc = vuln.description or "No description."
    cvss = vuln.cvss_v3_score
    cvss_vec = vuln.cvss_v3_vector or ""
    cwes = ", ".join(vuln.cwe_ids)
    attack_vec = vuln.attack_vector or "UNKNOWN"

    analysis: dict | None = None
    for e in vuln.exploits:
        if e.llm_analysis:
            analysis = e.llm_analysis
            break

    attack_type = analysis.get("attack_type", "unknown") if analysis else "unknown"
    complexity = analysis.get("complexity", "unknown") if analysis else "unknown"
    reliability = analysis.get("reliability", "unknown") if analysis else "unknown"
    target_sw = analysis.get("target_software", "") if analysis else ""
    summary = analysis.get("summary", "") if analysis else ""
    mitre = analysis.get("mitre_techniques", []) if analysis else []

    products_str = ""
    for p in vuln.affected_products[:5]:
        products_str += f"  - {p.vendor or '?'}/{p.product or '?'}\n"

    refs_str = "\n".join(f"  - {r.url}" for r in vuln.references[:8])

    prompt = f"""You are a security researcher writing a proof-of-concept exploit script.
Write a Python 3 exploit for the following vulnerability. The script should be
practical, well-documented, and include safety warnings.

=== VULNERABILITY ===
CVE: {cve}
Title: {title}
CVSS: {cvss} ({attack_vec}) {cvss_vec}
CWE: {cwes}
Attack Type: {attack_type}
Complexity: {complexity}
Reliability: {reliability}
Target Software: {target_sw}

Description:
{textwrap.fill(desc, width=80)}

Affected Products:
{products_str}
MITRE ATT&CK: {', '.join(str(t) for t in mitre)}

=== AI ANALYSIS ===
{textwrap.fill(summary, width=80)}

=== REFERENCES ===
{refs_str}
"""

    if writeup_text:
        truncated = writeup_text[:4000]
        if len(writeup_text) > 4000:
            truncated += "\n... [truncated]"
        prompt += f"""
=== WRITEUP / VULNERABILITY DETAILS ===
{truncated}
"""

    if image_descriptions:
        useful = [img for img in image_descriptions if "no actionable" not in img["description"].lower()]
        if useful:
            prompt += """
=== ADDITIONAL CONTEXT FROM SCREENSHOTS ===
The original writeup included screenshots. Below is a technical extraction of
what each screenshot shows. Use any relevant details (endpoints, parameters,
payloads, HTTP requests, commands) to make the exploit more accurate.
"""
            for i, img in enumerate(useful, 1):
                prompt += f"\nScreenshot {i}:\n{img['description']}\n"

    prompt += """
=== TASK ===
Write a simple, focused Python 3 proof-of-concept that demonstrates the
vulnerability. The goal is PROOF — not weaponization.

Requirements:
1. Takes target URL/IP as a command-line argument (argparse)
2. Proves the vulnerability exists with the LEAST harmful action possible:
   - RCE/command injection: inject `id` and show the uid output. Do NOT
     start services, open ports, spawn shells, or run telnetd.
   - SQLi: extract database version string or a single row
   - Auth bypass: show that a protected resource is accessible
   - File read/upload: read /etc/passwd or write a harmless marker file
   - Info leak: display the leaked data
3. Prints clear [*] status and [+] success / [-] failure messages
4. Includes a short disclaimer banner (no ASCII art)
5. Uses only standard library + requests
6. Has proper error handling and timeouts

Do NOT include:
- Backdoors, reverse shells, bind shells, telnetd, netcat listeners
- Credential dumping, lateral movement, persistence
- Multiple exploitation modes — just one clean proof

Use the exact HTTP requests, endpoints, parameters, and payloads from the
writeup or screenshots, but replace any destructive command with `id`.

Output ONLY the Python script, no explanations before or after.
"""
    return prompt


# ---------------------------------------------------------------------------
# Code generation (stage 2)
# ---------------------------------------------------------------------------

def generate_code(prompt: str, ollama_url: str, model: str) -> tuple[str, float]:
    """Send prompt to Ollama /api/generate. Returns (raw_code, elapsed_seconds)."""
    start = time.monotonic()
    r = httpx.post(f"{ollama_url}/api/generate", json={
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.3, "num_predict": 4096},
    }, timeout=600)
    r.raise_for_status()
    elapsed = time.monotonic() - start
    return r.json().get("response", ""), elapsed


def extract_python(raw: str) -> str:
    """Strip markdown fences and non-code preamble from model output."""
    match = re.search(r"```(?:python)?\s*\n(.+?)```", raw, re.DOTALL)
    if match:
        return match.group(1).strip()
    lines = raw.strip().split("\n")
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def wrap_output(raw_code: str, vuln: VulnDetail) -> str:
    """Wrap generated code in standard header with CVE metadata + disclaimer."""
    cve = vuln.cve_id or vuln.eip_id
    title = vuln.title or "Unknown"
    cvss = vuln.cvss_v3_score or "?"
    attack_vec = vuln.attack_vector or "?"
    cwes = ", ".join(vuln.cwe_ids)
    url = f"https://exploit-intel.com/vulns/{cve}"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    code = extract_python(raw_code)

    if code.startswith("#!/"):
        first_line, rest = code.split("\n", 1)
        shebang = first_line + "\n"
        code = rest
    else:
        shebang = "#!/usr/bin/env python3\n"

    header = f'''{shebang}"""
{cve} — {title}

CVSS:       {cvss} ({attack_vec})
CWE:        {cwes}
Source:     {url}
Generated:  {ts} (auto-generated, review before use)

DISCLAIMER: This script is provided for authorized security testing and
educational purposes only. Unauthorized access to computer systems is illegal.
Use responsibly and only against systems you have permission to test.
"""
'''
    # Strip any existing docstring from the generated code
    if code.lstrip().startswith('"""') or code.lstrip().startswith("'''"):
        quote = '"""' if code.lstrip().startswith('"""') else "'''"
        end = code.find(quote, 3)
        if end != -1:
            code = code[end + 3:].lstrip("\n")

    return header + code


# ---------------------------------------------------------------------------
# Feasibility scoring
# ---------------------------------------------------------------------------

def classify_feasibility(vuln: VulnDetail) -> dict[str, Any]:
    """Quick feasibility assessment. Returns score, tier, reasons, attack_type, complexity."""
    analysis: dict | None = None
    has_writeup = False
    has_code = False

    for e in vuln.exploits:
        if e.llm_analysis:
            analysis = e.llm_analysis
        if e.llm_classification == "writeup":
            has_writeup = True
        if e.llm_classification == "working_poc" and e.has_code:
            has_code = True

    attack_type = (analysis.get("attack_type", "") if analysis else "").split("|")[0].strip()
    complexity = analysis.get("complexity", "") if analysis else ""
    summary = (analysis.get("summary", "") if analysis else "").lower()

    score = 0
    reasons: list[str] = []

    if attack_type in {"RCE", "SQLi", "XSS", "auth_bypass", "info_leak", "SSRF"}:
        score += 3
        reasons.append(f"web-based ({attack_type})")
    if complexity == "trivial":
        score += 3
        reasons.append("trivial")
    elif complexity == "simple":
        score += 2
        reasons.append("simple")
    if has_writeup:
        score += 2
        reasons.append("has writeup")
    if any(kw in summary for kw in ["http", "post", "get", "endpoint", "parameter", "inject", "payload"]):
        score += 2
        reasons.append("HTTP details in summary")
    if has_code:
        score -= 2
        reasons.append("already has code")
    if any(c in {"CWE-78", "CWE-77", "CWE-89", "CWE-79", "CWE-22", "CWE-434"} for c in vuln.cwe_ids):
        score += 1
        reasons.append("known CWE pattern")

    tier = "excellent" if score >= 8 else "good" if score >= 5 else "possible" if score >= 3 else "difficult"
    return {"score": score, "tier": tier, "reasons": reasons, "attack_type": attack_type, "complexity": complexity}
