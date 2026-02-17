# eip-search

A modern **searchsploit replacement** powered by the [Exploit Intelligence Platform](https://exploit-intel.com).

Search 335K+ vulnerabilities and 164K+ exploits from 6 sources with risk intelligence, exploit quality ranking, Nuclei scanner integration, and trojan warnings — all from your terminal.

## Why eip-search?

**searchsploit** is grep over a CSV. It can tell you an exploit exists, but nothing about how dangerous the vulnerability is, how reliable the exploit is, or whether it's secretly a trojan.

**eip-search** combines data from NVD, CISA KEV, EPSS, ExploitDB, Metasploit, GitHub, nomi-sec, trickest, and GHSA into a single tool that answers questions searchsploit never could:

- "What critical Fortinet vulns are being actively exploited right now?"
- "Which of these 487 BlueKeep exploits is actually reliable — and which one is a trojan?"
- "Give me the Shodan dork to find exposed TeamCity instances for CVE-2024-27198"

## Installation

### Requirements

- **Python 3.10 or newer** (check with `python3 --version` or `python --version`)
- **pip** (comes with Python on most systems)

### Kali Linux / Debian / Ubuntu

```bash
# Python 3 is pre-installed on Kali. Install pip if needed:
sudo apt update && sudo apt install -y python3-pip python3-venv

# Option 1: Install into a virtual environment (recommended)
python3 -m venv ~/.venvs/eip
source ~/.venvs/eip/bin/activate
pip install eip-search

# Option 2: Install with pipx (isolated, no venv management)
sudo apt install -y pipx
pipx install eip-search

# The 'eip-search' command is now available
eip-search --version
```

> **Kali users**: If you see `error: externally-managed-environment`, use one of the virtual environment methods above. Kali 2024+ enforces PEP 668 which blocks global pip installs.

### macOS

```bash
# Install Python 3 via Homebrew (if not already installed)
brew install python3

# Option 1: Virtual environment
python3 -m venv ~/.venvs/eip
source ~/.venvs/eip/bin/activate
pip install eip-search

# Option 2: pipx
brew install pipx
pipx install eip-search

# The 'eip-search' command is now available
eip-search --version
```

### Windows

```powershell
# Install Python 3 from https://python.org (check "Add to PATH" during install)

# Option 1: Virtual environment
python -m venv %USERPROFILE%\.venvs\eip
%USERPROFILE%\.venvs\eip\Scripts\activate
pip install eip-search

# Option 2: pipx
pip install pipx
pipx install eip-search

# The 'eip-search' command is now available
eip-search --version
```

> **Windows Terminal** or **PowerShell** is recommended for full color and Unicode support. The classic `cmd.exe` may not render tables correctly.

### Arch Linux / Manjaro

```bash
sudo pacman -S python python-pip python-pipx
pipx install eip-search
```

### From Source (all platforms)

```bash
git clone https://github.com/exploit-intel/eip-search.git
cd eip-search
python3 -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows
pip install -e .
```

### Shell Completion (optional)

Enable tab completion for your shell:

```bash
# Bash
eip-search --install-completion bash

# Zsh
eip-search --install-completion zsh

# Fish
eip-search --install-completion fish

# PowerShell
eip-search --install-completion powershell
```

### Verify Installation

```bash
eip-search --version
# eip-search 0.1.0

eip-search stats
# Should display platform statistics if your network can reach exploit-intel.com
```

### Troubleshooting

| Problem | Solution |
|---|---|
| `command not found: eip-search` | Make sure your virtual environment is activated, or use `pipx` which manages PATH automatically |
| `externally-managed-environment` | Use a virtual environment or `pipx` — see instructions above |
| `SSL certificate error` | Your Python may lack certificates. On macOS: `brew reinstall python3`. On Linux: `sudo apt install ca-certificates` |
| `Connection refused` / timeouts | Check that you can reach `https://exploit-intel.com` — the tool requires internet access |
| Tables look broken | Use a terminal with Unicode support (Windows Terminal, iTerm2, any modern Linux terminal) |

## Quick Start

The simplest usage mirrors searchsploit — just type what you're looking for:

```
$ eip-search "palo alto"
```
```
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━┳━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃CVE              ┃    Sev     ┃  CVSS ┃   EPSS ┃  Exp ┃     ┃ Title                        ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━╇━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│CVE-2025-0108    │  CRITICAL  │   9.1 │  94.0% │   16 │ KEV │ Palo Alto Networks PAN-OS …  │
│CVE-2025-0107    │  CRITICAL  │   9.8 │  77.0% │    1 │     │ Palo Alto Networks Expedi…   │
│CVE-2025-0111    │   MEDIUM   │   6.5 │   2.0% │    2 │ KEV │ Palo Alto Networks PAN-OS …  │
│ ...             │            │       │        │      │     │                              │
└─────────────────┴────────────┴───────┴────────┴──────┴─────┴──────────────────────────────┘
Page 1/9 (41 total results)
```

Every result includes CVSS score, EPSS exploitation probability, exploit count, and CISA KEV status — context searchsploit simply doesn't have.

## CVE Intelligence Briefs

Type a CVE ID and get a full intelligence brief — no subcommand needed:

```
$ eip-search CVE-2024-3400
```
```
╭──────────────────────────────╮
│ CVE-2024-3400  CRITICAL  KEV │
╰──────────────────────────────╯
  Palo Alto Networks PAN-OS Unauthenticated Remote Code Execution
  CVSS: 10.0  (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
  EPSS: 94.3%  (99.9th percentile)
  Attack Vector: NETWORK | CWE: CWE-77, CWE-20 | Published: 2024-04-12 | KEV added: 2024-04-12

  A command injection as a result of arbitrary file creation vulnerability in
  the GlobalProtect feature of Palo Alto Networks PAN-OS software ...

  Affected Products
    - paloaltonetworks/pan-os
    ... and 40 more

  Exploits (43)

    MODULES
             metasploit  ruby      panos_telemetry_cmd_exec.rb
             Rank: excellent  LLM: working_poc  has code

    PROOF OF CONCEPT
             exploitdb   text      EDB-51996
             LLM: working_poc  has code
      ★ 161   github      http      h4x0r-dz/CVE-2024-3400
             LLM: working_poc  has code
      ★ 90    github      python    W01fh4cker/CVE-2024-3400-RCE-Scan
             LLM: working_poc  has code
      ★ 72    github      python    0x0d3ad/CVE-2024-3400
             LLM: working_poc  has code
      ...
    ... and 32 more PoCs (use --all to show)

  Also Known As
    - EDB: EDB-51996
    - GHSA: GHSA-v475-xhc9-wfxg

  References
    - [Vendor Advisory] https://security.paloaltonetworks.com/CVE-2024-3400
    - [Exploit, Vendor Advisory] https://unit42.paloaltonetworks.com/cve-2024-3400/
    ...
```

Exploits are **grouped by quality** (Metasploit modules first, then verified ExploitDB, then GitHub PoCs ranked by stars) and **ranked by a composite score**. Low-quality trickest entries (often 60-80% of results) are hidden by default.

## Trojan Detection

BlueKeep (CVE-2019-0708) has 487 exploits. One of them is a trojan. eip-search warns you:

```
$ eip-search info CVE-2019-0708
```
```
╭──────────────────────────────╮
│ CVE-2019-0708  CRITICAL  KEV │
╰──────────────────────────────╯
  CVE-2019-0708 BlueKeep RDP Remote Windows Kernel Use After Free
  CVSS: 9.8  EPSS: 94.5%  (100.0th percentile)

  Exploits (487)

    MODULES
             metasploit  ruby      cve_2019_0708_bluekeep_rce.rb
             Rank: manual  LLM: working_poc  has code
             metasploit  ruby      cve_2019_0708_bluekeep.rb
             LLM: working_poc  has code

    VERIFIED
             exploitdb   ruby      EDB-47416
             LLM: working_poc  ✓ verified  has code

    PROOF OF CONCEPT
      ★ 1187  nomisec               Ekultek/BlueKeep
      ★ 914   nomisec               robertdavidgraham/rdpscan
      ★ 497   nomisec               n1xbyte/CVE-2019-0708
      ...
    ... and 113 more PoCs (use --all to show)

    SUSPICIOUS
      ★ 2     nomisec               ttsite/CVE-2019-0708-
             ⚠ TROJAN — flagged by AI analysis

    + 360 more from trickest (use --all to show)
```

The Metasploit modules and verified ExploitDB entry surface to the top. The trojan sinks to the bottom with a clear warning. The 360 trickest noise entries are hidden unless you ask for them with `--all`.

## Risk-Based Triage

"What critical Fortinet vulnerabilities with public exploits should I worry about right now?"

```
$ eip-search triage --vendor fortinet --severity critical
```
```
TRIAGE — vulnerabilities with exploits, sorted by exploitation risk
Filters: vendor=fortinet, severity=critical, EPSS>=0.5

┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━┳━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃CVE              ┃    Sev     ┃  CVSS ┃   EPSS ┃  Exp ┃     ┃ Title                        ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━╇━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│CVE-2018-13379   │  CRITICAL  │   9.1 │  94.5% │   58 │ KEV │ Fortinet FortiProxy Path …   │
│CVE-2022-40684   │  CRITICAL  │   9.8 │  94.4% │   64 │ KEV │ Fortinet FortiProxy Auth …   │
│CVE-2023-48788   │  CRITICAL  │   9.8 │  94.2% │    9 │ KEV │ Fortinet FortiClient SQL …   │
│CVE-2024-55591   │  CRITICAL  │   9.8 │  94.2% │   17 │ KEV │ Fortinet FortiProxy Auth …   │
│CVE-2022-42475   │  CRITICAL  │   9.8 │  94.0% │   24 │ KEV │ Fortinet FortiOS Buffer …    │
└─────────────────┴────────────┴───────┴────────┴──────┴─────┴──────────────────────────────┘
Page 1/4 (19 total results)
```

Triage defaults to showing vulnerabilities with public exploits and EPSS >= 0.5, sorted by exploitation probability. Every result here is confirmed actively exploited (KEV), has dozens of public exploits, and has a >94% chance of being exploited in the wild.

## Nuclei Templates & Recon Dorks

Get scanner templates with ready-to-paste Shodan, FOFA, and Google dorks:

```
$ eip-search nuclei CVE-2024-27198
```
```
╭──────────────────────────────────╮
│ CVE-2024-27198  Nuclei Templates │
╰──────────────────────────────────╯
  TeamCity < 2023.11.4 - Authentication Bypass

  Nuclei Templates (1)

    CVE-2024-27198  ✓ verified  critical
    TeamCity < 2023.11.4 - Authentication Bypass
    Author: DhiyaneshDk
    Tags: cve, cve2024, teamcity, jetbrains, auth-bypass, kev, vkev, vuln

    Recon Queries:
      Shodan:  http.component:"TeamCity" || http.title:teamcity || http.component:"teamcity"
      FOFA:    title=teamcity
      Google:  intitle:teamcity

    Run:  nuclei -t CVE-2024-27198 -u https://target.com
```

## View Exploit Source Code

Read exploit code directly in your terminal with syntax highlighting:

```
$ eip-search view 77423
```
```
  fullhunt-log4j-scan-07f7e32/log4j-scan.py

      1 #!/usr/bin/env python3
      2 # coding=utf-8
      3 # ******************************************************************
      4 # log4j-scan: A generic scanner for Apache log4j RCE CVE-2021-44228
      5 # Author:
      6 # Mazin Ahmed <Mazin at FullHunt.io>
      7 # Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
      8 # Secure your Attack Surface with FullHunt.io.
      9 # ******************************************************************
     10
     11 import argparse
     12 import random
     13 import requests
     ...
```

When an exploit has multiple files, eip-search auto-selects the most relevant code file. Use `--file` to pick a specific one.

## Download Exploit Code

Download and optionally extract exploit archives:

```
$ eip-search download 77423 --extract
```
```
Downloaded: nomisec-fullhunt_log4j-scan.zip
ZIP password: eip (exploit archives are password-protected to prevent AV quarantine)
Extracted:  nomisec-fullhunt_log4j-scan/
Files (10):
  - fullhunt-log4j-scan-07f7e32/.gitignore
  - fullhunt-log4j-scan-07f7e32/Dockerfile
  - fullhunt-log4j-scan-07f7e32/FAQ.md
  - fullhunt-log4j-scan-07f7e32/LICENSE.txt
  - fullhunt-log4j-scan-07f7e32/README.md
  - fullhunt-log4j-scan-07f7e32/headers-large.txt
  - fullhunt-log4j-scan-07f7e32/headers-minimal.txt
  - fullhunt-log4j-scan-07f7e32/headers.txt
  - fullhunt-log4j-scan-07f7e32/log4j-scan.py
  - fullhunt-log4j-scan-07f7e32/requirements.txt
```

> **Note:** Downloaded ZIPs are encrypted with password **`eip`** as a safety measure to prevent antivirus software from quarantining exploit code. Use `--extract` / `-x` to automatically unzip.

## Advanced Search

The `search` subcommand exposes the full filter set:

```bash
# All SQL injection vulns with public exploits, sorted by CVSS
eip-search search --cwe 89 --has-exploits --sort cvss_desc

# Critical KEV entries with high exploitation probability
eip-search search --kev --severity critical --min-epss 0.9

# Recent npm vulnerabilities with exploits
eip-search search --ecosystem npm --has-exploits --sort newest

# Microsoft Exchange critical vulns
eip-search search --product exchange --severity critical --has-exploits
```

```
$ eip-search search --cwe 89 --has-exploits --sort cvss_desc -n 5
```
```
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━┳━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃CVE              ┃    Sev     ┃  CVSS ┃   EPSS ┃  Exp ┃     ┃ Title                        ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━╇━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│CVE-2024-3605    │  CRITICAL  │  10.0 │  64.9% │    1 │     │ Thimpress WP Hotel Booking…  │
│CVE-2024-3922    │  CRITICAL  │  10.0 │  88.5% │    3 │     │ Dokan Pro Plugin SQL Inje…   │
│CVE-2024-39911   │  CRITICAL  │  10.0 │  68.3% │    1 │     │ Fit2cloud 1panel SQL Inje…   │
│CVE-2025-52694   │  CRITICAL  │  10.0 │   9.7% │    1 │     │ Advantech IoT Edge SQL In…   │
│CVE-2024-43918   │  CRITICAL  │  10.0 │  48.9% │    1 │     │ Woobewoo Product Table SQ…   │
└─────────────────┴────────────┴───────┴────────┴──────┴─────┴──────────────────────────────┘
Page 1/1515 (7,574 total results)
```

## JSON Output for Scripting

Every command supports `--json` for piping into `jq`, scripts, or SIEMs:

```
$ eip-search search "log4j" --has-exploits --sort epss_desc -n 5 --json
```
```json
{
  "total": 15,
  "page": 1,
  "per_page": 5,
  "total_pages": 3,
  "items": [
    {
      "cve_id": "CVE-2021-44228",
      "title": "Log4Shell HTTP Header Injection",
      "severity_label": "critical",
      "cvss_v3_score": 10.0,
      "epss_score": 0.94358,
      "is_kev": true,
      "exploit_count": 401
    },
    ...
  ]
}
```

```bash
# Get all critical KEV CVE IDs as a flat list
eip-search search --kev --severity critical -n 100 --json | jq -r '.items[].cve_id'

# Feed into nuclei
eip-search search --has-nuclei --severity critical --json | jq -r '.items[].cve_id' | xargs -I{} nuclei -t {} -u https://target.com
```

## Platform Statistics

```
$ eip-search stats
```
```
╭───────────────────────────────╮
│ Exploit Intelligence Platform │
╰───────────────────────────────╯

  ┌──────────────────────────────┬─────────────────────┐
  │ Total Vulnerabilities        │             335,611 │
  │ Published                    │             191,235 │
  │ With CVSS Scores             │             238,491 │
  │ With EPSS Scores             │             315,597 │
  │ Critical Severity            │              29,129 │
  │ CISA KEV Entries             │               1,518 │
  │                              │                     │
  │ Vulns with Exploits          │              83,413 │
  │ Total Exploits               │             164,238 │
  │ With Nuclei Templates        │                 402 │
  │                              │                     │
  │ Vendors Tracked              │              37,500 │
  │ Exploit Authors              │              23,076 │
  │                              │                     │
  │ Last Updated                 │ 2026-02-17 12:06:03 │
  └──────────────────────────────┴─────────────────────┘
```

## All Commands

| Command | Description |
|---|---|
| `eip-search "query"` | Quick search (auto-routes CVE IDs to detail view) |
| `eip-search search "query" [filters]` | Search with full filter support |
| `eip-search info CVE-ID` | Full intelligence brief for a vulnerability |
| `eip-search triage [filters]` | Risk-sorted view of what to worry about |
| `eip-search nuclei CVE-ID` | Nuclei templates + Shodan/FOFA/Google dorks |
| `eip-search view EXPLOIT-ID` | Syntax-highlighted exploit source code |
| `eip-search download EXPLOIT-ID` | Download exploit code as ZIP |
| `eip-search stats` | Platform-wide statistics |

## Search Filters

| Filter | Short | Description |
|---|---|---|
| `--severity` | `-s` | critical, high, medium, low |
| `--has-exploits` | `-e` | Only CVEs with public exploit code |
| `--kev` | `-k` | Only CISA Known Exploited Vulnerabilities |
| `--has-nuclei` | | Only CVEs with Nuclei scanner templates |
| `--vendor` | `-v` | Filter by vendor name |
| `--product` | `-p` | Filter by product name |
| `--ecosystem` | | npm, pip, maven, go, crates |
| `--cwe` | | CWE ID (e.g. `79` or `CWE-79`) |
| `--year` | `-y` | CVE publication year |
| `--min-cvss` | | Minimum CVSS score (0-10) |
| `--min-epss` | | Minimum EPSS score (0-1) |
| `--date-from` | | Start date (YYYY-MM-DD) |
| `--date-to` | | End date (YYYY-MM-DD) |
| `--sort` | | newest, oldest, cvss_desc, epss_desc, relevance |
| `--json` | `-j` | JSON output for scripting |

## How Exploit Ranking Works

When a CVE has dozens or hundreds of exploits, eip-search ranks them by quality so the best ones surface first:

| Source | Base Score | Why |
|---|---|---|
| Metasploit (`excellent`) | 1000 | Peer-reviewed, maintained by Rapid7 |
| Metasploit (other ranks) | 500-900 | Still curated and tested |
| ExploitDB (verified) | 550 | Human-verified by Offsec |
| ExploitDB (unverified) | 300 | Published but not verified |
| nomi-sec / GitHub | log10(stars) * 100 + bonus | Community signal via GitHub stars |
| trickest | 10 | Bulk-scraped, often links to unrelated repos |

On top of the base score, LLM classification modifiers apply: `working_poc` gets +100, `scanner` gets +50, while `trojan` gets -9999 (always last, with a warning).

Trickest entries are hidden by default because they account for 60-80% of exploit counts but carry zero quality signals. Use `--all` to see everything.

## Configuration

Optional config at `~/.eip-search.toml`:

```toml
[api]
base_url = "https://exploit-intel.com"
api_key = "your-key-here"   # optional, for higher rate limits

[display]
per_page = 20               # default results per page
```

No API key is required. The public API allows 60 requests/minute.

## Security

- **ZIP Slip protection**: All ZIP extraction paths are validated against directory traversal attacks
- **Filename sanitization**: Download filenames are stripped of path components and special characters
- **Download size cap**: 50 MB hard limit prevents memory exhaustion from malicious responses
- **Markup injection prevention**: All API data is escaped before terminal rendering
- **TLS verification**: All connections use standard certificate verification

## License

MIT
