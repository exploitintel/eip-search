# eip-search user guide

This guide covers the supported user workflows for the EIP command-line client.
Run `eip-search COMMAND --help` for the exact options accepted by an installed
version.

## Installation

Python 3.12 or later is required.

Install the application in an isolated environment with
[`pipx`](https://pipx.pypa.io/):

```sh
pipx install eip-search
eip-search --version
```

Upgrade or remove it normally:

```sh
pipx upgrade eip-search
pipx uninstall eip-search
```

### Docker

To use the CLI without installing Python locally, build the image from a source
checkout:

```sh
docker build -t eip-search .
docker run --rm eip-search --version
docker run --rm eip-search CVE-2024-3400
```

The image runs as an unprivileged user and uses `/work` as its working
directory. Mount a writable host directory when saving downloads, screenshots,
or STIX bundles:

```sh
docker run --rm \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" \
  eip-search stix vuln CVE-2024-3400 --output docker-cve.json
```

## First connection

Verify the default public API and its required subsystems:

```sh
eip-search doctor
```

`doctor` distinguishes a valid empty search from an unavailable API or code
index. The CLI is an API client only; it cannot repair or rebuild server-side
data.

## Configuration

The default configuration file is:

```text
~/.config/eip-search/config.toml
```

Set `XDG_CONFIG_HOME` to relocate the containing configuration directory, or
set `EIP_SEARCH_CONFIG` to select an exact file. A complete configuration is:

```toml
[api]
timeout_seconds = 30
max_download_bytes = 104857600
```

Configuration precedence, highest first:

1. CLI options such as `--timeout`
2. Environment variables
3. The configuration file
4. Built-in defaults

Supported environment variables:

| Variable | Purpose |
| --- | --- |
| `EIP_SEARCH_TIMEOUT_SECONDS` | Request timeout from 1 to 900 seconds |
| `EIP_SEARCH_MAX_DOWNLOAD_BYTES` | Maximum protected download size, from 1 MiB to 1 GiB |
| `EIP_SEARCH_CONFIG` | Exact configuration-file path |
| `NO_COLOR` | Disable terminal color and styling when present |

The timeout is a shared budget across retries and streamed response chunks,
rather than a fresh allowance for each retry. It is checked between network
operations, so a blocked low-level call can be reported immediately after that
call returns. For predictable public-API behavior, the client does not read
proxy, `netrc`, or certificate settings implicitly from the process
environment.

## Vulnerabilities

The root shortcut opens an exact CVE or GHSA identifier and otherwise performs
a vulnerability search:

```sh
eip-search apache
eip-search CVE-2024-3400
eip-search GHSA-V475-XHC9-WFXG
```

Use `vuln search` for filters and sorting:

```sh
eip-search vuln search apache --severity CRITICAL --severity HIGH
eip-search vuln search --vendor Microsoft --product Windows
eip-search vuln search --ecosystem PyPI --package Django
eip-search vuln search --cisa-kev --sort epss --limit 20
```

Package names require an exact ecosystem. Vendor, product, ecosystem, package,
and CWE values remain source-native. `--with-artifacts` means the API's
`artifact_count > 0`; it is not presented as a “has PoC” predicate.

Vulnerability detail includes exploitation context, affected ranges, PoCs,
Nuclei, labs, references, and accepted research resources when present:

```sh
eip-search vuln show CVE-2024-3400
eip-search vuln show CVE-2024-3400 --all --section-limit 20
eip-search vuln show CVE-2024-3400 --section exploitation --section pocs
eip-search vuln nuclei CVE-2024-3400
```

Accepted `--section` values are:

```text
exploitation  affected  pocs  artifacts  related-artifacts  nuclei  labs
references    writeups  research  weaknesses  lifecycle
```

## Exploits and PoCs

Exploit search includes CVE-unlinked artifacts:

```sh
eip-search exploit search CVE-2024-3400
eip-search exploit search --association unlinked
eip-search exploit search --source exploitdb --catalog-kind exploitdb-exploit
eip-search exploit search --language Python --source-date-from 2026-01-01
```

Inspect an artifact by its stable numeric public ID:

```sh
eip-search exploit show 8700882207674114
eip-search exploit analysis 8700882207674114
eip-search exploit files 8700882207674114
eip-search exploit view 8700882207674114 README.md
```

GitHub stars are source metadata and do not affect ordering. Technical class
and backdoor-review fields are separately attributed stored model
interpretation. They are not EIP verification, reliability, quality, or safety
verdicts, and missing analysis is not a benign finding.

### Protected downloads

```sh
eip-search exploit download 8700882207674114 --output poc.zip
```

File viewing and downloads request a fresh short-lived POST token for each
operation. Tokens are never printed or retained. Downloads remain
password-protected ZIP archives with password `eip`; the CLI never extracts or
executes them. Without `--output`, the archive is written to the current working
directory using the API-suggested safe filename. Existing files are not
overwritten unless `--force` is passed.

## Code search

```sh
eip-search code 'subprocess.run('
eip-search code 'http://' --source metasploit --limit 10
eip-search code 'jndi ldap' --vulnerability CVE-2021-44228
eip-search code 'request session' --public-id 8700882207674114
```

Results can include the public exploit ID, source, path, path/content match
location, nearby line context, snippet span, linked vulnerability identifiers,
and the API-provided source excerpt. An unassigned repository match is labelled
as excerpt-only instead of being presented as an openable public PoC. Ordering
is textual relevance with deterministic tie-breaking, not exploit quality or
effectiveness.

Queries must contain between 2 and 200 characters. Each whitespace-separated
chunk containing a letter, digit, or `_` is required as an FTS phrase;
punctuation-only chunks are ignored. `--public-id` searches exactly one public
PoC; `--vulnerability` searches only explicitly associated PoCs. The two scopes
cannot be combined and are bound into pagination cursors by the API.

A valid zero-match result exits successfully. Run `eip-search doctor` when you
need to distinguish no matches from an unavailable code index.

## Docker labs

```sh
eip-search lab search CVE-2024 --kind compose
eip-search lab search --association unlinked --analysis pending
eip-search lab search CVE-2024 --include-analysis --limit 5
eip-search lab screenshot 43471308592392 --output lab.png
```

`--include-analysis` is bounded to at most ten results. Stored analysis is
evidence-grounded interpretation. The CLI does not claim a lab is runnable,
vulnerable, complete, or safe and never builds or runs one.

## Discovery directories

```sh
eip-search vendor Microsoft
eip-search product --vendor Microsoft Windows
eip-search ecosystem PyPI
eip-search package --ecosystem PyPI Django
eip-search cwe list injection
eip-search cwe show CWE-78
eip-search author list exploitintel --source github --role owner
eip-search author show 8195520625892450
eip-search author exploits 8195520625892450
eip-search artifact 4134af29-1554-5627-9c62-16de2390ed0a
```

Contributor identities remain source-scoped. Author-to-exploit lookup uses the
API's exact contributor public-ID filter; the CLI does not infer relationships
locally.

## Statistics and STIX

```sh
eip-search stats
eip-search stats --trends all
eip-search stix vuln CVE-2024-3400 --mapping v2 --output cve.json
eip-search stix exploit 8700882207674114 --output exploit.json
```

STIX output is the exact API-owned STIX 2.1 bundle. The CLI performs no local
mapping. TAXII uses its standard client protocol and is not reimplemented by
`eip-search`.

## Limits and pagination

Collection commands return one bounded page. `--limit` controls the page size;
the accepted maximum depends on the command and is shown in its help.

When a page reports a next cursor, request the next page with the same query,
filters, sort, and limit:

```sh
eip-search exploit search --source exploitdb --limit 25
eip-search exploit search --source exploitdb --limit 25 --cursor 'OPAQUE_VALUE'
```

Cursors are opaque and query-bound. Copy them exactly. The CLI does not decode
them or provide unbounded automatic traversal.

## JSON and shell use

Every data command accepts `--json`; STIX emits JSON unless `--output` is used.
Successful JSON mode writes one valid JSON document and nothing else to stdout.
Diagnostics go to stderr.

```sh
eip-search vuln search apache --limit 10 --json >results.json
eip-search exploit show 8700882207674114 --json | jq '.poc.public_id'
```

API field names, nulls, arrays, provenance, and cursors are preserved rather
than translated into a separate client model.

## Shell completion

The CLI supports Typer's completion commands. Inspect the command appropriate
for the active shell:

```sh
eip-search --show-completion
eip-search --install-completion
```

## Exit status

| Status | Meaning |
| ---: | --- |
| `0` | Success, including a valid empty search |
| `2` | Invalid CLI input or API validation rejection |
| `3` | Detail record not found |
| `4` | API or required subsystem unavailable |
| `5` | Rate or capacity limited after bounded handling |
| `6` | Transport, timeout, or TLS failure |
| `7` | Local file or output failure |

## Troubleshooting

### The API cannot be reached

Run `doctor` against the public API:

```sh
eip-search doctor
```

Exit status `6` indicates transport, timeout, DNS, or TLS failure. Exit status
`4` means the API responded but the requested API or subsystem is unavailable.

### Code search returns no results

A valid empty result is not an error. `doctor` reports whether the code-search
subsystem is ready.

### A cursor is rejected

Use the exact cursor with the same command, query, filters, sort, and limit that
produced it. Changing any of those values invalidates a query-bound cursor.

### Output is difficult to read in automation

Use `--json` for structured output and `--no-color` or `NO_COLOR=1` to disable
terminal styling.

### A download already exists

Choose another output path or pass `--force` explicitly. The CLI will not
overwrite a local file by default.
