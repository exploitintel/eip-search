<p align="center">
  <a href="https://exploit-intel.com">
    <img src="https://raw.githubusercontent.com/exploitintel/eip-search/main/docs/assets/eip-hero-banner.svg" alt="Exploit Intelligence Platform" width="100%">
  </a>
</p>

<h1 align="center">eip-search</h1>

<p align="center"><strong>The official command-line client for the Exploit Intelligence Platform.</strong></p>

<p align="center">
  <a href="https://pypi.org/project/eip-search/"><img src="https://img.shields.io/pypi/v/eip-search.svg" alt="PyPI release"></a>
  <a href="https://pypi.org/project/eip-search/"><img src="https://img.shields.io/pypi/pyversions/eip-search.svg" alt="Supported Python versions"></a>
  <a href="https://github.com/exploitintel/eip-search/actions/workflows/quality.yml"><img src="https://github.com/exploitintel/eip-search/actions/workflows/quality.yml/badge.svg" alt="Quality checks"></a>
  <a href="https://github.com/exploitintel/eip-search/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-16b8c4.svg" alt="MIT License"></a>
</p>

Search vulnerability intelligence, exploit artifacts, readable PoC source,
Docker labs, vendors, packages, CWEs, and exploit authors from a terminal or a
JSON-aware script. Results preserve the API's source attribution, ordering,
identifiers, and opaque pagination cursors.

`eip-search` is read-only. It does not execute acquired code, build labs, call a
model, rank exploits, or claim that an artifact works, is verified, reliable,
effective, or safe.

## Install

Python 3.12 or newer is required. Install the isolated application with
[`pipx`](https://pipx.pypa.io/):

```sh
pipx install eip-search
eip-search doctor
```

Upgrade later with `pipx upgrade eip-search`.

### Docker alternative

Build the image directly from this checkout:

```sh
docker build -t eip-search .
docker run --rm eip-search CVE-2024-3400
```

Mount the current directory when a command needs to save a download,
screenshot, or STIX bundle:

```sh
docker run --rm \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" \
  eip-search stix vuln CVE-2024-3400 --output docker-cve.json
```

## Try it

Search vulnerabilities or open one directly:

```sh
eip-search apache
eip-search CVE-2024-3400
eip-search vuln search --vendor Microsoft --product Windows --limit 10
```

Find and inspect exploit artifacts:

```sh
eip-search exploit search CVE-2024-3400 --limit 10
eip-search exploit search --association unlinked --limit 10
eip-search exploit show 8700882207674114
eip-search exploit analysis 8700882207674114
```

Search readable PoC source and Docker labs:

```sh
eip-search code 'subprocess.run(' --limit 10
eip-search code 'jndi ldap' --vulnerability CVE-2021-44228
eip-search lab search CVE-2024 --kind compose --limit 10
```

Explore the discovery directories:

```sh
eip-search package --ecosystem PyPI Django
eip-search cwe show CWE-78
eip-search author list exploitintel --source github --role owner
```

Add `--json` to a data command for machine-readable output:

```sh
eip-search vuln search apache --limit 10 --json
```

Run `eip-search --help` or `eip-search COMMAND --help` for the complete runtime
reference.

## What it covers

- Vulnerabilities, affected products and versions, exploitation context, and
  accepted research references
- ExploitDB, Metasploit, repository PoCs, files, and stored model analysis
- Private, non-indexable source-code search and protected PoC downloads
- Docker/Compose lab units and stored lab analysis
- Vendors, products, ecosystems, packages, official CWEs, and exploit authors
- Corpus health, statistics, and API-owned STIX 2.1 bundles

## Configuration

The CLI connects to `https://exploit-intel.com` automatically; users do not
need to provide an API URL on any command.

CLI options override environment variables, which override the optional
configuration file at `~/.config/eip-search/config.toml` or
`$XDG_CONFIG_HOME/eip-search/config.toml`.

## Safety and trust

- Corpus text and source code are treated as hostile terminal input.
- PoC file and download access uses fresh, short-lived tokens that are never
  printed or retained.
- Downloads remain AES-encrypted ZIP archives with password `eip`. AES entries
  need an AES-capable tool such as 7-Zip rather than the stock `unzip`; the CLI
  never extracts or executes them.
- Stored analysis is attributed model interpretation, not an EIP verdict.
- Missing analysis never means that an artifact was reviewed and found safe.

See the [security policy](https://github.com/exploitintel/eip-search/security/policy)
before reporting a vulnerability or sharing diagnostic output.

## Documentation

- [User guide](https://github.com/exploitintel/eip-search/blob/main/docs/user-guide.md)
- [Contributing](https://github.com/exploitintel/eip-search/blob/main/CONTRIBUTING.md)
- [Security policy](https://github.com/exploitintel/eip-search/security/policy)
- [EIP MCP server](https://github.com/exploitintel/eip-mcp)

## License

[MIT](https://github.com/exploitintel/eip-search/blob/main/LICENSE)
