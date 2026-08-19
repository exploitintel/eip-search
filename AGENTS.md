# eip-search

## Boundary

This repository is the human command-line client for the public, read-only EIP
v3 API. It is a peer of the WebUI and MCP server.

It must not connect to PostgreSQL, read the corpus or code index, acquire or
execute PoC material, build labs, call a model, or write EIP state. It imports
no code from another EIP repository.

## Product rules

- Preserve API meaning, ordering, attribution, identifiers, and opaque cursors.
- Never rank artifacts or claim that an exploit or lab works, is verified,
  reliable, effective, or safe.
- GitHub stars are source metadata only.
- Stored technical and backdoor analysis is attributed model interpretation,
  not an EIP verdict. Missing analysis is not a benign finding.
- Corpus text and source code are hostile. Remove terminal control sequences,
  escape Rich markup, and keep output bounded.
- PoC file and download access uses fresh short-lived POST tokens. Tokens must
  never enter output, logs, tracebacks, configuration, or retained state.
- Downloads remain AES-encrypted ZIP archives (password `eip`) and are never
  extracted or executed by this tool.
- No client-side page filtering or sorting. Add missing global predicates to
  the API in a separate slice rather than returning misleading partial results.
- No offline database until EIP publishes an upstream-owned versioned export.

## Development

The public source repository, distribution, and executable are all
`eip-search`. Version 3 begins at `3.0.0` and releases only from a matching
`v*` tag on `main`. Do not publish or tag without explicit operator
authorization.

```sh
python3 -m venv --clear .venv   # --clear: a uv-made .venv has no pip
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip install -e .
ruff check src tests
ruff format --check src tests
mypy
pytest -q -m 'not live' --cov=eip_search_v3 --cov-fail-under=92
! git grep --untracked -n -I -P '[\x{2013}\x{2014}]' -- .   # CI rejects en/em dashes
```

Run that with a narrow or unset `COLUMNS`. Rich sizes its output to the terminal,
so a wide terminal executes render branches a narrow one does not: this suite
reports 93 percent unset or at 80 columns and 95 percent at 140. CI has no tty and
sees 93, so a wide local terminal will suggest roughly twice the headroom that
actually exists.

CI enforces that dash check, the coverage floor, and a packaging job that
asserts CLI help text and examples, so changing a banner or an example string
can fail the build. `CONTRIBUTING.md` carries the full local suite.

Live tests require `EIP_SEARCH_TEST_API_BASE_URL` and must verify parameter
effects, not merely HTTP success. Keep them bounded and courteous to the shared
review API.

User-visible behavior belongs in `docs/user-guide.md`; keep the README concise,
user-first, and suitable for both GitHub and PyPI rendering. The project uses
the MIT License and GitHub private vulnerability reporting.

## Layout

- `cli.py` - every Typer command, and the only place option parsing lives.
- `client.py` - the sole HTTP caller. Nothing else talks to the API.
- `config.py` - configuration loading (see below).
- `safety.py` - terminal and filesystem containment for hostile corpus values.
  Untrusted text passes through here before it reaches the terminal.
- `render/` - one module per domain: `vulnerability`, `exploit`, `labs`,
  `discovery`, `system`, plus shared helpers in `common`.
- `errors.py` - the exit-code hierarchy documented in the user guide.

## Configuration

Precedence, highest first: CLI option where one exists, environment variable,
configuration file, built-in default. The variables are `EIP_API_BASE_URL`,
`EIP_SEARCH_CONFIG`, `EIP_SEARCH_TIMEOUT_SECONDS`, and
`EIP_SEARCH_MAX_DOWNLOAD_BYTES`; the last has no CLI option.
`XDG_CONFIG_HOME` locates the configuration file when `EIP_SEARCH_CONFIG` is
unset. `NO_COLOR` disables styling, as does `--no-color`.

Python 3.12 or newer is required, and CI runs the suite on 3.12 and 3.14, so a
green single-interpreter run locally is not proof.

## Working in this repository

Work on a short-lived topic branch named `feat/`, `fix/`, `chore/`, `docs/`, or
`agent/` plus a short slug, and open a pull request; never commit to `main`.
Inspect status and preserve unrelated work before editing. Commits, PRs,
merges, package publication, and deployment require operator authorization.
