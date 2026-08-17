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
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip install -e .
ruff check src tests
pytest -q -m 'not live' --cov=eip_search_v3 --cov-fail-under=90
! git grep -n -I -P '[\x{2013}\x{2014}]' -- .   # CI rejects en/em dashes
```

CI enforces that dash check, the coverage floor, and a packaging job that
asserts CLI help text and examples, so changing a banner or an example string
can fail the build. `CONTRIBUTING.md` carries the full local suite.

Live tests require `EIP_SEARCH_TEST_API_BASE_URL` and must verify parameter
effects, not merely HTTP success. Keep them bounded and courteous to the shared
review API.

User-visible behavior belongs in `docs/user-guide.md`; keep the README concise,
user-first, and suitable for both GitHub and PyPI rendering. The project uses
the MIT License and GitHub private vulnerability reporting.

Work on a short-lived topic branch named `feat/`, `fix/`, `chore/`, `docs/`, or
`agent/` plus a short slug, and open a pull request; never commit to `main`.
Inspect status and preserve unrelated work before editing. Commits, PRs,
merges, package publication, and deployment require operator authorization.
