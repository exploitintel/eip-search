# Contributing to eip-search

Contributions must preserve the public, read-only API boundary and the product
rules in [AGENTS.md](AGENTS.md).

## Development setup

Python 3.12 or later is required.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip install -e .
```

Run the local quality suite before opening a pull request:

```sh
ruff check src tests
pytest -q -m 'not live' --cov=eip_search_v3 --cov-fail-under=90
python -m build
```

Install the built wheel in a clean environment when changing packaging,
entrypoints, or dependencies:

```sh
python3 -m venv /tmp/eip-search-wheel-check
/tmp/eip-search-wheel-check/bin/python -m pip install dist/*.whl
/tmp/eip-search-wheel-check/bin/eip-search --version
/tmp/eip-search-wheel-check/bin/eip-search --help
```

## Live verification

Live tests are opt-in, sequential, and bounded. They require an explicitly
selected review API:

```sh
EIP_SEARCH_TEST_API_BASE_URL=http://127.0.0.1:13002 pytest -q -m live
```

Live verification must test parameter meaning, not merely HTTP success. Never
point exploratory or unbounded testing at a shared deployment.

## Pull requests

- Keep changes within the CLI's API-client boundary.
- Preserve API ordering, identifiers, attribution, nulls, and opaque cursors.
- Treat all corpus text and source code as hostile terminal input.
- Add behavior-focused tests for changed commands, parameters, output, and
  failure handling.
- Update the user guide when behavior visible to users changes.
- Do not add client-side ranking, page-local filtering, inferred verdicts,
  unbounded traversal, source execution, or direct data-store access.

Commits, pull requests, releases, publication, and deployment remain explicit
operator actions.
