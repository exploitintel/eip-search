.PHONY: release build clean check

# ── Release a new version to PyPI ─────────────────────────────────────────────
#   make release VERSION=0.2.0
#
# This will: bump version in both files, clean, build, upload to PyPI,
# git commit, tag, and push.
# Requires: pip install build twine  (already in .venv from earlier setup)
# PyPI credentials: ~/.pypirc (see README or run `make pypirc`)

release:
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=0.2.0)
endif
	@echo ""
	@echo "==> Releasing eip-search $(VERSION)"
	@echo ""
	@# Validate version looks like semver (X.Y.Z)
	@echo "$(VERSION)" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$$' || \
		(echo "ERROR: VERSION must be semver (e.g. 0.2.0), got: $(VERSION)" && exit 1)
	@# Bump version in both files
	@echo "--- Bumping version to $(VERSION)"
	python3 scripts/bump_version.py $(VERSION)
	@# Clean, build, check, upload
	$(MAKE) clean
	$(MAKE) build
	$(MAKE) check
	@echo "--- Uploading to PyPI"
	twine upload dist/*
	@# Git commit, tag, push
	@echo "--- Git commit and tag"
	git add pyproject.toml eip_search/__init__.py
	git commit -m "release $(VERSION)"
	git tag v$(VERSION)
	git push
	git push --tags
	@echo ""
	@echo "==> eip-search $(VERSION) released!"
	@echo "    https://pypi.org/project/eip-search/$(VERSION)/"
	@echo ""

# ── Build sdist + wheel ───────────────────────────────────────────────────────
build:
	@echo "--- Building package"
	python3 -m build

# ── Remove build artifacts ────────────────────────────────────────────────────
clean:
	@echo "--- Cleaning build artifacts"
	rm -rf dist/ build/ eip_search.egg-info/

# ── Dry-run: build and validate with twine ────────────────────────────────────
check:
	@echo "--- Checking package"
	twine check dist/*
