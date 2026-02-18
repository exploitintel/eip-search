.PHONY: release build clean check deb pypi

# ── Dependency checks ────────────────────────────────────────────────────────
require = $(if $(shell command -v $(1) 2>/dev/null),,$(error "$(1)" not found. $(2)))

# ── Release a new version ────────────────────────────────────────────────────
#   make release VERSION=0.2.0
#
# This will: bump version, clean, build PyPI + .debs, upload to PyPI,
# git commit, tag, push, and create a GitHub release with .debs attached.
# Requires: pip install build twine, Docker, gh CLI

release:
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=0.2.0)
endif
	$(call require,python3,Install Python 3)
	$(call require,twine,pip install twine)
	$(call require,docker,Install Docker Desktop or docker-ce)
	$(call require,gh,Install GitHub CLI: https://cli.github.com)
	@echo ""
	@echo "==> Releasing eip-search $(VERSION)"
	@echo ""
	@# Validate version looks like semver (X.Y.Z)
	@echo "$(VERSION)" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$$' || \
		(echo "ERROR: VERSION must be semver (e.g. 0.2.0), got: $(VERSION)" && exit 1)
	@# 1. Bump version in both files
	@echo "--- Bumping version to $(VERSION)"
	python3 scripts/bump_version.py $(VERSION)
	@# 2. Clean
	$(MAKE) clean
	@# 3. Build PyPI wheel+sdist, twine check
	$(MAKE) build
	$(MAKE) check
	@# 4. Build all .debs
	$(MAKE) deb
	@# 5. Upload to PyPI
	$(MAKE) pypi
	@# 6. Git commit, tag, push
	@echo "--- Git commit and tag"
	git add pyproject.toml eip_search/__init__.py
	git commit -m "Bump version to $(VERSION)"
	git tag v$(VERSION)
	git push
	git push --tags
	@# 7. GitHub release with .debs attached
	@echo "--- Creating GitHub release"
	gh release create v$(VERSION) \
		--title "v$(VERSION)" \
		--generate-notes \
		dist/eip-search_$(VERSION)_*_all.deb
	@echo ""
	@echo "==> eip-search $(VERSION) released!"
	@echo "    https://pypi.org/project/eip-search/$(VERSION)/"
	@echo ""

# ── Build sdist + wheel ───────────────────────────────────────────────────────
build:
	$(call require,python3,Install Python 3)
	@python3 -c "import build" 2>/dev/null || { echo "ERROR: 'build' module not found. Run: pip install build"; exit 1; }
	@echo "--- Building package"
	python3 -m build

# ── Remove build artifacts ────────────────────────────────────────────────────
clean:
	@echo "--- Cleaning build artifacts"
	rm -rf dist/ build/ eip_search.egg-info/

# ── Dry-run: build and validate with twine ────────────────────────────────────
check:
	$(call require,twine,pip install twine)
	@echo "--- Checking package"
	twine check dist/*

# ── Upload to PyPI (wheel + sdist only, not .debs) ───────────────────────────
pypi:
	$(call require,twine,pip install twine)
	@echo "--- Uploading to PyPI"
	twine upload dist/*.whl dist/*.tar.gz

# ── Build .deb package(s) (requires Docker) ──────────────────────────────────
#   make deb              — build all 4 distros
#   make deb DISTRO=kali  — build one distro
deb:
	$(call require,docker,Install Docker Desktop or docker-ce)
	@echo "--- Building .deb package(s)"
ifdef DISTRO
	packaging/deb/build.sh $(DISTRO)
else
	packaging/deb/build.sh
endif
