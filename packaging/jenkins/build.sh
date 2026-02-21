#!/usr/bin/env bash
# Jenkins "Execute shell" — eip-search release pipeline
# Triggered by: tag push (v*) or manual build with VERSION parameter
#
# Builds PyPI packages + per-distro .deb packages (arm64, native),
# smoke-tests every .deb, uploads to PyPI, Codeberg, and APT repo.
#
# Required Jenkins credentials (environment variables):
#   TWINE_USERNAME  — PyPI username (__token__)
#   TWINE_PASSWORD  — PyPI API token
#   CODEBERG_TOKEN  — Codeberg API token for releases
#   REPO_SSH_KEY    — (optional) path to SSH key for APT repo, or use agent

set -euo pipefail
echo "Building on: $(uname -a)"
export COLUMNS=160

# Load credentials (PyPI token, Codeberg token)
[ -f REDACTED ] && source REDACTED

cd "$WORKSPACE"

VERSION=$(grep '^__version__' eip_search/__init__.py | cut -d'"' -f2)
echo "==> eip-search ${VERSION}"

###############################################################################
# 1. Build PyPI packages
###############################################################################
echo ""
echo "--- Building PyPI packages"
make clean
make build
make check

###############################################################################
# 2. Build .deb packages (arm64 native via Docker)
###############################################################################
echo ""
echo "--- Building .deb packages"

DISTROS=(
    "ubuntu-jammy|ubuntu:22.04|ubuntu-jammy"
    "ubuntu-noble|ubuntu:24.04|ubuntu-noble"
    "ubuntu-plucky|ubuntu:25.04|ubuntu-plucky"
    "ubuntu-questing|ubuntu:25.10|ubuntu-questing"
    "debian-bookworm|debian:12|debian-bookworm"
    "debian-trixie|debian:13|debian-trixie"
    "kali|kalilinux/kali-rolling|kali-rolling"
)

ARCH=$(uname -m)
case "$ARCH" in
    aarch64|arm64) PLATFORM="linux/arm64" ;;
    x86_64)        PLATFORM="linux/amd64" ;;
    *)             echo "ERROR: Unsupported arch: $ARCH"; exit 1 ;;
esac

for entry in "${DISTROS[@]}"; do
    IFS='|' read -r name base_image distro_tag <<< "${entry}"

    echo ""
    echo "==> Building ${distro_tag} (${PLATFORM})"

    docker build \
        --platform "${PLATFORM}" \
        --build-arg BASE_IMAGE="${base_image}" \
        --build-arg DISTRO_TAG="${distro_tag}" \
        --build-arg VERSION="${VERSION}" \
        -f packaging/deb/Dockerfile \
        -t "eip-search-deb-${name}" \
        .

    container=$(docker create --platform "${PLATFORM}" "eip-search-deb-${name}")
    docker cp "${container}:/out/." dist/
    docker rm "${container}" > /dev/null

    DEB="dist/eip-search_${VERSION}_${distro_tag}_all.deb"
    if [ ! -f "$DEB" ]; then
        echo "ERROR: Expected ${DEB} not found"
        exit 1
    fi

    # Smoke test in a clean container
    echo "--- Smoke testing ${DEB}"
    docker run --rm --platform "${PLATFORM}" \
        -v "$(pwd)/dist:/pkg:ro" \
        "${base_image}" \
        bash -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq /pkg/$(basename ${DEB}) >/dev/null 2>&1 && eip-search --version"
    echo "  PASS: $(basename ${DEB})"
done

echo ""
ls -lh dist/*.deb dist/*.whl dist/*.tar.gz

###############################################################################
# 3. Upload to PyPI
###############################################################################
echo ""
echo "--- Uploading to PyPI"
export TWINE_USERNAME="${TWINE_USERNAME:-__token__}"
twine upload dist/*.whl dist/*.tar.gz

###############################################################################
# 4. Create Codeberg release
###############################################################################
echo ""
echo "--- Creating Codeberg release"
TAG="v${VERSION}"
API_URL="https://codeberg.org/api/v1/repos/exploit-intel/eip-search"

RELEASE_ID=$(curl -sf -X POST \
    -H "Authorization: token ${CODEBERG_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"tag_name\": \"${TAG}\", \"name\": \"${TAG}\", \"draft\": false, \"prerelease\": false}" \
    "${API_URL}/releases" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

echo "Created release ${TAG} (id: ${RELEASE_ID})"

for file in dist/*.deb dist/*.whl dist/*.tar.gz; do
    [ -f "$file" ] || continue
    echo "  Uploading $(basename "$file")..."
    curl -sf -X POST \
        -H "Authorization: token ${CODEBERG_TOKEN}" \
        -F "attachment=@${file}" \
        "${API_URL}/releases/${RELEASE_ID}/assets" > /dev/null
done

###############################################################################
# 5. Upload .debs to APT repo
###############################################################################
echo ""
echo "--- Uploading .debs to APT repo"
scp -o REDACTED dist/*.deb root@REDACTED:/var/www/apt/incoming/
ssh -o REDACTED root@REDACTED "bash /root/upload-debs.sh"

###############################################################################
# Done
###############################################################################
echo ""
echo "==> eip-search ${VERSION} released!"
echo "    https://pypi.org/project/eip-search/${VERSION}/"
echo "    https://codeberg.org/exploit-intel/eip-search/releases/tag/${TAG}"
