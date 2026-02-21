#!/usr/bin/env bash
# Jenkins "Execute shell" — eip-search release pipeline
# Triggered by: tag push (v*) or manual build with VERSION parameter
#
# Builds PyPI packages + per-distro .deb packages (arm64 native + amd64 via
# remote build box), smoke-tests every .deb, uploads to PyPI, Codeberg,
# and APT repo.
#
# Required Jenkins credentials (environment variables):
#   TWINE_USERNAME  — PyPI username (__token__)
#   TWINE_PASSWORD  — PyPI API token
#   CODEBERG_TOKEN  — Codeberg API token for releases
#   REDACTED — IP of remote x86_64 build box (for amd64 .debs)
#   REPO_SSH_KEY    — (optional) path to SSH key for APT repo, or use agent

set -euo pipefail
echo "Building on: $(uname -a)"
export COLUMNS=160

# Load credentials (PyPI token, Codeberg token)
[ -f REDACTED ] && source REDACTED

# Use isolated build tools venv (avoids polluting system packages)
export PATH="REDACTED:${PATH}"

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

###############################################################################
# 2. Build .deb packages (arm64 native + amd64 remote via SSH)
###############################################################################
echo ""
echo "--- Building .deb packages"

PKG="eip-search"

DISTROS=(
    "ubuntu-jammy|ubuntu:22.04|ubuntu-jammy|jammy"
    "ubuntu-noble|ubuntu:24.04|ubuntu-noble|noble"
    "ubuntu-plucky|ubuntu:25.04|ubuntu-plucky|plucky"
    "ubuntu-questing|ubuntu:25.10|ubuntu-questing|questing"
    "debian-bookworm|debian:12|debian-bookworm|bookworm"
    "debian-trixie|debian:13|debian-trixie|trixie"
    "kali|kalilinux/kali-rolling|kali-rolling|kali-rolling"
)

LOCAL_ARCH=$(uname -m)
case "$LOCAL_ARCH" in
    aarch64|arm64) LOCAL_PLATFORM="linux/arm64"; LOCAL_DEB_ARCH="arm64" ;;
    x86_64)        LOCAL_PLATFORM="linux/amd64"; LOCAL_DEB_ARCH="amd64" ;;
    *)             echo "ERROR: Unsupported arch: $LOCAL_ARCH"; exit 1 ;;
esac

AMD64_HOST="${REDACTED:-}"
REMOTE_DIR="/tmp/${PKG}-build"

if [ -n "$AMD64_HOST" ]; then
    echo "Remote amd64 build box: ${AMD64_HOST}"
    echo "--- Syncing source to remote box"
    rsync -az --delete \
        --exclude='.git' --exclude='dist' --exclude='__pycache__' --exclude='.eggs' \
        "$WORKSPACE/" "root@${AMD64_HOST}:${REMOTE_DIR}/"
    echo "  Sync complete"
fi

for entry in "${DISTROS[@]}"; do
    IFS='|' read -r name base_image distro_tag suite <<< "${entry}"

    # ── Local build (native) ────────────────────────────────────────────────
    echo ""
    echo "==> Building ${distro_tag} ${LOCAL_DEB_ARCH} (local)"

    docker build \
        --platform "${LOCAL_PLATFORM}" \
        --build-arg BASE_IMAGE="${base_image}" \
        --build-arg DISTRO_TAG="${distro_tag}" \
        --build-arg SUITE="${suite}" \
        --build-arg VERSION="${VERSION}" \
        -f packaging/deb/Dockerfile \
        -t "${PKG}-deb-${name}-${LOCAL_DEB_ARCH}" \
        .

    container=$(docker create --platform "${LOCAL_PLATFORM}" "${PKG}-deb-${name}-${LOCAL_DEB_ARCH}")
    docker cp "${container}:/out/." dist/
    docker rm "${container}" > /dev/null

    DEB_LOCAL="dist/${PKG}_${VERSION}_${distro_tag}_${LOCAL_DEB_ARCH}.deb"
    if [ ! -f "$DEB_LOCAL" ]; then
        echo "ERROR: Expected ${DEB_LOCAL} not found"; ls -la dist/; exit 1
    fi

    echo "--- Smoke testing ${DEB_LOCAL}"
    docker run --rm --platform "${LOCAL_PLATFORM}" \
        -v "$(pwd)/dist:/pkg:ro" \
        "${base_image}" \
        bash -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq /pkg/$(basename ${DEB_LOCAL}) >/dev/null 2>&1 && ${PKG} --version"
    echo "  PASS: $(basename ${DEB_LOCAL})"

    # ── Remote amd64 build (native on remote box) ──────────────────────────
    if [ -n "$AMD64_HOST" ]; then
        echo ""
        echo "==> Building ${distro_tag} amd64 (remote: ${AMD64_HOST})"

        ssh "root@${AMD64_HOST}" "cd ${REMOTE_DIR} && docker build \
            --platform linux/amd64 \
            --build-arg BASE_IMAGE=${base_image} \
            --build-arg DISTRO_TAG=${distro_tag} \
            --build-arg SUITE=${suite} \
            --build-arg VERSION=${VERSION} \
            -f packaging/deb/Dockerfile \
            -t ${PKG}-deb-${name}-amd64 \
            ."

        DEB_AMD64="${PKG}_${VERSION}_${distro_tag}_amd64.deb"

        ssh "root@${AMD64_HOST}" "cd ${REMOTE_DIR} && mkdir -p dist && \
            container=\$(docker create --platform linux/amd64 ${PKG}-deb-${name}-amd64) && \
            docker cp \${container}:/out/. dist/ && \
            docker rm \${container} > /dev/null"

        scp "root@${AMD64_HOST}:${REMOTE_DIR}/dist/${DEB_AMD64}" dist/

        if [ ! -f "dist/${DEB_AMD64}" ]; then
            echo "ERROR: Expected dist/${DEB_AMD64} not found"; exit 1
        fi

        echo "--- Smoke testing dist/${DEB_AMD64}"
        ssh "root@${AMD64_HOST}" "docker run --rm --platform linux/amd64 \
            -v ${REMOTE_DIR}/dist:/pkg:ro \
            ${base_image} \
            bash -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq /pkg/${DEB_AMD64} >/dev/null 2>&1 && ${PKG} --version'"
        echo "  PASS: ${DEB_AMD64}"
    fi
done

echo ""
ls -lh dist/*.deb dist/*.whl dist/*.tar.gz

###############################################################################
# 3. Upload to PyPI (skip if version already exists)
###############################################################################
echo ""
echo "--- Uploading to PyPI"
export TWINE_USERNAME="${TWINE_USERNAME:-__token__}"
twine upload --skip-existing dist/*.whl dist/*.tar.gz

###############################################################################
# 4. Create Codeberg release (or find existing)
###############################################################################
echo ""
echo "--- Creating Codeberg release"
TAG="v${VERSION}"
API_URL="https://codeberg.org/api/v1/repos/exploit-intel/eip-search"

RELEASE_ID=$(curl -s -X POST \
    -H "Authorization: token ${CODEBERG_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"tag_name\": \"${TAG}\", \"name\": \"${TAG}\", \"draft\": false, \"prerelease\": false}" \
    "${API_URL}/releases" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null)

if [ -z "$RELEASE_ID" ]; then
    echo "Release ${TAG} already exists, looking up ID..."
    RELEASE_ID=$(curl -s \
        -H "Authorization: token ${CODEBERG_TOKEN}" \
        "${API_URL}/releases/tags/${TAG}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
fi

echo "Release ${TAG} (id: ${RELEASE_ID})"

for file in dist/*.deb dist/*.whl dist/*.tar.gz; do
    [ -f "$file" ] || continue
    echo "  Uploading $(basename "$file")..."
    curl -s -X POST \
        -H "Authorization: token ${CODEBERG_TOKEN}" \
        -F "attachment=@${file}" \
        "${API_URL}/releases/${RELEASE_ID}/assets" > /dev/null
done

###############################################################################
# 5. Upload .debs to APT repo
###############################################################################
echo ""
echo "--- Uploading .debs to APT repo"
ssh -o REDACTED root@REDACTED "rm -f /var/www/apt/incoming/*.deb"
scp -o REDACTED dist/*.deb root@REDACTED:/var/www/apt/incoming/
ssh -o REDACTED root@REDACTED "bash /root/upload-debs.sh"

###############################################################################
# Done
###############################################################################
echo ""
echo "==> eip-search ${VERSION} released!"
echo "    https://pypi.org/project/eip-search/${VERSION}/"
echo "    https://codeberg.org/exploit-intel/eip-search/releases/tag/${TAG}"
