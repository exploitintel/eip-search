#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

VERSION=$(grep '^__version__' eip_search/__init__.py | cut -d'"' -f2)
FILTER="${1:-}"

# Distro matrix: name | base image | distro tag
DISTROS=(
    "ubuntu-jammy|ubuntu:22.04|ubuntu-jammy"
    "ubuntu-noble|ubuntu:24.04|ubuntu-noble"
    "ubuntu-plucky|ubuntu:25.04|ubuntu-plucky"
    "ubuntu-questing|ubuntu:25.10|ubuntu-questing"
    "debian-bookworm|debian:12|debian-bookworm"
    "debian-trixie|debian:13|debian-trixie"
    "kali|kalilinux/kali-rolling|kali-rolling"
)

PLATFORMS=("linux/amd64" "linux/arm64")

# Ensure buildx multi-platform support is available
docker buildx inspect --bootstrap >/dev/null 2>&1 || true

build_and_test() {
    local name="$1" base_image="$2" distro_tag="$3" platform="$4"
    local arch="${platform#linux/}"
    local image_tag="eip-search-deb-${name}-${arch}"
    local deb_file="eip-search_${VERSION}_${distro_tag}_${arch}.deb"

    echo ""
    echo "==> Building eip-search ${VERSION} for ${name} (${base_image}, ${arch})"
    echo ""

    docker build \
        --platform "${platform}" \
        --build-arg BASE_IMAGE="${base_image}" \
        --build-arg DISTRO_TAG="${distro_tag}" \
        --build-arg VERSION="${VERSION}" \
        -f packaging/deb/Dockerfile \
        -t "${image_tag}" \
        .

    # Extract the .deb
    local container
    container=$(docker create --platform "${platform}" "${image_tag}")
    mkdir -p dist
    docker cp "${container}:/out/." dist/
    docker rm "${container}" > /dev/null

    # Rename to include arch
    if [ -f "dist/eip-search_${VERSION}_${distro_tag}_all.deb" ]; then
        mv "dist/eip-search_${VERSION}_${distro_tag}_all.deb" "dist/${deb_file}"
    fi

    echo ""
    echo "--- Testing ${deb_file} in clean container"
    echo ""

    # Smoke test: install the deb in a clean container and run --version
    docker run --rm --platform "${platform}" \
        -v "$(pwd)/dist:/pkg:ro" \
        "${base_image}" \
        bash -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq /pkg/${deb_file} >/dev/null 2>&1 && eip-search --version" \
    && echo "  PASS: ${deb_file}" \
    || { echo "  FAIL: ${deb_file}"; exit 1; }

    echo ""
    ls -lh "dist/${deb_file}"
}

built=0
for entry in "${DISTROS[@]}"; do
    IFS='|' read -r name base_image distro_tag <<< "${entry}"
    if [[ -z "${FILTER}" || "${name}" == "${FILTER}" ]]; then
        for platform in "${PLATFORMS[@]}"; do
            build_and_test "${name}" "${base_image}" "${distro_tag}" "${platform}"
            built=$((built + 1))
        done
    fi
done

if [[ ${built} -eq 0 ]]; then
    echo "ERROR: Unknown distro '${FILTER}'. Available: ubuntu-jammy, ubuntu-noble, ubuntu-plucky, ubuntu-questing, debian-bookworm, debian-trixie, kali" >&2
    exit 1
fi

echo ""
echo "==> Done: ${built} package(s) built and tested"
