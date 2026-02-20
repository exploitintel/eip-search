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
    "debian-bookworm|debian:12|debian-bookworm"
    "debian-trixie|debian:13|debian-trixie"
    "kali|kalilinux/kali-rolling|kali-rolling"
)

build_distro() {
    local name="$1" base_image="$2" distro_tag="$3"
    local image_tag="eip-search-deb-${name}"

    echo ""
    echo "==> Building eip-search ${VERSION} .deb for ${name} (${base_image})"
    echo ""

    docker build \
        --platform linux/amd64 \
        --build-arg BASE_IMAGE="${base_image}" \
        --build-arg DISTRO_TAG="${distro_tag}" \
        --build-arg VERSION="${VERSION}" \
        -f packaging/deb/Dockerfile \
        -t "${image_tag}" \
        .

    # Extract the .deb from the container
    local container
    container=$(docker create "${image_tag}")
    mkdir -p dist
    docker cp "${container}:/out/." dist/
    docker rm "${container}" > /dev/null

    echo ""
    echo "==> Built: dist/eip-search_${VERSION}_${distro_tag}_all.deb"
    echo ""
    ls -lh "dist/eip-search_${VERSION}_${distro_tag}_all.deb"
}

built=0
for entry in "${DISTROS[@]}"; do
    IFS='|' read -r name base_image distro_tag <<< "${entry}"
    if [[ -z "${FILTER}" || "${name}" == "${FILTER}" ]]; then
        build_distro "${name}" "${base_image}" "${distro_tag}"
        built=$((built + 1))
    fi
done

if [[ ${built} -eq 0 ]]; then
    echo "ERROR: Unknown distro '${FILTER}'. Available: ubuntu-jammy, ubuntu-noble, ubuntu-plucky, debian-bookworm, debian-trixie, kali" >&2
    exit 1
fi

echo ""
echo "==> Done: ${built} package(s) built"
