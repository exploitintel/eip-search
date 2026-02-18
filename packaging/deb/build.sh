#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

VERSION=$(grep '^__version__' eip_search/__init__.py | cut -d'"' -f2)

echo "==> Building eip-search ${VERSION} .deb package"
echo ""

docker build \
    --platform linux/amd64 \
    --build-arg VERSION="${VERSION}" \
    -f packaging/deb/Dockerfile \
    -t eip-search-deb-builder \
    .

# Extract the .deb from the container
CONTAINER=$(docker create eip-search-deb-builder)
mkdir -p dist
docker cp "${CONTAINER}:/out/." dist/
docker rm "${CONTAINER}" > /dev/null

echo ""
echo "==> Built: dist/eip-search_${VERSION}_amd64.deb"
echo ""
ls -lh "dist/eip-search_${VERSION}_amd64.deb"
