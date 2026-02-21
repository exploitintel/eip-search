#!/bin/sh
set -e

VERSION=$(cat /opt/eip-search/.package-version)

python3 -m venv /opt/eip-search
/opt/eip-search/bin/pip install --no-cache-dir "eip-search==${VERSION}"
ln -sf /opt/eip-search/bin/eip-search /usr/local/bin/eip-search

exit 0
