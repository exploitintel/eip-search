ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}

ARG DISTRO_TAG

ENV DEBIAN_FRONTEND=noninteractive

# Build dependencies: Python for venv, Ruby for fpm
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip \
        ruby ruby-dev gcc make \
    && gem install --no-document fpm \
    && rm -rf /var/lib/apt/lists/*

# Copy source and build wheel inside the container
WORKDIR /src
COPY pyproject.toml LICENSE README.md ./
COPY eip_search/ eip_search/
COPY packaging/deb/preinst.sh /scripts/preinst.sh
COPY packaging/deb/postrm.sh /scripts/postrm.sh
RUN python3 -m venv /tmp/buildenv \
    && /tmp/buildenv/bin/pip install --no-cache-dir build \
    && /tmp/buildenv/bin/python -m build --wheel \
    && rm -rf /tmp/buildenv

# Install into the target venv location
RUN python3 -m venv /opt/eip-search \
    && /opt/eip-search/bin/pip install --no-cache-dir dist/*.whl

# Strip pip cache and unnecessary files from the venv
RUN find /opt/eip-search -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
    rm -rf /opt/eip-search/lib/python*/site-packages/pip* \
           /opt/eip-search/lib/python*/site-packages/setuptools* \
           /opt/eip-search/lib/python*/site-packages/pkg_resources*

# Create the CLI symlink
RUN mkdir -p /usr/local/bin \
    && ln -sf /opt/eip-search/bin/eip-search /usr/local/bin/eip-search

# Build .deb
ARG VERSION
RUN test -n "$VERSION" || { echo "ERROR: --build-arg VERSION is required"; exit 1; }
RUN test -n "$DISTRO_TAG" || { echo "ERROR: --build-arg DISTRO_TAG is required"; exit 1; }

RUN mkdir /out && fpm \
    -s dir \
    -t deb \
    -n eip-search \
    -v "${VERSION}" \
    -a all \
    --description "CLI intelligence tool for the Exploit Intelligence Platform — a modern searchsploit replacement" \
    --url "https://github.com/exploit-intel/eip-search" \
    --license "MIT" \
    --maintainer "Exploit Intelligence Platform" \
    --vendor "Exploit Intelligence Platform" \
    --category utils \
    --depends python3 \
    --deb-no-default-config-files \
    --before-install /scripts/preinst.sh \
    --after-remove /scripts/postrm.sh \
    -p "/out/eip-search_${VERSION}_${DISTRO_TAG}_all.deb" \
    -C / \
    opt/eip-search \
    usr/local/bin/eip-search
