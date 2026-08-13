FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="eip-search" \
      org.opencontainers.image.description="Command-line client for the Exploit Intelligence Platform" \
      org.opencontainers.image.source="https://github.com/exploitintel/eip-search" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/eip-search

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --no-cache-dir . \
    && groupadd --system eip \
    && useradd --system --gid eip --create-home eip \
    && install -d -o eip -g eip /work

USER eip
WORKDIR /work

ENTRYPOINT ["eip-search"]
