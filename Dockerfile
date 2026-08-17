FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src
COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY osai_security ./osai_security
RUN python -m pip wheel --wheel-dir /wheels .

FROM python:3.12-slim

ENV ADVERSCOPE_HOME=/state \
    AISEC_PORT=8091 \
    AISEC_CONTAINER_API_ONLY=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --gid 10001 adverscope \
    && useradd --uid 10001 --gid adverscope --create-home --shell /usr/sbin/nologin adverscope \
    && mkdir -p /state \
    && chown adverscope:adverscope /state
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

USER adverscope
EXPOSE 8091
VOLUME ["/state"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8091/api/runtime', timeout=3).read(100)"
CMD ["python", "-m", "osai_security.container_entrypoint"]
