FROM ghcr.io/google/osv-scanner:v2.2.4@sha256:f7ba4be68bac8086b1f88fd598fdca1ca67239c79ad2c2b5c78e03a82e5187c4 AS osv

FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp/scanner-home

WORKDIR /srv/scanner

RUN groupadd --gid 65532 scanner \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /tmp/scanner-home \
       --shell /usr/sbin/nologin scanner

COPY requirements.lock ./locks/endpoint.requirements.lock
COPY cloud/requirements.lock ./locks/cloud.requirements.lock
RUN python -m pip install --no-cache-dir -r locks/endpoint.requirements.lock \
    && python -m pip install --no-cache-dir -r locks/cloud.requirements.lock

COPY app ./app
COPY cloud_service ./cloud_service
COPY policies ./policies
COPY cloud/entrypoints ./cloud/entrypoints

RUN chmod 0555 cloud/entrypoints/*.sh \
    && mkdir -p /tmp/scanner-home /var/cache/scanner-tools \
    && chown -R scanner:scanner /tmp/scanner-home /var/cache/scanner-tools

USER 65532:65532

FROM runtime AS api
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=6 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=2).read()"]
ENTRYPOINT ["/srv/scanner/cloud/entrypoints/api.sh"]

FROM runtime AS worker
USER 0:0
COPY --from=osv /osv-scanner /usr/local/bin/osv-scanner
COPY cloud/tools.requirements.lock ./locks/tools.requirements.lock
RUN python -m pip install --no-cache-dir -r locks/tools.requirements.lock \
    && chmod 0555 /usr/local/bin/osv-scanner
USER 65532:65532
ENTRYPOINT ["/srv/scanner/cloud/entrypoints/worker.sh"]
