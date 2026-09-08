FROM python:3.12-slim AS test

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /scanner
COPY pyproject.toml README.md requirements.lock requirements-dev.lock ./
COPY app ./app
COPY policies ./policies
COPY packaging ./packaging
COPY tests ./tests
RUN python -m pip install --no-cache-dir -r requirements-dev.lock \
    && python -m pip install --no-cache-dir --no-deps .

USER 65532:65532
ENTRYPOINT ["pytest"]
CMD ["--cov=app", "--cov-report=term-missing"]
