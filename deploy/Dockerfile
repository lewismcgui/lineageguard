FROM python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b AS builder

ENV UV_NO_PROGRESS=1 \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app
RUN python -m pip install --no-cache-dir uv==0.11.26
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
COPY config ./config
COPY demo/acme_dbt ./demo/acme_dbt
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LINEAGEGUARD_RUN_ARTIFACT=/data/latest.json \
    PATH=/app/.venv/bin:$PATH

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
RUN useradd --no-create-home --uid 10001 lineageguard \
    && mkdir -p /data \
    && chown -R lineageguard:lineageguard /data

USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/runs/latest', timeout=2)"

CMD ["uvicorn", "lineageguard.review_ui.app:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
