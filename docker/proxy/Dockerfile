FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim

RUN groupadd -r proxy && useradd -r -g proxy -d /app -s /sbin/nologin proxy

WORKDIR /app

COPY --from=builder /install /usr/local
COPY proxy/ ./proxy/

RUN chown -R proxy:proxy /app

USER proxy

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

CMD ["uvicorn", "proxy.main:app", "--host", "0.0.0.0", "--port", "8080"]
