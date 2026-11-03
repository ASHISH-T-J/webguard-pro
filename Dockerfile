FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY webguard ./webguard
RUN pip install --no-cache-dir ".[all]" \
 && python -m playwright install --with-deps chromium   # headless browser for DOM XSS verification

# reports and the findings database live in mounted volumes
VOLUME ["/reports", "/root/.webguard"]
WORKDIR /reports
ENTRYPOINT ["webguard"]
CMD ["--help"]
