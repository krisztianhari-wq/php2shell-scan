# php2shell-scan – sadrobot. Nem root, csak olvasható kód, csak a /data írható (használati napló).
# Kizárólag kimenő GET kéréseket indít (fejléc-lekérés); nincs emelt jogosultság.
FROM python:3.12.14-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TZ=Europe/Budapest \
    PHP2SHELL_LOG=/data/usage.log.jsonl PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --system --uid 10009 --home /app --shell /usr/sbin/nologin php2s \
    && mkdir -p /data && chown php2s:php2s /data && chmod 700 /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip uninstall -y pip setuptools wheel 2>/dev/null || true
COPY app ./app
RUN chmod -R a-w /app
USER php2s
EXPOSE 8862
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request;urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8862/healthz',headers={'Host':'localhost'}),timeout=4)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8862", "--proxy-headers", "--forwarded-allow-ips", "*", \
     "--no-server-header", "--limit-concurrency", "64", "--timeout-keep-alive", "5", "--no-access-log"]
