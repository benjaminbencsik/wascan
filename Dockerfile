FROM python:3.11-slim

LABEL maintainer="security@example.com"
LABEL description="wascan - Web Application Vulnerability Scanner"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY wascan.py .

RUN playwright install --with-deps chromium

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "wascan.py"]
