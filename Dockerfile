# Stage 1: Build dependencies and download binaries
FROM python:3.11-slim as builder
WORKDIR /app
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt

# Install tools required to download binaries
RUN apt-get update && apt-get install -y wget unzip curl

# ProjectDiscovery (Subfinder & Httpx)
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && \
    unzip subfinder_2.6.6_linux_amd64.zip -d /bin/ && \
    chmod +x /bin/subfinder

RUN wget https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip && \
    unzip httpx_1.6.0_linux_amd64.zip -d /bin/ && \
    chmod +x /bin/httpx

# Tomnomnom (Assetfinder)
RUN wget https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz && \
    tar -xzf assetfinder-linux-amd64-0.1.1.tgz -C /bin/ && \
    chmod +x /bin/assetfinder

# Findomain (Rust)
RUN curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux && \
    mv findomain-linux /bin/findomain && \
    chmod +x /bin/findomain

# Stage 2: Final Image
FROM python:3.11-slim
WORKDIR /app

RUN useradd -m -s /bin/bash wascanuser

# Copy python dependencies
COPY --from=builder /app/wheels /wheels
COPY --from=builder /app/requirements.txt .
RUN pip install --no-cache /wheels/*

# Copy binaries from builder
COPY --from=builder /bin/subfinder /usr/local/bin/
COPY --from=builder /bin/httpx /usr/local/bin/
COPY --from=builder /bin/assetfinder /usr/local/bin/
COPY --from=builder /bin/findomain /usr/local/bin/

COPY . /app
RUN chown -R wascanuser:wascanuser /app

USER wascanuser
ENTRYPOINT ["python", "wascan.py"]
