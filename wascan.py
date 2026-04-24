#!/usr/bin/env python3
"""
wascan — Web Application Vulnerability Scanner
Usage: python3 wascan.py <target_url> [options]
"""

import asyncio
import argparse
import csv
import json
import logging
import os
import random
import sys
import urllib.parse
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import aiohttp
from bs4 import BeautifulSoup

warnings.filterwarnings("ignore", category=DeprecationWarning)

# ==========================================
# 1. Standardize Logging
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("wascan")

# ==========================================
# 2. Scan Configuration (Replaces Globals)
# ==========================================
@dataclass
class ScanConfig:
    auth_headers: dict[str, str] = field(default_factory=dict)
    auth_cookies: dict[str, str] = field(default_factory=dict)
    proxy_url: str = ""
    request_delay: float = 0.0
    stealth_mode: bool = False
    waf_detected: bool = False
    waf_bypass_mode: bool = False
    quiet_mode: bool = False
    max_concurrency: int = 20

    xss_payloads: list[str] = field(default_factory=lambda: [
        "<script>alert('XSS_CANARY')</script>",
        "<img src=x onerror=alert('XSS_CANARY')>",
        "'\"><svg onload=alert('XSS_CANARY')>",
        "javascript:alert('XSS_CANARY')",
    ])
    sqli_payloads: list[str] = field(default_factory=lambda: [
        "'", '"', "' OR '1'='1", "' OR 1=1--",
        "\" OR \"\"=\"", "') OR ('1'='1", "'; WAITFOR DELAY '0:0:2'--",
    ])

# ==========================================
# Data Structures
# ==========================================
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

@dataclass
class Finding:
    title: str
    severity: str
    description: str
    evidence: str = ""
    url: str = ""
    recommendation: str = ""

@dataclass
class Subdomain:
    name: str
    ip: str = ""
    status: int = 0
    title: str = ""

@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    crawled_urls: list[str] = field(default_factory=list)
    discovered_subdomains: list[Subdomain] = field(default_factory=list)

    def add(self, finding: Finding):
        self.findings.append(finding)

    def sorted_findings(self):
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

# ==========================================
# Wordlists (Keep your existing arrays here)
# ==========================================
CONTENT_WORDLIST = [
    "admin", "administrator", "api", "app", "assets", "auth", "backup",
    # ... (Paste your existing 100+ paths here) ...
]

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "pop3", "imap", "ns1", "ns2",
    # ... (Paste your existing subdomain prefixes here) ...
]

# ==========================================
# 3. HTTP Helpers with Concurrency Throttling
# ==========================================
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (wascan/2.0; security-research)",
    "Accept": "text/html,application/xhtml+xml,application/json,*/*",
}

STEALTH_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
]

async def fetch(
    session: aiohttp.ClientSession, 
    url: str, 
    config: ScanConfig,
    semaphore: asyncio.Semaphore,
    method: str = "GET",
    data: dict = None, 
    headers: dict = None, 
    allow_redirects: bool = True,
    timeout: int = 10
) -> Optional[aiohttp.ClientResponse]:
    
    async with semaphore:
        if config.request_delay > 0:
            delay = config.request_delay * random.uniform(0.7, 1.8) if config.stealth_mode else config.request_delay
            await asyncio.sleep(delay)

        base_headers = DEFAULT_HEADERS.copy()
        if config.stealth_mode:
            base_headers["User-Agent"] = random.choice(STEALTH_UAS)

        merged_headers = {**base_headers, **config.auth_headers, **(headers or {})}
        
        kwargs = dict(
            data=data, 
            headers=merged_headers,
            cookies=config.auth_cookies if config.auth_cookies else None,
            allow_redirects=allow_redirects,
            timeout=aiohttp.ClientTimeout(total=timeout),
            ssl=False,
        )
        
        if config.proxy_url:
            kwargs["proxy"] = config.proxy_url

        try:
            resp = await session.request(method, url, **kwargs)
            await resp.read()
            return resp
        except Exception as e:
            if not config.quiet_mode:
                logger.debug(f"Request failed for {url}: {e}")
            return None

# ==========================================
# 4. Spider / Crawler Module
# ==========================================
@dataclass
class DiscoveredForm:
    page_url: str
    action: str
    method: str
    inputs: list[dict]

async def spider(
    session: aiohttp.ClientSession, 
    base_url: str, 
    config: ScanConfig,
    semaphore: asyncio.Semaphore,
    max_depth: int = 2, 
    max_pages: int = 50
) -> tuple[list[str], list[DiscoveredForm]]:
    
    parsed_base = urllib.parse.urlparse(base_url)
    base_domain = parsed_base.netloc

    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(base_url, 0)]
    found_forms: list[DiscoveredForm] = []

    def in_scope(url: str) -> bool:
        p = urllib.parse.urlparse(url)
        return p.netloc == base_domain and p.scheme in ("http", "https")

    def normalise(url: str, page_url: str) -> Optional[str]:
        url = url.strip()
        if not url or url.startswith(("#", "mailto:", "javascript:", "tel:")):
            return None
        joined = urllib.parse.urljoin(page_url, url)
        return urllib.parse.urldefrag(joined)[0]

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        if not config.quiet_mode:
            logger.info(f"Crawling: {url}")

        resp = await fetch(session, url, config, semaphore)
        if not resp or resp.status != 200:
            continue

        ct = resp.headers.get("Content-Type", "")
        if "html" not in ct:
            continue

        body = (await resp.read()).decode(errors="ignore")
        soup = BeautifulSoup(body, "lxml")

        if depth < max_depth:
            for tag in soup.find_all("a", href=True):
                norm = normalise(tag["href"], url)
                if norm and norm not in visited and in_scope(norm):
                    queue.append((norm, depth + 1))

        for form in soup.find_all("form"):
            action = form.get("action", url)
            action = normalise(action, url) or url
            method = (form.get("method", "get") or "get").upper()
            inputs = []
            
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text").lower(),
                    "value": inp.get("value", ""),
                })
            
            if any(i["name"] for i in inputs):
                found_forms.append(DiscoveredForm(
                    page_url=url, action=action, method=method, inputs=inputs
                ))

    return list(visited), found_forms

# ==========================================
# 5. Security Checks
# ==========================================
async def check_sensitive_files(session: aiohttp.ClientSession, base_url: str, config: ScanConfig, semaphore: asyncio.Semaphore, result: ScanResult):
    paths = [
        ("/.env", "Exposed .env file", "critical"),
        ("/.git/config", "Exposed .git directory", "critical"),
        ("/backup.sql", "Exposed database backup", "critical"),
        ("/phpinfo.php", "PHP info page exposed", "high"),
    ]
    
    for path, title, severity in paths:
        target = urllib.parse.urljoin(base_url, path)
        resp = await fetch(session, target, config, semaphore)
        if resp and resp.status == 200:
            result.add(Finding(
                title=title,
                severity=severity,
                description=f"Sensitive file found at {path}",
                url=target,
                recommendation="Remove the file or restrict access to it."
            ))

# ==========================================
# Core Engine
# ==========================================
async def run_scan(target_url: str, config: ScanConfig) -> ScanResult:
    semaphore = asyncio.Semaphore(config.max_concurrency)
    result = ScanResult(target=target_url, started_at=datetime.now(timezone.utc).isoformat())
    
    logger.info(f"Starting scan against {target_url} with concurrency {config.max_concurrency}")
    
    async with aiohttp.ClientSession() as session:
        urls, forms = await spider(session, target_url, config, semaphore)
        logger.info(f"Spider completed. Found {len(urls)} URLs and {len(forms)} forms.")
        result.crawled_urls = urls
        
        # Execute checks concurrently using asyncio.gather
        tasks = [
            check_sensitive_files(session, target_url, config, semaphore, result),
            # Add other remaining vulnerability checks here
        ]
        
        await asyncio.gather(*tasks)
        
    result.finished_at = datetime.now(timezone.utc).isoformat()
    return result

# ==========================================
# CLI Entry Point
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="wascan — Web Application Vulnerability Scanner")
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument("--concurrency", type=int, default=20, help="Maximum concurrent requests (default: 20)")
    parser.add_argument("--quiet", action="store_true", help="Suppress logging output")
    args = parser.parse_args()
    
    config = ScanConfig(
        max_concurrency=args.concurrency,
        quiet_mode=args.quiet
    )
    
    if config.quiet_mode:
        logger.setLevel(logging.WARNING)

    result = asyncio.run(run_scan(args.target, config))
    
    if not config.quiet_mode:
        logger.info(f"Scan complete. Found {len(result.findings)} issues.")
