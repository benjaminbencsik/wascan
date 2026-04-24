#!/usr/bin/env python3
"""
wascan — Web Application Vulnerability Scanner
Usage: python3 wascan.py <target_url> [options]
"""

import asyncio
import argparse
import json
import logging
import os
import pkgutil
import importlib
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
# 1. Standardize & Colorize Logging
# ==========================================
class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\033[90m",     # Grey
        logging.INFO: "\033[94m",      # Blue
        logging.WARNING: "\033[93m",   # Yellow
        logging.ERROR: "\033[91m",     # Red
        logging.CRITICAL: "\033[1;91m" # Bold Red
    }
    RESET = "\033[0m"

    def format(self, record):
        log_color = self.COLORS.get(record.levelno, self.RESET)
        format_str = f"{log_color}[%(levelname)s]{self.RESET} %(message)s"
        formatter = logging.Formatter(format_str)
        return formatter.format(record)

logger = logging.getLogger("wascan")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(ColorFormatter())
logger.handlers = [handler]
logger.propagate = False

# ==========================================
# 2. Scan Configuration
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

    # Payloads
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
# 3. Data Structures
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
class DiscoveredForm:
    page_url: str
    action: str
    method: str
    inputs: list[dict]

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
# 4. Utilities
# ==========================================
def load_wordlist(filepath: str) -> list[str]:
    if not os.path.exists(filepath):
        logger.warning(f"Wordlist not found: {filepath}")
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def export_sarif(result: ScanResult, filename: str = "wascan_results.sarif"):
    sarif_output = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "wascan", 
                    "informationUri": "https://github.com/benjaminbencsik/wascan"
                }
            },
            "results": []
        }]
    }
    
    for finding in result.findings:
        sarif_output["runs"][0]["results"].append({
            "ruleId": finding.title.replace(" ", "_").upper(),
            "message": {"text": finding.description},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.url}}}],
        })

    with open(filename, 'w') as f:
        json.dump(sarif_output, f, indent=2)
    logger.info(f"Exported findings to {filename}")

# ==========================================
# 5. HTTP Helpers with Concurrency Throttling
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
            kwargs["proxy"] = kwargs["proxy"] = config.proxy_url

        try:
            resp = await session.request(method, url, **kwargs)
            await resp.read()
            return resp
        except Exception as e:
            if not config.quiet_mode:
                logger.debug(f"Request failed for {url}: {e}")
            return None

# ==========================================
# 6. Spider / Crawler Module 
# ==========================================
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
    visited = set()
    queue = [(base_url, 0)]
    found_forms = []

    def in_scope(url: str) -> bool:
        p = urllib.parse.urlparse(url)
        return p.netloc == base_domain and p.scheme in ("http", "https")

    def normalise(url: str, page_url: str) -> Optional[str]:
        if not url or url.startswith(("#", "mailto:", "javascript:", "tel:")): 
            return None
        return urllib.parse.urldefrag(urllib.parse.urljoin(page_url, url.strip()))[0]

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        if url in visited: 
            continue
        visited.add(url)

        # Removed the per-URL logging here to keep the terminal clean

        resp = await fetch(session, url, config, semaphore)
        if not resp or resp.status != 200 or "html" not in resp.headers.get("Content-Type", ""):
            continue

        body = (await resp.read()).decode(errors="ignore")
        soup = BeautifulSoup(body, "lxml")

        if depth < max_depth:
            for tag in soup.find_all("a", href=True):
                norm = normalise(tag.get("href"), url)
                if norm and norm not in visited and in_scope(norm):
                    queue.append((norm, depth + 1))

        for form in soup.find_all("form"):
            action = normalise(form.get("action", url), url) or url
            method = (form.get("method", "get") or "get").upper()
            inputs = []
            
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text").lower(),
                    "value": inp.get("value", ""),
                })
            
            if any(i["name"] for i in inputs):
                found_forms.append(DiscoveredForm(page_url=url, action=action, method=method, inputs=inputs))

    return list(visited), found_forms

# ==========================================
# 7. Dynamic Module Loader
# ==========================================
async def run_plugins(
    session: aiohttp.ClientSession, 
    target_url: str, 
    config: ScanConfig, 
    semaphore: asyncio.Semaphore, 
    result: ScanResult
):
    tasks = []
    try:
        import modules
        for _, module_name, _ in pkgutil.iter_modules(modules.__path__):
            # Exclude subdomain recon since we run it in Phase 1 now
            if module_name == "subdomain_recon":
                continue
                
            mod = importlib.import_module(f"modules.{module_name}")
            if hasattr(mod, "run_check"):
                tasks.append(mod.run_check(session, target_url, config, semaphore, result))
        
        if tasks:
            await asyncio.gather(*tasks)
    except ImportError:
        logger.warning("No 'modules' package found. Create a 'modules/' directory with an '__init__.py' file to enable plugins.")

# ==========================================
# 8. Core Engine
# ==========================================
async def run_scan(target_url: str, config: ScanConfig) -> ScanResult:
    # Ensure scheme is present so urllib parses it correctly
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"
        
    semaphore = asyncio.Semaphore(config.max_concurrency)
    result = ScanResult(target=target_url, started_at=datetime.now(timezone.utc).isoformat())
    
    logger.info(f"Starting scan against {target_url} with concurrency {config.max_concurrency}")
    
    async with aiohttp.ClientSession() as session:
        # Phase 1: Subdomain Reconnaissance
        try:
            from modules import subdomain_recon
            if hasattr(subdomain_recon, "run_check"):
                # The subdomain_recon module handles its own high-level logging
                await subdomain_recon.run_check(session, target_url, config, semaphore, result)
        except ImportError:
            pass 
        
        # Phase 2: Application Spider
        logger.info("Phase: Spidering target application...")
        urls, forms = await spider(session, target_url, config, semaphore)
        logger.info(f"Phase: Spider completed. Found {len(urls)} URLs and {len(forms)} forms.")
        result.crawled_urls = urls
        
        # Phase 3: Active Vulnerability Scanning Plugins
        logger.info("Phase: Executing active vulnerability scanning plugins...")
        await run_plugins(session, target_url, config, semaphore, result)
        
    result.finished_at = datetime.now(timezone.utc).isoformat()
    export_sarif(result)
    return result

# ==========================================
# 9. CLI Entry Point
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
        for f in result.sorted_findings():
            # Apply color to the final finding output based on severity
            color = ColorFormatter.COLORS.get(logging.CRITICAL) if f.severity == "critical" else \
                    ColorFormatter.COLORS.get(logging.ERROR) if f.severity == "high" else \
                    ColorFormatter.COLORS.get(logging.WARNING) if f.severity == "medium" else \
                    ColorFormatter.COLORS.get(logging.INFO)
            print(f"{color}[{f.severity.upper()}]\033[0m {f.title} - {f.url}")
