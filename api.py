cat << 'EOF' > wascan.py
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
        logging.DEBUG: "\033[90m",
        logging.INFO: "\033[94m",
        logging.WARNING: "\033[93m",
        logging.ERROR: "\033[91m",
        logging.CRITICAL: "\033[1;91m"
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
    max_concurrency: int = 20
    quiet_mode: bool = False
    output_dir: str = ""
    request_delay: float = 0.0
    stealth_mode: bool = False
    auth_headers: dict = field(default_factory=dict)
    auth_cookies: dict = field(default_factory=dict)
    proxy_url: str = ""

# ==========================================
# 3. Data Structures
# ==========================================
@dataclass
class Finding:
    title: str
    severity: str
    description: str
    url: str = ""
    recommendation: str = ""

@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str = ""
    findings: list = field(default_factory=list)
    crawled_urls: list = field(default_factory=list)
    discovered_subdomains: list = field(default_factory=list)

    def add(self, finding: Finding): 
        self.findings.append(finding)

    def sorted_findings(self): 
        return sorted(self.findings, key=lambda f: {"critical":0, "high":1, "medium":2, "low":3, "info":4}.get(f.severity, 99))

# ==========================================
# 4. Utilities
# ==========================================
def export_sarif(result: ScanResult, filename: str):
    sarif_output = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "wascan"}}, "results": []}]
    }
    for finding in result.findings:
        sarif_output["runs"][0]["results"].append({
            "ruleId": finding.title.replace(" ", "_").upper(),
            "message": {"text": finding.description},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.url}}}],
        })
    with open(filename, 'w') as f:
        json.dump(sarif_output, f, indent=2)

# ==========================================
# 5. HTTP Helpers
# ==========================================
async def fetch(session, url, config, semaphore, method="GET", headers=None, allow_redirects=True):
    async with semaphore:
        merged_headers = {"User-Agent": "wascan/2.0"}
        if headers: 
            merged_headers.update(headers)
        try:
            resp = await session.request(method, url, headers=merged_headers, allow_redirects=allow_redirects, ssl=False)
            await resp.read()
            return resp
        except Exception:
            return None

# ==========================================
# 6. Spider / Crawler Module 
# ==========================================
async def spider(session, base_url, config, semaphore):
    base_domain = urllib.parse.urlparse(base_url).netloc
    visited, queue = set(), [(base_url, 0)]

    while queue and len(visited) < 50:
        url, depth = queue.pop(0)
        if url in visited: 
            continue
        visited.add(url)

        resp = await fetch(session, url, config, semaphore)
        if not resp or resp.status != 200 or "html" not in resp.headers.get("Content-Type", ""):
            continue

        if depth < 2:
            soup = BeautifulSoup((await resp.read()).decode(errors="ignore"), "lxml")
            for tag in soup.find_all("a", href=True):
                norm = urllib.parse.urldefrag(urllib.parse.urljoin(url, tag.get("href", "").strip()))[0]
                if urllib.parse.urlparse(norm).netloc == base_domain and norm not in visited:
                    queue.append((norm, depth + 1))
                    
    return list(visited)

# ==========================================
# 7. Dynamic Module Loader
# ==========================================
async def run_plugins(session, target_url, config, semaphore, result):
    tasks = []
    try:
        import modules
        for _, module_name, _ in pkgutil.iter_modules(modules.__path__):
            if module_name in ["subdomain_recon", "archive_recon"]:
                continue
            mod = importlib.import_module(f"modules.{module_name}")
            if hasattr(mod, "run_check"):
                tasks.append(mod.run_check(session, target_url, config, semaphore, result))
        if tasks:
            await asyncio.gather(*tasks)
    except ImportError:
        pass

# ==========================================
# 8. Core Engine
# ==========================================
async def run_scan(target_url: str, config: ScanConfig) -> ScanResult:
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"
        
    domain_name = urllib.parse.urlparse(target_url).netloc.split(':')[0]
    if domain_name.startswith("www."): 
        domain_name = domain_name[4:]
        
    output_dir = os.path.join(os.getcwd(), domain_name)
    os.makedirs(output_dir, exist_ok=True)
    config.output_dir = output_dir
    
    semaphore = asyncio.Semaphore(config.max_concurrency)
    result = ScanResult(target=target_url, started_at=datetime.now(timezone.utc).isoformat())
    
    logger.info(f"Starting scan against {target_url}")
    logger.info(f"Output directory initialized at: {output_dir}")
    
    async with aiohttp.ClientSession() as session:
        # Phase 1: Subdomain Recon
        try:
            from modules import subdomain_recon
            if hasattr(subdomain_recon, "run_check"):
                await subdomain_recon.run_check(session, target_url, config, semaphore, result)
                if result.discovered_subdomains:
                    with open(os.path.join(output_dir, "subdomains.txt"), "w") as f:
                        for sub in result.discovered_subdomains:
                            f.write(f"{sub.name} - {sub.ip} [{sub.status}]\n")
        except ImportError: 
            pass 

        # Phase 1.5: Archive Recon (gau + gf)
        try:
            from modules import archive_recon
            if hasattr(archive_recon, "run_check"):
                await archive_recon.run_check(session, target_url, config, semaphore, result)
        except ImportError: 
            pass 
        
        # Phase 2: Application Spider
        logger.info("Phase: Spidering target application...")
        urls = await spider(session, target_url, config, semaphore)
        for u in urls:
            if u not in result.crawled_urls:
                result.crawled_urls.append(u)
                
        logger.info(f"Phase: Spider completed. Testing {len(result.crawled_urls)} total URLs.")
        
        with open(os.path.join(output_dir, "crawled_urls.txt"), "w") as f:
            for u in result.crawled_urls: 
                f.write(u + "\n")
        
        # Phase 3: Active Vulnerability Scanning
        logger.info("Phase: Executing active vulnerability plugins...")
        await run_plugins(session, target_url, config, semaphore, result)
        
    result.finished_at = datetime.now(timezone.utc).isoformat()
    export_sarif(result, os.path.join(output_dir, f"{domain_name}_results.sarif"))
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    
    config = ScanConfig(max_concurrency=args.concurrency, quiet_mode=args.quiet)
    if config.quiet_mode:
        logger.setLevel(logging.WARNING)

    result = asyncio.run(run_scan(args.target, config))
    
    if not config.quiet_mode:
        logger.info(f"Scan complete. Found {len(result.findings)} issues.")
        for f in result.sorted_findings():
            color = ColorFormatter.COLORS.get(logging.CRITICAL) if f.severity == "critical" else \
                    ColorFormatter.COLORS.get(logging.ERROR) if f.severity == "high" else \
                    ColorFormatter.COLORS.get(logging.WARNING) if f.severity == "medium" else \
                    ColorFormatter.COLORS.get(logging.INFO)
            print(f"{color}[{f.severity.upper()}]\033[0m {f.title} - {f.url}")
EOF
