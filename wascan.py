#!/usr/bin/env python3
"""
wascan — Web Application Vulnerability Scanner
"""

import asyncio
import argparse
import json
import logging
import os
import pkgutil
import importlib
import sys
import urllib.parse
import warnings
import shutil
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
import aiohttp
from bs4 import BeautifulSoup

warnings.filterwarnings("ignore", category=DeprecationWarning)

# ==========================================
# 1. Logging & Config
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

@dataclass
class ScanConfig:
    max_concurrency: int = 20
    quiet_mode: bool = False
    output_dir: str = ""

@dataclass
class SubdomainItem:
    name: str
    status: int = 0
    title: str = ""

@dataclass
class Finding:
    title: str
    severity: str
    description: str
    url: str = ""

@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str = ""
    findings: list = field(default_factory=list)
    crawled_urls: list = field(default_factory=list)
    discovered_subdomains: list = field(default_factory=list)

    def sorted_findings(self): 
        return sorted(self.findings, key=lambda f: {"critical":0, "high":1, "medium":2, "low":3, "info":4}.get(f.severity, 99))

# ==========================================
# 2. Reconnaissance Engine (Built-in)
# ==========================================
async def execute_subdomain_recon(domain: str, result: ScanResult):
    logger.info(f"Phase: Gathering subdomains for {domain}...")
    subdomains = set()

    # Passive Gathering 
    cmds = [
        f"subfinder -d {domain} -silent",
        f"assetfinder --subs-only {domain}",
        f"findomain -t {domain} -q 2> /dev/null"
    ]
    
    for cmd in cmds:
        try:
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
            for line in stdout.splitlines():
                sub = line.strip().decode('utf-8').lower()
                if sub.endswith(domain): subdomains.add(sub)
        except Exception: 
            pass

    if not subdomains:
        logger.warning(f"No subdomains found for {domain}.")
        return

    logger.info(f"Phase: Probing {len(subdomains)} discovered subdomains with httpx...")
    httpx_path = shutil.which("httpx")
    
    if not httpx_path:
        logger.error("httpx not found. Saving unprobed subdomains directly.")
        for sub in subdomains:
            result.discovered_subdomains.append(SubdomainItem(name=sub))
        return

    try:
        target_input = "\n".join([f"http://{s}" for s in subdomains]).encode()
        proc = await asyncio.create_subprocess_shell(
            f"{httpx_path} -silent -status-code -no-color",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate(input=target_input)
        
        for line in stdout.splitlines():
            output = line.strip().decode('utf-8')
            if not output: continue
            parts = output.split(' ')
            url = parts[0]
            name = urllib.parse.urlparse(url).netloc.split(':')[0]
            
            status = 0
            for part in parts[1:]:
                if part.startswith('[') and part.endswith(']'):
                    inner = part[1:-1]
                    if inner.isdigit(): status = int(inner)

            result.discovered_subdomains.append(SubdomainItem(name=name, status=status, title="Live"))
            
    except Exception as e:
        logger.error(f"httpx failed: {e}")

    # Fallback safety net
    if not result.discovered_subdomains:
        for sub in subdomains:
            result.discovered_subdomains.append(SubdomainItem(name=sub))

async def execute_archive_recon(domain: str, result: ScanResult, output_dir: str):
    targets = {domain}
    for sub in result.discovered_subdomains:
        targets.add(sub.name)
            
    target_list_str = "\n".join(targets)
    logger.info(f"Phase: Fetching historical URLs for {len(targets)} domains/subdomains via gau...")
    
    gau_path = shutil.which("gau")
    if not gau_path:
        logger.warning("gau not found. Skipping archive recon.")
        return

    try:
        proc = await asyncio.create_subprocess_shell(
            f"{gau_path} --threads 10",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate(input=target_list_str.encode())
        historical_urls = set(line.strip().decode('utf-8') for line in stdout.splitlines() if line.strip())
        
        useful_urls = set()
        excluded_exts = ('.jpg', '.jpeg', '.png', '.gif', '.css', '.woff', '.woff2', '.svg', '.ttf', '.js', '.ico')
        
        for url in historical_urls:
            try:
                p = urllib.parse.urlparse(url)
                if p.path.lower().endswith(excluded_exts): continue
                if p.query: useful_urls.add(url)
            except: pass
        
        if useful_urls:
            logger.info(f"Found {len(useful_urls)} historical URLs with parameters.")
            with open(os.path.join(output_dir, "historical_parameters.txt"), "w") as f:
                for u in useful_urls:
                    f.write(u + "\n")
                    if u not in result.crawled_urls:
                        result.crawled_urls.append(u)
        else:
            logger.warning("gau returned 0 viable URLs with parameters.")
            
    except Exception as e:
        logger.error(f"gau execution failed: {e}")

# ==========================================
# 3. Crawler & Plugin Engine
# ==========================================
async def fetch(session, url, config, semaphore, method="GET"):
    async with semaphore:
        try:
            resp = await session.request(method, url, headers={"User-Agent": "wascan/3.0"}, allow_redirects=True, ssl=False)
            await resp.read()
            return resp
        except Exception:
            return None

async def spider(session, base_url, config, semaphore):
    base_domain = urllib.parse.urlparse(base_url).netloc
    visited, queue = set(), [(base_url, 0)]
    while queue and len(visited) < 50:
        url, depth = queue.pop(0)
        if url in visited: continue
        visited.add(url)
        resp = await fetch(session, url, config, semaphore)
        if not resp or resp.status != 200 or "html" not in resp.headers.get("Content-Type", ""): continue
        if depth < 2:
            soup = BeautifulSoup((await resp.read()).decode(errors="ignore"), "lxml")
            for tag in soup.find_all("a", href=True):
                norm = urllib.parse.urldefrag(urllib.parse.urljoin(url, tag.get("href", "").strip()))[0]
                if urllib.parse.urlparse(norm).netloc == base_domain and norm not in visited:
                    queue.append((norm, depth + 1))
    return list(visited)

async def run_plugins(session, target_url, config, semaphore, result):
    tasks = []
    try:
        import modules
        for _, module_name, _ in pkgutil.iter_modules(modules.__path__):
            # Skip the old separated recon modules if they still exist in the folder
            if module_name in ["subdomain_recon", "archive_recon"]: continue
            mod = importlib.import_module(f"modules.{module_name}")
            if hasattr(mod, "run_check"):
                tasks.append(mod.run_check(session, target_url, config, semaphore, result))
        if tasks: await asyncio.gather(*tasks)
    except ImportError: pass

# ==========================================
# 4. Main Execution
# ==========================================
async def run_scan(target_url: str, config: ScanConfig) -> ScanResult:
    if not target_url.startswith(("http://", "https://")): target_url = f"http://{target_url}"
    domain = urllib.parse.urlparse(target_url).netloc.split(':')[0]
    if domain.startswith("www."): domain = domain[4:]
        
    output_dir = os.path.join(os.getcwd(), domain)
    os.makedirs(output_dir, exist_ok=True)
    config.output_dir = output_dir
    
    semaphore = asyncio.Semaphore(config.max_concurrency)
    result = ScanResult(target=target_url, started_at=datetime.now(timezone.utc).isoformat())
    
    logger.info(f"Starting scan against {target_url}")
    logger.info(f"Output directory initialized at: {output_dir}")
    
    # Run the built-in Recon Phases
    await execute_subdomain_recon(domain, result)
    await execute_archive_recon(domain, result, output_dir)
    
    async with aiohttp.ClientSession() as session:
        logger.info("Phase: Spidering target application...")
        urls = await spider(session, target_url, config, semaphore)
        for u in urls:
            if u not in result.crawled_urls:
                result.crawled_urls.append(u)
                
        logger.info(f"Phase: Spider completed. Testing {len(result.crawled_urls)} total URLs.")
        
        with open(os.path.join(output_dir, "crawled_urls.txt"), "w") as f:
            for u in result.crawled_urls: f.write(u + "\n")
        
        logger.info("Phase: Executing active vulnerability plugins...")
        await run_plugins(session, target_url, config, semaphore, result)
        
    result.finished_at = datetime.now(timezone.utc).isoformat()
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="wascan — Web Application Vulnerability Scanner")
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument("--concurrency", type=int, default=20)
    args = parser.parse_args()
    
    config = ScanConfig(max_concurrency=args.concurrency)
    result = asyncio.run(run_scan(args.target, config))
    
    logger.info(f"Scan complete. Found {len(result.findings)} issues.")
    for f in result.sorted_findings():
        color = ColorFormatter.COLORS.get(logging.CRITICAL) if f.severity == "critical" else \
                ColorFormatter.COLORS.get(logging.ERROR) if f.severity == "high" else \
                ColorFormatter.COLORS.get(logging.WARNING) if f.severity == "medium" else \
                ColorFormatter.COLORS.get(logging.INFO)
        print(f"{color}[{f.severity.upper()}]\033[0m {f.title} - {f.url}")
