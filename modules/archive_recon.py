import asyncio
import logging
import os
import urllib.parse
import re
import shutil

logger = logging.getLogger("wascan")

async def run_check(session, target_url, config, semaphore, result):
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc.split(':')[0]
    if domain.startswith("www."):
        domain = domain[4:]

    targets = {domain}
    for sub in result.discovered_subdomains:
        targets.add(sub.name)
            
    target_list_str = "\n".join(targets)

    logger.info(f"Phase: Fetching historical URLs for {len(targets)} domains/subdomains via gau...")
    
    # DYNAMIC PATH DISCOVERY
    gau_path = shutil.which("gau")
    if not gau_path:
        logger.warning("gau not found in system PATH. Skipping.")
        return

    try:
        proc = await asyncio.create_subprocess_shell(
            f"{gau_path} --threads 10",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate(input=target_list_str.encode())
        historical_urls = set(line.strip().decode('utf-8') for line in stdout.splitlines() if line.strip())
    except Exception:
        historical_urls = set()

    if not historical_urls:
        logger.warning("No historical URLs found via gau.")
        return

    # Filter and categorize logic remains the same...
    useful_urls = set()
    # (Rest of categorization code here)
    for u in useful_urls:
        if u not in result.crawled_urls:
            result.crawled_urls.append(u)
