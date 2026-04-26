import asyncio
import logging
import urllib.parse
import re
import shutil

logger = logging.getLogger("wascan")

async def run_check(session, target_url, config, semaphore, result):
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc.split(':')[0]
    if domain.startswith("www."):
        domain = domain[4:]

    # FIX: Grab the root domain PLUS every discovered subdomain name
    # This ensures we fetch history even if httpx failed to probe them
    targets = {domain}
    if hasattr(result, 'discovered_subdomains'):
        for sub in result.discovered_subdomains:
            # We take the name regardless of whether status was 200
            targets.add(sub.name)
            
    target_list_str = "\n".join(targets)

    logger.info(f"Phase: Fetching historical URLs for {len(targets)} domains/subdomains via gau...")
    
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

    # Filter for URLs with parameters (potential attack vectors)
    useful_urls = set()
    excluded_exts = ('.jpg', '.jpeg', '.png', '.gif', '.css', '.woff', '.woff2', '.svg', '.ttf', '.js', '.ico')
    
    for url in historical_urls:
        try:
            p = urllib.parse.urlparse(url)
            if p.path.lower().endswith(excluded_exts): continue
            if p.query:
                useful_urls.add(url)
        except: pass
            
    logger.info(f"Found {len(useful_urls)} historical URLs containing query parameters.")
    
    for u in useful_urls:
        if u not in result.crawled_urls:
            result.crawled_urls.append(u)
