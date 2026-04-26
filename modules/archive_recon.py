import asyncio
import logging
import urllib.parse
import re
import shutil

logger = logging.getLogger("wascan")

async def run_check(session, target_url, config, semaphore, result):
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc.split(':')[0]
    if domain.startswith("www."): domain = domain[4:]

    # Use EVERY subdomain we found, not just the ones httpx liked
    targets = {domain}
    # This logic ensures we don't just have '1 domain'
    if hasattr(result, 'discovered_subdomains'):
        for sub in result.discovered_subdomains:
            targets.add(sub.name)
            
    target_list_str = "\n".join(targets)
    logger.info(f"Phase: Fetching historical URLs for {len(targets)} domains/subdomains via gau...")
    
    gau_path = shutil.which("gau")
    if not gau_path:
        logger.warning("gau not found. Skipping.")
        return

    try:
        proc = await asyncio.create_subprocess_shell(
            f"{gau_path} --threads 10",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate(input=target_list_str.encode())
        historical_urls = set(line.strip().decode('utf-8') for line in stdout.splitlines() if line.strip())
        
        if historical_urls:
            logger.info(f"Found {len(historical_urls)} historical URLs. Adding to crawl list.")
            for u in historical_urls:
                if u not in result.crawled_urls:
                    result.crawled_urls.append(u)
        else:
            logger.warning("gau returned 0 URLs.")
            
    except Exception as e:
        logger.error(f"gau failed: {e}")
