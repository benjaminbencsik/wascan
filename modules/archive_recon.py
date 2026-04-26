import asyncio
import logging
import urllib.parse
import shutil

logger = logging.getLogger("wascan")

async def run_check(session, target_url, config, semaphore, result):
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc.split(':')[0]
    if domain.startswith("www."): domain = domain[4:]

    # Fetch root domain PLUS the robust list of subdomains we safely stored
    targets = {domain}
    if hasattr(result, 'discovered_subdomains'):
        for sub in result.discovered_subdomains:
            if hasattr(sub, 'name'):
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
        
        useful_urls = set()
        excluded_exts = ('.jpg', '.jpeg', '.png', '.gif', '.css', '.woff', '.woff2', '.svg', '.ttf', '.js', '.ico')
        
        for url in historical_urls:
            try:
                p = urllib.parse.urlparse(url)
                if p.path.lower().endswith(excluded_exts): continue
                if p.query:
                    useful_urls.add(url)
            except: pass
        
        if useful_urls:
            logger.info(f"Found {len(useful_urls)} historical URLs with parameters. Adding to attack queue.")
            for u in useful_urls:
                if u not in result.crawled_urls:
                    result.crawled_urls.append(u)
        else:
            logger.warning("gau returned 0 viable URLs.")
            
    except Exception as e:
        logger.error(f"gau failed: {e}")
