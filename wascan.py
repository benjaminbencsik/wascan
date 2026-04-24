import asyncio
import logging
import os
import urllib.parse

logger = logging.getLogger("wascan")

async def run_check(session, target_url, config, semaphore, result):
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc.split(':')[0]
    if domain.startswith("www."):
        domain = domain[4:]

    logger.info(f"Phase: Fetching historical URLs and parameters for {domain} via gau...")
    
    try:
        # Run gau on the domain and silence stderr
        proc = await asyncio.create_subprocess_shell(
            f"gau {domain} --threads 10 2>/dev/null",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        historical_urls = set(line.strip().decode('utf-8') for line in stdout.splitlines() if line.strip())
    except Exception as e:
        logger.debug(f"Failed to run gau: {e}")
        historical_urls = set()

    if not historical_urls:
        logger.warning("No historical URLs found. Ensure 'gau' is installed and in your PATH.")
        return

    useful_urls = set()
    # Ignore static assets that are useless for active injection scanning
    excluded_exts = ('.jpg', '.jpeg', '.png', '.gif', '.css', '.woff', '.woff2', '.svg', '.ttf', '.js', '.ico')
    
    for url in historical_urls:
        try:
            p = urllib.parse.urlparse(url)
            if p.path.lower().endswith(excluded_exts):
                continue
                
            # We ONLY want URLs that contain query parameters (e.g. ?id=1) for our active scanners
            if p.query:
                useful_urls.add(url)
        except:
            pass
            
    logger.info(f"Found {len(useful_urls)} historical URLs containing query parameters.")
    
    # 1. Save the parameters to a dedicated file in the target's folder
    if config.output_dir and useful_urls:
        archive_file = os.path.join(config.output_dir, "historical_parameters.txt")
        with open(archive_file, "w") as f:
            for u in useful_urls:
                f.write(u + "\n")
        logger.info(f"Saved historical parameters to {archive_file}")
        
    # 2. Feed these parameter-heavy URLs directly into the active scanning queue!
    for u in useful_urls:
        if u not in result.crawled_urls:
            result.crawled_urls.append(u)
