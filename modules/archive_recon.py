import asyncio
import logging
import os
import urllib.parse
import re

logger = logging.getLogger("wascan")

# Native Python equivalents of Tomnomnom's most popular gf patterns
GF_PATTERNS = {
    "xss": re.compile(r'(?i)[?&](q|s|search|lang|keyword|query|page|q1|view|id|name)='),
    "sqli": re.compile(r'(?i)[?&](id|select|report|role|update|query|user|name|sort|where|search|params|dir|row|table|from|sel|results|sleep|fetch|order|limit|column|group|cat)='),
    "ssrf": re.compile(r'(?i)[?&](dest|redirect|uri|path|continue|url|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|show|navigation|open)='),
    "lfi": re.compile(r'(?i)[?&](file|document|folder|root|path|pg|style|pdf|template|dir|ret|download|log|doc)='),
    "redirect": re.compile(r'(?i)[?&](redirect|redirect_to|redirect_uri|url|return|return_to|next|continue|dest|destination|goto)=')
}

async def run_check(session, target_url, config, semaphore, result):
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc.split(':')[0]
    if domain.startswith("www."):
        domain = domain[4:]

    logger.info(f"Phase: Fetching historical URLs for {domain} via gau...")
    
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
    gf_results = {key: set() for key in GF_PATTERNS}
    
    # Ignore static assets that are useless for active injection scanning
    excluded_exts = ('.jpg', '.jpeg', '.png', '.gif', '.css', '.woff', '.woff2', '.svg', '.ttf', '.js', '.ico')
    
    for url in historical_urls:
        try:
            p = urllib.parse.urlparse(url)
            if p.path.lower().endswith(excluded_exts):
                continue
                
            # We ONLY want URLs that contain query parameters
            if p.query:
                useful_urls.add(url)
                
                # Apply our native gf patterns to categorize the URL
                for pattern_name, regex in GF_PATTERNS.items():
                    if regex.search(url):
                        gf_results[pattern_name].add(url)
        except:
            pass
            
    logger.info(f"Found {len(useful_urls)} historical URLs containing query parameters.")
    
    if config.output_dir and useful_urls:
        # 1. Save the master list of parameters
        archive_file = os.path.join(config.output_dir, "historical_parameters.txt")
        with open(archive_file, "w") as f:
            for u in useful_urls:
                f.write(u + "\n")
        logger.info(f"Saved master parameter list to historical_parameters.txt")
        
        # 2. Save the GF pattern specific lists
        for pattern_name, urls in gf_results.items():
            if urls:
                file_path = os.path.join(config.output_dir, f"gf_{pattern_name}.txt")
                with open(file_path, "w") as f:
                    for u in urls:
                        f.write(u + "\n")
                logger.info(f"Categorized {len(urls)} URLs into gf_{pattern_name}.txt")
        
    # 3. Feed these parameter-heavy URLs directly into the active scanning queue
    for u in useful_urls:
        if u not in result.crawled_urls:
            result.crawled_urls.append(u)
