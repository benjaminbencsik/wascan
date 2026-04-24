import asyncio
import logging
import urllib.parse
import sys

logger = logging.getLogger("wascan")

async def run_check(session, target_url, config, semaphore, result):
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc.split(':')[0]
    if domain.startswith("www."):
        domain = domain[4:]

    logger.info(f"Phase: Gathering subdomains for {domain} via passive sources...")

    subdomains = set()

    # 1. Fetch subdomains using subfinder
    try:
        proc = await asyncio.create_subprocess_shell(
            f"subfinder -d {domain} -silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if stderr: logger.debug(f"Subfinder error: {stderr.decode()}")
        for line in stdout.splitlines():
            sub = line.strip().decode('utf-8').lower()
            if sub.endswith(domain):
                subdomains.add(sub)
    except Exception as e:
        logger.debug(f"Subfinder execution failed: {e}")

    # 2. Fetch subdomains using assetfinder
    try:
        proc2 = await asyncio.create_subprocess_shell(
            f"assetfinder --subs-only {domain}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout2, stderr2 = await proc2.communicate()
        for line in stdout2.splitlines():
            sub = line.strip().decode('utf-8').lower()
            if sub.endswith(domain):
                subdomains.add(sub)
    except Exception:
        pass

    if not subdomains:
        logger.warning(f"No subdomains found for {domain}.")
        return

    logger.info(f"Phase: Probing {len(subdomains)} discovered subdomains with httpx...")

    # 3. Use the absolute path and pipe the subdomains directly to httpx
    try:
        target_input = "\n".join(subdomains).encode()
        proc3 = await asyncio.create_subprocess_shell(
            "/usr/local/bin/httpx -silent -title -status-code -no-color",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout3, stderr3 = await proc3.communicate(input=target_input)
        
        if stderr3: 
            logger.error(f"httpx error output: {stderr3.decode()}")
        
        Subdomain = getattr(sys.modules.get('__main__'), 'Subdomain', None)
        
        for line in stdout3.splitlines():
            output = line.strip().decode('utf-8')
            if not output: continue
            
            parts = output.split(' ')
            url = parts[0]
            status = 0
            title = ""
            
            # Simple parsing for status and title
            for part in parts[1:]:
                if part.startswith('[') and part.endswith(']'):
                    inner = part[1:-1]
                    if inner.isdigit(): status = int(inner)
                    else: title = inner
            
            name = urllib.parse.urlparse(url).netloc.split(':')[0]
            if Subdomain:
                result.discovered_subdomains.append(Subdomain(name=name, status=status, title=title))
                
    except Exception as e:
        logger.error(f"httpx failed to execute: {e}")
        
    logger.info(f"Phase: Subdomain recon finished. Added {len(result.discovered_subdomains)} live targets.")
