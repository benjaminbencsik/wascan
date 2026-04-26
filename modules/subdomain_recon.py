import asyncio
import logging
import urllib.parse
import sys
import shutil

logger = logging.getLogger("wascan")

async def run_check(session, target_url, config, semaphore, result):
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc.split(':')[0]
    if domain.startswith("www."):
        domain = domain[4:]

    logger.info(f"Phase: Gathering subdomains for {domain} via passive sources...")
    subdomains = set()

    # 1. Passive Gathering
    for cmd in [f"subfinder -d {domain} -silent", f"assetfinder --subs-only {domain}"]:
        try:
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
            for line in stdout.splitlines():
                sub = line.strip().decode('utf-8').lower()
                if sub.endswith(domain): subdomains.add(sub)
        except: pass

    if not subdomains:
        logger.warning(f"No subdomains found for {domain}.")
        return

    # 2. Probing with httpx
    logger.info(f"Phase: Probing {len(subdomains)} discovered subdomains with httpx...")
    httpx_path = shutil.which("httpx")
    if not httpx_path:
        logger.error("httpx not found. Skipping live probe.")
        return

    try:
        # We prepend http:// so httpx knows how to handle the input
        target_input = "\n".join([f"http://{s}" for s in subdomains]).encode()
        proc = await asyncio.create_subprocess_shell(
            f"{httpx_path} -silent -status-code -no-color",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate(input=target_input)
        
        # We need the Subdomain class from the main engine
        Subdomain = getattr(sys.modules.get('__main__'), 'Subdomain', None)
        
        for line in stdout.splitlines():
            output = line.strip().decode('utf-8')
            if not output: continue
            parts = output.split(' ')
            url = parts[0]
            name = urllib.parse.urlparse(url).netloc.split(':')[0]
            if Subdomain:
                result.discovered_subdomains.append(Subdomain(name=name, status=200, title="Live"))
    except Exception as e:
        logger.error(f"httpx failed: {e}")

    logger.info(f"Phase: Subdomain recon finished. Found {len(subdomains)} total subs.")
