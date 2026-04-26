import asyncio
import logging
import urllib.parse
import shutil

logger = logging.getLogger("wascan")

# 1. Define the data structure locally so we never lose our targets
class SubdomainItem:
    def __init__(self, name, ip="", status=0, title=""):
        self.name = name
        self.ip = ip
        self.status = status
        self.title = title

async def run_check(session, target_url, config, semaphore, result):
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc.split(':')[0]
    if domain.startswith("www."):
        domain = domain[4:]

    logger.info(f"Phase: Gathering subdomains for {domain} via passive sources...")
    subdomains = set()

    # Passive Gathering
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

            # 2. Save targets directly into the results array
            result.discovered_subdomains.append(SubdomainItem(name=name, status=status, title="Live"))
            
    except Exception as e:
        logger.error(f"httpx failed: {e}")

    # 3. Safety Net: If httpx fails completely, retain the raw targets for gau
    if not result.discovered_subdomains:
        for sub in subdomains:
            result.discovered_subdomains.append(SubdomainItem(name=sub))

    logger.info(f"Phase: Subdomain recon finished. Successfully stored {len(result.discovered_subdomains)} targets in memory.")
