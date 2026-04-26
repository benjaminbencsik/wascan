import asyncio
import json
import logging
import urllib.parse
import aiohttp
import sys
import shutil
from wascan import ScanConfig, ScanResult, Subdomain

logger = logging.getLogger("wascan")

async def fetch_crtsh(domain: str) -> set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        if name:
                            subdomains.update(name.split("\n"))
    except Exception as e:
        logger.debug(f"crt.sh error: {e}")
    return {s.strip().lower() for s in subdomains if s.strip().endswith(domain)}

async def run_tool(cmd: list | str, shell: bool = False) -> set[str]:
    try:
        if shell:
            proc = await asyncio.create_subprocess_shell(
                cmd, 
                stdout=asyncio.subprocess.PIPE, 
                stderr=asyncio.subprocess.PIPE
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                *cmd, 
                stdout=asyncio.subprocess.PIPE, 
                stderr=asyncio.subprocess.PIPE
            )
        stdout, _ = await proc.communicate()
        return {line.strip().decode('utf-8').lower() for line in stdout.splitlines() if line.strip()}
    except Exception as e:
        logger.debug(f"Tool execution failed: {e}")
        return set()

async def enumerate_subdomains(domain: str) -> list[str]:
    logger.info(f"Gathering subdomains for {domain} via passive sources...")
    
    crtsh_task = fetch_crtsh(domain)
    subfinder_task = run_tool(['subfinder', '-d', domain, '-silent'])
    assetfinder_task = run_tool(['assetfinder', '--subs-only', domain])
    findomain_task = run_tool(f'findomain -t {domain} -q 2> /dev/null', shell=True)
    
    results = await asyncio.gather(crtsh_task, subfinder_task, assetfinder_task, findomain_task)
    
    all_subs = set()
    for res in results:
        all_subs.update(res)
        
    return [sub for sub in all_subs if sub.endswith(domain)]

async def run_httpx(subdomains: list[str], result: ScanResult):
    if not subdomains:
        return
    
    httpx_path = shutil.which("httpx")
    if not httpx_path:
        logger.error("httpx not found in system PATH.")
        return

    logger.info(f"Probing {len(subdomains)} discovered subdomains with httpx...")
    try:
        # Prepend http:// to ensure httpx processes stdin correctly
        target_input = "\n".join([f"http://{s}" for s in subdomains]).encode()

        proc = await asyncio.create_subprocess_exec(
            httpx_path, '-silent', '-json',
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate(input=target_input)
        
        if stderr:
            logger.debug(f"httpx stderr: {stderr.decode()}")

        for line in stdout.splitlines():
            try:
                data = json.loads(line.decode('utf-8'))
                url = data.get("url", "")
                host = data.get("host", "")
                ip = data.get("a", [""])[0] if data.get("a") else ""
                status = data.get("status_code", 0)
                title = data.get("title", "")
                
                result.discovered_subdomains.append(Subdomain(
                    name=host or url,
                    ip=ip,
                    status=status,
                    title=title
                ))
            except json.JSONDecodeError:
                pass
    except Exception as e:
        logger.error(f"Failed to run httpx: {e}")

async def run_check(session: aiohttp.ClientSession, target_url: str, config: ScanConfig, semaphore: asyncio.Semaphore, result: ScanResult):
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc.split(':')[0]
    
    if domain.startswith("www."):
        domain = domain[4:]
        
    subdomains = await enumerate_subdomains(domain)
    await run_httpx(subdomains, result)
