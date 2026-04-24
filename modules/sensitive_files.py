import urllib.parse
from wascan import fetch, Finding

async def run_check(session, target_url, config, semaphore, result):
    # Common sensitive files and directories to check for
    paths = [
        ("/.env", "Exposed .env file", "critical"),
        ("/.git/config", "Exposed .git directory", "critical"),
        ("/backup.sql", "Exposed database backup", "critical"),
        ("/phpinfo.php", "PHP info page exposed", "high"),
        ("/config.php", "Exposed configuration file", "high"),
        ("/server-status", "Apache Server Status exposed", "medium"),
        ("/.DS_Store", "Exposed macOS .DS_Store file", "low"),
        ("/docker-compose.yml", "Exposed Docker configuration", "high")
    ]
    
    # Strip any paths from the target_url to scan the root domain for these files
    parsed = urllib.parse.urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    for path, title, severity in paths:
        target = urllib.parse.urljoin(base_url, path)
        resp = await fetch(session, target, config, semaphore)
        
        if resp and resp.status == 200:
            # Add an extra check to ensure it's not a soft 404 (custom 404 page returning 200 OK)
            body = (await resp.read()).decode(errors="ignore").lower()
            if "page not found" not in body and "404" not in body[:500]:
                result.add(Finding(
                    title=title,
                    severity=severity,
                    description=f"Sensitive file found at {path}",
                    url=target,
                    recommendation="Remove the file from the webroot or restrict access to it using server configurations."
                ))
