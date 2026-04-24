import urllib.parse
from bs4 import BeautifulSoup
from wascan import fetch, Finding

async def run_check(session, target_url, config, semaphore, result):
    # Common names for anti-CSRF token inputs
    anti_csrf_keywords = ["csrf", "xsrf", "token", "authenticity_token", "_csrf"]
    
    # Check a sample of up to 15 URLs to prevent excessive parsing overhead
    urls_to_check = result.crawled_urls[:15] if result.crawled_urls else [target_url]
    
    for url in urls_to_check:
        resp = await fetch(session, url, config, semaphore)
        if not resp or resp.status != 200 or "html" not in resp.headers.get("Content-Type", ""):
            continue
            
        body = (await resp.read()).decode(errors="ignore")
        soup = BeautifulSoup(body, "lxml")
        
        for form in soup.find_all("form"):
            method = form.get("method", "get").lower()
            
            # GET forms usually don't alter state, so we focus on POST
            if method == "post":
                has_token = False
                
                for inp in form.find_all("input"):
                    name = inp.get("name", "").lower()
                    if any(keyword in name for keyword in anti_csrf_keywords):
                        has_token = True
                        break
                        
                if not has_token:
                    action = form.get("action", url)
                    action = urllib.parse.urljoin(url, action)
                    
                    result.add(Finding(
                        title="Cross-Site Request Forgery (CSRF)",
                        severity="medium",
                        description=f"Form submitting via POST to '{action}' appears to lack an Anti-CSRF token.",
                        url=url,
                        recommendation="Implement synchronized, cryptographically strong Anti-CSRF tokens for all state-changing operations."
                    ))
                    return  # We only need to flag the vulnerability class once per scan
