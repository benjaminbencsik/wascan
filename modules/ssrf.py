import urllib.parse
from wascan import fetch, Finding

async def run_check(session, target_url, config, semaphore, result):
    # Payloads to access local system resources or cloud metadata
    ssrf_payloads = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd"
    ]
    
    # Parameters that frequently handle external resources
    vuln_params = ["url", "uri", "path", "dest", "target", "window", "next", "redirect", "out", "view", "file"]
    
    for url in result.crawled_urls:
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            continue

        params = urllib.parse.parse_qsl(parsed.query)
        for i in range(len(params)):
            param_name = params[i][0].lower()
            
            # Skip if the parameter name doesn't imply a redirect or resource fetch
            if param_name not in vuln_params:
                continue
                
            for payload in ssrf_payloads:
                test_params = params.copy()
                test_params[i] = (test_params[i][0], payload)
                test_query = urllib.parse.urlencode(test_params)
                test_url = parsed._replace(query=test_query).geturl()

                resp = await fetch(session, test_url, config, semaphore)
                if resp and resp.status == 200:
                    body = (await resp.read()).decode(errors="ignore")
                    
                    # Check for explicit indicators of local access
                    if "root:x:0:0" in body or "ami-id" in body or "instance-id" in body:
                        result.add(Finding(
                            title="Server-Side Request Forgery (SSRF)",
                            severity="critical",
                            description=f"SSRF successful on parameter '{test_params[i][0]}'. Extracted internal system/cloud data.",
                            url=test_url,
                            recommendation="Validate all user-supplied URLs, use a strict allow-list of permitted domains, and disable server-side URL fetching if not required."
                        ))
                        return  # Prevent duplicate findings
