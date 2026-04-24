import urllib.parse
from wascan import fetch, Finding

async def run_check(session, target_url, config, semaphore, result):
    payloads = ["http://example.com", "//example.com"]
    
    for url in result.crawled_urls:
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            continue

        params = urllib.parse.parse_qsl(parsed.query)
        for i in range(len(params)):
            for payload in payloads:
                test_params = params.copy()
                test_params[i] = (test_params[i][0], payload)
                test_query = urllib.parse.urlencode(test_params)
                test_url = parsed._replace(query=test_query).geturl()

                # MUST prevent aiohttp from automatically following the redirect
                resp = await fetch(session, test_url, config, semaphore, allow_redirects=False)
                
                if resp and resp.status in [301, 302, 303, 307, 308]:
                    location = resp.headers.get("Location", "")
                    
                    # If the Location header matches our external payload exactly
                    if location == payload or location.startswith(payload):
                        result.add(Finding(
                            title="Open Redirect",
                            severity="medium",
                            description=f"Open Redirect found on parameter '{test_params[i][0]}'. The server automatically redirects to {location}.",
                            url=test_url,
                            recommendation="Avoid using raw user input for redirect locations. Use a mapped index or strictly validate the destination against a trusted allow-list."
                        ))
                        return
