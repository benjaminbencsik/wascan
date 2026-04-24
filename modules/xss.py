import urllib.parse
from wascan import fetch, Finding

async def run_check(session, target_url, config, semaphore, result):
    parsed = urllib.parse.urlparse(target_url)
    if not parsed.query:
        return

    params = urllib.parse.parse_qsl(parsed.query)
    
    for payload in config.xss_payloads:
        for i in range(len(params)):
            test_params = params.copy()
            # Replace the parameter value with our XSS payload
            test_params[i] = (test_params[i][0], payload)
            test_query = urllib.parse.urlencode(test_params)
            test_url = parsed._replace(query=test_query).geturl()

            resp = await fetch(session, test_url, config, semaphore)
            if resp and resp.status == 200:
                body = (await resp.read()).decode(errors="ignore")
                
                # Check if the payload is reflected in the DOM
                if payload in body:
                    result.add(Finding(
                        title="Reflected Cross-Site Scripting (XSS)",
                        severity="high",
                        description=f"Reflected XSS payload execution found in parameter: '{test_params[i][0]}'",
                        url=test_url,
                        recommendation="Implement contextual output encoding and neutralize HTML entities."
                    ))
