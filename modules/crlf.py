import urllib.parse
from wascan import fetch, Finding

async def run_check(session, target_url, config, semaphore, result):
    # Payload attempts to break out of the current header and set a new malicious cookie
    payload = "%0d%0aSet-Cookie:%20crlf_canary=vulnerable;"

    urls_to_test = result.crawled_urls[:10] if result.crawled_urls else [target_url]

    for url in urls_to_test:
        parsed = urllib.parse.urlparse(url)
        
        # Test 1: Append payload to the URL path (common in location headers)
        test_url = parsed._replace(path=parsed.path + payload).geturl()

        # MUST prevent aiohttp from following redirects, as CRLF often triggers on 301/302 Location headers
        resp = await fetch(session, test_url, config, semaphore, allow_redirects=False)

        if resp:
            # Check if our fake cookie was successfully injected into the raw headers
            crlf_successful = False
            
            # Check aiohttp's parsed cookies
            if "crlf_canary" in resp.cookies:
                crlf_successful = True
                
            # Fallback: check raw Set-Cookie headers
            for header_name, header_val in resp.headers.items():
                if header_name.lower() == "set-cookie" and "crlf_canary" in header_val:
                    crlf_successful = True

            if crlf_successful:
                result.add(Finding(
                    title="CRLF Injection (HTTP Response Splitting)",
                    severity="medium",
                    description=f"Successfully injected HTTP headers via CRLF characters (%0d%0a).",
                    url=test_url,
                    recommendation="Strip or URL-encode carriage return (CR) and line feed (LF) characters from user input before reflecting it in HTTP headers."
                ))
                return
