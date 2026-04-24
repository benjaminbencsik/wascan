import re
from wascan import fetch, Finding

async def run_check(session, target_url, config, semaphore, result):
    # Standard regex signatures for high-value cloud and API secrets
    patterns = {
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
        "AWS Access Key ID": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "Stripe Live API Key": r"sk_live_[0-9a-zA-Z]{24}",
        "Slack Bot Token": r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9]*"
    }

    # Check the first 15 crawled URLs (prioritizing the root and main pages)
    urls_to_test = result.crawled_urls[:15] if result.crawled_urls else [target_url]

    for url in urls_to_test:
        resp = await fetch(session, url, config, semaphore)
        if resp and resp.status == 200:
            try:
                body = (await resp.read()).decode(errors="ignore")
                
                # Check for each secret pattern
                found_keys = []
                for name, pattern in patterns.items():
                    if re.search(pattern, body):
                        result.add(Finding(
                            title=f"Exposed Secret: {name}",
                            severity="critical",
                            description=f"A potential {name} was found exposed in the response body.",
                            url=url,
                            recommendation="Revoke the exposed secret immediately, rotate keys, and ensure secrets are not hardcoded in frontend source code."
                        ))
                        found_keys.append(name)
                
                # Remove found patterns so we don't alert on the same type of key repeatedly
                for key in found_keys:
                    patterns.pop(key)
                    
                if not patterns:
                    return # Exit if we've found one of every kind of secret
            except Exception:
                pass
