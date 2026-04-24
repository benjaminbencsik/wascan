import urllib.parse
from wascan import fetch, Finding

async def run_check(session, target_url, config, semaphore, result):
    test_origin = "https://evil-cors-target.com"
    headers = {"Origin": test_origin}

    # Test a sample of crawled URLs to check different endpoints (APIs often have different CORS rules)
    urls_to_test = result.crawled_urls[:10] if result.crawled_urls else [target_url]

    for url in urls_to_test:
        resp = await fetch(session, url, config, semaphore, headers=headers)
        
        if resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            # The deadly combination: reflecting arbitrary origins AND allowing credentials
            if acao == test_origin and acac == "true":
                result.add(Finding(
                    title="CORS Misconfiguration",
                    severity="high",
                    description=f"Arbitrary Origin reflection with credentials enabled found.",
                    url=url,
                    recommendation="Configure the CORS policy to use a strict allow-list of trusted domains. Do not dynamically reflect the Origin header if credentials are required."
                ))
                return  # Flag once per scan to avoid duplicates
