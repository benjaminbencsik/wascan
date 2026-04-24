import urllib.parse
from wascan import fetch, Finding

async def run_check(session, target_url, config, semaphore, result):
    # Common database syntax errors
    db_errors = [
        "syntax error", "mysql_fetch", "ora-", "postgresql query failed", 
        "unclosed quotation mark", "sql syntax"
    ]
    
    parsed = urllib.parse.urlparse(target_url)
    if not parsed.query:
        return

    params = urllib.parse.parse_qsl(parsed.query)
    
    for payload in config.sqli_payloads:
        for i in range(len(params)):
            test_params = params.copy()
            # Append the SQLi payload to the existing value
            test_params[i] = (test_params[i][0], test_params[i][1] + payload)
            test_query = urllib.parse.urlencode(test_params)
            test_url = parsed._replace(query=test_query).geturl()

            resp = await fetch(session, test_url, config, semaphore)
            if resp:
                body = (await resp.read()).decode(errors="ignore").lower()
                
                for error in db_errors:
                    if error in body:
                        result.add(Finding(
                            title="Error-Based SQL Injection",
                            severity="critical",
                            description=f"Database syntax error detected on parameter '{test_params[i][0]}' when injected with {payload}",
                            url=test_url,
                            recommendation="Utilize parameterized queries or prepared statements for all database interactions."
                        ))
                        return  # Exit early to avoid duplicate findings for the same parameter
