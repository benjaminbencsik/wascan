# wascan - Web Application Vulnerability Scanner

A comprehensive, asynchronous web application security scanner that detects OWASP Top 10 vulnerabilities, misconfigurations, and security weaknesses.

## Features

- **40+ Security Checks**: XSS, SQL injection, path traversal, SSRF, command injection, XXE, JWT vulnerabilities, and more
- **Web Crawler**: Integrated spider to discover pages and forms
- **Subdomain Enumeration**: DNS + Certificate Transparency discovery
- **Content Discovery**: Brute-force common paths and files
- **Technology Fingerprinting**: Detect frameworks and servers
- **WAF Detection**: Automatic WAF detection with bypass encoding
- **Plugin System**: Extensible via custom Python plugins
- **Multiple Output Formats**: Text, HTML, JSON, CSV
- **SQLite Storage**: Track scan history and diff results

## Installation

```bash
# Clone or download the scanner
git clone https://github.com/yourrepo/vulnscan.git
cd vulnscan

# Install dependencies
pip install -r requirements.txt

# Optional: install Playwright for screenshots
pip install playwright
playwright install chromium
```

### Requirements

- Python 3.8+
- aiohttp
- beautifulsoup4
- lxml
- playwright (optional, for screenshots)

## Quick Start

```bash
# Basic scan
python3 scanner.py https://example.com

# Quick profile (fast checks)
python3 scanner.py https://example.com --profile quick

# Full scan with all checks
python3 scanner.py https://example.com --profile full
```

## Usage Examples

### Scan Profiles

```bash
# Quick - 10 fast checks for active scanning
python3 scanner.py https://example.com --profile quick

# Stealth - slower, quieter, avoids WAFs
python3 scanner.py https://example.com --profile stealth

# Full - all checks enabled
python3 scanner.py https://example.com --profile full
```

### Output Formats

```bash
# HTML report
python3 scanner.py https://example.com --output html --report-file report.html

# JSON output
python3 scanner.py https://example.com --output json

# CSV for spreadsheets
python3 scanner.py https://example.com --output csv

# Plain text (default)
python3 scanner.py https://example.com --output text --no-color
```

### Authentication

```bash
# Login before scanning (extracts session cookies)
python3 scanner.py https://example.com \
  --login-url https://example.com/login \
  --login-data "username=admin&password=secret123" \
  --login-success "Dashboard"

# Use existing cookies
python3 scanner.py https://example.com --cookie "session=abc123; role=admin"
```

### Proxy Support

```bash
# Route through proxy (Burp, ZAP, etc.)
python3 scanner.py https://example.com --proxy http://127.0.0.1:8080
```

### Custom Checks

```bash
# Run specific checks only
python3 scanner.py https://example.com --checks xss sqli headers

# Content discovery with custom wordlist
python3 scanner.py https://example.com --checks content --content-wordlist paths.txt
```

### Spider Configuration

```bash
# Configure crawler depth and page limits
python3 scanner.py https://example.com --spider-depth 3 --spider-pages 100
```

### Database & History

```bash
# Save results to SQLite
python3 scanner.py https://example.com --db wascan.db

# List all stored scans
python3 scanner.py --db wascan.db --list-scans

# Diff two scans (see what changed)
python3 scanner.py --db wascan.db --diff-scans 1:2

# Mark finding as false positive
python3 scanner.py --db wascan.db --mark-fp 42
```

### Notifications

```bash
# Slack/Discord webhook (sends critical/high findings)
python3 scanner.py https://example.com --notify https://hooks.slack.com/services/XXX

# Email report
python3 scanner.py https://example.com \
  --smtp-host smtp.gmail.com \
  --smtp-user user@gmail.com \
  --smtp-pass apppassword \
  --email-to target@example.com
```

### Screenshots

```bash
# Capture screenshots of discovered pages
python3 scanner.py https://example.com --screenshots ./screenshots
```

### CI/CD Integration

```bash
# Exit with code 1 if high+ severity found
python3 scanner.py https://example.com --fail-on high
```

## Available Checks

| Category | Checks |
|----------|--------|
| Injection | xss, sqli, traversal, ssrf, cmdi, xxe, ssti, crlf |
| Auth/Session | jwt, defaultcreds, cookies, hostheader, idor |
| Config/Headers | headers, files, methods, ssl, clickjack, dirlist, cors |
| Discovery | secrets, jslibs, jsendpoints, techfingerprint, waf, graphql |
| Advanced | fileupload, protopollution, smuggling, parampollution, deserial |
| DNS/Recon | subdomains, zonetransfer, certtransparency |
| Active | spider, ratelimit |
| TLS | tls, depcve, oauth |

## Plugin Development

Create custom checks in a Python file:

```python
# myplugin.py
async def check(session, url, result):
    # Your check logic here
    resp = await session.get(url)
    # Add findings using result.add(Finding(...))
```

Load plugins:

```bash
python3 scanner.py https://example.com --plugin-dir ./plugins
```

## License

MIT
