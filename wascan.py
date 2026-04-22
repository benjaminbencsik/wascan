#!/usr/bin/env python3
"""
wascan ΓÇö Web Application Vulnerability Scanner
Usage: python3 scanner.py <target_url> [options]
"""

import asyncio
import argparse
import csv
import importlib.util
import io
import json
import os
import random
import smtplib
import ssl as ssl_module
import sys
import time
import re
import socket
import sqlite3
import subprocess
import urllib.parse
import html as html_escape
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

import aiohttp
from bs4 import BeautifulSoup

# ΓöÇΓöÇ Runtime globals (populated from CLI before scan starts) ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
_AUTH_HEADERS: dict[str, str] = {}
_AUTH_COOKIES: dict[str, str] = {}
_PROXY_URL:    str   = ""
_REQUEST_DELAY: float = 0.0
_STEALTH_MODE: bool  = False
_WAF_DETECTED: bool  = False   # set by check_waf; triggers bypass payloads
_WAF_BYPASS_MODE: bool = False  # forced by --waf-bypass flag
_LOADED_PLUGINS: list = []      # (name, async_fn) tuples from --plugin-dir

# Custom payload lists ΓÇö overridden by --xss-payloads / --sqli-payloads
_XSS_PAYLOADS: list[str] = [
    "<script>alert('XSS_CANARY')</script>",
    "<img src=x onerror=alert('XSS_CANARY')>",
    "'\"><svg onload=alert('XSS_CANARY')>",
    "javascript:alert('XSS_CANARY')",
]
_SQLI_PAYLOADS: list[str] = [
    "'", '"', "' OR '1'='1", "' OR 1=1--",
    "\" OR \"\"=\"", "') OR ('1'='1", "'; WAITFOR DELAY '0:0:2'--",
]

# WAF-bypass encoded variants (used when _WAF_DETECTED or _WAF_BYPASS_MODE)
WAF_BYPASS_XSS: list[str] = [
    "%3Cscript%3Ealert('XSS_CANARY')%3C%2Fscript%3E",           # URL-encoded
    "%253Cscript%253Ealert('XSS_CANARY')%253C%2Fscript%253E",   # Double URL-encoded
    "<ScRiPt>alert('XSS_CANARY')</sCrIpT>",                      # Case variation
    "<scr\x00ipt>alert('XSS_CANARY')</scr\x00ipt>",             # Null byte
    "<scr/**/ipt>alert('XSS_CANARY')</scr/**/ipt>",             # Comment insertion
    "&#x3C;script&#x3E;alert('XSS_CANARY')&#x3C;/script&#x3E;", # HTML entities
    "<svg/onload=alert('XSS_CANARY')>",                          # SVG vector
    "<details open ontoggle=alert('XSS_CANARY')>",              # HTML5 event
    "<img src=x onerror=\u0061lert('XSS_CANARY')>",             # Unicode escape
    "';alert('XSS_CANARY')//",                                    # JS break-out
]
WAF_BYPASS_SQLI: list[str] = [
    "'/**/OR/**/1=1--",          # Comment-padded
    "' oR 1=1--",                # Case variation
    "%27%20OR%201%3D1--",        # URL-encoded
    "' OR 1=1/*",                # MySQL block comment
    "' OR 'x'='x",              # Alternate tautology
    "1' AND '1'='1",            # AND injection
    "' OR 1=1#",                 # MySQL hash comment
    "') OR ('1'='1'--",         # Parenthesis bypass
    "\x27 OR 1=1--",            # Hex-escaped quote
    "' /*!OR*/ 1=1--",          # MySQL versioned comment
]

# ΓöÇΓöÇ Scan profiles ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
SCAN_PROFILES: dict[str, list[str]] = {
    "quick": [
        "headers", "files", "ssl", "cookies", "secrets",
        "cors", "clickjack", "methods", "techfingerprint", "waf",
    ],
    "stealth": [
        "headers", "files", "ssl", "cookies", "secrets",
        "cors", "clickjack", "techfingerprint",
    ],
    "full": [],  # empty = ALL_CHECKS
}

# ΓöÇΓöÇ Data structures ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#e74c3c",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#3498db",
    "info":     "#95a5a6",
}

@dataclass
class Finding:
    title: str
    severity: str
    description: str
    evidence: str = ""
    url: str = ""
    recommendation: str = ""


@dataclass
class Subdomain:
    name: str
    ip: str = ""
    status: int = 0
    title: str = ""


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    crawled_urls: list[str] = field(default_factory=list)
    discovered_subdomains: list[Subdomain] = field(default_factory=list)

    def add(self, finding: Finding):
        self.findings.append(finding)

    def sorted_findings(self):
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    def severity_counts(self) -> dict:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


# ΓöÇΓöÇ Content discovery wordlist ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

CONTENT_WORDLIST = [
    # Directories ΓÇö general
    "admin", "administrator", "api", "app", "assets", "auth", "backup",
    "backups", "bin", "cache", "cgi-bin", "config", "console", "control",
    "core", "dashboard", "data", "database", "db", "debug", "dev",
    "dist", "docs", "download", "downloads", "error", "errors", "files",
    "fonts", "help", "hidden", "home", "images", "img", "include",
    "includes", "index", "internal", "js", "json", "lib", "libs",
    "log", "logs", "login", "logout", "media", "misc", "modules",
    "old", "panel", "portal", "private", "public", "resources",
    "root", "scripts", "secure", "server", "service", "services",
    "settings", "setup", "shop", "src", "ssl", "static", "status",
    "storage", "system", "temp", "test", "testing", "tmp", "tools",
    "uploads", "user", "users", "util", "utils", "vendor", "web",
    # API versioning
    "v1", "v2", "v3", "api/v1", "api/v2", "api/v3",
    "rest", "graphql", "gql", "rpc", "soap",
    # Auth / identity
    "login", "logout", "signin", "signout", "signup", "register",
    "forgot", "reset", "verify", "oauth", "oauth2", "sso", "token",
    "refresh", "callback", "auth/login", "auth/logout",
    # CMS / framework specific
    "wp-admin", "wp-login.php", "wp-content", "wp-includes",
    "wp-json", "xmlrpc.php",
    "administrator", "joomla", "components",
    "sites/default", "drupal",
    "phpmyadmin", "pma", "mysql", "phpMyAdmin",
    "laravel", "artisan", "horizon", "telescope",
    "django-admin", "admin/login",
    "rails/info", "sidekiq",
    # Dev tooling
    ".git", ".svn", ".hg", ".bzr",
    ".git/config", ".git/HEAD", ".git/index",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.backup", ".env.old",
    "Makefile", "Vagrantfile", "Procfile",
    "package.json", "package-lock.json", "yarn.lock",
    "composer.json", "composer.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock",
    "Gemfile", "Gemfile.lock",
    "go.mod", "go.sum",
    # Config & secrets
    "config.php", "config.py", "config.rb", "config.js",
    "config.json", "config.yaml", "config.yml",
    "settings.py", "settings.php", "settings.json",
    "web.config", "application.properties", "application.yml",
    "database.yml", "database.php",
    "secrets.json", "secrets.yml", ".secrets",
    ".npmrc", ".yarnrc", ".pypirc", ".htpasswd", ".htaccess",
    # Logs & backups
    "error.log", "access.log", "debug.log", "app.log",
    "backup.sql", "db.sql", "dump.sql", "database.sql",
    "backup.zip", "backup.tar.gz", "backup.tar",
    "site.zip", "www.zip", "web.zip",
    # API / documentation
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "api/swagger.json", "api/swagger-ui.html", "api-docs",
    "graphiql", "playground",
    # Monitoring / ops
    "healthz", "health", "health/check", "ping", "ready", "live",
    "metrics", "prometheus", "actuator", "actuator/health",
    "actuator/env", "actuator/mappings",
    "server-status", "server-info",
    # Test / debug
    "test.php", "test.html", "phpinfo.php", "info.php",
    "test/", "debug/", "trace",
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    ".well-known/security.txt", ".well-known/acme-challenge",
    "crossdomain.xml", "clientaccesspolicy.xml",
    # Shell / admin tools
    "shell.php", "webshell.php", "cmd.php", "eval.php",
    "adminer.php", "filemanager", "elfinder",
    # Common 403/hidden paths worth noting
    "cron", "crons", "queue", "jobs", "tasks",
    "report", "reports", "export", "exports",
    "import", "migrate", "migrations",
    "install", "installer", "install.php",
    "update", "upgrade", "maintenance",
]

# ΓöÇΓöÇ Subdomain wordlist ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

SUBDOMAIN_WORDLIST = [
    # Common / infrastructure
    "www", "mail", "ftp", "smtp", "pop", "pop3", "imap", "ns1", "ns2", "ns3",
    "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "relay", "gateway",
    # App / API
    "api", "api2", "api-v1", "api-v2", "apis", "app", "apps", "application",
    "graphql", "rest", "rpc", "grpc", "webhook", "webhooks", "ws", "wss",
    # Environments
    "dev", "develop", "development", "staging", "stage", "stg", "stg1",
    "prod", "production", "uat", "sit", "qa", "qat", "test", "testing",
    "sandbox", "demo", "preview", "canary", "alpha", "beta", "nightly",
    "pre", "preprod", "pre-prod", "rc",
    # Admin / ops
    "admin", "administrator", "panel", "dashboard", "portal", "console",
    "manage", "management", "control", "cp", "cPanel", "plesk", "webmin",
    "phpmyadmin", "pma",
    # Auth / identity
    "auth", "login", "sso", "oauth", "oauth2", "id", "identity", "iam",
    "account", "accounts", "profile", "user", "users", "member", "members",
    "register", "signup",
    # Content / media
    "blog", "news", "press", "media", "cdn", "static", "assets", "img",
    "images", "video", "videos", "audio", "files", "upload", "uploads",
    "download", "downloads", "storage", "s3", "backup",
    # Commerce / payments
    "shop", "store", "checkout", "cart", "pay", "payment", "payments",
    "billing", "invoice", "invoices", "subscription", "subscriptions",
    # Support / docs
    "support", "help", "helpdesk", "tickets", "service", "servicedesk",
    "docs", "documentation", "wiki", "kb", "knowledge", "faq",
    "forum", "community", "feedback", "survey",
    # Dev tooling / CI-CD
    "git", "gitlab", "github", "bitbucket", "svn", "ci", "cd", "jenkins",
    "travis", "circleci", "build", "builds", "artifact", "artifacts",
    "registry", "repo", "repository", "sonar", "nexus",
    # Monitoring / observability
    "monitoring", "monitor", "grafana", "kibana", "prometheus", "alertmanager",
    "status", "uptime", "health", "metrics", "logs", "elk", "splunk",
    "apm", "trace", "newrelic", "datadog",
    # Internal / corporate
    "internal", "intranet", "corp", "corporate", "vpn", "remote",
    "rdp", "ssh", "bastion", "jump", "proxy", "waf", "firewall",
    # Databases / infra
    "db", "database", "mysql", "postgres", "postgresql", "redis",
    "mongo", "mongodb", "elastic", "elasticsearch", "solr", "kafka",
    "rabbit", "rabbitmq", "mq", "queue",
    # Containers / cloud
    "k8s", "kubernetes", "docker", "rancher", "nomad",
    "cloud", "aws", "azure", "gcp", "heroku",
    # Email
    "email", "webmail", "owa", "autodiscover", "exchange", "spam",
    "calendar", "meet", "video", "conference",
    # Marketing / analytics
    "analytics", "tracking", "stats", "report", "reports",
    "marketing", "crm", "sales", "affiliate", "partner", "partners",
    # Misc
    "old", "legacy", "archive", "new", "v2", "v3", "v4",
    "search", "chat", "slack", "careers", "jobs",
    "m", "mobile", "wap", "pwa", "spa",
    "lab", "labs", "research", "poc", "proof",
]


# ΓöÇΓöÇ HTTP helpers ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (wascan/1.0; security-research)",
    "Accept": "text/html,application/xhtml+xml,application/json,*/*",
}


_STEALTH_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

async def fetch(session: aiohttp.ClientSession, url: str, method="GET",
                data=None, headers=None, allow_redirects=True,
                timeout=10) -> Optional[aiohttp.ClientResponse]:
    if _REQUEST_DELAY > 0:
        delay = _REQUEST_DELAY * random.uniform(0.7, 1.8) if _STEALTH_MODE else _REQUEST_DELAY
        await asyncio.sleep(delay)

    base = DEFAULT_HEADERS.copy()
    if _STEALTH_MODE:
        base["User-Agent"] = random.choice(_STEALTH_UAS)

    try:
        merged = {**base, **_AUTH_HEADERS, **(headers or {})}
        kwargs: dict = dict(
            data=data, headers=merged,
            cookies=_AUTH_COOKIES if _AUTH_COOKIES else None,
            allow_redirects=allow_redirects,
            timeout=aiohttp.ClientTimeout(total=timeout),
            ssl=False,
        )
        if _PROXY_URL:
            kwargs["proxy"] = _PROXY_URL
        resp = await session.request(method, url, **kwargs)
        await resp.read()
        return resp
    except Exception:
        return None


async def get_baseline(session: aiohttp.ClientSession, url: str) -> tuple[int, int]:
    """Return (status_code, body_length) for a clean request ΓÇö used to filter false positives."""
    resp = await fetch(session, url)
    if not resp:
        return 0, 0
    body = await resp.read()
    return resp.status, len(body)


# ΓöÇΓöÇ Spider ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

@dataclass
class DiscoveredForm:
    page_url: str
    action: str
    method: str
    inputs: list[dict]   # [{"name": ..., "type": ..., "value": ...}]


async def spider(session: aiohttp.ClientSession, base_url: str,
                 max_depth: int = 2, max_pages: int = 50,
                 verbose: bool = False) -> tuple[list[str], list[DiscoveredForm]]:
    """Crawl the target within scope, returning (urls, forms)."""
    parsed_base = urllib.parse.urlparse(base_url)
    base_domain = parsed_base.netloc

    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(base_url, 0)]
    found_forms: list[DiscoveredForm] = []

    def in_scope(url: str) -> bool:
        p = urllib.parse.urlparse(url)
        return p.netloc == base_domain and p.scheme in ("http", "https")

    def normalise(url: str, page_url: str) -> Optional[str]:
        url = url.strip()
        if not url or url.startswith(("#", "mailto:", "javascript:", "tel:")):
            return None
        joined = urllib.parse.urljoin(page_url, url)
        # strip fragment
        return urllib.parse.urldefrag(joined)[0]

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        if verbose:
            print(f"  [spider] {url}", file=sys.stderr)

        resp = await fetch(session, url)
        if not resp or resp.status != 200:
            continue

        ct = resp.headers.get("Content-Type", "")
        if "html" not in ct:
            continue

        body = (await resp.read()).decode(errors="ignore")
        soup = BeautifulSoup(body, "lxml")

        # Collect links
        if depth < max_depth:
            for tag in soup.find_all("a", href=True):
                norm = normalise(tag["href"], url)
                if norm and norm not in visited and in_scope(norm):
                    queue.append((norm, depth + 1))

        # Collect forms
        for form in soup.find_all("form"):
            action = form.get("action", url)
            action = normalise(action, url) or url
            method = (form.get("method", "get") or "get").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name":  inp.get("name", ""),
                    "type":  inp.get("type", "text").lower(),
                    "value": inp.get("value", ""),
                })
            if any(i["name"] for i in inputs):
                found_forms.append(DiscoveredForm(
                    page_url=url, action=action,
                    method=method, inputs=inputs,
                ))

    return list(visited), found_forms


# ΓöÇΓöÇ Checks ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

async def check_security_headers(session, url, result):
    resp = await fetch(session, url)
    if not resp:
        return

    headers = {k.lower(): v for k, v in resp.headers.items()}

    checks = [
        ("strict-transport-security", "Missing HSTS",
         "Browsers will not enforce HTTPS without Strict-Transport-Security.",
         "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        ("content-security-policy", "Missing Content-Security-Policy",
         "Without CSP, XSS payloads can load arbitrary scripts.",
         "Define a restrictive CSP that whitelists trusted sources."),
        ("x-frame-options", "Missing X-Frame-Options",
         "Page may be embeddable in iframes, enabling clickjacking.",
         "Add: X-Frame-Options: DENY or SAMEORIGIN"),
        ("x-content-type-options", "Missing X-Content-Type-Options",
         "Browsers may MIME-sniff responses, enabling content injection.",
         "Add: X-Content-Type-Options: nosniff"),
        ("referrer-policy", "Missing Referrer-Policy",
         "Sensitive URL parameters may leak to third-party sites.",
         "Add: Referrer-Policy: strict-origin-when-cross-origin"),
        ("permissions-policy", "Missing Permissions-Policy",
         "Browser features (camera, mic, geolocation) are unrestricted.",
         "Add a Permissions-Policy header to restrict unneeded features."),
    ]

    for header, title, desc, rec in checks:
        if header not in headers:
            result.add(Finding(
                title=title, severity="medium", description=desc,
                evidence=f"Header '{header}' absent from response",
                url=url, recommendation=rec,
            ))

    for leak_header in ("x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version"):
        if leak_header in headers:
            result.add(Finding(
                title=f"Server information disclosure via '{leak_header}'",
                severity="low",
                description="Response headers reveal backend technology versions.",
                evidence=f"{leak_header}: {headers[leak_header]}",
                url=url,
                recommendation=f"Remove or obscure the '{leak_header}' header.",
            ))


async def check_sensitive_files(session, base_url, result):
    paths = [
        ("/.env",                     "Exposed .env file",               "critical"),
        ("/.env.local",               "Exposed .env.local file",         "critical"),
        ("/.env.production",          "Exposed .env.production file",    "critical"),
        ("/.git/config",              "Exposed .git directory",          "critical"),
        ("/.git/HEAD",                "Exposed .git HEAD",               "critical"),
        ("/wp-config.php.bak",        "Exposed WordPress config backup", "critical"),
        ("/config.php.bak",           "Exposed config backup",           "high"),
        ("/backup.sql",               "Exposed database backup",         "critical"),
        ("/db.sql",                   "Exposed database dump",           "critical"),
        ("/dump.sql",                 "Exposed database dump",           "critical"),
        ("/phpinfo.php",              "PHP info page exposed",           "high"),
        ("/server-status",            "Apache server-status exposed",    "high"),
        ("/server-info",              "Apache server-info exposed",      "medium"),
        ("/robots.txt",               "robots.txt present",              "info"),
        ("/sitemap.xml",              "sitemap.xml present",             "info"),
        ("/.well-known/security.txt", "security.txt present",            "info"),
        ("/admin",                    "Admin panel path exists",         "medium"),
        ("/administrator",            "Admin panel path exists",         "medium"),
        ("/wp-admin/",                "WordPress admin path exists",     "medium"),
        ("/api/swagger.json",         "Swagger/OpenAPI spec exposed",    "medium"),
        ("/api/swagger-ui.html",      "Swagger UI exposed",              "medium"),
        ("/swagger.yaml",             "OpenAPI spec exposed",            "medium"),
        ("/openapi.json",             "OpenAPI spec exposed",            "medium"),
        ("/.DS_Store",                "macOS .DS_Store file exposed",    "low"),
        ("/crossdomain.xml",          "Flash crossdomain policy",        "low"),
        ("/clientaccesspolicy.xml",   "Silverlight access policy",       "low"),
        ("/.htaccess",                "Exposed .htaccess file",          "medium"),
        ("/web.config",               "Exposed web.config file",         "high"),
        ("/package.json",             "Exposed package.json",            "low"),
        ("/composer.json",            "Exposed composer.json",           "low"),
        ("/.npmrc",                   "Exposed .npmrc file",             "high"),
        ("/.dockerignore",            "Exposed .dockerignore",           "info"),
        ("/Dockerfile",               "Exposed Dockerfile",              "medium"),
        ("/docker-compose.yml",       "Exposed docker-compose.yml",      "high"),
    ]

    async def probe(path, title, severity):
        url = base_url.rstrip("/") + path
        resp = await fetch(session, url, allow_redirects=False)
        if resp and resp.status in (200, 206):
            body = (await resp.read()).decode(errors="ignore")
            result.add(Finding(
                title=title, severity=severity,
                description=f"The path '{path}' returned HTTP {resp.status}.",
                evidence=body[:200] if body else "",
                url=url,
                recommendation=f"Restrict access to '{path}' via server config or remove the file.",
            ))

    await asyncio.gather(*[probe(p, t, s) for p, t, s in paths])


async def check_http_methods(session, url, result):
    dangerous = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
    for method in dangerous:
        resp = await fetch(session, url, method=method)
        if resp and resp.status not in (405, 501, 400, 403):
            result.add(Finding(
                title=f"HTTP method {method} allowed",
                severity="medium" if method in ("TRACE", "CONNECT") else "low",
                description=f"The server accepted HTTP {method} with status {resp.status}.",
                evidence=f"HTTP {resp.status}",
                url=url,
                recommendation=f"Disable the {method} method in your server/framework configuration.",
            ))


async def check_ssl_redirect(session, url, result):
    if not url.startswith("https://"):
        return
    http_url = "http://" + url[8:]
    resp = await fetch(session, http_url, allow_redirects=False)
    if resp and resp.status not in (301, 302, 307, 308):
        result.add(Finding(
            title="HTTP does not redirect to HTTPS",
            severity="high",
            description="Plain HTTP requests are not redirected to HTTPS.",
            evidence=f"HTTP {resp.status} on {http_url}",
            url=http_url,
            recommendation="Configure a permanent 301 redirect from HTTP to HTTPS.",
        ))


async def check_xss(session, url, result):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    targets = list(params.keys())[:5] if params else ["q"]
    base_params = params if params else {}
    payloads = _XSS_PAYLOADS + (WAF_BYPASS_XSS if (_WAF_DETECTED or _WAF_BYPASS_MODE) else [])

    for param in targets:
        for canary in payloads[:6]:
            new_params = {**base_params, param: [canary]}
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            resp = await fetch(session, test_url)
            if resp:
                body = (await resp.read()).decode(errors="ignore")
                if canary in body or "XSS_CANARY" in body:
                    result.add(Finding(
                        title=f"Reflected XSS in parameter '{param}'",
                        severity="high",
                        description="A script tag injected via query parameter was reflected unescaped.",
                        evidence=f"Payload: {canary!r} reflected at {test_url}",
                        url=test_url,
                        recommendation="HTML-encode all user-supplied output; implement a Content-Security-Policy.",
                    ))
                    break


async def check_sqli(session, url, result):
    payloads = _SQLI_PAYLOADS + (WAF_BYPASS_SQLI if (_WAF_DETECTED or _WAF_BYPASS_MODE) else [])
    error_patterns = [
        r"sql syntax", r"mysql_fetch", r"ORA-\d{5}", r"sqlite3\.",
        r"pg_query", r"microsoft ole db", r"odbc sql", r"unclosed quotation",
        r"unterminated string", r"invalid query", r"syntax error",
    ]
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query) or {"id": ["1"]}

    for param in list(params.keys())[:5]:
        for payload in payloads:
            new_params = {**params, param: [payload]}
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            resp = await fetch(session, test_url)
            if resp:
                body = (await resp.read()).decode(errors="ignore").lower()
                for pattern in error_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        result.add(Finding(
                            title=f"Possible SQL injection in parameter '{param}'",
                            severity="critical",
                            description="A SQL error message was returned after injecting a payload.",
                            evidence=f"Payload: {payload!r} triggered pattern '{pattern}'",
                            url=test_url,
                            recommendation="Use parameterised queries / prepared statements.",
                        ))
                        return


async def check_open_redirect(session, url, result):
    redirect_params = ["redirect", "url", "next", "return", "returnUrl",
                       "redirect_uri", "goto", "dest", "destination", "redir"]
    canary = "https://evil.example.com"
    for param in redirect_params:
        test_url = url + ("&" if "?" in url else "?") + f"{param}={urllib.parse.quote(canary)}"
        resp = await fetch(session, test_url, allow_redirects=False)
        if resp and resp.status in (301, 302, 307, 308):
            location = resp.headers.get("Location", "")
            if "evil.example.com" in location:
                result.add(Finding(
                    title=f"Open redirect via parameter '{param}'",
                    severity="medium",
                    description="The application redirects to attacker-controlled URLs.",
                    evidence=f"Location: {location}",
                    url=test_url,
                    recommendation="Validate redirect destinations against an allowlist of trusted URLs.",
                ))


async def check_cors(session, url, result):
    origin = "https://evil.example.com"
    resp = await fetch(session, url, headers={"Origin": origin})
    if not resp:
        return
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
    if acao == "*":
        result.add(Finding(
            title="Wildcard CORS policy",
            severity="low",
            description="Access-Control-Allow-Origin: * permits any origin to read responses.",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            url=url,
            recommendation="Restrict CORS origins to an explicit allowlist.",
        ))
    elif acao == origin:
        sev = "high" if acac == "true" else "medium"
        result.add(Finding(
            title="CORS reflects arbitrary Origin" + (" with credentials" if acac == "true" else ""),
            severity=sev,
            description="The server mirrors the Origin header, allowing cross-origin reads" +
                        (" including cookies/auth tokens." if acac == "true" else "."),
            evidence=f"Origin: {origin} ΓåÆ ACAO: {acao}, ACAC: {acac}",
            url=url,
            recommendation="Validate the Origin against an explicit allowlist before reflecting it.",
        ))


async def check_clickjacking(session, url, result):
    resp = await fetch(session, url)
    if not resp:
        return
    headers = {k.lower(): v for k, v in resp.headers.items()}
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp:
        result.add(Finding(
            title="Clickjacking protection absent",
            severity="medium",
            description="No X-Frame-Options or CSP frame-ancestors directive prevents the page from being framed.",
            evidence="Neither X-Frame-Options nor frame-ancestors CSP directive present.",
            url=url,
            recommendation="Add X-Frame-Options: DENY or CSP: frame-ancestors 'none'.",
        ))


async def check_directory_listing(session, base_url, result):
    dirs = ["/images/", "/static/", "/assets/", "/css/", "/js/",
            "/uploads/", "/files/", "/backup/", "/logs/", "/tmp/"]

    async def probe(path):
        url = base_url.rstrip("/") + path
        resp = await fetch(session, url)
        if not resp or resp.status != 200:
            return
        body = (await resp.read()).decode(errors="ignore")
        soup = BeautifulSoup(body, "lxml")
        title = (soup.title.string or "").lower() if soup.title else ""
        if "index of" in title or "directory listing" in title:
            result.add(Finding(
                title=f"Directory listing enabled at {path}",
                severity="medium",
                description="The web server returns a directory index, exposing file names.",
                evidence=f"Title: {soup.title.string if soup.title else ''}",
                url=url,
                recommendation="Disable directory listing (Options -Indexes in Apache; autoindex off in Nginx).",
            ))

    await asyncio.gather(*[probe(d) for d in dirs])


async def check_cookie_flags(session, url, result):
    resp = await fetch(session, url)
    if not resp:
        return
    raw_cookies = resp.headers.getall("Set-Cookie", [])
    for raw in raw_cookies:
        lower = raw.lower()
        name = raw.split("=")[0].strip()
        if "httponly" not in lower:
            result.add(Finding(
                title=f"Cookie '{name}' missing HttpOnly flag",
                severity="medium",
                description="Without HttpOnly, JavaScript can read this cookie, aiding XSS attacks.",
                evidence=raw[:200], url=url,
                recommendation="Set the HttpOnly attribute on all session/auth cookies.",
            ))
        if "secure" not in lower and url.startswith("https://"):
            result.add(Finding(
                title=f"Cookie '{name}' missing Secure flag",
                severity="medium",
                description="Without Secure, the cookie may be sent over unencrypted HTTP.",
                evidence=raw[:200], url=url,
                recommendation="Set the Secure attribute on all session/auth cookies.",
            ))
        if "samesite" not in lower:
            result.add(Finding(
                title=f"Cookie '{name}' missing SameSite attribute",
                severity="low",
                description="Without SameSite, the cookie is sent with cross-site requests, enabling CSRF.",
                evidence=raw[:200], url=url,
                recommendation="Set SameSite=Strict or SameSite=Lax on session cookies.",
            ))


async def check_path_traversal(session, url, result):
    """Test for path traversal via query parameters."""
    payloads = [
        "../../etc/passwd",
        "../../../etc/passwd",
        "..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..\\..\\windows\\win.ini",
        "..%5C..%5Cwindows%5Cwin.ini",
    ]
    unix_indicator = re.compile(r"root:.*:0:0:|daemon:|nobody:", re.IGNORECASE)
    win_indicator  = re.compile(r"\[fonts\]|\[extensions\]", re.IGNORECASE)

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    # Prefer params whose names suggest file/path handling
    path_params = [p for p in params if re.search(r"file|path|page|include|doc|template|load|view", p, re.I)]
    targets = path_params[:3] or list(params.keys())[:3]
    if not targets:
        targets = ["file"]

    for param in targets:
        for payload in payloads:
            new_params = {**params, param: [payload]}
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_params, doseq=True)))
            resp = await fetch(session, test_url)
            if resp:
                body = (await resp.read()).decode(errors="ignore")
                if unix_indicator.search(body) or win_indicator.search(body):
                    result.add(Finding(
                        title=f"Path traversal in parameter '{param}'",
                        severity="critical",
                        description="The application returned OS file contents after a directory traversal payload.",
                        evidence=body[:300].replace("\n", " "),
                        url=test_url,
                        recommendation="Resolve and validate file paths against an allowed base directory; reject any path containing '..'.",
                    ))
                    return


async def check_ssrf(session, url, result):
    """Test for SSRF by injecting internal/metadata URLs into parameters."""
    # Cloud metadata endpoints and internal addresses
    ssrf_targets = [
        "http://169.254.169.254/latest/meta-data/",          # AWS IMDSv1
        "http://metadata.google.internal/computeMetadata/v1/", # GCP
        "http://169.254.169.254/metadata/instance",           # Azure
        "http://127.0.0.1/",
        "http://localhost/",
        "http://0.0.0.0/",
    ]
    # Indicators in response body that suggest SSRF worked
    metadata_patterns = [
        r"ami-id", r"instance-id", r"iam/security-credentials",
        r"computeMetadata", r"project-id", r"serviceAccounts",
        r"\"compute\"", r"azure", r"root:.*:0:0:",
    ]

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    url_params = [p for p in params if re.search(r"url|uri|src|href|link|host|dest|redirect|proxy|fetch|load|image", p, re.I)]
    targets = url_params[:3] or list(params.keys())[:2]
    if not targets:
        targets = ["url"]

    for param in targets:
        for ssrf_url in ssrf_targets[:3]:
            new_params = {**params, param: [ssrf_url]}
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_params, doseq=True)))
            resp = await fetch(session, test_url, timeout=6)
            if resp:
                body = (await resp.read()).decode(errors="ignore")
                for pattern in metadata_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        result.add(Finding(
                            title=f"SSRF via parameter '{param}'",
                            severity="critical",
                            description="The server fetched an internal URL and returned metadata in the response.",
                            evidence=f"Payload: {ssrf_url} ΓåÆ pattern '{pattern}' found",
                            url=test_url,
                            recommendation="Validate and allowlist URLs before server-side fetching; block requests to private IP ranges.",
                        ))
                        return


async def check_command_injection(session, url, result):
    """Test for OS command injection via query parameters."""
    # Use a time-based canary so we don't need OOB infrastructure
    payloads = [
        ("; echo CMDINJ_CANARY", "CMDINJ_CANARY"),
        ("| echo CMDINJ_CANARY", "CMDINJ_CANARY"),
        ("`echo CMDINJ_CANARY`", "CMDINJ_CANARY"),
        ("$(echo CMDINJ_CANARY)", "CMDINJ_CANARY"),
        ("& echo CMDINJ_CANARY &", "CMDINJ_CANARY"),
        ("; echo CMDINJ_CANARY #", "CMDINJ_CANARY"),
    ]

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query) or {"q": ["test"]}

    for param in list(params.keys())[:4]:
        for payload, canary in payloads:
            new_params = {**params, param: [payload]}
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_params, doseq=True)))
            resp = await fetch(session, test_url)
            if resp:
                body = (await resp.read()).decode(errors="ignore")
                if canary in body:
                    result.add(Finding(
                        title=f"Command injection in parameter '{param}'",
                        severity="critical",
                        description="An OS command injected via a query parameter was executed and its output was reflected.",
                        evidence=f"Payload: {payload!r} | Canary '{canary}' in response",
                        url=test_url,
                        recommendation="Never pass user input to shell commands; use language APIs instead of shell execution.",
                    ))
                    return


async def check_xxe(session, url, result):
    """Submit an XML payload with an external entity reference to detect XXE."""
    xxe_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<root><data>&xxe;</data></root>"
    )
    unix_indicator = re.compile(r"root:.*:0:0:|daemon:|nobody:", re.IGNORECASE)

    # Try common XML-accepting endpoints
    xml_paths = ["/api", "/api/v1", "/soap", "/xml", "/graphql", "/rpc", ""]
    base = url.rstrip("/")

    for path in xml_paths:
        test_url = base + path
        resp = await fetch(session, test_url, method="POST",
                           data=xxe_payload,
                           headers={"Content-Type": "application/xml"})
        if resp:
            body = (await resp.read()).decode(errors="ignore")
            if unix_indicator.search(body):
                result.add(Finding(
                    title="XML External Entity (XXE) injection",
                    severity="critical",
                    description="The server parsed an XML external entity and returned file contents.",
                    evidence=body[:300].replace("\n", " "),
                    url=test_url,
                    recommendation="Disable external entity processing in your XML parser (e.g. FEATURE_EXTERNAL_GENERAL_ENTITIES=false).",
                ))
                return


async def check_jwt(session, url, result):
    """Probe for weak JWT handling on common auth endpoints."""
    import base64

    # alg:none token ΓÇö unsigned JWT with admin claim
    header  = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(b'{"sub":"1","role":"admin","exp":9999999999}').rstrip(b"=").decode()
    none_token = f"{header}.{payload}."

    auth_paths = ["/api/me", "/api/user", "/api/profile", "/api/v1/me",
                  "/me", "/profile", "/dashboard", "/admin"]
    base = url.rstrip("/")

    for path in auth_paths:
        test_url = base + path
        resp = await fetch(session, test_url,
                           headers={"Authorization": f"Bearer {none_token}"})
        if resp and resp.status == 200:
            body = (await resp.read()).decode(errors="ignore")
            # If we got a 200 with user-looking data it might have worked
            if any(k in body.lower() for k in ("email", "username", "user_id", "userid", "role")):
                result.add(Finding(
                    title="Possible JWT 'alg:none' acceptance",
                    severity="critical",
                    description=f"The endpoint {path} returned HTTP 200 with an unsigned (alg:none) JWT token.",
                    evidence=f"Token: {none_token[:80]}... | Status 200 at {test_url}",
                    url=test_url,
                    recommendation="Enforce a strict algorithm allowlist (e.g. RS256 only); reject tokens with alg=none.",
                ))
                return


async def check_sensitive_data_exposure(session, url, result):
    """Scan response bodies for leaked secrets, keys, and internal data."""
    patterns = [
        (r"AKIA[0-9A-Z]{16}",                          "AWS Access Key ID",        "critical"),
        (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
                                                         "AWS Secret Key",           "critical"),
        (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",   "Private key in response",  "critical"),
        (r"(?i)api[_-]?key['\"\s:=]+[0-9a-zA-Z\-_]{16,}",
                                                         "API key in response",      "high"),
        (r"(?i)password['\"\s:=]+[^\s'\"]{8,}",         "Password in response",     "high"),
        (r"(?i)secret['\"\s:=]+[^\s'\"]{8,}",           "Secret in response",       "high"),
        (r"ghp_[0-9a-zA-Z]{36}",                        "GitHub personal token",    "critical"),
        (r"xox[baprs]-[0-9a-zA-Z\-]{10,}",              "Slack token",              "critical"),
        (r"AIza[0-9A-Za-z\-_]{35}",                     "Google API key",           "high"),
        (r"(?i)mongodb(\+srv)?://[^\s\"']+",             "MongoDB connection string","high"),
        (r"(?i)postgres(?:ql)?://[^\s\"']+",             "PostgreSQL connection URL", "high"),
        (r"(?i)mysql://[^\s\"']+",                       "MySQL connection URL",     "high"),
        (r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
                                                         "Internal IP in response",  "low"),
        (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                                                         "Email address in response","info"),
    ]

    resp = await fetch(session, url)
    if not resp:
        return
    body = (await resp.read()).decode(errors="ignore")
    seen_titles: set[str] = set()

    for pattern, title, severity in patterns:
        match = re.search(pattern, body)
        if match and title not in seen_titles:
            seen_titles.add(title)
            result.add(Finding(
                title=title,
                severity=severity,
                description=f"A sensitive value matching '{title}' was found in the HTTP response body.",
                evidence=match.group(0)[:120],
                url=url,
                recommendation="Remove sensitive data from responses; use environment variables and secret managers.",
            ))


# Vulnerable JS library versions (library_name ΓåÆ {version_regex: (severity, cve)})
VULN_JS_LIBS = {
    "jquery": {
        r"jQuery v?(1\.[0-9]\.|2\.0\.|2\.1\.[0-3]|3\.[0-5]\.)": ("high",   "XSS ΓÇö CVE-2019-11358 and earlier"),
        r"jQuery v?(1\.[0-6]\.)":                                  ("critical","Multiple XSS ΓÇö jQuery < 1.7"),
    },
    "bootstrap": {
        r"Bootstrap v?(3\.[0-3]\.|2\.)":                          ("medium", "XSS ΓÇö Bootstrap < 3.4"),
        r"Bootstrap v?(4\.[0-2]\.)":                              ("medium", "XSS ΓÇö Bootstrap 4 < 4.3"),
    },
    "lodash": {
        r"lodash[/ ]v?(4\.[0-9]\.|3\.|2\.|1\.)":                 ("high",   "Prototype pollution ΓÇö lodash < 4.17.21"),
    },
    "moment": {
        r"moment\.js v?(2\.[0-9]\.|1\.)":                         ("medium", "ReDoS ΓÇö moment < 2.29.4"),
    },
    "angular": {
        r"AngularJS v?(1\.[0-7]\.)":                              ("high",   "Multiple XSS ΓÇö AngularJS < 1.8"),
    },
    "vue": {
        r"Vue\.js v?(2\.[0-5]\.)":                                ("medium", "XSS ΓÇö Vue < 2.6"),
    },
    "handlebars": {
        r"Handlebars v?(4\.[0-6]\.|[0-3]\.)":                    ("high",   "Template injection ΓÇö Handlebars < 4.7.7"),
    },
}


async def check_js_libraries(session, url, result):
    """Detect outdated and vulnerable JavaScript libraries in page source."""
    resp = await fetch(session, url)
    if not resp:
        return
    body = (await resp.read()).decode(errors="ignore")
    soup = BeautifulSoup(body, "lxml")

    # Gather all JS content: inline scripts + linked JS files
    js_sources = [tag.string or "" for tag in soup.find_all("script") if not tag.get("src")]
    for tag in soup.find_all("script", src=True):
        src = urllib.parse.urljoin(url, tag["src"])
        if urllib.parse.urlparse(src).netloc == urllib.parse.urlparse(url).netloc:
            r = await fetch(session, src)
            if r:
                js_sources.append((await r.read()).decode(errors="ignore"))

    combined = "\n".join(js_sources) + "\n" + body

    for lib, version_map in VULN_JS_LIBS.items():
        for pattern, (severity, cve_note) in version_map.items():
            m = re.search(pattern, combined, re.IGNORECASE)
            if m:
                result.add(Finding(
                    title=f"Outdated/vulnerable {lib} library",
                    severity=severity,
                    description=f"A known-vulnerable version of {lib} was detected. {cve_note}.",
                    evidence=m.group(0)[:100],
                    url=url,
                    recommendation=f"Upgrade {lib} to the latest stable release.",
                ))
                break  # one finding per library


async def check_default_credentials(session, url, result):
    """Detect login forms and test common default credentials."""
    common_creds = [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("admin", "admin123"), ("root", "root"), ("root", "toor"),
        ("test", "test"), ("guest", "guest"), ("admin", ""),
        ("administrator", "administrator"), ("admin", "pass"),
    ]
    success_indicators = [
        "dashboard", "logout", "welcome", "signed in", "log out",
        "my account", "profile", "settings", "admin panel",
    ]
    fail_indicators = [
        "invalid", "incorrect", "wrong", "failed", "error",
        "try again", "bad credentials", "unauthorized",
    ]

    resp = await fetch(session, url)
    if not resp:
        return
    body = (await resp.read()).decode(errors="ignore")
    soup = BeautifulSoup(body, "lxml")

    # Find login forms on the page
    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        user_field = next((i for i in inputs if re.search(
            r"user|login|email|name", i.get("name", ""), re.I)), None)
        pass_field = next((i for i in inputs if i.get("type", "").lower() == "password"), None)

        if not (user_field and pass_field):
            continue

        action = form.get("action", url)
        action_url = urllib.parse.urljoin(url, action)
        method = (form.get("method", "post") or "post").upper()

        # Build base form data (hidden fields etc.)
        base_data = {}
        for inp in inputs:
            name = inp.get("name", "")
            if name and inp.get("type", "").lower() not in ("submit", "button"):
                base_data[name] = inp.get("value", "")

        for username, password in common_creds:
            data = {
                **base_data,
                user_field.get("name"): username,
                pass_field.get("name"): password,
            }
            resp2 = await fetch(session, action_url, method=method, data=data)
            if not resp2:
                continue
            body2 = (await resp2.read()).decode(errors="ignore").lower()

            failed = any(ind in body2 for ind in fail_indicators)
            succeeded = any(ind in body2 for ind in success_indicators)

            if succeeded and not failed:
                result.add(Finding(
                    title=f"Default credentials accepted: {username} / {password}",
                    severity="critical",
                    description="The application accepted a well-known default username and password combination.",
                    evidence=f"Credentials: {username!r} / {password!r} ΓåÆ form at {action_url}",
                    url=url,
                    recommendation="Change all default credentials immediately and enforce strong password policies.",
                ))
                return  # one finding per form is enough


async def check_rate_limiting(session, url, result):
    """Check whether the target enforces rate limiting on repeated requests."""
    # Send 15 rapid requests and see if any are throttled/blocked
    probe_url = url
    statuses = []
    for _ in range(15):
        resp = await fetch(session, probe_url, timeout=5)
        statuses.append(resp.status if resp else 0)

    throttled = any(s in (429, 503) for s in statuses)
    blocked   = statuses.count(0) > 5

    if not throttled and not blocked:
        result.add(Finding(
            title="No rate limiting detected",
            severity="medium",
            description="15 rapid requests were sent without receiving HTTP 429 or any throttling response.",
            evidence=f"Status codes received: {statuses}",
            url=url,
            recommendation="Implement rate limiting (e.g. token bucket) on all public endpoints, especially login and API routes.",
        ))


# ΓöÇΓöÇ Form testing ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

CSRF_TOKEN_NAMES = {
    "csrf", "csrf_token", "_csrf", "_token", "authenticity_token",
    "csrfmiddlewaretoken", "xsrf", "xsrf_token", "_xsrf", "nonce",
    "anti_csrf", "requestverificationtoken",
}

FUZZABLE_TYPES = {"text", "search", "email", "url", "tel", "number",
                  "password", "textarea", "", "hidden"}

XSS_CANARY = "<script>alert('FORM_XSS')</script>"
SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1"]
SQLI_PATTERNS = [
    r"sql syntax", r"mysql_fetch", r"ORA-\d{5}", r"sqlite3\.",
    r"pg_query", r"microsoft ole db", r"odbc sql", r"unclosed quotation",
    r"unterminated string", r"syntax error",
]


def has_csrf_token(form: DiscoveredForm) -> bool:
    for inp in form.inputs:
        if inp["name"].lower() in CSRF_TOKEN_NAMES:
            return True
    return False


async def test_form(session: aiohttp.ClientSession, form: DiscoveredForm,
                    result: ScanResult):
    # CSRF check (POST forms without token)
    if form.method == "POST" and not has_csrf_token(form):
        result.add(Finding(
            title="Form may lack CSRF protection",
            severity="medium",
            description=f"A POST form at '{form.page_url}' has no detectable CSRF token field.",
            evidence=f"Action: {form.action} | Inputs: {[i['name'] for i in form.inputs]}",
            url=form.page_url,
            recommendation="Add a per-session CSRF token to all state-changing forms.",
        ))

    text_inputs = [i for i in form.inputs if i["type"] in FUZZABLE_TYPES and i["name"]]
    if not text_inputs:
        return

    # XSS fuzz
    data = {i["name"]: i["value"] or "test" for i in form.inputs if i["name"]}
    for inp in text_inputs[:3]:
        fuzz = {**data, inp["name"]: XSS_CANARY}
        resp = await fetch(session, form.action, method=form.method,
                           data=fuzz if form.method == "POST" else None,
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
        if resp:
            body = (await resp.read()).decode(errors="ignore")
            if XSS_CANARY in body or "FORM_XSS" in body:
                result.add(Finding(
                    title=f"Reflected XSS in form field '{inp['name']}'",
                    severity="high",
                    description="A script tag injected into a form input was reflected unescaped.",
                    evidence=f"Field: {inp['name']} | Action: {form.action}",
                    url=form.page_url,
                    recommendation="HTML-encode all user-supplied output.",
                ))

    # SQLi fuzz (error-based)
    for inp in text_inputs[:3]:
        for payload in SQLI_PAYLOADS:
            fuzz = {**data, inp["name"]: payload}
            resp = await fetch(session, form.action, method=form.method,
                               data=fuzz if form.method == "POST" else None)
            if resp:
                body = (await resp.read()).decode(errors="ignore")
                for pattern in SQLI_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        result.add(Finding(
                            title=f"Possible SQL injection in form field '{inp['name']}'",
                            severity="critical",
                            description="A SQL error was triggered by injecting into a form input.",
                            evidence=f"Payload: {payload!r} | Pattern: {pattern}",
                            url=form.page_url,
                            recommendation="Use parameterised queries / prepared statements.",
                        ))
                        return


async def check_spider_and_forms(session, target, result, max_depth, max_pages, verbose):
    print(f"[*] Crawling {target} (depth={max_depth}, max={max_pages} pages)...",
          file=sys.stderr)
    urls, forms = await spider(session, target, max_depth=max_depth,
                                max_pages=max_pages, verbose=verbose)
    result.crawled_urls = urls
    print(f"[*] Found {len(urls)} pages, {len(forms)} forms", file=sys.stderr)

    await asyncio.gather(*[test_form(session, f, result) for f in forms])


# ΓöÇΓöÇ Subdomain enumeration ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

def _resolve(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


async def check_subdomains(session: aiohttp.ClientSession, target: str,
                           result: ScanResult, wordlist: list[str],
                           verbose: bool = False):
    parsed = urllib.parse.urlparse(target)
    base_domain = parsed.netloc.split(":")[0]
    scheme = parsed.scheme

    # Strip leading www
    if base_domain.startswith("www."):
        base_domain = base_domain[4:]

    print(f"[*] Enumerating subdomains for {base_domain} ({len(wordlist)} words)...",
          file=sys.stderr)

    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=50)

    async def probe(word: str):
        hostname = f"{word}.{base_domain}"
        ip = await loop.run_in_executor(executor, _resolve, hostname)
        if not ip:
            return

        sub = Subdomain(name=hostname, ip=ip)
        url = f"{scheme}://{hostname}"
        resp = await fetch(session, url)
        if resp:
            sub.status = resp.status
            body = (await resp.read()).decode(errors="ignore")
            soup = BeautifulSoup(body, "lxml")
            sub.title = (soup.title.string or "").strip()[:80] if soup.title else ""

            # Check for subdomain takeover indicators
            takeover_patterns = [
                "there is no app", "no such app", "herokucdn.com",
                "this domain is not connected", "github pages", "404 not found",
                "fastly error", "no such bucket", "s3.amazonaws.com",
                "azure websites", "azurewebsites.net",
            ]
            for pattern in takeover_patterns:
                if pattern in body.lower():
                    result.add(Finding(
                        title=f"Potential subdomain takeover: {hostname}",
                        severity="high",
                        description="The subdomain resolves but the hosted service is unclaimed.",
                        evidence=f"Pattern '{pattern}' found on {url}",
                        url=url,
                        recommendation="Remove the DNS record or reclaim the service.",
                    ))

        if verbose:
            print(f"  [sub] {hostname} ΓåÆ {ip} (HTTP {sub.status})", file=sys.stderr)
        result.discovered_subdomains.append(sub)

    await asyncio.gather(*[probe(w) for w in wordlist])
    executor.shutdown(wait=False)

    found = len(result.discovered_subdomains)
    print(f"[*] Discovered {found} subdomains", file=sys.stderr)


# ΓöÇΓöÇ HTML report ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

def generate_html_report(result: ScanResult) -> str:
    counts = result.severity_counts()
    total = len(result.findings)
    subdomain_count = len(result.discovered_subdomains)
    page_count = len(result.crawled_urls)

    def badge(sev: str) -> str:
        colors = {
            "critical": "#e74c3c", "high": "#e67e22",
            "medium": "#f39c12", "low": "#3498db", "info": "#95a5a6",
        }
        c = colors.get(sev, "#999")
        return (f'<span style="background:{c};color:#fff;padding:2px 8px;'
                f'border-radius:3px;font-size:0.8em;font-weight:bold;">'
                f'{sev.upper()}</span>')

    # Severity bar chart rows
    bar_rows = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        n = counts.get(sev, 0)
        if n == 0:
            continue
        pct = int(n / total * 100) if total else 0
        color = SEVERITY_COLORS.get(sev, "#999")
        bar_rows += f"""
        <tr>
          <td style="width:80px;font-weight:bold;color:{color}">{sev.upper()}</td>
          <td style="padding-left:8px">
            <div style="background:{color};width:{max(pct,2)}%;height:18px;border-radius:3px;
                        display:inline-block;min-width:4px"></div>
            <span style="margin-left:6px">{n}</span>
          </td>
        </tr>"""

    # Findings rows
    finding_rows = ""
    for i, f in enumerate(result.sorted_findings(), 1):
        color = SEVERITY_COLORS.get(f.severity, "#999")
        ev = html_escape.escape(f.evidence[:300]).replace("\n", "<br>") if f.evidence else ""
        finding_rows += f"""
        <tr style="border-left:4px solid {color}">
          <td style="padding:10px 8px;font-weight:bold;vertical-align:top">{i:02d}</td>
          <td style="padding:10px 4px;vertical-align:top">{badge(f.severity)}</td>
          <td style="padding:10px 8px;vertical-align:top">
            <strong>{html_escape.escape(f.title)}</strong><br>
            <small style="color:#666">{html_escape.escape(f.url)}</small><br>
            <span style="color:#333">{html_escape.escape(f.description)}</span>
            {"<br><code style='font-size:0.8em;color:#c0392b;background:#fdf2f2;padding:2px 4px'>" + ev + "</code>" if ev else ""}
            {"<br><em style='color:#27ae60;font-size:0.9em'>Fix: " + html_escape.escape(f.recommendation) + "</em>" if f.recommendation else ""}
          </td>
        </tr>"""

    # Subdomain rows
    subdomain_rows = ""
    for s in sorted(result.discovered_subdomains, key=lambda x: x.name):
        status_color = "#27ae60" if s.status == 200 else "#e67e22" if s.status else "#95a5a6"
        subdomain_rows += f"""
        <tr>
          <td style="padding:6px 8px;font-family:monospace">{html_escape.escape(s.name)}</td>
          <td style="padding:6px 8px;font-family:monospace">{html_escape.escape(s.ip)}</td>
          <td style="padding:6px 8px;color:{status_color}">{s.status or "ΓÇö"}</td>
          <td style="padding:6px 8px;color:#555">{html_escape.escape(s.title)}</td>
        </tr>"""

    # Crawled URL rows
    url_rows = ""
    for u in result.crawled_urls[:200]:
        url_rows += f'<tr><td style="padding:4px 8px;font-family:monospace;font-size:0.85em">{html_escape.escape(u)}</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>wascan Report ΓÇö {html_escape.escape(result.target)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
          background: #f4f6f8; color: #2c3e50; line-height: 1.5; }}
  .header {{ background: #1a1a2e; color: #eee; padding: 24px 32px; }}
  .header h1 {{ font-size: 1.8em; color: #e94560; letter-spacing: 2px; }}
  .header h2 {{ font-size: 1.1em; font-weight: normal; margin-top: 4px; }}
  .header .meta {{ font-size: 0.85em; color: #aaa; margin-top: 8px; }}
  .content {{ max-width: 1200px; margin: 24px auto; padding: 0 16px; }}
  .card {{ background: #fff; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,.1);
           margin-bottom: 24px; overflow: hidden; }}
  .card-header {{ padding: 14px 20px; font-weight: bold; font-size: 1em;
                  background: #f8f9fa; border-bottom: 1px solid #e9ecef; }}
  .card-body {{ padding: 16px 20px; }}
  .stat-grid {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }}
  .stat {{ background: #fff; border-radius: 6px; padding: 16px 24px; flex: 1;
           box-shadow: 0 1px 4px rgba(0,0,0,.1); text-align: center; min-width: 120px; }}
  .stat .num {{ font-size: 2.4em; font-weight: bold; }}
  .stat .label {{ font-size: 0.85em; color: #666; margin-top: 2px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  tr:nth-child(even) {{ background: #fafafa; }}
  th {{ padding: 10px 8px; text-align: left; background: #f1f3f4;
        font-size: 0.85em; color: #555; border-bottom: 2px solid #dee2e6; }}
  .footer {{ text-align: center; color: #aaa; font-size: 0.8em; padding: 24px; }}
</style>
</head>
<body>
<div class="header">
  <h1>wascan</h1>
  <h2>{html_escape.escape(result.target)}</h2>
  <div class="meta">
    Started: {result.started_at} &nbsp;|&nbsp; Finished: {result.finished_at}
  </div>
</div>
<div class="content">

  <div class="stat-grid">
    <div class="stat">
      <div class="num" style="color:#e74c3c">{counts.get("critical",0)}</div>
      <div class="label">Critical</div>
    </div>
    <div class="stat">
      <div class="num" style="color:#e67e22">{counts.get("high",0)}</div>
      <div class="label">High</div>
    </div>
    <div class="stat">
      <div class="num" style="color:#f39c12">{counts.get("medium",0)}</div>
      <div class="label">Medium</div>
    </div>
    <div class="stat">
      <div class="num" style="color:#3498db">{counts.get("low",0)}</div>
      <div class="label">Low</div>
    </div>
    <div class="stat">
      <div class="num" style="color:#95a5a6">{counts.get("info",0)}</div>
      <div class="label">Info</div>
    </div>
    <div class="stat">
      <div class="num" style="color:#8e44ad">{subdomain_count}</div>
      <div class="label">Subdomains</div>
    </div>
    <div class="stat">
      <div class="num" style="color:#16a085">{page_count}</div>
      <div class="label">Pages Crawled</div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">Severity Distribution</div>
    <div class="card-body">
      <table style="width:auto">
        {bar_rows if bar_rows else "<tr><td>No findings.</td></tr>"}
      </table>
    </div>
  </div>

  <div class="card">
    <div class="card-header">Findings ({total})</div>
    <div class="card-body" style="padding:0">
      <table>
        <thead><tr>
          <th>#</th><th>Severity</th><th>Details</th>
        </tr></thead>
        <tbody>
          {finding_rows if finding_rows else "<tr><td colspan='3' style='padding:16px'>No findings.</td></tr>"}
        </tbody>
      </table>
    </div>
  </div>

  {"" if not result.discovered_subdomains else f'''
  <div class="card">
    <div class="card-header">Discovered Subdomains ({subdomain_count})</div>
    <div class="card-body" style="padding:0">
      <table>
        <thead><tr>
          <th>Hostname</th><th>IP</th><th>HTTP Status</th><th>Page Title</th>
        </tr></thead>
        <tbody>{subdomain_rows}</tbody>
      </table>
    </div>
  </div>'''}

  {"" if not result.crawled_urls else f'''
  <div class="card">
    <div class="card-header">Crawled URLs ({page_count})</div>
    <div class="card-body" style="padding:0">
      <table>
        <thead><tr><th>URL</th></tr></thead>
        <tbody>{url_rows}</tbody>
      </table>
    </div>
  </div>'''}

</div>
<div class="footer">Generated by wascan &bull; {result.finished_at}</div>
</body>
</html>"""


# ΓöÇΓöÇ Output formatters ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

COLORS = {
    "critical": "\033[91m", "high": "\033[31m", "medium": "\033[33m",
    "low": "\033[36m", "info": "\033[37m",
    "reset": "\033[0m", "bold": "\033[1m",
}


def severity_badge(s: str, use_color: bool) -> str:
    badge = s.upper().ljust(8)
    if use_color:
        c = COLORS.get(s, "")
        return f"{c}{badge}{COLORS['reset']}"
    return badge


def print_text_report(result: ScanResult, use_color: bool):
    b = COLORS["bold"] if use_color else ""
    r = COLORS["reset"] if use_color else ""
    counts = result.severity_counts()

    print(f"\n{b}{'='*70}{r}")
    print(f"{b}  wascan ΓÇö Web Application Vulnerability Scanner{r}")
    print(f"{b}{'='*70}{r}")
    print(f"  Target     : {result.target}")
    print(f"  Started    : {result.started_at}")
    print(f"  Finished   : {result.finished_at}")
    print(f"  Findings   : {len(result.findings)}")
    print(f"  Pages crawled : {len(result.crawled_urls)}")
    print(f"  Subdomains : {len(result.discovered_subdomains)}")

    for sev in ["critical", "high", "medium", "low", "info"]:
        if counts.get(sev):
            print(f"    {severity_badge(sev, use_color)} {counts[sev]}")

    if result.discovered_subdomains:
        print(f"\n{b}  Discovered Subdomains{r}")
        print(f"  {'ΓöÇ'*66}")
        for s in sorted(result.discovered_subdomains, key=lambda x: x.name):
            status = f"HTTP {s.status}" if s.status else "no HTTP"
            print(f"  {s.name:<40} {s.ip:<16} {status}")

    print(f"\n{b}{'ΓöÇ'*70}{r}")

    for i, f in enumerate(result.sorted_findings(), 1):
        badge = severity_badge(f.severity, use_color)
        print(f"\n  [{i:02d}] {badge} {b}{f.title}{r}")
        print(f"       URL  : {f.url}")
        print(f"       Desc : {f.description}")
        if f.evidence:
            ev = f.evidence[:120].replace("\n", " ")
            print(f"       Evidence : {ev}")
        if f.recommendation:
            print(f"       Fix  : {f.recommendation}")

    print(f"\n{b}{'='*70}{r}\n")


def print_json_report(result: ScanResult):
    data = {
        "target": result.target,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "summary": result.severity_counts(),
        "crawled_urls": result.crawled_urls,
        "discovered_subdomains": [asdict(s) for s in result.discovered_subdomains],
        "findings": [asdict(f) for f in result.sorted_findings()],
    }
    print(json.dumps(data, indent=2))


def generate_csv_report(result: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["#", "Severity", "Title", "URL", "Description", "Evidence", "Recommendation"])
    for i, f in enumerate(result.sorted_findings(), 1):
        writer.writerow([i, f.severity.upper(), f.title, f.url,
                         f.description, f.evidence.replace("\n", " "), f.recommendation])
    return buf.getvalue()


# ΓöÇΓöÇ New checks ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

async def check_ssti(session, url, result):
    """Server-Side Template Injection via query parameters."""
    # Each tuple: (payload, expected_output, engine_hint)
    payloads = [
        ("{{7*7}}",        "49", "Jinja2/Twig"),
        ("${7*7}",         "49", "FreeMarker/Groovy/EL"),
        ("<%= 7*7 %>",     "49", "ERB/JSP"),
        ("#{7*7}",         "49", "Ruby/Pebble"),
        ("{{7*'7'}}",      "7777777", "Jinja2"),
        ("${{7*7}}",       "49", "Thymeleaf"),
        ("{7*7}",          "49", "Smarty/generic"),
    ]
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query) or {"q": ["test"]}

    base_status, base_len = await get_baseline(session, url)

    for param in list(params.keys())[:4]:
        for payload, expected, engine in payloads:
            new_params = {**params, param: [payload]}
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(new_params, doseq=True)))
            resp = await fetch(session, test_url)
            if resp:
                body = (await resp.read()).decode(errors="ignore")
                if expected in body and len(body) != base_len:
                    result.add(Finding(
                        title=f"Server-Side Template Injection in '{param}' ({engine})",
                        severity="critical",
                        description=f"Template expression {payload!r} evaluated to '{expected}' in the response.",
                        evidence=f"Payload: {payload!r} ΓåÆ found '{expected}' | engine hint: {engine}",
                        url=test_url,
                        recommendation="Never pass user input into template engines. Use sandboxed rendering or whitelist-only templates.",
                    ))
                    return


async def check_crlf(session, url, result):
    """CRLF injection ΓÇö inject newlines into params and check for reflected headers."""
    header_name = "X-Wascan-Injected"
    header_val  = "crlf_test"
    payloads = [
        f"%0d%0a{header_name}:%20{header_val}",
        f"%0a{header_name}:%20{header_val}",
        f"%0d%0a%20{header_name}:%20{header_val}",
        f"\r\n{header_name}: {header_val}",
    ]
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query) or {"q": ["test"]}

    for param in list(params.keys())[:4]:
        for payload in payloads:
            new_params = {**params, param: [payload]}
            # Build URL manually to avoid double-encoding the CRLF sequences
            raw_query = "&".join(
                f"{urllib.parse.quote(k)}={urllib.parse.quote(str(v[0]), safe='%')}"
                for k, v in new_params.items()
            )
            test_url = urllib.parse.urlunparse(parsed._replace(query=raw_query))
            resp = await fetch(session, test_url, allow_redirects=False)
            if resp:
                if header_name.lower() in {h.lower() for h in resp.headers}:
                    result.add(Finding(
                        title=f"CRLF injection in parameter '{param}'",
                        severity="high",
                        description="A CRLF sequence injected into a query parameter was reflected as an HTTP response header.",
                        evidence=f"Payload: {payload!r} ΓåÆ header '{header_name}' appeared in response",
                        url=test_url,
                        recommendation="Strip or reject CR (\\r) and LF (\\n) from any value used in HTTP headers or redirects.",
                    ))
                    return


async def check_host_header_injection(session, url, result):
    """Test for Host header injection reflected in response or redirects."""
    canary_host = "evil-wascan.example.com"
    resp = await fetch(session, url,
                       headers={"Host": canary_host},
                       allow_redirects=False)
    if not resp:
        return

    body = (await resp.read()).decode(errors="ignore")
    location = resp.headers.get("Location", "")

    if canary_host in body:
        result.add(Finding(
            title="Host header reflected in response body",
            severity="high",
            description="The injected Host header value was reflected in the response body, enabling cache poisoning or password-reset link hijacking.",
            evidence=f"Host: {canary_host} reflected in body",
            url=url,
            recommendation="Never use the Host header to construct URLs or links without validating it against a strict allowlist.",
        ))
    elif canary_host in location:
        result.add(Finding(
            title="Host header reflected in redirect Location",
            severity="high",
            description="The injected Host header value was reflected in a redirect, enabling open redirect / cache poisoning.",
            evidence=f"Host: {canary_host} ΓåÆ Location: {location}",
            url=url,
            recommendation="Hardcode the domain in redirects; never trust the Host header for URL construction.",
        ))


async def check_idor(session, url, result):
    """Probe for IDOR by incrementing/decrementing numeric IDs in URL params and path."""
    parsed = urllib.parse.urlparse(url)

    # Find numeric params
    params = urllib.parse.parse_qs(parsed.query)
    numeric_params = {k: v for k, v in params.items()
                      if v and re.match(r"^\d+$", v[0])}

    # Also check path segments like /users/42/
    path_ids = re.findall(r"/(\d+)(?:/|$)", parsed.path)

    tested = False

    for param, vals in list(numeric_params.items())[:3]:
        orig_id = int(vals[0])
        base_status, base_len = await get_baseline(session, url)

        for delta in (-1, 1, orig_id + 100):
            new_params = {**params, param: [str(delta)]}
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(new_params, doseq=True)))
            resp = await fetch(session, test_url)
            if resp and resp.status == 200 and base_status == 200:
                body = await resp.read()
                # Significant body similarity but different ID ΓåÆ possible IDOR
                if abs(len(body) - base_len) < base_len * 0.3 and len(body) > 200:
                    result.add(Finding(
                        title=f"Possible IDOR via parameter '{param}'",
                        severity="high",
                        description=f"Changing '{param}' from {orig_id} to {delta} returned a similar-sized 200 response, suggesting access to another object.",
                        evidence=f"Original ID: {orig_id} | Tested: {delta} | Body diff: {abs(len(body)-base_len)} bytes",
                        url=test_url,
                        recommendation="Enforce object-level authorisation on every resource endpoint ΓÇö verify the requesting user owns the object.",
                    ))
                    tested = True
                    break
        if tested:
            break

    # Path-based ID check
    if not tested and path_ids:
        orig_id = int(path_ids[-1])
        base_status, base_len = await get_baseline(session, url)
        for delta in (orig_id - 1, orig_id + 1):
            if delta < 0:
                continue
            test_path = re.sub(r"/" + str(orig_id) + r"(?=/|$)",
                                f"/{delta}", parsed.path, count=1)
            test_url = urllib.parse.urlunparse(parsed._replace(path=test_path))
            resp = await fetch(session, test_url)
            if resp and resp.status == 200 and base_status == 200:
                body = await resp.read()
                if abs(len(body) - base_len) < base_len * 0.3 and len(body) > 200:
                    result.add(Finding(
                        title=f"Possible IDOR via path ID ({orig_id} ΓåÆ {delta})",
                        severity="high",
                        description=f"Changing the path ID from {orig_id} to {delta} returned a similar-sized 200 response.",
                        evidence=f"Original: {url} | Tested: {test_url}",
                        url=test_url,
                        recommendation="Enforce object-level authorisation ΓÇö verify the requesting user owns the object.",
                    ))
                    break


async def check_graphql(session, url, result):
    """Detect exposed GraphQL endpoints and enabled introspection."""
    introspection_query = json.dumps({"query": "{__schema{types{name kind}}}"})
    endpoints = ["/graphql", "/api/graphql", "/graphiql", "/gql",
                 "/api/gql", "/v1/graphql", "/query"]
    base = url.rstrip("/")

    for path in endpoints:
        test_url = base + path
        resp = await fetch(session, test_url, method="POST", data=introspection_query,
                           headers={"Content-Type": "application/json"})
        if not resp or resp.status not in (200, 201):
            # Try GET for GraphiQL
            resp = await fetch(session, test_url)
        if not resp:
            continue

        body = (await resp.read()).decode(errors="ignore")

        if '"__schema"' in body or '"types"' in body:
            result.add(Finding(
                title=f"GraphQL introspection enabled at {path}",
                severity="medium",
                description="GraphQL introspection is publicly accessible, exposing the full API schema including all types, queries, and mutations.",
                evidence=body[:300],
                url=test_url,
                recommendation="Disable introspection in production. If needed, restrict it to authenticated admin users.",
            ))
            return

        if "graphql" in body.lower() or "graphiql" in body.lower():
            result.add(Finding(
                title=f"GraphQL endpoint detected at {path}",
                severity="info",
                description="A GraphQL endpoint was found. Introspection appears disabled, but the endpoint warrants further review.",
                evidence=body[:200],
                url=test_url,
                recommendation="Ensure introspection is disabled in production and all queries are authenticated.",
            ))
            return


TECH_SIGNATURES: list[tuple[str, str, str]] = [
    # (category, indicator_type, pattern)
    ("WordPress",        "path",    r"wp-content|wp-includes|wp-json"),
    ("Drupal",           "path",    r"/sites/default/|drupal\.js"),
    ("Joomla",           "path",    r"/components/com_|joomla"),
    ("Laravel",          "cookie",  r"laravel_session"),
    ("Django",           "cookie",  r"csrftoken|django"),
    ("Django",           "path",    r"/static/admin/"),
    ("Ruby on Rails",    "cookie",  r"_session_id"),
    ("ASP.NET",          "cookie",  r"ASP\.NET_SessionId|\.ASPXAUTH"),
    ("ASP.NET",          "header",  r"x-aspnet-version|x-aspnetmvc-version"),
    ("PHP",              "cookie",  r"PHPSESSID"),
    ("Java/Tomcat",      "cookie",  r"JSESSIONID"),
    ("Express/Node.js",  "header",  r"x-powered-by.*express"),
    ("Next.js",          "header",  r"x-powered-by.*next\.js"),
    ("Nginx",            "header",  r"server.*nginx"),
    ("Apache",           "header",  r"server.*apache"),
    ("IIS",              "header",  r"server.*iis|server.*microsoft"),
    ("Cloudflare",       "header",  r"cf-ray|server.*cloudflare"),
    ("Varnish",          "header",  r"x-varnish|via.*varnish"),
    ("Shopify",          "header",  r"x-shopify"),
    ("Magento",          "cookie",  r"frontend|adminhtml"),
]


async def check_tech_fingerprint(session, url, result):
    """Identify the technology stack from headers, cookies, and HTML."""
    resp = await fetch(session, url)
    if not resp:
        return

    headers_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
    cookies_str = " ".join(resp.headers.getall("Set-Cookie", [])).lower()
    body = (await resp.read()).decode(errors="ignore")
    soup = BeautifulSoup(body, "lxml")
    meta_gen = ""
    for meta in soup.find_all("meta", attrs={"name": re.compile(r"generator", re.I)}):
        meta_gen += meta.get("content", "").lower()

    detected: set[str] = set()

    for tech, check_type, pattern in TECH_SIGNATURES:
        source = {
            "header": headers_str,
            "cookie": cookies_str,
            "path":   body.lower(),
            "meta":   meta_gen,
        }.get(check_type, "")
        if re.search(pattern, source, re.IGNORECASE) and tech not in detected:
            detected.add(tech)

    if detected:
        result.add(Finding(
            title=f"Technology stack detected: {', '.join(sorted(detected))}",
            severity="info",
            description="The following technologies were fingerprinted from HTTP headers, cookies, and page content.",
            evidence=", ".join(sorted(detected)),
            url=url,
            recommendation="Suppress version disclosures in headers (Server, X-Powered-By) to reduce attacker fingerprinting.",
        ))


WAF_SIGNATURES = [
    ("Cloudflare",    r"cloudflare|__cfduid|cf-ray"),
    ("AWS WAF",       r"aws-waf|x-amzn-requestid|x-amz-cf-id"),
    ("Imperva",       r"incap_ses|visid_incap|x-cdn.*imperva|imperva"),
    ("Akamai",        r"akamai|ak_bmsc|bm_sz"),
    ("F5 BIG-IP",     r"bigipserver|f5-"),
    ("Sucuri",        r"x-sucuri|sucuri"),
    ("ModSecurity",   r"mod_security|modsecurity"),
    ("Barracuda",     r"barra_counter_session"),
    ("Wordfence",     r"wordfence"),
    ("Fastly",        r"x-fastly|fastly"),
]


async def check_waf(session, url, result):
    """Fingerprint WAF by sending a known malicious payload and inspecting the response."""
    global _WAF_DETECTED
    probe_url = url + ("&" if "?" in url else "?") + "wascan=<script>alert(1)</script>'"

    resp_clean = await fetch(session, url)
    resp_probe = await fetch(session, probe_url, allow_redirects=False)

    if not resp_probe:
        return

    headers_str  = " ".join(f"{k}:{v}" for k, v in resp_probe.headers.items()).lower()
    body         = (await resp_probe.read()).decode(errors="ignore").lower()
    combined     = headers_str + " " + body

    for waf_name, pattern in WAF_SIGNATURES:
        if re.search(pattern, combined, re.IGNORECASE):
            _WAF_DETECTED = True
            result.add(Finding(
                title=f"WAF detected: {waf_name}",
                severity="info",
                description=f"A {waf_name} WAF was fingerprinted. Injection checks will automatically retry with bypass encodings.",
                evidence=f"Pattern '{pattern}' matched in response headers/body",
                url=url,
                recommendation=f"Ensure {waf_name} rules are kept up to date and cover OWASP Top 10 attack patterns.",
            ))
            return

    # WAF-blocked response (403/406/429) with no known signature
    if resp_clean and resp_probe.status in (403, 406, 429, 503) and resp_clean.status == 200:
        _WAF_DETECTED = True
        result.add(Finding(
            title="Unknown WAF or IP-level blocking detected",
            severity="info",
            description=f"The malicious probe returned HTTP {resp_probe.status} while the clean request returned {resp_clean.status}.",
            evidence=f"Clean: HTTP {resp_clean.status} | Probe: HTTP {resp_probe.status}",
            url=url,
            recommendation="Verify WAF rules and ensure they cover OWASP Top 10.",
        ))


async def check_js_endpoints(session, url, result):
    """Extract API endpoint paths from linked JavaScript files and report novel ones."""
    resp = await fetch(session, url)
    if not resp:
        return
    body = (await resp.read()).decode(errors="ignore")
    soup = BeautifulSoup(body, "lxml")

    # Collect JS file URLs
    js_urls: list[str] = []
    for tag in soup.find_all("script", src=True):
        src = urllib.parse.urljoin(url, tag["src"])
        if urllib.parse.urlparse(src).netloc == urllib.parse.urlparse(url).netloc:
            js_urls.append(src)

    if not js_urls:
        return

    api_pattern = re.compile(
        r'["\']'                          # opening quote
        r'(/(?:api|v\d|graphql|rest|gql|rpc|internal)'
        r'(?:/[\w\-\.{}:]+){0,5})'       # path segments
        r'["\']',                          # closing quote
        re.IGNORECASE,
    )

    discovered: set[str] = set()
    for js_url in js_urls[:10]:
        js_resp = await fetch(session, js_url)
        if not js_resp:
            continue
        js_body = (await js_resp.read()).decode(errors="ignore")
        for match in api_pattern.finditer(js_body):
            discovered.add(match.group(1))

    if discovered:
        sample = sorted(discovered)[:20]
        result.add(Finding(
            title=f"API endpoints extracted from JavaScript ({len(discovered)} found)",
            severity="info",
            description="JavaScript source files contain hardcoded API endpoint paths that may expose undocumented functionality.",
            evidence="\n".join(sample),
            url=url,
            recommendation="Audit extracted endpoints for missing authentication, excessive data exposure, or undocumented functionality.",
        ))


def _run_dig(args: list[str], timeout: int = 5) -> str:
    try:
        out = subprocess.run(["dig"] + args, capture_output=True, text=True, timeout=timeout)
        return out.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


async def check_zone_transfer(session, url, result):
    """Attempt a DNS zone transfer (AXFR) against the target's nameservers."""
    loop = asyncio.get_event_loop()
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]

    # Resolve nameservers
    ns_output = await loop.run_in_executor(None, lambda: _run_dig(["+short", "NS", domain]))
    nameservers = [ns.rstrip(".") for ns in ns_output.strip().splitlines() if ns.strip()]

    if not nameservers:
        return

    for ns in nameservers[:3]:
        axfr_output = await loop.run_in_executor(
            None, lambda n=ns: _run_dig([f"@{n}", domain, "AXFR"], timeout=8))

        if axfr_output and "Transfer failed" not in axfr_output and len(axfr_output) > 200:
            # Count records returned
            records = [l for l in axfr_output.splitlines() if l and not l.startswith(";")]
            if len(records) > 5:
                result.add(Finding(
                    title=f"DNS zone transfer (AXFR) succeeded via {ns}",
                    severity="high",
                    description=f"Nameserver {ns} allowed a full zone transfer, exposing all DNS records for {domain}.",
                    evidence=f"{len(records)} records returned:\n" + "\n".join(records[:10]),
                    url=f"dns://{domain}",
                    recommendation="Restrict AXFR to authorised secondary nameservers only (ACL on your DNS server).",
                ))
                return


async def check_cert_transparency(session, url, result):
    """Query crt.sh certificate transparency logs to discover subdomains passively."""
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]

    ct_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    resp = await fetch(session, ct_url, timeout=15)
    if not resp or resp.status != 200:
        return

    try:
        data = json.loads((await resp.read()).decode(errors="ignore"))
    except (json.JSONDecodeError, Exception):
        return

    found: set[str] = set()
    for entry in data:
        name = entry.get("name_value", "")
        for line in name.splitlines():
            line = line.strip().lower().lstrip("*.")
            if line.endswith(domain) and line != domain:
                found.add(line)

    if found:
        sample = sorted(found)[:30]
        result.add(Finding(
            title=f"Certificate Transparency: {len(found)} subdomains found for {domain}",
            severity="info",
            description="Certificate transparency logs reveal subdomains that may expose internal or forgotten services.",
            evidence="\n".join(sample),
            url=ct_url,
            recommendation="Review all discovered subdomains for outdated, forgotten, or misconfigured services.",
        ))
        # Merge into result.discovered_subdomains (without overwriting existing entries)
        existing_names = {s.name for s in result.discovered_subdomains}
        for name in found:
            if name not in existing_names:
                result.discovered_subdomains.append(Subdomain(name=name))


# ΓöÇΓöÇ Additional vulnerability checks ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

async def check_file_upload(session, url, result):
    """Find file upload forms and test for unrestricted file upload."""
    resp = await fetch(session, url)
    if not resp:
        return
    body = (await resp.read()).decode(errors="ignore")
    soup = BeautifulSoup(body, "lxml")

    # Webshell content for each language
    test_files = [
        ("wascan_test.php",  b"<?php echo 'WASCAN_RCE_' . (7*7) . '_CANARY'; ?>",  "image/jpeg"),
        ("wascan_test.php5", b"<?php echo 'WASCAN_RCE_' . (7*7) . '_CANARY'; ?>",  "image/png"),
        ("wascan_test.phtml",b"<?php echo 'WASCAN_RCE_' . (7*7) . '_CANARY'; ?>",  "image/gif"),
        ("wascan_test.asp",  b"<% Response.Write(\"WASCAN_RCE_\"&(7*7)&\"_CANARY\") %>", "image/jpeg"),
        ("wascan_test.jsp",  b'<%= "WASCAN_RCE_" + (7*7) + "_CANARY" %>',          "image/jpeg"),
        ("wascan_test.svg",  b'<svg><script>alert("WASCAN_XSS")</script></svg>',    "image/svg+xml"),
    ]
    canary = "WASCAN_RCE_49_CANARY"

    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        file_input = next((i for i in inputs if i.get("type", "").lower() == "file"), None)
        if not file_input:
            continue

        action = urllib.parse.urljoin(url, form.get("action", url))
        method = (form.get("method", "post") or "post").upper()

        # Base form data (hidden fields etc.)
        base_data = {i["name"]: i.get("value", "")
                     for i in inputs
                     if i.get("name") and i.get("type", "").lower() not in ("file", "submit")}

        for filename, content, mime in test_files:
            field_name = file_input.get("name", "file")
            form_data = aiohttp.FormData()
            for k, v in base_data.items():
                form_data.add_field(k, v)
            form_data.add_field(field_name, content,
                                filename=filename, content_type=mime)
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector) as s:
                    upload_resp = await s.request(
                        method, action, data=form_data,
                        headers={**DEFAULT_HEADERS, **_AUTH_HEADERS},
                        cookies=_AUTH_COOKIES or None,
                        proxy=_PROXY_URL or None,
                        timeout=aiohttp.ClientTimeout(total=15),
                        ssl=False,
                    )
                    upload_body = await upload_resp.read()
                    upload_text = upload_body.decode(errors="ignore")
            except Exception:
                continue

            # Look for a path to the uploaded file in the response
            upload_path = None
            for match in re.finditer(r'["\']([^"\']*' + re.escape(filename) + r'[^"\']*)["\']',
                                     upload_text):
                upload_path = match.group(1)
                break
            if not upload_path:
                for match in re.finditer(r'((?:/[\w\-\.]+){1,6}/' + re.escape(filename) + r')',
                                         upload_text):
                    upload_path = match.group(1)
                    break

            if upload_path:
                exec_url = urllib.parse.urljoin(url, upload_path)
                exec_resp = await fetch(session, exec_url)
                if exec_resp:
                    exec_body = (await exec_resp.read()).decode(errors="ignore")
                    if canary in exec_body:
                        result.add(Finding(
                            title=f"Remote Code Execution via unrestricted file upload ({filename})",
                            severity="critical",
                            description=f"A server-side script ({filename}) was uploaded and executed successfully.",
                            evidence=f"Upload URL: {exec_url} | Canary: {canary} found in response",
                            url=action,
                            recommendation="Whitelist allowed file extensions; store uploads outside webroot; rename files on upload; scan for malicious content.",
                        ))
                        return
                    elif "WASCAN_XSS" in exec_body or filename.endswith(".svg"):
                        result.add(Finding(
                            title=f"Stored XSS via SVG file upload",
                            severity="high",
                            description="An SVG file containing a script tag was uploaded and is served directly.",
                            evidence=f"Upload URL: {exec_url}",
                            url=action,
                            recommendation="Sanitize SVG uploads; serve user content from a separate cookieless domain; set Content-Disposition: attachment.",
                        ))
                        return
                else:
                    result.add(Finding(
                        title=f"File upload accepted: {filename} (execution unconfirmed)",
                        severity="high",
                        description=f"The server accepted a {filename.split('.')[-1].upper()} file upload. Execution could not be confirmed automatically.",
                        evidence=f"Upload path hint: {upload_path}",
                        url=action,
                        recommendation="Restrict uploadable file types to a strict whitelist; rename files and store outside webroot.",
                    ))
                    return


async def check_prototype_pollution(session, url, result):
    """Test for prototype pollution via URL params and JSON body."""
    canary_key = "wascan_polluted"
    canary_val = "wascan_pp_7x7"

    payloads_url = [
        f"__proto__[{canary_key}]={canary_val}",
        f"constructor[prototype][{canary_key}]={canary_val}",
        f"__proto__.{canary_key}={canary_val}",
    ]
    payloads_json = [
        {f"__proto__": {canary_key: canary_val}},
        {"constructor": {"prototype": {canary_key: canary_val}}},
    ]

    async def _check_response(resp) -> bool:
        if not resp:
            return False
        body = (await resp.read()).decode(errors="ignore")
        return canary_val in body

    # URL parameter injection
    for payload_qs in payloads_url:
        sep = "&" if "?" in url else "?"
        test_url = url + sep + payload_qs
        resp = await fetch(session, test_url)
        if await _check_response(resp):
            result.add(Finding(
                title="Prototype pollution via URL parameter",
                severity="high",
                description=f"Injecting '{payload_qs}' caused the canary value to appear in the response, indicating Object.prototype was modified.",
                evidence=f"Payload: {payload_qs}",
                url=test_url,
                recommendation="Sanitize keys in all object merges/assignments; use Object.create(null) for config objects; apply the 'prototype-pollution' ESLint rule.",
            ))
            return

    # JSON body injection
    for payload_json in payloads_json:
        resp = await fetch(session, url, method="POST",
                           data=json.dumps(payload_json),
                           headers={"Content-Type": "application/json"})
        if await _check_response(resp):
            result.add(Finding(
                title="Prototype pollution via JSON body",
                severity="high",
                description="Injecting a __proto__ key in a JSON request body caused the canary value to appear in the response.",
                evidence=f"Payload: {json.dumps(payload_json)}",
                url=url,
                recommendation="Use safe merge libraries (e.g. lodash >= 4.17.21 with _.merge); block __proto__ / constructor keys at input validation.",
            ))
            return


async def check_request_smuggling(session, url, result):
    """Basic CL.TE / TE.CL HTTP request smuggling probe using raw sockets."""
    loop = asyncio.get_event_loop()
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    def _cl_te_probe() -> tuple[float, int]:
        """Send CL.TE probe: Content-Length is short, Transfer-Encoding is chunked with extra data."""
        try:
            import ssl as ssl_mod
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(8)
            if parsed.scheme == "https":
                ctx = ssl_mod.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl_mod.CERT_NONE
                raw = ctx.wrap_socket(raw, server_hostname=host)
            raw.connect((host, port))

            # CL=6 but TE sends 12 bytes of chunk body ΓÇö if CL wins, 6 bytes consumed.
            # The remaining "G" leaks into the next request pipeline ΓåÆ server may return 400/405.
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 6\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Connection: keep-alive\r\n\r\n"
                "0\r\n\r\n"
                "G"
            ).encode()
            t0 = time.time()
            raw.sendall(request)
            resp_data = b""
            try:
                while True:
                    chunk = raw.recv(4096)
                    if not chunk:
                        break
                    resp_data += chunk
                    if b"\r\n\r\n" in resp_data:
                        break
            except OSError:
                pass
            elapsed = time.time() - t0
            raw.close()
            status = int(resp_data.split(b" ")[1]) if b" " in resp_data[:20] else 0
            return elapsed, status
        except Exception:
            return 0.0, 0

    elapsed, status = await loop.run_in_executor(None, _cl_te_probe)

    if elapsed > 5.0:
        result.add(Finding(
            title="Possible HTTP request smuggling (CL.TE) ΓÇö timeout indicator",
            severity="high",
            description=f"A CL.TE smuggling probe caused the server to hang for {elapsed:.1f}s, suggesting the front-end uses Content-Length while the back-end uses Transfer-Encoding.",
            evidence=f"Probe elapsed: {elapsed:.1f}s | Status: {status}",
            url=url,
            recommendation="Normalise all HTTP/1.1 requests at the edge; reject ambiguous requests with both CL and TE headers; prefer HTTP/2 end-to-end.",
        ))
    elif status in (400, 405, 501) and elapsed < 3.0:
        result.add(Finding(
            title="Possible HTTP request smuggling (server rejected malformed headers)",
            severity="medium",
            description=f"The server returned HTTP {status} for a request with both Content-Length and Transfer-Encoding, which may indicate unusual header parsing.",
            evidence=f"Status: {status} | Elapsed: {elapsed:.1f}s",
            url=url,
            recommendation="Audit reverse-proxy / load-balancer HTTP parsing to ensure consistent CL vs TE handling.",
        ))


async def check_param_pollution(session, url, result):
    """HTTP Parameter Pollution ΓÇö send duplicate params and detect inconsistent handling."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        params = {"id": ["1"]}

    canary = "WASCAN_PP_CANARY"

    for param in list(params.keys())[:3]:
        original_val = params[param][0]
        # Send param twice: original value first, canary second
        polluted_query = (urllib.parse.urlencode({**params, param: [original_val]})
                          + f"&{urllib.parse.quote(param)}={urllib.parse.quote(canary)}")
        test_url = urllib.parse.urlunparse(parsed._replace(query=polluted_query))

        base_resp  = await fetch(session, url)
        poll_resp  = await fetch(session, test_url)

        if not base_resp or not poll_resp:
            continue

        base_body  = (await base_resp.read()).decode(errors="ignore")
        poll_body  = (await poll_resp.read()).decode(errors="ignore")

        if canary in poll_body and canary not in base_body:
            result.add(Finding(
                title=f"HTTP Parameter Pollution in '{param}'",
                severity="medium",
                description=f"Sending '{param}' twice caused the second (attacker-controlled) value to appear in the response, indicating the application uses the last occurrence.",
                evidence=f"Param: {param} | Canary: {canary} found in polluted response",
                url=test_url,
                recommendation="Explicitly define which occurrence of a duplicate parameter to use; reject or deduplicate repeated parameters at input validation.",
            ))
            return

        if poll_resp.status != base_resp.status:
            result.add(Finding(
                title=f"HTTP Parameter Pollution causes status change in '{param}'",
                severity="low",
                description=f"Sending '{param}' twice changed the HTTP status from {base_resp.status} to {poll_resp.status}.",
                evidence=f"Normal: HTTP {base_resp.status} | Polluted: HTTP {poll_resp.status}",
                url=test_url,
                recommendation="Normalise duplicate parameter handling; use strict input validation.",
            ))
            return


async def check_insecure_deserialization(session, url, result):
    """Detect Java, PHP, and Python serialized objects in cookies and response bodies."""
    import base64

    resp = await fetch(session, url)
    if not resp:
        return

    body = (await resp.read()).decode(errors="ignore")

    # Java serialized object magic bytes: AC ED 00 05 (base64: rO0AB)
    java_b64_pattern  = re.compile(r'rO0[A-Za-z0-9+/=]{10,}')
    # PHP serialized: a:N:{...} / O:N:"ClassName":...
    php_serial_pattern = re.compile(r'[OoAa]:\d+:"[^"]{1,50}":\d+:\{|[OoAa]:\d+:\{')
    # Python pickle magic: base64 of \x80\x02 or \x80\x04
    pickle_b64_pattern = re.compile(r'gASV[A-Za-z0-9+/=]{8,}|gAJ[A-Za-z0-9+/=]{8,}')

    # Check cookies
    raw_cookies = resp.headers.getall("Set-Cookie", [])
    all_cookie_vals = " ".join(raw_cookies)

    # Decode URL-encoded and base64 cookie values for inspection
    for raw in raw_cookies:
        name = raw.split("=")[0].strip()
        val_part = raw.split("=", 1)[1].split(";")[0].strip() if "=" in raw else ""
        try:
            decoded = base64.b64decode(urllib.parse.unquote(val_part) + "==")
            if decoded[:2] == b"\xac\xed":
                result.add(Finding(
                    title=f"Java serialized object in cookie '{name}'",
                    severity="high",
                    description="A cookie value decodes to a Java serialized object (magic bytes AC ED). Insecure deserialization may allow RCE if the application deserializes it without validation.",
                    evidence=f"Cookie: {name} | Magic bytes: AC ED 00 05",
                    url=url,
                    recommendation="Never deserialize untrusted data. Use a safe data format (JSON). If Java serialization is required, use SerialKiller or similar allowlist-based filter.",
                ))
        except Exception:
            pass

    checks = [
        (java_b64_pattern,   "Java serialized object (base64)",  "high",
         "Deserialize Java objects only from trusted sources; use allowlist deserialization filters."),
        (php_serial_pattern, "PHP serialized object",            "high",
         "Replace PHP serialize/unserialize with JSON; never deserialize user-supplied data."),
        (pickle_b64_pattern, "Python pickle object (base64)",    "critical",
         "Never unpickle untrusted data ΓÇö pickle allows arbitrary code execution. Use JSON or msgpack."),
    ]

    for pattern, title, severity, rec in checks:
        sources = [body, all_cookie_vals]
        for source in sources:
            m = pattern.search(source)
            if m:
                result.add(Finding(
                    title=title,
                    severity=severity,
                    description=f"A {title} was detected in the HTTP response or cookies. Deserializing attacker-controlled objects can lead to remote code execution.",
                    evidence=m.group(0)[:120],
                    url=url,
                    recommendation=rec,
                ))
                break


# ΓöÇΓöÇ Content discovery ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

async def check_content_discovery(session, base_url, result, wordlist=None):
    """Brute-force common paths and report accessible or forbidden endpoints."""
    paths = wordlist or CONTENT_WORDLIST
    base = base_url.rstrip("/")
    sem = asyncio.Semaphore(25)

    async def probe(path):
        async with sem:
            url = f"{base}/{path.lstrip('/')}"
            resp = await fetch(session, url, allow_redirects=False)
            if not resp:
                return
            if resp.status == 200:
                body = (await resp.read()).decode(errors="ignore")
                sev = "info"
                # Escalate severity for juicy content
                if any(k in path for k in (".env", ".git", ".sql", "backup", "shell",
                                           "phpinfo", "config", "secret", "passwd")):
                    sev = "high"
                elif any(k in path for k in ("admin", "panel", "dashboard", "console",
                                             "swagger", "graphiql", "actuator")):
                    sev = "medium"
                result.add(Finding(
                    title=f"Content discovered: /{path}",
                    severity=sev,
                    description=f"The path /{path} returned HTTP 200.",
                    evidence=body[:200].replace("\n", " "),
                    url=url,
                    recommendation="Remove or restrict access to this path if it should not be public.",
                ))
            elif resp.status == 403:
                result.add(Finding(
                    title=f"Forbidden path exists: /{path}",
                    severity="low",
                    description=f"/{path} returned HTTP 403 ΓÇö the resource exists but access is denied.",
                    evidence="HTTP 403",
                    url=url,
                    recommendation="Verify this path requires authentication and is properly protected.",
                ))
            elif resp.status in (301, 302, 307, 308):
                location = resp.headers.get("Location", "")
                result.add(Finding(
                    title=f"Redirect at /{path}",
                    severity="info",
                    description=f"/{path} redirects to {location}.",
                    evidence=f"HTTP {resp.status} ΓåÆ {location}",
                    url=url,
                    recommendation="Verify the redirect destination is intentional.",
                ))

    print(f"[*] Content discovery: probing {len(paths)} paths...", file=sys.stderr)
    await asyncio.gather(*[probe(p) for p in paths])


# ΓöÇΓöÇ Login automation ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

async def perform_login(login_url: str, login_data: str,
                        login_success: str) -> bool:
    """POST credentials, extract session cookies into _AUTH_COOKIES. Returns True on success."""
    global _AUTH_COOKIES

    data = dict(urllib.parse.parse_qsl(login_data))
    connector = aiohttp.TCPConnector(ssl=False)
    try:
        async with aiohttp.ClientSession(connector=connector,
                                         cookie_jar=aiohttp.CookieJar()) as s:
            resp = await s.post(
                login_url, data=data,
                headers={**DEFAULT_HEADERS, **_AUTH_HEADERS},
                proxy=_PROXY_URL or None,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False,
            )
            body = await resp.text(errors="ignore")

            if login_success and login_success.lower() not in body.lower():
                return False

            # Extract cookies from jar
            for cookie in s.cookie_jar:
                _AUTH_COOKIES[cookie.key] = cookie.value
            # Also grab Set-Cookie from headers
            for raw in resp.headers.getall("Set-Cookie", []):
                name = raw.split("=")[0].strip()
                val  = raw.split("=", 1)[1].split(";")[0].strip() if "=" in raw else ""
                if name:
                    _AUTH_COOKIES[name] = val
            return True
    except Exception as e:
        print(f"[!] Login failed: {e}", file=sys.stderr)
        return False


# ΓöÇΓöÇ WebSocket testing ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

async def check_websockets(session, url, result):
    """Detect WebSocket endpoints and test for missing origin validation / auth."""
    resp = await fetch(session, url)
    if not resp:
        return
    body = (await resp.read()).decode(errors="ignore")

    # Find ws:// / wss:// URLs in source
    ws_urls: set[str] = set()
    for m in re.finditer(r'["\']((wss?://[^\s"\'<>]+))["\']', body):
        ws_urls.add(m.group(1))

    # Also probe common WS paths
    parsed = urllib.parse.urlparse(url)
    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
    for path in ["/ws", "/websocket", "/socket", "/socket.io", "/ws/chat",
                 "/api/ws", "/live", "/realtime", "/stream", "/events"]:
        ws_urls.add(f"{ws_scheme}://{parsed.netloc}{path}")

    evil_origin = "https://evil.example.com"

    async def probe_ws(ws_url: str):
        # Test 1: connect without auth
        try:
            async with session.ws_connect(ws_url, ssl=False,
                                          timeout=aiohttp.ClientTimeout(total=5),
                                          headers={"Origin": evil_origin}) as ws:
                await ws.send_str('{"type":"ping"}')
                try:
                    msg = await asyncio.wait_for(ws.receive(), timeout=3)
                    if msg.type in (aiohttp.WSMsgType.TEXT, aiohttp.WSMsgType.BINARY):
                        result.add(Finding(
                            title=f"WebSocket accepts arbitrary Origin: {ws_url}",
                            severity="medium",
                            description="The WebSocket endpoint accepted a connection from an untrusted Origin and returned data.",
                            evidence=f"Origin: {evil_origin} ΓåÆ received: {str(msg.data)[:200]}",
                            url=ws_url,
                            recommendation="Validate the Origin header on WebSocket upgrade requests against an allowlist.",
                        ))
                except asyncio.TimeoutError:
                    # Connected but no response ΓÇö still flag as open
                    result.add(Finding(
                        title=f"WebSocket endpoint open (no Origin check): {ws_url}",
                        severity="low",
                        description="A WebSocket connection was established without authentication or Origin validation.",
                        evidence=f"Connected to {ws_url} with Origin: {evil_origin}",
                        url=ws_url,
                        recommendation="Enforce Origin validation and authentication on all WebSocket endpoints.",
                    ))
        except Exception:
            pass  # WS not available at this path

    await asyncio.gather(*[probe_ws(u) for u in list(ws_urls)[:10]])


# ΓöÇΓöÇ API fuzzing ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

STACK_TRACE_PATTERNS = re.compile(
    r"Traceback \(most recent|at \w+\.\w+\([\w\.]+:\d+\)|"
    r"Exception in thread|java\.lang\.\w+Exception|"
    r"System\.NullReferenceException|Fatal error:|"
    r"PHP Fatal error|SyntaxError:|ReferenceError:|"
    r"undefined method|NoMethodError|ActiveRecord::|"
    r"SQLSTATE\[|ORA-\d{5}",
    re.IGNORECASE,
)

API_TYPE_PAYLOADS = [
    ("null",          None),
    ("boolean",       True),
    ("negative int",  -1),
    ("large int",     999999999999),
    ("empty string",  ""),
    ("long string",   "A" * 5000),
    ("array",         []),
    ("object",        {}),
    ("sql fragment",  "' OR 1=1--"),
    ("format string", "%s%s%s%s%s"),
]


async def check_api_fuzzing(session, url, result):
    """Type-confusion and boundary fuzzing on JSON API endpoints."""
    api_paths = ["/api", "/api/v1", "/api/v2", "/graphql", "/rest",
                 "/v1", "/v2", "/json", "/data"]
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    endpoints: list[str] = [url]
    for path in api_paths:
        endpoints.append(base + path)

    # Also use any endpoints found by jsendpoints if already in result
    for finding in result.findings:
        if "API endpoints extracted" in finding.title:
            for line in finding.evidence.splitlines():
                if line.strip():
                    endpoints.append(base + line.strip())

    tested: set[str] = set()

    for endpoint in endpoints[:15]:
        if endpoint in tested:
            continue
        tested.add(endpoint)

        # GET baseline
        base_resp = await fetch(session, endpoint)
        if not base_resp:
            continue

        base_ct = base_resp.headers.get("Content-Type", "")
        if "json" not in base_ct and "json" not in endpoint:
            continue  # not a JSON endpoint, skip

        base_body = (await base_resp.read()).decode(errors="ignore")
        base_status = base_resp.status

        # Fuzz each field from baseline JSON response
        try:
            data = json.loads(base_body)
            if not isinstance(data, dict):
                data = {"value": "test"}
        except Exception:
            data = {"value": "test", "id": 1, "name": "test"}

        for field in list(data.keys())[:5]:
            for type_name, fuzz_val in API_TYPE_PAYLOADS:
                fuzz_body = {**data, field: fuzz_val}
                resp = await fetch(session, endpoint, method="POST",
                                   data=json.dumps(fuzz_body),
                                   headers={"Content-Type": "application/json"})
                if not resp:
                    continue
                resp_body = (await resp.read()).decode(errors="ignore")

                if resp.status == 500 or STACK_TRACE_PATTERNS.search(resp_body):
                    result.add(Finding(
                        title=f"API type confusion crash on field '{field}' ({type_name})",
                        severity="high",
                        description=f"Sending a {type_name} value for field '{field}' caused a server error or stack trace leak.",
                        evidence=resp_body[:400].replace("\n", " "),
                        url=endpoint,
                        recommendation="Add strict input type validation; catch all exceptions before they reach the HTTP response; disable stack trace exposure in production.",
                    ))
                    break

                # Mass assignment: send extra admin field
                admin_fuzz = {**data, "isAdmin": True, "role": "admin",
                              "is_admin": True, "admin": True}
                resp2 = await fetch(session, endpoint, method="POST",
                                    data=json.dumps(admin_fuzz),
                                    headers={"Content-Type": "application/json"})
                if resp2 and resp2.status == 200:
                    body2 = (await resp2.read()).decode(errors="ignore")
                    if any(k in body2.lower() for k in
                           ("admin", "role", "privilege", "permission", "isadmin")):
                        result.add(Finding(
                            title=f"Possible mass assignment at {endpoint}",
                            severity="high",
                            description="Extra privilege fields (isAdmin, role) sent in a JSON body were reflected in the response, suggesting mass assignment.",
                            evidence=body2[:300],
                            url=endpoint,
                            recommendation="Use an explicit allowlist of accepted fields (DTO pattern); never bind request bodies directly to model objects.",
                        ))
                        break


# ΓöÇΓöÇ DB utilities (diff, false positive) ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

def db_connect(db_path: str) -> sqlite3.Connection:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    # Ensure is_fp column exists (added in updated schema)
    try:
        con.execute("ALTER TABLE findings ADD COLUMN is_fp INTEGER DEFAULT 0")
        con.commit()
    except sqlite3.OperationalError:
        pass  # column already exists
    return con


def cmd_diff_scans(db_path: str, id1: int, id2: int, use_color: bool):
    """Compare two scan IDs from the DB and print new / fixed / unchanged findings."""
    b = "\033[1m" if use_color else ""
    r = "\033[0m" if use_color else ""
    green  = "\033[32m" if use_color else ""
    red    = "\033[31m" if use_color else ""
    yellow = "\033[33m" if use_color else ""

    con = db_connect(db_path)

    def get_findings(scan_id):
        rows = con.execute(
            "SELECT severity, title, url FROM findings WHERE scan_id=? AND (is_fp IS NULL OR is_fp=0)",
            (scan_id,)).fetchall()
        return {(r["title"], r["url"]): r["severity"] for r in rows}

    def get_scan_meta(scan_id):
        return con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()

    s1, s2 = get_scan_meta(id1), get_scan_meta(id2)
    if not s1:
        print(f"[!] Scan ID {id1} not found in {db_path}", file=sys.stderr); return
    if not s2:
        print(f"[!] Scan ID {id2} not found in {db_path}", file=sys.stderr); return

    f1, f2 = get_findings(id1), get_findings(id2)
    keys1, keys2 = set(f1), set(f2)

    new_findings     = keys2 - keys1
    fixed_findings   = keys1 - keys2
    unchanged        = keys1 & keys2

    print(f"\n{b}{'='*70}{r}")
    print(f"{b}  wascan ΓÇö Scan Diff{r}")
    print(f"{'='*70}")
    print(f"  Scan {id1}: {s1['target']}  ({s1['started_at']})")
    print(f"  Scan {id2}: {s2['target']}  ({s2['started_at']})")
    print(f"\n  {green}Fixed:     {len(fixed_findings)}{r}   "
          f"{red}New:       {len(new_findings)}{r}   "
          f"{yellow}Unchanged: {len(unchanged)}{r}")

    if new_findings:
        print(f"\n{red}  NEW (in scan {id2}, not in {id1}):{r}")
        for (title, url) in sorted(new_findings):
            sev = f2[(title, url)].upper().ljust(8)
            print(f"    [{sev}] {title}\n            {url}")

    if fixed_findings:
        print(f"\n{green}  FIXED (in scan {id1}, not in {id2}):{r}")
        for (title, url) in sorted(fixed_findings):
            sev = f1[(title, url)].upper().ljust(8)
            print(f"    [{sev}] {title}\n            {url}")

    print(f"\n{'='*70}\n")
    con.close()


def cmd_mark_fp(db_path: str, finding_id: int):
    """Mark a finding as a false positive in the DB."""
    con = db_connect(db_path)
    cur = con.execute("UPDATE findings SET is_fp=1 WHERE id=?", (finding_id,))
    con.commit()
    if cur.rowcount:
        print(f"[*] Finding {finding_id} marked as false positive.", file=sys.stderr)
    else:
        print(f"[!] Finding {finding_id} not found.", file=sys.stderr)
    con.close()


def cmd_list_scans(db_path: str):
    """Print a table of all scans stored in the DB."""
    con = db_connect(db_path)
    rows = con.execute(
        "SELECT id, target, started_at, total_findings, critical, high, medium, low, info"
        " FROM scans ORDER BY id DESC LIMIT 50").fetchall()
    con.close()
    if not rows:
        print("No scans in database.", file=sys.stderr)
        return
    print(f"\n{'ID':>4}  {'Target':<40}  {'Date':<20}  "
          f"{'Total':>5}  {'C':>3}  {'H':>3}  {'M':>3}  {'L':>3}")
    print("-" * 90)
    for r in rows:
        print(f"{r['id']:>4}  {str(r['target']):<40}  "
              f"{str(r['started_at'])[:19]:<20}  "
              f"{r['total_findings']:>5}  {r['critical']:>3}  "
              f"{r['high']:>3}  {r['medium']:>3}  {r['low']:>3}")
    print()


# ΓöÇΓöÇ TLS / SSL deep analysis ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

async def check_tls(session, url, result):
    """Check TLS certificate, protocol versions, and cipher suite quality."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        result.add(Finding(
            title="Site not served over HTTPS",
            severity="high",
            description="The target uses HTTP, not HTTPS. All traffic is unencrypted.",
            url=url,
            recommendation="Obtain a TLS certificate and redirect all HTTP traffic to HTTPS.",
        ))
        return

    host = parsed.hostname or ""
    port = parsed.port or 443
    loop = asyncio.get_event_loop()

    def _get_cert_and_cipher():
        ctx = ssl_module.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert(), ssock.cipher(), ssock.version()

    def _test_old_protocol(min_ver, max_ver):
        try:
            ctx = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl_module.CERT_NONE
            ctx.minimum_version = min_ver
            ctx.maximum_version = max_ver
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False

    # Certificate checks
    try:
        cert, cipher, tls_version = await loop.run_in_executor(None, _get_cert_and_cipher)

        # Expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            try:
                expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                if days_left < 0:
                    result.add(Finding(
                        title="TLS certificate has expired",
                        severity="critical",
                        description=f"The certificate expired {abs(days_left)} days ago on {not_after_str}.",
                        evidence=f"notAfter: {not_after_str}",
                        url=url,
                        recommendation="Renew the certificate immediately.",
                    ))
                elif days_left < 14:
                    result.add(Finding(
                        title=f"TLS certificate expires in {days_left} days",
                        severity="high",
                        description="The certificate is close to expiry; browsers will show security warnings when it expires.",
                        evidence=f"notAfter: {not_after_str}",
                        url=url,
                        recommendation="Renew the certificate now.",
                    ))
                elif days_left < 30:
                    result.add(Finding(
                        title=f"TLS certificate expires in {days_left} days",
                        severity="medium",
                        description="The certificate expires within 30 days.",
                        evidence=f"notAfter: {not_after_str}",
                        url=url,
                        recommendation="Schedule certificate renewal.",
                    ))
            except ValueError:
                pass

        # Weak ciphers
        cipher_name = cipher[0] if cipher else ""
        weak_keywords = ("RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "MD5", "IDEA")
        if any(w in cipher_name.upper() for w in weak_keywords):
            result.add(Finding(
                title=f"Weak TLS cipher suite: {cipher_name}",
                severity="high",
                description="The negotiated cipher suite is considered cryptographically weak.",
                evidence=f"Cipher: {cipher_name} | TLS version: {tls_version}",
                url=url,
                recommendation="Disable weak cipher suites; prefer ECDHE+AES-GCM or CHACHA20-POLY1305.",
            ))

        # Info: report what's in use
        result.add(Finding(
            title=f"TLS info: {tls_version} / {cipher_name}",
            severity="info",
            description="TLS version and cipher suite in use.",
            evidence=f"Protocol: {tls_version} | Cipher: {cipher_name}",
            url=url,
            recommendation="Ensure TLS 1.3 is preferred and weak suites are disabled.",
        ))

    except ssl_module.SSLCertVerificationError as e:
        result.add(Finding(
            title="TLS certificate validation failed",
            severity="high",
            description="The server's TLS certificate could not be verified (self-signed, wrong hostname, or untrusted CA).",
            evidence=str(e)[:200],
            url=url,
            recommendation="Use a certificate from a trusted CA; ensure the hostname matches the certificate CN/SANs.",
        ))
    except Exception:
        pass

    # Old protocol version checks
    for label, min_v, max_v in [
        ("TLS 1.0", ssl_module.TLSVersion.TLSv1,   ssl_module.TLSVersion.TLSv1),
        ("TLS 1.1", ssl_module.TLSVersion.TLSv1_1, ssl_module.TLSVersion.TLSv1_1),
    ]:
        accepted = await loop.run_in_executor(None, _test_old_protocol, min_v, max_v)
        if accepted:
            result.add(Finding(
                title=f"Deprecated protocol supported: {label}",
                severity="medium",
                description=f"The server accepts {label} connections, which are deprecated and have known vulnerabilities (POODLE, BEAST).",
                evidence=f"{label} handshake succeeded against {host}:{port}",
                url=url,
                recommendation=f"Disable {label} in your TLS configuration; require TLS 1.2 minimum, prefer TLS 1.3.",
            ))


# ΓöÇΓöÇ Dependency CVE scanning ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

def _parse_package_json(body: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(body)
        pkgs = {}
        pkgs.update(data.get("dependencies", {}))
        pkgs.update(data.get("devDependencies", {}))
        result = []
        for name, ver in pkgs.items():
            ver = re.sub(r"[^0-9.]", "", ver.lstrip("^~>=<"))
            if ver:
                result.append((name, ver))
        return result
    except Exception:
        return []


def _parse_requirements_txt(body: str) -> list[tuple[str, str]]:
    pkgs = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_\-\.]+)==([^\s;]+)", line)
        if m:
            pkgs.append((m.group(1), m.group(2)))
    return pkgs


def _parse_composer_json(body: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(body)
        pkgs = {}
        pkgs.update(data.get("require", {}))
        result = []
        for name, ver in pkgs.items():
            if name == "php":
                continue
            ver = re.sub(r"[^0-9.]", "", ver.lstrip("^~>=<"))
            if ver:
                result.append((name, ver))
        return result
    except Exception:
        return []


def _parse_go_mod(body: str) -> list[tuple[str, str]]:
    pkgs = []
    for line in body.splitlines():
        m = re.match(r"^\s+([^\s]+)\s+v([0-9][^\s]+)", line)
        if m:
            pkgs.append((m.group(1), m.group(2)))
    return pkgs


async def _query_osv(session, name: str, version: str, ecosystem: str) -> list[dict]:
    payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    resp = await fetch(session, "https://api.osv.dev/v1/query",
                       method="POST", data=json.dumps(payload),
                       headers={"Content-Type": "application/json"}, timeout=12)
    if not resp or resp.status != 200:
        return []
    try:
        data = json.loads((await resp.read()).decode(errors="ignore"))
        return data.get("vulns", [])
    except Exception:
        return []


async def check_dependency_cves(session, url, result):
    """Fetch dependency manifests and query OSV for known CVEs."""
    dep_files = [
        ("package.json",      "npm",        _parse_package_json),
        ("requirements.txt",  "PyPI",       _parse_requirements_txt),
        ("composer.json",     "Packagist",  _parse_composer_json),
        ("go.mod",            "Go",         _parse_go_mod),
    ]
    base = url.rstrip("/")
    found_any = False

    for filename, ecosystem, parser in dep_files:
        resp = await fetch(session, f"{base}/{filename}")
        if not resp or resp.status != 200:
            continue

        body = (await resp.read()).decode(errors="ignore")
        packages = parser(body)
        if not packages:
            continue

        found_any = True
        print(f"[*] depCVE: checking {len(packages)} {ecosystem} packages from {filename}",
              file=sys.stderr)

        tasks = [_query_osv(session, name, ver, ecosystem) for name, ver in packages[:30]]
        all_vulns = await asyncio.gather(*tasks)

        for (pkg_name, pkg_ver), vulns in zip(packages[:30], all_vulns):
            if not vulns:
                continue
            vuln = vulns[0]
            vuln_id    = vuln.get("id", "UNKNOWN")
            summary    = vuln.get("summary", "No summary")
            severity   = "high"
            aliases    = vuln.get("aliases", [])
            cve_ids    = [a for a in aliases if a.startswith("CVE-")]
            sev_data   = vuln.get("database_specific", {}).get("severity", "")
            if sev_data.upper() == "CRITICAL":
                severity = "critical"
            elif sev_data.upper() in ("LOW", "NEGLIGIBLE"):
                severity = "low"

            result.add(Finding(
                title=f"Vulnerable dependency: {pkg_name}@{pkg_ver} ({vuln_id})",
                severity=severity,
                description=f"{ecosystem} package '{pkg_name}' version {pkg_ver} has a known vulnerability: {summary}",
                evidence=f"IDs: {', '.join([vuln_id] + cve_ids[:2])} | Severity: {sev_data or 'unknown'}",
                url=f"{base}/{filename}",
                recommendation=f"Upgrade {pkg_name} to a patched version. Check {vuln_id} for fix details.",
            ))

    if not found_any:
        pass  # No dependency files reachable ΓÇö normal, not a finding


# ΓöÇΓöÇ OAuth / OIDC testing ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

async def check_oauth(session, url, result):
    """Detect OAuth/OIDC flows and test for common misconfigurations."""
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Check for OIDC discovery endpoint
    discovery_url = f"{base}/.well-known/openid-configuration"
    disc_resp = await fetch(session, discovery_url)
    oauth_config = {}
    if disc_resp and disc_resp.status == 200:
        try:
            oauth_config = json.loads((await disc_resp.read()).decode(errors="ignore"))
            result.add(Finding(
                title="OIDC discovery endpoint exposed",
                severity="info",
                description="An OpenID Connect discovery document was found. This reveals authorization, token, and JWKS endpoints.",
                evidence=discovery_url,
                url=discovery_url,
                recommendation="Restrict discovery endpoint to known clients if possible; ensure all listed endpoints are secured.",
            ))
        except Exception:
            pass

    # Fetch the page and look for OAuth patterns
    resp = await fetch(session, url)
    if not resp:
        return
    body = (await resp.read()).decode(errors="ignore")

    # Check 1: implicit flow (response_type=token in URLs)
    if re.search(r"response_type=token(?:&|%26|$)", body, re.IGNORECASE):
        result.add(Finding(
            title="OAuth implicit flow detected",
            severity="medium",
            description="The application uses OAuth implicit flow (response_type=token), which returns access tokens in the URL fragment ΓÇö vulnerable to token leakage via referrer headers and browser history.",
            evidence="response_type=token found in page source",
            url=url,
            recommendation="Use authorization code flow with PKCE instead of implicit flow.",
        ))

    # Check 2: state parameter missing from auth URLs
    auth_url_pattern = re.compile(r'(https?://[^\s"\']+(?:authorize|auth|oauth)[^\s"\']*)', re.IGNORECASE)
    for auth_url in auth_url_pattern.findall(body)[:5]:
        if "state=" not in auth_url and "response_type=" in auth_url:
            result.add(Finding(
                title="OAuth authorization URL missing 'state' parameter",
                severity="high",
                description="An OAuth authorization URL was found without a 'state' parameter, making it vulnerable to CSRF attacks that could hijack the OAuth flow.",
                evidence=auth_url[:200],
                url=url,
                recommendation="Always include a cryptographically random 'state' parameter and verify it on callback.",
            ))
            break

    # Check 3: token appears in URL parameters
    token_in_url = re.search(r"[?&](access_token|id_token|token)=([A-Za-z0-9\-_\.]+)", body)
    if token_in_url:
        result.add(Finding(
            title=f"OAuth token in URL: '{token_in_url.group(1)}'",
            severity="high",
            description="An OAuth access token appears in a URL, which may be logged by servers, proxies, and browsers and accessible via Referrer headers.",
            evidence=token_in_url.group(0)[:150],
            url=url,
            recommendation="Deliver tokens only in response bodies or secure headers, never in URLs.",
        ))

    # Check 4: open redirect in redirect_uri
    redirect_uri_pattern = re.compile(r"redirect_uri=([^&\s\"']+)", re.IGNORECASE)
    for match in redirect_uri_pattern.findall(body)[:3]:
        decoded = urllib.parse.unquote(match)
        if not decoded.startswith(base):
            result.add(Finding(
                title="OAuth redirect_uri points outside origin",
                severity="high",
                description=f"The redirect_uri '{decoded}' does not match the application origin, potentially allowing token theft via open redirect.",
                evidence=f"redirect_uri={decoded}",
                url=url,
                recommendation="Validate redirect_uri against an exact allowlist of pre-registered URIs.",
            ))
            break

    # Check 5: PKCE required?
    if oauth_config:
        methods = oauth_config.get("code_challenge_methods_supported", [])
        if not methods:
            result.add(Finding(
                title="OIDC server does not advertise PKCE support",
                severity="low",
                description="The OIDC discovery document does not list code_challenge_methods_supported. PKCE may not be enforced for public clients.",
                evidence=str(oauth_config.get("code_challenge_methods_supported", "not listed")),
                url=discovery_url,
                recommendation="Enforce PKCE (S256) for all public OAuth clients to prevent authorization code interception.",
            ))


# ΓöÇΓöÇ Plugin system ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

def load_plugins(plugin_dir: str) -> list[tuple[str, object]]:
    """Load all .py files from plugin_dir exposing an async check(session, url, result) function."""
    plugins: list[tuple[str, object]] = []
    plugin_path = Path(plugin_dir)
    if not plugin_path.is_dir():
        print(f"[!] Plugin dir not found: {plugin_dir}", file=sys.stderr)
        return plugins

    for py_file in sorted(plugin_path.glob("*.py")):
        try:
            spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
            mod  = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore
            if hasattr(mod, "check") and callable(mod.check):
                plugins.append((py_file.stem, mod.check))
                print(f"[*] Plugin loaded: {py_file.stem}", file=sys.stderr)
            else:
                print(f"[!] {py_file.name} has no async check(session, url, result) ΓÇö skipped",
                      file=sys.stderr)
        except Exception as e:
            print(f"[!] Plugin {py_file.name} failed to load: {e}", file=sys.stderr)

    return plugins


async def run_plugins(session, url: str, result: ScanResult):
    """Execute all loaded plugins concurrently."""
    if not _LOADED_PLUGINS:
        return
    print(f"[*] Running {len(_LOADED_PLUGINS)} plugin(s)...", file=sys.stderr)
    tasks = [fn(session, url, result) for _, fn in _LOADED_PLUGINS]
    await asyncio.gather(*tasks, return_exceptions=True)


# ΓöÇΓöÇ Screenshot capture ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

async def capture_screenshots(urls: list[str], screenshot_dir: str,
                               auth_cookies: dict | None = None):
    """Take screenshots of the given URLs using Playwright Chromium."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("[!] playwright not installed ΓÇö run: pip install playwright && playwright install chromium",
              file=sys.stderr)
        return

    os.makedirs(screenshot_dir, exist_ok=True)
    taken = 0

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx_opts: dict = {"ignore_https_errors": True}
        if auth_cookies:
            # Convert to Playwright cookie format
            ctx_opts["storage_state"] = {
                "cookies": [{"name": k, "value": v, "url": urls[0]}
                            for k, v in auth_cookies.items()]
            }
        context = await browser.new_context(**ctx_opts)

        for url in urls[:60]:
            try:
                page = await context.new_page()
                await page.goto(url, timeout=15_000, wait_until="domcontentloaded")
                safe = re.sub(r"[^\w\-.]", "_", url.split("//", 1)[-1])[:80]
                out_path = os.path.join(screenshot_dir, f"{safe}.png")
                await page.screenshot(path=out_path, full_page=False)
                await page.close()
                taken += 1
            except Exception:
                pass

        await browser.close()

    print(f"[*] Screenshots: {taken} saved to {screenshot_dir}/", file=sys.stderr)


# ΓöÇΓöÇ Email reporting ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

def send_email_report(result: ScanResult, smtp_host: str, smtp_port: int,
                       smtp_user: str, smtp_pass: str,
                       from_addr: str, to_addrs: list[str]):
    counts = result.severity_counts()
    netloc = urllib.parse.urlparse(result.target).netloc
    subject = (f"wascan: {counts['critical']}C / {counts['high']}H findings on {netloc}")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_addr
    msg["To"]      = ", ".join(to_addrs)
    msg.attach(MIMEText(generate_html_report(result), "html", "utf-8"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as s:
            s.ehlo()
            try:
                s.starttls()
            except smtplib.SMTPException:
                pass  # server doesn't support STARTTLS ΓÇö proceed unencrypted
            if smtp_user:
                s.login(smtp_user, smtp_pass)
            s.sendmail(from_addr, to_addrs, msg.as_string())
        print(f"[*] Report emailed to {', '.join(to_addrs)}", file=sys.stderr)
    except Exception as e:
        print(f"[!] Email failed: {e}", file=sys.stderr)


# ΓöÇΓöÇ Scheduled scanning ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

def cmd_schedule_add(db_path: str, target: str, cron_expr: str, extra_args: str):
    """Store a scheduled scan in the DB and add it to the user's crontab."""
    con = db_connect(db_path)
    con.execute("""
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT, cron_expr TEXT, extra_args TEXT,
            last_run TEXT, created_at TEXT, enabled INTEGER DEFAULT 1
        )""")
    con.execute(
        "INSERT INTO schedules (target, cron_expr, extra_args, created_at) VALUES (?,?,?,?)",
        (target, cron_expr, extra_args, datetime.utcnow().isoformat()),
    )
    con.commit()
    con.close()

    # Build crontab entry
    scanner_abs = os.path.abspath(__file__)
    db_abs      = os.path.abspath(db_path)
    cron_cmd    = (f"python3 {scanner_abs} {target} {extra_args} "
                   f"--db {db_abs} --output html")
    cron_line   = f"{cron_expr} {cron_cmd}\n"

    try:
        existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
        if cron_cmd in existing:
            print("[*] Identical cron entry already exists ΓÇö not duplicating.", file=sys.stderr)
            return
        new_crontab = existing.rstrip("\n") + "\n" + cron_line
        subprocess.run(["crontab", "-"], input=new_crontab, text=True, check=True)
        print(f"[*] Scheduled: '{cron_expr}'  ΓåÆ  {target}", file=sys.stderr)
        print(f"    Full command: {cron_cmd}", file=sys.stderr)
    except FileNotFoundError:
        print("[!] 'crontab' not available ΓÇö schedule saved to DB only.", file=sys.stderr)
        print(f"    Manually add to cron: {cron_line.strip()}", file=sys.stderr)


def cmd_list_schedules(db_path: str):
    con = db_connect(db_path)
    try:
        rows = con.execute(
            "SELECT id, target, cron_expr, extra_args, last_run, enabled FROM schedules ORDER BY id"
        ).fetchall()
    except sqlite3.OperationalError:
        print("No schedules found.", file=sys.stderr)
        return
    finally:
        con.close()

    if not rows:
        print("No scheduled scans.", file=sys.stderr)
        return

    print(f"\n{'ID':>3}  {'Target':<35}  {'Cron':<20}  {'Last run':<20}  En")
    print("-" * 90)
    for r in rows:
        last = str(r["last_run"] or "never")[:19]
        print(f"{r['id']:>3}  {str(r['target']):<35}  {str(r['cron_expr']):<20}  {last:<20}  {'Y' if r['enabled'] else 'N'}")
    print()


# ΓöÇΓöÇ SQLite storage ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

def save_to_db(db_path: str, result: ScanResult):
    con = db_connect(db_path)
    con.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT, started_at TEXT, finished_at TEXT,
            total_findings INTEGER, critical INTEGER, high INTEGER,
            medium INTEGER, low INTEGER, info INTEGER
        )""")
    con.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER, severity TEXT, title TEXT,
            description TEXT, evidence TEXT, url TEXT, recommendation TEXT,
            is_fp INTEGER DEFAULT 0,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )""")
    counts = result.severity_counts()
    cur = con.execute(
        "INSERT INTO scans (target,started_at,finished_at,total_findings,"
        "critical,high,medium,low,info) VALUES (?,?,?,?,?,?,?,?,?)",
        (result.target, result.started_at, result.finished_at,
         len(result.findings), counts["critical"], counts["high"],
         counts["medium"], counts["low"], counts["info"]),
    )
    scan_id = cur.lastrowid
    con.executemany(
        "INSERT INTO findings (scan_id,severity,title,description,evidence,url,recommendation,is_fp)"
        " VALUES (?,?,?,?,?,?,?,0)",
        [(scan_id, f.severity, f.title, f.description, f.evidence, f.url, f.recommendation)
         for f in result.sorted_findings()],
    )
    con.commit()
    con.close()


# ΓöÇΓöÇ Webhook notifications ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

async def send_webhook(webhook_url: str, result: ScanResult):
    """Send critical + high findings to a Slack or Discord webhook."""
    urgent = [f for f in result.sorted_findings()
              if f.severity in ("critical", "high")]
    if not urgent:
        return

    is_discord = "discord.com" in webhook_url or "discordapp.com" in webhook_url

    if is_discord:
        # Discord embeds format
        embeds = []
        for f in urgent[:10]:
            color = 0xe74c3c if f.severity == "critical" else 0xe67e22
            embeds.append({
                "title": f.title,
                "color": color,
                "fields": [
                    {"name": "Severity", "value": f.severity.upper(), "inline": True},
                    {"name": "URL", "value": f.url[:200] or "ΓÇö", "inline": False},
                    {"name": "Description", "value": f.description[:500], "inline": False},
                    {"name": "Fix", "value": f.recommendation[:300] or "ΓÇö", "inline": False},
                ],
            })
        payload = {
            "username": "wascan",
            "content": f"**wascan** found {len(urgent)} critical/high findings on `{result.target}`",
            "embeds": embeds,
        }
    else:
        # Slack blocks format
        blocks = [
            {"type": "header", "text": {"type": "plain_text",
             "text": f"wascan ΓÇö {len(urgent)} critical/high findings on {result.target}"}},
        ]
        for f in urgent[:10]:
            icon = ":red_circle:" if f.severity == "critical" else ":large_orange_circle:"
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"{icon} *{f.title}*\n{f.description}\n_Fix: {f.recommendation}_\n<{f.url}>"}})
        payload = {"blocks": blocks}

    try:
        connector = aiohttp.TCPConnector(ssl=True)
        async with aiohttp.ClientSession(connector=connector) as s:
            await s.post(webhook_url, json=payload,
                         timeout=aiohttp.ClientTimeout(total=10))
        print(f"[*] Webhook notification sent ({len(urgent)} findings)", file=sys.stderr)
    except Exception as e:
        print(f"[!] Webhook failed: {e}", file=sys.stderr)


# ΓöÇΓöÇ Orchestrator ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

ALL_CHECKS = [
    "headers", "files", "methods", "ssl", "xss", "sqli",
    "redirect", "cors", "clickjack", "dirlist", "cookies",
    "traversal", "ssrf", "cmdi", "xxe", "jwt",
    "secrets", "jslibs", "defaultcreds", "ratelimit",
    "ssti", "crlf", "hostheader", "idor", "graphql",
    "techfingerprint", "waf", "jsendpoints", "zonetransfer", "certtransparency",
    "fileupload", "protopollution", "smuggling", "parampollution", "deserial",
    "content", "websockets", "apifuzz",
    "tls", "depcve", "oauth",
    "spider", "subdomains",
]


async def run_scan(target: str, checks: list[str], spider_depth: int,
                   spider_pages: int, subdomain_wordlist: list[str],
                   verbose: bool, webhook_url: str = "", db_path: str = "",
                   content_wordlist: Optional[list[str]] = None,
                   screenshot_dir: str = "") -> ScanResult:
    result = ScanResult(target=target, started_at=datetime.utcnow().isoformat())

    connector = aiohttp.TCPConnector(ssl=False, limit=30)
    async with aiohttp.ClientSession(connector=connector) as session:
        selected = checks if checks else ALL_CHECKS

        # Spider runs first so crawled URLs are available for other checks
        if "spider" in selected:
            await check_spider_and_forms(session, target, result,
                                          spider_depth, spider_pages, verbose)

        check_map = {
            "headers":        lambda: check_security_headers(session, target, result),
            "files":          lambda: check_sensitive_files(session, target, result),
            "methods":        lambda: check_http_methods(session, target, result),
            "ssl":            lambda: check_ssl_redirect(session, target, result),
            "xss":            lambda: check_xss(session, target, result),
            "sqli":           lambda: check_sqli(session, target, result),
            "redirect":       lambda: check_open_redirect(session, target, result),
            "cors":           lambda: check_cors(session, target, result),
            "clickjack":      lambda: check_clickjacking(session, target, result),
            "dirlist":        lambda: check_directory_listing(session, target, result),
            "cookies":        lambda: check_cookie_flags(session, target, result),
            "traversal":      lambda: check_path_traversal(session, target, result),
            "ssrf":           lambda: check_ssrf(session, target, result),
            "cmdi":           lambda: check_command_injection(session, target, result),
            "xxe":            lambda: check_xxe(session, target, result),
            "jwt":            lambda: check_jwt(session, target, result),
            "secrets":        lambda: check_sensitive_data_exposure(session, target, result),
            "jslibs":         lambda: check_js_libraries(session, target, result),
            "defaultcreds":   lambda: check_default_credentials(session, target, result),
            "ratelimit":      lambda: check_rate_limiting(session, target, result),
            "ssti":           lambda: check_ssti(session, target, result),
            "crlf":           lambda: check_crlf(session, target, result),
            "hostheader":     lambda: check_host_header_injection(session, target, result),
            "idor":           lambda: check_idor(session, target, result),
            "graphql":        lambda: check_graphql(session, target, result),
            "techfingerprint":lambda: check_tech_fingerprint(session, target, result),
            "waf":            lambda: check_waf(session, target, result),
            "jsendpoints":    lambda: check_js_endpoints(session, target, result),
            "zonetransfer":   lambda: check_zone_transfer(session, target, result),
            "certtransparency":lambda: check_cert_transparency(session, target, result),
            "fileupload":      lambda: check_file_upload(session, target, result),
            "protopollution":  lambda: check_prototype_pollution(session, target, result),
            "smuggling":       lambda: check_request_smuggling(session, target, result),
            "parampollution":  lambda: check_param_pollution(session, target, result),
            "deserial":        lambda: check_insecure_deserialization(session, target, result),
            "content":         lambda: check_content_discovery(session, target, result,
                                                               content_wordlist),
            "websockets":      lambda: check_websockets(session, target, result),
            "apifuzz":         lambda: check_api_fuzzing(session, target, result),
            "tls":             lambda: check_tls(session, target, result),
            "depcve":          lambda: check_dependency_cves(session, target, result),
            "oauth":           lambda: check_oauth(session, target, result),
            "subdomains":      lambda: check_subdomains(session, target, result,
                                                        subdomain_wordlist, verbose),
        }

        tasks = [check_map[c]() for c in selected if c in check_map and c != "spider"]
        if _LOADED_PLUGINS:
            tasks.append(run_plugins(session, target, result))
        await asyncio.gather(*tasks)

    result.finished_at = datetime.utcnow().isoformat()

    if screenshot_dir:
        all_urls = [target] + result.crawled_urls[:19]
        await capture_screenshots(all_urls, screenshot_dir, _AUTH_COOKIES)

    if db_path:
        save_to_db(db_path, result)
        print(f"[*] Results saved to {db_path}", file=sys.stderr)

    if webhook_url:
        await send_webhook(webhook_url, result)

    return result


# ΓöÇΓöÇ CLI ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

def normalise_target(t: str) -> str:
    t = t.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t


def output_result(result: ScanResult, args, index: int = 0, total: int = 1,
                  email_cfg: Optional[dict] = None):
    """Write one scan result according to --output / --report-file flags."""
    hostname = urllib.parse.urlparse(result.target).netloc.replace(":", "_")

    if args.output == "csv":
        csv_text = generate_csv_report(result)
        if args.report_file and total == 1:
            with open(args.report_file, "w", newline="") as f:
                f.write(csv_text)
            print(f"[*] CSV report saved to {args.report_file}", file=sys.stderr)
        else:
            out_file = f"wascan_{hostname}.csv"
            with open(out_file, "w", newline="") as f:
                f.write(csv_text)
            print(f"[*] CSV report saved to {out_file}", file=sys.stderr)
        return

    if args.output == "html":
        html = generate_html_report(result)
        if args.report_file and total == 1:
            out_file = args.report_file
        else:
            out_file = f"wascan_{hostname}.html"
        with open(out_file, "w") as f:
            f.write(html)
        print(f"[*] HTML report saved to {out_file}", file=sys.stderr)

    elif args.output == "json":
        if args.report_file and total == 1:
            with open(args.report_file, "w") as f:
                f.write(json.dumps(_result_to_dict(result), indent=2))
            print(f"[*] JSON saved to {args.report_file}", file=sys.stderr)
        else:
            print(json.dumps(_result_to_dict(result), indent=2))

    else:
        print_text_report(result, use_color=not args.no_color)

    if email_cfg and email_cfg.get("smtp_host") and email_cfg.get("to_addrs"):
        try:
            send_email_report(
                result,
                smtp_host=email_cfg["smtp_host"],
                smtp_port=email_cfg.get("smtp_port", 587),
                smtp_user=email_cfg.get("smtp_user", ""),
                smtp_pass=email_cfg.get("smtp_pass", ""),
                from_addr=email_cfg.get("from_addr", email_cfg.get("smtp_user", "")),
                to_addrs=email_cfg["to_addrs"],
            )
            print(f"[*] Email report sent to {', '.join(email_cfg['to_addrs'])}", file=sys.stderr)
        except Exception as exc:
            print(f"[!] Email failed: {exc}", file=sys.stderr)


def _result_to_dict(result: ScanResult) -> dict:
    return {
        "target": result.target,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "summary": result.severity_counts(),
        "crawled_urls": result.crawled_urls,
        "discovered_subdomains": [asdict(s) for s in result.discovered_subdomains],
        "findings": [asdict(f) for f in result.sorted_findings()],
    }


def main():
    parser = argparse.ArgumentParser(
        prog="wascan",
        description="wascan ΓÇö Web Application Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Profiles:  --profile quick | stealth | full\n\n"
            "Checks:\n"
            "  Injection:      xss, sqli, traversal, ssrf, cmdi, xxe, ssti, crlf\n"
            "  Auth/Session:   jwt, defaultcreds, cookies, hostheader, idor\n"
            "  Config/Headers: headers, files, methods, ssl, clickjack, dirlist, cors\n"
            "  Discovery:      secrets, jslibs, jsendpoints, techfingerprint, waf, graphql\n"
            "  Advanced:       fileupload, protopollution, smuggling, parampollution, deserial\n"
            "  New:            content, websockets, apifuzz\n"
            "  DNS/Recon:      subdomains, zonetransfer, certtransparency\n"
            "  Active:         spider, ratelimit\n\n"
            "DB commands (require --db):\n"
            "  --list-scans                 Show all stored scans\n"
            "  --diff-scans ID1:ID2         Diff two scan IDs (new/fixed/unchanged)\n"
            "  --mark-fp FINDING_ID         Mark a finding as a false positive\n\n"
            "Examples:\n"
            "  python3 scanner.py https://example.com --profile quick\n"
            "  python3 scanner.py https://example.com --profile stealth --delay 2.0\n"
            "  python3 scanner.py https://example.com --proxy http://127.0.0.1:8080\n"
            "  python3 scanner.py https://example.com --login-url https://example.com/login "
            "--login-data 'user=admin&pass=x' --login-success 'Dashboard'\n"
            "  python3 scanner.py https://example.com --checks content --content-wordlist words.txt\n"
            "  python3 scanner.py https://example.com --output html --report-file out.html\n"
            "  python3 scanner.py https://example.com --fail-on high\n"
            "  python3 scanner.py --db scans.db --list-scans\n"
            "  python3 scanner.py --db scans.db --diff-scans 1:2\n"
            "  python3 scanner.py --db scans.db --mark-fp 42\n"
        ),
    )
    parser.add_argument("target", nargs="?", default=None,
                        help="Target URL (e.g. https://example.com)")
    parser.add_argument("--target-file", metavar="FILE",
                        help="File of hostnames/URLs to scan, one per line")
    parser.add_argument("--profile", choices=list(SCAN_PROFILES), metavar="PROFILE",
                        help="Scan profile: quick (10 fast checks), stealth (slow+quiet), full (everything)")
    parser.add_argument("--checks", nargs="+", choices=ALL_CHECKS, metavar="CHECK",
                        help="Run only these checks ΓÇö overrides --profile")
    parser.add_argument("--output", choices=["text", "json", "html", "csv"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--report-file", metavar="FILE",
                        help="Write output to file (single-target only)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colour output")
    parser.add_argument("--spider-depth", type=int, default=2, metavar="N",
                        help="Spider crawl depth (default: 2)")
    parser.add_argument("--spider-pages", type=int, default=50, metavar="N",
                        help="Max pages to crawl (default: 50)")
    parser.add_argument("--subdomain-file", metavar="FILE",
                        help="Custom subdomain wordlist file (one per line)")
    parser.add_argument("--cookie", metavar="COOKIES",
                        help="Cookies for every request (e.g. 'session=abc; role=admin')")
    parser.add_argument("--header", metavar="HEADER", action="append", dest="extra_headers",
                        help="Extra header(s) for every request. Repeatable.")
    parser.add_argument("--proxy", metavar="URL",
                        help="HTTP/S proxy for all requests (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--delay", type=float, default=0.0, metavar="SECONDS",
                        help="Delay between requests in seconds (e.g. 0.5). Stealth profile adds jitter.")
    parser.add_argument("--xss-payloads", metavar="FILE",
                        help="Custom XSS payload file (one payload per line)")
    parser.add_argument("--sqli-payloads", metavar="FILE",
                        help="Custom SQLi payload file (one payload per line)")
    parser.add_argument("--login-url", metavar="URL",
                        help="URL to POST credentials to before scanning")
    parser.add_argument("--login-data", metavar="DATA",
                        help="Form data for login (e.g. 'user=admin&pass=secret')")
    parser.add_argument("--login-success", metavar="STRING",
                        help="String in response body that confirms successful login")
    parser.add_argument("--content-wordlist", metavar="FILE",
                        help="Custom wordlist for content discovery (one path per line)")
    parser.add_argument("--fail-on", metavar="SEVERITY",
                        choices=list(SEVERITY_ORDER),
                        help="Exit code 1 if any findings at this severity or higher (e.g. high)")
    parser.add_argument("--notify", metavar="WEBHOOK_URL",
                        help="Slack or Discord webhook URL ΓÇö alerts on critical/high findings")
    parser.add_argument("--db", metavar="FILE",
                        help="SQLite database to persist scan results (e.g. wascan.db)")
    # DB subcommands
    parser.add_argument("--list-scans", action="store_true",
                        help="List all scans stored in --db and exit")
    parser.add_argument("--diff-scans", metavar="ID1:ID2",
                        help="Diff two scan IDs from --db (e.g. --diff-scans 3:5)")
    parser.add_argument("--mark-fp", metavar="FINDING_ID", type=int,
                        help="Mark a finding ID as false positive in --db and exit")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show per-request details during crawl/subdomain scan")
    # WAF bypass
    parser.add_argument("--waf-bypass", action="store_true",
                        help="Force WAF bypass encoding on XSS/SQLi payloads even without WAF detection")
    # Plugin system
    parser.add_argument("--plugin-dir", metavar="DIR",
                        help="Directory of Python plugin files (each must expose check(session, url, result))")
    # Screenshots
    parser.add_argument("--screenshots", metavar="DIR",
                        help="Capture Playwright screenshots of target + crawled URLs to this directory")
    # Email reporting
    parser.add_argument("--smtp-host", metavar="HOST", help="SMTP server for email reports")
    parser.add_argument("--smtp-port", metavar="PORT", type=int, default=587,
                        help="SMTP port (default: 587)")
    parser.add_argument("--smtp-user", metavar="USER", help="SMTP username")
    parser.add_argument("--smtp-pass", metavar="PASS", help="SMTP password")
    parser.add_argument("--smtp-from", metavar="ADDR", help="From address for email reports")
    parser.add_argument("--email-to", metavar="ADDR", action="append", dest="email_to",
                        help="Recipient address for email reports. Repeatable.")
    # Scheduled scanning
    parser.add_argument("--schedule", metavar="CRON_EXPR",
                        help="Add a scheduled scan with this cron expression (e.g. '0 3 * * *') and exit")
    parser.add_argument("--schedule-args", metavar="ARGS", default="",
                        help="Extra wascan arguments to include in the scheduled scan command")
    parser.add_argument("--list-schedules", action="store_true",
                        help="List all scheduled scans stored in --db and exit")
    args = parser.parse_args()

    # ΓöÇΓöÇ DB-only subcommands ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    if args.list_scans or args.diff_scans or args.mark_fp is not None \
            or args.list_schedules or args.schedule:
        if not args.db:
            parser.error("--list-scans / --diff-scans / --mark-fp / --list-schedules / --schedule require --db")
        if args.list_scans:
            cmd_list_scans(args.db)
        if args.diff_scans:
            try:
                id1, id2 = (int(x) for x in args.diff_scans.split(":"))
            except ValueError:
                parser.error("--diff-scans expects format ID1:ID2 (e.g. 1:2)")
            cmd_diff_scans(args.db, id1, id2, use_color=not args.no_color)
        if args.mark_fp is not None:
            cmd_mark_fp(args.db, args.mark_fp)
        if args.list_schedules:
            cmd_list_schedules(args.db)
        if args.schedule:
            tgt = args.target or (
                open(args.target_file).readline().strip() if args.target_file else None
            )
            if not tgt:
                parser.error("--schedule requires a target URL (positional or --target-file)")
            cmd_schedule_add(args.db, normalise_target(tgt), args.schedule, args.schedule_args)
        sys.exit(0)

    # Build target list
    targets: list[str] = []
    if args.target_file:
        try:
            with open(args.target_file) as f:
                targets = [normalise_target(l) for l in f
                           if l.strip() and not l.strip().startswith("#")]
        except OSError as e:
            print(f"[!] Cannot read target file: {e}", file=sys.stderr)
            sys.exit(1)
    if args.target:
        targets.insert(0, normalise_target(args.target))

    if not targets:
        parser.error("Provide a target URL or --target-file")

    # Resolve which checks to run (--checks overrides --profile)
    if args.checks:
        selected_checks = args.checks
    elif args.profile:
        selected_checks = SCAN_PROFILES[args.profile]  # empty list = full
    else:
        selected_checks = []  # empty = ALL_CHECKS inside run_scan

    # Configure runtime globals
    global _AUTH_HEADERS, _AUTH_COOKIES, _PROXY_URL, _REQUEST_DELAY
    global _STEALTH_MODE, _XSS_PAYLOADS, _SQLI_PAYLOADS
    global _WAF_BYPASS_MODE, _LOADED_PLUGINS

    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                _AUTH_COOKIES[k.strip()] = v.strip()

    if args.extra_headers:
        for raw in args.extra_headers:
            if ":" in raw:
                k, v = raw.split(":", 1)
                _AUTH_HEADERS[k.strip()] = v.strip()

    if args.proxy:
        _PROXY_URL = args.proxy
        print(f"[*] Routing via proxy: {_PROXY_URL}", file=sys.stderr)

    _REQUEST_DELAY = args.delay
    _STEALTH_MODE  = (args.profile == "stealth")
    _WAF_BYPASS_MODE = args.waf_bypass

    if args.plugin_dir:
        _LOADED_PLUGINS = load_plugins(args.plugin_dir)
        print(f"[*] Loaded {len(_LOADED_PLUGINS)} plugin(s) from {args.plugin_dir}", file=sys.stderr)

    if _STEALTH_MODE and _REQUEST_DELAY == 0.0:
        _REQUEST_DELAY = 1.5  # stealth default

    def _load_payloads(path: str) -> list[str]:
        with open(path) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if args.xss_payloads:
        try:
            _XSS_PAYLOADS = _load_payloads(args.xss_payloads)
            print(f"[*] Loaded {len(_XSS_PAYLOADS)} XSS payloads from {args.xss_payloads}", file=sys.stderr)
        except OSError as e:
            print(f"[!] Cannot read XSS payload file: {e}", file=sys.stderr)

    if args.sqli_payloads:
        try:
            _SQLI_PAYLOADS = _load_payloads(args.sqli_payloads)
            print(f"[*] Loaded {len(_SQLI_PAYLOADS)} SQLi payloads from {args.sqli_payloads}", file=sys.stderr)
        except OSError as e:
            print(f"[!] Cannot read SQLi payload file: {e}", file=sys.stderr)

    # Load content discovery wordlist
    content_wl: Optional[list[str]] = None
    if args.content_wordlist:
        try:
            with open(args.content_wordlist) as f:
                content_wl = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            print(f"[*] Content wordlist: {len(content_wl)} paths", file=sys.stderr)
        except OSError as e:
            print(f"[!] Cannot read content wordlist: {e}", file=sys.stderr)

    # Load subdomain wordlist
    if args.subdomain_file:
        try:
            with open(args.subdomain_file) as f:
                wordlist = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except OSError as e:
            print(f"[!] Cannot read wordlist: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        wordlist = SUBDOMAIN_WORDLIST

    # Perform login and extract session cookies before scanning
    if args.login_url:
        print(f"[*] Authenticating via {args.login_url} ...", file=sys.stderr)
        ok = asyncio.run(perform_login(
            args.login_url,
            args.login_data or "",
            args.login_success or "",
        ))
        if ok:
            print(f"[*] Login succeeded ΓÇö {len(_AUTH_COOKIES)} cookies extracted", file=sys.stderr)
        else:
            print("[!] Login failed or success string not found ΓÇö continuing unauthenticated", file=sys.stderr)

    if len(targets) > 1:
        print(f"[*] wascan ΓÇö scanning {len(targets)} targets", file=sys.stderr)

    total_t0 = time.time()
    all_results: list[ScanResult] = []

    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n[*] [{i}/{len(targets)}] {target}", file=sys.stderr)
        else:
            print(f"[*] wascan starting ΓÇö target: {target}", file=sys.stderr)

        t0 = time.time()
        result = asyncio.run(run_scan(
            target,
            checks=selected_checks,
            spider_depth=args.spider_depth,
            spider_pages=args.spider_pages,
            subdomain_wordlist=wordlist,
            verbose=args.verbose,
            webhook_url=args.notify or "",
            db_path=args.db or "",
            content_wordlist=content_wl,
            screenshot_dir=args.screenshots or "",
        ))
        elapsed = time.time() - t0
        print(f"[*] Done in {elapsed:.1f}s ΓÇö {len(result.findings)} findings", file=sys.stderr)

        email_cfg = None
        if args.smtp_host and args.email_to:
            email_cfg = {
                "smtp_host": args.smtp_host,
                "smtp_port": args.smtp_port,
                "smtp_user": args.smtp_user or "",
                "smtp_pass": args.smtp_pass or "",
                "from_addr": args.smtp_from or args.smtp_user or "",
                "to_addrs": args.email_to,
            }
        output_result(result, args, index=i - 1, total=len(targets), email_cfg=email_cfg)
        all_results.append(result)

    if len(targets) > 1:
        total_elapsed = time.time() - total_t0
        total_findings = sum(len(r.findings) for r in all_results)
        print(f"\n[*] All done in {total_elapsed:.1f}s ΓÇö "
              f"{len(targets)} targets, {total_findings} total findings", file=sys.stderr)

    # CI/CD exit code
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        triggered = any(
            SEVERITY_ORDER.get(f.severity, 99) <= threshold
            for r in all_results for f in r.findings
        )
        if triggered:
            print(f"[!] --fail-on {args.fail_on}: findings at or above threshold detected. Exiting 1.",
                  file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
