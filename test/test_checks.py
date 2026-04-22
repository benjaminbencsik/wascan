import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from wascan import (
    Finding,
    ScanResult,
    check_security_headers,
    check_sensitive_files,
    check_http_methods,
    check_xss,
    check_sqli,
    check_open_redirect,
    check_cors,
    check_clickjacking,
    check_cookie_flags,
)


class DummyResponse:
    def __init__(self, status=200, headers=None, body=b"", content_type="text/html"):
        self.status = status
        self._headers = dict(headers or {}) if headers else {}
        self._body = body
        if content_type:
            self._headers["Content-Type"] = content_type

    def headers(self):
        return self._headers

    async def read(self):
        return self._body


class DummySession:
    def __init__(self, response=None):
        self._response = response or DummyResponse()

    async def request(self, method, url, **kwargs):
        return self._response

    async def get(self, url, **kwargs):
        return self._response

    async def post(self, url, **kwargs):
        return self._response


@pytest.mark.asyncio
async def test_security_headers_missing(sample_result):
    session = DummySession(response=DummyResponse(
        headers={"X-Frame-Options": "DENY"},
        body=b"<html>test</html>",
    ))
    await check_security_headers(session, "https://example.com", sample_result)
    assert len(sample_result.findings) >= 1


@pytest.mark.asyncio
async def test_security_headers_present(sample_result):
    session = DummySession(response=DummyResponse(
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        },
        body=b"<html>test</html>",
    ))
    await check_security_headers(session, "https://example.com", sample_result)
    header_findings = [
        f for f in sample_result.findings
        if "Missing" in f.title or "disclosure" in f.title
    ]
    assert len(header_findings) == 0


@pytest.mark.asyncio
async def test_sensitive_files_env_exposed(sample_result):
    session = DummySession(response=DummyResponse(status=200, body=b"SECRET=abc123"))
    await check_sensitive_files(session, "https://example.com", sample_result)
    env_findings = [f for f in sample_result.findings if ".env" in f.title]
    assert len(env_findings) >= 1
    assert env_findings[0].severity == "critical"


@pytest.mark.asyncio
async def test_sensitive_files_not_exposed(sample_result):
    session = DummySession(response=DummyResponse(status=404))
    await check_sensitive_files(session, "https://example.com", sample_result)
    critical_findings = [
        f for f in sample_result.findings
        if f.severity == "critical"
    ]
    assert len(critical_findings) == 0


@pytest.mark.asyncio
async def test_http_methods_dangerous_allowed(sample_result):
    session = DummySession(response=DummyResponse(status=200))
    await check_http_methods(session, "https://example.com", sample_result)
    assert len(sample_result.findings) >= 1


@pytest.mark.asyncio
async def test_xss_reflected(sample_result):
    session = DummySession(response=DummyResponse(
        body=b"<script>alert('XSS_CANARY')</script>",
    ))
    await check_xss(session, "https://example.com?q=test", sample_result)
    assert len(sample_result.findings) >= 1
    assert "XSS" in sample_result.findings[0].title


@pytest.mark.asyncio
async def test_xss_not_reflected(sample_result):
    session = DummySession(response=DummyResponse(body=b"<html>no xss here</html>"))
    await check_xss(session, "https://example.com?q=test", sample_result)
    xss_findings = [f for f in sample_result.findings if "XSS" in f.title]
    assert len(xss_findings) == 0


@pytest.mark.asyncio
async def test_sqli_error_detected(sample_result):
    session = DummySession(response=DummyResponse(
        body=b"mysql_fetch_array(): sql syntax error",
    ))
    await check_sqli(session, "https://example.com?id=1", sample_result)
    assert len(sample_result.findings) >= 1
    assert sample_result.findings[0].severity == "critical"


@pytest.mark.asyncio
async def test_open_redirect_detected(sample_result):
    session = DummySession(response=DummyResponse(
        status=302,
        headers={"Location": "https://evil.example.com"},
    ))
    await check_open_redirect(session, "https://example.com?redirect=https://legit.com", sample_result)
    assert len(sample_result.findings) >= 1


@pytest.mark.asyncio
async def test_cors_wildcard_detected(sample_result):
    session = DummySession(response=DummyResponse(
        headers={"Access-Control-Allow-Origin": "*"},
    ))
    await check_cors(session, "https://example.com", sample_result)
    assert len(sample_result.findings) >= 1


@pytest.mark.asyncio
async def test_clickjacking_protection_absent(sample_result):
    session = DummySession(response=DummyResponse(headers={}))
    await check_clickjacking(session, "https://example.com", sample_result)
    assert len(sample_result.findings) >= 1


@pytest.mark.asyncio
async def test_cookie_flags_missing(sample_result):
    session = DummySession(response=DummyResponse(
        headers={"Set-Cookie": "session=abc123; Path=/"},
    ))
    await check_cookie_flags(session, "https://example.com", sample_result)
    assert len(sample_result.findings) >= 1


def test_scan_result_add():
    result = ScanResult(target="https://example.com", started_at="2024-01-01T00:00:00")
    finding = Finding(
        title="Test finding",
        severity="high",
        description="Test description",
    )
    result.add(finding)
    assert len(result.findings) == 1
    assert result.findings[0].title == "Test finding"


def test_scan_result_severity_counts():
    result = ScanResult(target="https://example.com", started_at="2024-01-01T00:00:00")
    result.add(Finding(title="1", severity="critical", description=""))
    result.add(Finding(title="2", severity="high", description=""))
    result.add(Finding(title="3", severity="high", description=""))
    result.add(Finding(title="4", severity="medium", description=""))
    counts = result.severity_counts()
    assert counts["critical"] == 1
    assert counts["high"] == 2
    assert counts["medium"] == 1
    assert counts["low"] == 0
    assert counts["info"] == 0


def test_scan_result_sorted_findings():
    result = ScanResult(target="https://example.com", started_at="2024-01-01T00:00:00")
    result.add(Finding(title="Low", severity="low", description=""))
    result.add(Finding(title="Critical", severity="critical", description=""))
    result.add(Finding(title="High", severity="high", description=""))
    result.add(Finding(title="Medium", severity="medium", description=""))
    sorted_findings = result.sorted_findings()
    assert sorted_findings[0].severity == "critical"
    assert sorted_findings[1].severity == "high"
    assert sorted_findings[2].severity == "medium"
    assert sorted_findings[3].severity == "low"
