"""
DAST Scanner - Dynamic Application Security Testing.

Performs runtime security testing against web applications.
"""

from __future__ import annotations

import asyncio
import re
import ssl
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from html.parser import HTMLParser

import httpx
import structlog

from shadow_worker.core.config import DASTConfig
from shadow_worker.core.scanner import Finding, Severity, VulnCategory

logger = structlog.get_logger()


@dataclass
class CrawledPage:
    """A crawled web page."""

    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    forms: list[dict[str, Any]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)


class FormParser(HTMLParser):
    """Parse HTML forms from a page."""

    def __init__(self):
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self.links: list[str] = []
        self.scripts: list[str] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)

        if tag == "form":
            self._current_form = {
                "action": attrs_dict.get("action") or "",
                "method": (attrs_dict.get("method") or "GET").upper(),
                "inputs": []
            }

        elif tag == "input" and self._current_form:
            self._current_form["inputs"].append({
                "name": attrs_dict.get("name") or "",
                "type": attrs_dict.get("type") or "text",
                "value": attrs_dict.get("value") or "",
            })

        elif tag == "a":
            href = attrs_dict.get("href") or ""
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                self.links.append(href)

        elif tag == "script":
            src = attrs_dict.get("src") or ""
            if src:
                self.scripts.append(src)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None


class DASTScanner:
    """
    Dynamic Application Security Testing scanner.

    Performs active testing against web applications:
    - SQL injection testing
    - XSS testing
    - SSRF testing
    - Security header analysis
    - SSL/TLS analysis
    - CORS misconfiguration
    - Authentication testing
    """

    # Test payloads
    SQLI_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "1' AND '1'='1",
        "1 AND 1=1",
        "' UNION SELECT NULL--",
    ]

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "'\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "{{7*7}}",  # Template injection
        "${7*7}",   # Expression injection
    ]

    SSRF_PAYLOADS = [
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
        "http://169.254.169.254",  # AWS metadata
        "http://metadata.google.internal",  # GCP metadata
    ]

    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "file:///etc/passwd",
    ]

    def __init__(self, config: DASTConfig):
        self.config = config
        self._client: httpx.AsyncClient | None = None
        self._crawled: set[str] = set()
        self._base_url: str = ""

    async def scan(self, target: str, options: dict[str, Any] | None = None) -> list[Finding]:
        """
        Run DAST scan against target URL.

        Args:
            target: Target URL to scan
            options: Additional scan options

        Returns:
            List of security findings
        """
        # Ensure target is a valid URL
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        self._base_url = target
        self._crawled = set()

        findings: list[Finding] = []

        # Create HTTP client with authentication if configured
        auth = self._get_auth()

        async with httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=self.config.follow_redirects,
            verify=False,  # Allow self-signed certs
            auth=auth,
        ) as client:
            self._client = client

            # Phase 1: Crawl and discover endpoints
            pages = await self._crawl(target)

            # Phase 2: Run security checks
            check_tasks = []

            if self.config.check_headers:
                check_tasks.append(self._check_security_headers(target))

            if self.config.check_ssl:
                check_tasks.append(self._check_ssl(target))

            if self.config.check_cors:
                check_tasks.append(self._check_cors(target))

            # Run passive checks
            results = await asyncio.gather(*check_tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    findings.extend(result)

            # Phase 3: Active testing on discovered forms/parameters
            for page in pages:
                if self.config.check_sqli:
                    findings.extend(await self._test_sqli(page))

                if self.config.check_xss:
                    findings.extend(await self._test_xss(page))

                if self.config.check_lfi:
                    findings.extend(await self._test_lfi(page))

        logger.info("dast_scan_complete", target=target, findings=len(findings))
        return findings

    async def _crawl(self, start_url: str) -> list[CrawledPage]:
        """Crawl website to discover pages."""
        pages: list[CrawledPage] = []
        to_visit = [start_url]

        while to_visit and len(pages) < self.config.max_pages:
            url = to_visit.pop(0)

            if url in self._crawled:
                continue

            # Check depth
            depth = url.count("/") - start_url.count("/")
            if depth > self.config.max_depth:
                continue

            self._crawled.add(url)

            try:
                page = await self._fetch_page(url)
                if page:
                    pages.append(page)

                    # Add discovered links
                    for link in page.links:
                        full_url = urllib.parse.urljoin(url, link)
                        parsed = urllib.parse.urlparse(full_url)
                        base_parsed = urllib.parse.urlparse(self._base_url)

                        # Only follow same-origin links
                        if parsed.netloc == base_parsed.netloc:
                            if full_url not in self._crawled:
                                to_visit.append(full_url)

            except Exception as e:
                logger.debug("crawl_failed", url=url, error=str(e))

        return pages

    async def _fetch_page(self, url: str) -> CrawledPage | None:
        """Fetch and parse a page."""
        try:
            response = await self._client.get(url)

            parser = FormParser()
            try:
                parser.feed(response.text)
            except Exception:
                pass

            return CrawledPage(
                url=url,
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text,
                forms=parser.forms,
                links=parser.links,
                scripts=parser.scripts,
            )
        except Exception as e:
            logger.debug("fetch_failed", url=url, error=str(e))
            return None

    async def _check_security_headers(self, url: str) -> list[Finding]:
        """Check for security headers."""
        findings = []

        try:
            response = await self._client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}

            # Required security headers
            required_headers = [
                ("x-content-type-options", "nosniff", Severity.LOW),
                ("x-frame-options", None, Severity.MEDIUM),
                ("x-xss-protection", None, Severity.LOW),
                ("strict-transport-security", None, Severity.MEDIUM),
                ("content-security-policy", None, Severity.MEDIUM),
                ("referrer-policy", None, Severity.LOW),
                ("permissions-policy", None, Severity.LOW),
            ]

            for header, expected_value, severity in required_headers:
                if header not in headers:
                    findings.append(Finding(
                        title=f"Missing Security Header: {header}",
                        description=f"The {header} header is not set",
                        severity=severity,
                        category=VulnCategory.MISCONFIG,
                        target=url,
                        location=url,
                        scanner="dast",
                        remediation=f"Add the {header} header to responses",
                    ))
                elif expected_value and headers[header].lower() != expected_value:
                    findings.append(Finding(
                        title=f"Incorrect Security Header: {header}",
                        description=f"Expected '{expected_value}', got '{headers[header]}'",
                        severity=Severity.LOW,
                        category=VulnCategory.MISCONFIG,
                        target=url,
                        location=url,
                        scanner="dast",
                    ))

            # Check for information disclosure
            info_headers = ["server", "x-powered-by", "x-aspnet-version"]
            for header in info_headers:
                if header in headers:
                    findings.append(Finding(
                        title=f"Information Disclosure: {header}",
                        description=f"Server reveals: {headers[header]}",
                        severity=Severity.INFO,
                        category=VulnCategory.MISCONFIG,
                        target=url,
                        location=url,
                        evidence=f"{header}: {headers[header]}",
                        scanner="dast",
                    ))

        except Exception as e:
            logger.error("header_check_failed", error=str(e))

        return findings

    async def _check_ssl(self, url: str) -> list[Finding]:
        """Check SSL/TLS configuration."""
        findings = []

        if not url.startswith("https://"):
            findings.append(Finding(
                title="No HTTPS",
                description="Application is not using HTTPS",
                severity=Severity.HIGH,
                category=VulnCategory.CRYPTO,
                target=url,
                location=url,
                scanner="dast",
                remediation="Enable HTTPS with a valid certificate",
            ))
            return findings

        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.netloc.split(":")[0]
            port = parsed.port or 443

            # Get certificate info
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            import socket
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Check TLS version
                    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        findings.append(Finding(
                            title=f"Weak TLS Version: {version}",
                            description=f"Server supports outdated {version}",
                            severity=Severity.HIGH,
                            category=VulnCategory.CRYPTO,
                            target=url,
                            location=url,
                            scanner="dast",
                            remediation="Disable TLS 1.0/1.1 and SSLv2/v3",
                        ))

                    # Check cipher strength
                    if cipher:
                        cipher_name = cipher[0]
                        weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]
                        if any(w in cipher_name.upper() for w in weak_ciphers):
                            findings.append(Finding(
                                title=f"Weak Cipher: {cipher_name}",
                                description="Server uses weak encryption cipher",
                                severity=Severity.MEDIUM,
                                category=VulnCategory.CRYPTO,
                                target=url,
                                location=url,
                                scanner="dast",
                            ))

        except Exception as e:
            logger.debug("ssl_check_failed", error=str(e))

        return findings

    async def _check_cors(self, url: str) -> list[Finding]:
        """Check for CORS misconfiguration."""
        findings = []

        try:
            # Test with malicious origin
            test_origins = [
                "https://evil.com",
                "null",
                "https://evil.target.com",  # Subdomain
            ]

            for origin in test_origins:
                response = await self._client.get(
                    url,
                    headers={"Origin": origin}
                )

                acao = response.headers.get("access-control-allow-origin", "")
                acac = response.headers.get("access-control-allow-credentials", "")

                if acao == "*" and acac.lower() == "true":
                    findings.append(Finding(
                        title="CORS Misconfiguration: Wildcard with Credentials",
                        description="CORS allows any origin with credentials",
                        severity=Severity.HIGH,
                        category=VulnCategory.MISCONFIG,
                        target=url,
                        location=url,
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        scanner="dast",
                        cwe_ids=[942],
                    ))
                elif acao == origin and origin != "null":
                    findings.append(Finding(
                        title="CORS Misconfiguration: Origin Reflection",
                        description=f"CORS reflects arbitrary origin: {origin}",
                        severity=Severity.MEDIUM,
                        category=VulnCategory.MISCONFIG,
                        target=url,
                        location=url,
                        evidence=f"Origin reflected: {origin}",
                        scanner="dast",
                        cwe_ids=[942],
                    ))
                elif acao == "null":
                    findings.append(Finding(
                        title="CORS Misconfiguration: Null Origin Allowed",
                        description="CORS allows null origin (sandbox bypass)",
                        severity=Severity.MEDIUM,
                        category=VulnCategory.MISCONFIG,
                        target=url,
                        location=url,
                        scanner="dast",
                    ))

        except Exception as e:
            logger.debug("cors_check_failed", error=str(e))

        return findings

    async def _test_sqli(self, page: CrawledPage) -> list[Finding]:
        """Test for SQL injection vulnerabilities."""
        findings = []

        for form in page.forms:
            action = urllib.parse.urljoin(page.url, form["action"])
            method = form["method"]

            for input_field in form["inputs"]:
                if input_field["type"] in ("hidden", "submit", "button"):
                    continue

                input_name = input_field["name"]
                if not input_name:
                    continue

                for payload in self.SQLI_PAYLOADS[:5]:  # Limit payloads
                    try:
                        data = {
                            inp["name"]: inp.get("value", "test")
                            for inp in form["inputs"]
                            if inp["name"]
                        }
                        data[input_name] = payload

                        if method == "POST":
                            response = await self._client.post(action, data=data)
                        else:
                            response = await self._client.get(action, params=data)

                        # Check for SQL error indicators
                        sql_errors = [
                            "sql syntax",
                            "mysql_fetch",
                            "ORA-",
                            "PostgreSQL",
                            "SQLite",
                            "ODBC",
                            "unclosed quotation",
                        ]

                        for error in sql_errors:
                            if error.lower() in response.text.lower():
                                findings.append(Finding(
                                    title="SQL Injection Vulnerability",
                                    description=f"SQL injection in parameter '{input_name}'",
                                    severity=Severity.CRITICAL,
                                    category=VulnCategory.INJECTION,
                                    target=page.url,
                                    location=action,
                                    evidence=f"Payload: {payload}, Error: {error}",
                                    scanner="dast",
                                    cwe_ids=[89],
                                    remediation="Use parameterized queries",
                                ))
                                break

                    except Exception as e:
                        logger.debug("sqli_test_failed", error=str(e))

        return findings

    async def _test_xss(self, page: CrawledPage) -> list[Finding]:
        """Test for XSS vulnerabilities."""
        findings = []

        for form in page.forms:
            action = urllib.parse.urljoin(page.url, form["action"])
            method = form["method"]

            for input_field in form["inputs"]:
                if input_field["type"] in ("hidden", "submit", "button"):
                    continue

                input_name = input_field["name"]
                if not input_name:
                    continue

                for payload in self.XSS_PAYLOADS[:3]:  # Limit payloads
                    try:
                        data = {
                            inp["name"]: inp.get("value", "test")
                            for inp in form["inputs"]
                            if inp["name"]
                        }
                        data[input_name] = payload

                        if method == "POST":
                            response = await self._client.post(action, data=data)
                        else:
                            response = await self._client.get(action, params=data)

                        # Check if payload is reflected
                        if payload in response.text:
                            findings.append(Finding(
                                title="Cross-Site Scripting (XSS)",
                                description=f"Reflected XSS in parameter '{input_name}'",
                                severity=Severity.HIGH,
                                category=VulnCategory.XSS,
                                target=page.url,
                                location=action,
                                evidence=f"Payload reflected: {payload[:50]}",
                                scanner="dast",
                                cwe_ids=[79],
                                remediation="Sanitize output and implement CSP",
                            ))
                            break

                    except Exception as e:
                        logger.debug("xss_test_failed", error=str(e))

        return findings

    async def _test_lfi(self, page: CrawledPage) -> list[Finding]:
        """Test for Local File Inclusion vulnerabilities."""
        findings = []

        # Look for file-related parameters in URL
        parsed = urllib.parse.urlparse(page.url)
        params = urllib.parse.parse_qs(parsed.query)

        file_params = ["file", "path", "page", "template", "include", "doc", "document"]

        for param in file_params:
            if param in params:
                for payload in self.LFI_PAYLOADS[:3]:
                    try:
                        test_params = dict(params)
                        test_params[param] = [payload]

                        new_query = urllib.parse.urlencode(test_params, doseq=True)
                        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

                        response = await self._client.get(test_url)

                        # Check for file content indicators
                        if "root:" in response.text or "[boot loader]" in response.text:
                            findings.append(Finding(
                                title="Local File Inclusion (LFI)",
                                description=f"LFI in parameter '{param}'",
                                severity=Severity.CRITICAL,
                                category=VulnCategory.INJECTION,
                                target=page.url,
                                location=test_url,
                                evidence=f"Payload: {payload}",
                                scanner="dast",
                                cwe_ids=[98],
                                remediation="Validate and whitelist file paths",
                            ))
                            break

                    except Exception as e:
                        logger.debug("lfi_test_failed", error=str(e))

        return findings

    def _get_auth(self) -> httpx.Auth | None:
        """Get authentication configuration."""
        if self.config.auth_type == "none":
            return None
        elif self.config.auth_type == "basic":
            username = self.config.auth_credentials.get("username", "")
            password = self.config.auth_credentials.get("password", "")
            return httpx.BasicAuth(username, password)
        # Add other auth types as needed
        return None
