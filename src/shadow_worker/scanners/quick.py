"""
Quick Scanner - Fast reconnaissance and high-severity checks.

Provides rapid security assessment for immediate insights.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from shadow_worker.core.config import ShadowConfig
from shadow_worker.core.scanner import Finding, Severity, VulnCategory

logger = structlog.get_logger()


@dataclass
class QuickScanResult:
    """Result from quick scan."""

    target: str
    timestamp: datetime
    findings: list[Finding]
    recon_data: dict[str, Any]
    scan_duration_seconds: float


class QuickScanner:
    """
    Quick reconnaissance and security scanner.

    Performs fast checks for:
    - Open ports on common services
    - SSL/TLS issues
    - Critical security headers
    - Known vulnerable paths
    - Technology fingerprinting
    """

    # Common ports to check
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 27017]

    # Sensitive paths to probe
    SENSITIVE_PATHS = [
        "/.git/config",
        "/.env",
        "/.svn/entries",
        "/wp-config.php.bak",
        "/config.php.bak",
        "/phpinfo.php",
        "/server-status",
        "/debug",
        "/actuator/health",
        "/api/swagger.json",
        "/swagger.json",
        "/.well-known/security.txt",
        "/robots.txt",
        "/sitemap.xml",
        "/crossdomain.xml",
        "/.htaccess",
        "/web.config",
        "/WEB-INF/web.xml",
        "/admin",
        "/administrator",
        "/backup",
        "/test",
        "/dev",
    ]

    def __init__(self, config: ShadowConfig):
        self.config = config

    async def scan(self, target: str, options: dict[str, Any] | None = None) -> list[Finding]:
        """
        Run quick scan against target.

        Args:
            target: Target URL or IP
            options: Additional options

        Returns:
            List of findings
        """
        import time

        start_time = time.time()
        findings: list[Finding] = []

        # Determine target type
        if target.startswith(("http://", "https://")):
            findings.extend(await self._scan_web_target(target))
        else:
            # Assume IP/hostname
            findings.extend(await self._scan_host_target(target))

        duration = time.time() - start_time
        logger.info(
            "quick_scan_complete",
            target=target,
            findings=len(findings),
            duration=duration
        )

        return findings

    async def _scan_web_target(self, url: str) -> list[Finding]:
        """Scan a web target."""
        findings = []

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=False,
        ) as client:
            # Check sensitive paths
            findings.extend(await self._check_sensitive_paths(client, url))

            # Check security headers
            findings.extend(await self._check_quick_headers(client, url))

            # Check SSL
            if url.startswith("https://"):
                findings.extend(await self._quick_ssl_check(url))

            # Technology fingerprint
            findings.extend(await self._fingerprint_technology(client, url))

        return findings

    async def _scan_host_target(self, host: str) -> list[Finding]:
        """Scan a host/IP target."""
        findings = []

        # Port scan
        open_ports = await self._quick_port_scan(host)

        for port, service in open_ports:
            if port in [21, 23, 25, 110, 143]:  # Unencrypted protocols
                findings.append(Finding(
                    title=f"Unencrypted Service: {service} on port {port}",
                    description=f"Service {service} on port {port} does not use encryption",
                    severity=Severity.MEDIUM,
                    category=VulnCategory.CRYPTO,
                    target=host,
                    location=f"{host}:{port}",
                    scanner="quick",
                ))

            if port == 3389:  # RDP
                findings.append(Finding(
                    title="RDP Service Exposed",
                    description="Remote Desktop Protocol is exposed to the network",
                    severity=Severity.MEDIUM,
                    category=VulnCategory.MISCONFIG,
                    target=host,
                    location=f"{host}:3389",
                    scanner="quick",
                    remediation="Restrict RDP access with VPN or jump host",
                ))

            if port in [6379, 27017]:  # Redis, MongoDB
                findings.append(Finding(
                    title=f"Database Port Exposed: {port}",
                    description=f"Database service on port {port} is exposed",
                    severity=Severity.HIGH,
                    category=VulnCategory.MISCONFIG,
                    target=host,
                    location=f"{host}:{port}",
                    scanner="quick",
                    remediation="Restrict database access to internal networks only",
                ))

        return findings

    async def _check_sensitive_paths(
        self,
        client: httpx.AsyncClient,
        base_url: str
    ) -> list[Finding]:
        """Check for exposed sensitive paths."""
        findings = []

        async def check_path(path: str) -> Finding | None:
            try:
                url = f"{base_url.rstrip('/')}{path}"
                response = await client.get(url, follow_redirects=False)

                if response.status_code == 200:
                    content_type = response.headers.get("content-type", "")

                    # Check for sensitive content indicators
                    sensitive_indicators = [
                        (".git", "[core]"),
                        (".env", "="),
                        ("phpinfo", "PHP Version"),
                        ("swagger", "swagger"),
                        ("actuator", "status"),
                    ]

                    for indicator, content in sensitive_indicators:
                        if indicator in path and content in response.text:
                            severity = Severity.HIGH if indicator in [".git", ".env"] else Severity.MEDIUM

                            return Finding(
                                title=f"Sensitive Path Exposed: {path}",
                                description=f"Sensitive content accessible at {path}",
                                severity=severity,
                                category=VulnCategory.SENSITIVE_DATA,
                                target=base_url,
                                location=url,
                                scanner="quick",
                                remediation="Remove or restrict access to this path",
                            )

                    # Generic check for successful access to sensitive paths
                    if any(s in path for s in [".git", ".env", ".svn", "backup", "config"]):
                        if len(response.text) > 0 and response.status_code == 200:
                            return Finding(
                                title=f"Potentially Sensitive Path Accessible: {path}",
                                description=f"Path {path} returns content",
                                severity=Severity.MEDIUM,
                                category=VulnCategory.SENSITIVE_DATA,
                                target=base_url,
                                location=url,
                                scanner="quick",
                            )

            except Exception:
                pass
            return None

        # Check paths concurrently
        tasks = [check_path(path) for path in self.SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                findings.append(result)

        return findings

    async def _check_quick_headers(
        self,
        client: httpx.AsyncClient,
        url: str
    ) -> list[Finding]:
        """Quick security header check."""
        findings = []

        try:
            response = await client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}

            # Critical headers only for quick scan
            critical_headers = [
                ("strict-transport-security", Severity.MEDIUM, "Enable HSTS"),
                ("content-security-policy", Severity.MEDIUM, "Implement CSP"),
                ("x-content-type-options", Severity.LOW, "Add X-Content-Type-Options: nosniff"),
            ]

            for header, severity, fix in critical_headers:
                if header not in headers:
                    findings.append(Finding(
                        title=f"Missing Header: {header}",
                        description=f"Security header {header} is not set",
                        severity=severity,
                        category=VulnCategory.MISCONFIG,
                        target=url,
                        location=url,
                        scanner="quick",
                        remediation=fix,
                    ))

        except Exception as e:
            logger.debug("header_check_failed", error=str(e))

        return findings

    async def _quick_ssl_check(self, url: str) -> list[Finding]:
        """Quick SSL/TLS check."""
        findings = []

        try:
            parsed = urlparse(url)
            hostname = parsed.netloc.split(":")[0]
            port = parsed.port or 443

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()

                    if version in ("TLSv1", "TLSv1.1"):
                        findings.append(Finding(
                            title=f"Weak TLS Version: {version}",
                            description=f"Server supports deprecated {version}",
                            severity=Severity.HIGH,
                            category=VulnCategory.CRYPTO,
                            target=url,
                            location=url,
                            scanner="quick",
                            remediation="Upgrade to TLS 1.2 or 1.3",
                        ))

        except Exception as e:
            logger.debug("ssl_check_failed", error=str(e))

        return findings

    async def _fingerprint_technology(
        self,
        client: httpx.AsyncClient,
        url: str
    ) -> list[Finding]:
        """Fingerprint web technologies."""
        findings = []

        try:
            response = await client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.text.lower()

            # Check for version disclosure
            server = headers.get("server", "")
            powered_by = headers.get("x-powered-by", "")

            version_patterns = [
                (server, r"\d+\.\d+(?:\.\d+)?"),
                (powered_by, r"\d+\.\d+(?:\.\d+)?"),
            ]

            import re
            for value, pattern in version_patterns:
                if value and re.search(pattern, value):
                    findings.append(Finding(
                        title="Version Information Disclosure",
                        description=f"Server reveals version: {value}",
                        severity=Severity.INFO,
                        category=VulnCategory.MISCONFIG,
                        target=url,
                        location=url,
                        evidence=value,
                        scanner="quick",
                    ))

            # Check for CMS/Framework indicators
            cms_indicators = [
                ("wordpress", "/wp-content/", Severity.INFO),
                ("drupal", "drupal.settings", Severity.INFO),
                ("joomla", "/administrator/", Severity.INFO),
            ]

            for cms, indicator, severity in cms_indicators:
                if indicator.lower() in body or indicator.lower() in str(headers):
                    findings.append(Finding(
                        title=f"CMS Detected: {cms.title()}",
                        description=f"{cms.title()} detected on target",
                        severity=severity,
                        category=VulnCategory.OTHER,
                        target=url,
                        location=url,
                        scanner="quick",
                    ))

        except Exception as e:
            logger.debug("fingerprint_failed", error=str(e))

        return findings

    async def _quick_port_scan(self, host: str) -> list[tuple[int, str]]:
        """Quick port scan on common ports."""
        open_ports = []

        service_names = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            27017: "MongoDB",
        }

        async def check_port(port: int) -> tuple[int, str] | None:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=2.0
                )
                writer.close()
                await writer.wait_closed()
                return (port, service_names.get(port, "Unknown"))
            except Exception:
                return None

        tasks = [check_port(port) for port in self.COMMON_PORTS]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                open_ports.append(result)

        return open_ports
