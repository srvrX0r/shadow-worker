"""
Core scanning engine for Shadow Worker.

Orchestrates vulnerability scanning across different modules and targets.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, AsyncIterator
from uuid import UUID, uuid4

import structlog
from asyncio_throttle import Throttler

from shadow_worker.core.config import ShadowConfig

logger = structlog.get_logger()


def host_authorized(host: str, domains: list[str]) -> bool:
    """Return True when host is exactly an authorized domain or a subdomain of one.

    A bare suffix check is not safe: ``notexample.com`` endswith ``example.com``.
    Empty domain entries are ignored so a blank allowlist item cannot match every host.
    """
    normalized = host.lower().strip().rstrip(".")
    if not normalized:
        return False
    for domain in domains:
        allowed = domain.lower().strip().rstrip(".")
        if not allowed:
            continue
        if normalized == allowed or normalized.endswith("." + allowed):
            return True
    return False


def host_listed(host: str, hosts: list[str]) -> bool:
    """Match a host against the explicit host allowlist, including IP equality."""
    import ipaddress

    normalized = host.lower().strip()
    for item in hosts:
        candidate = item.strip()
        if candidate.lower() == normalized:
            return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    for item in hosts:
        try:
            if ipaddress.ip_address(item.strip()) == ip:
                return True
        except ValueError:
            continue
    return False


class ScanStatus(str, Enum):
    """Status of a scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class Severity(str, Enum):
    """Vulnerability severity levels (CVSS-aligned)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        """Convert CVSS score to severity."""
        if score == 0:
            return cls.INFO
        elif score < 4.0:
            return cls.LOW
        elif score < 7.0:
            return cls.MEDIUM
        elif score < 9.0:
            return cls.HIGH
        else:
            return cls.CRITICAL


class VulnCategory(str, Enum):
    """OWASP-aligned vulnerability categories."""

    INJECTION = "injection"                    # A03:2021
    BROKEN_AUTH = "broken_authentication"      # A07:2021
    SENSITIVE_DATA = "sensitive_data_exposure" # A02:2021
    XXE = "xxe"                               # A05:2021
    BROKEN_ACCESS = "broken_access_control"    # A01:2021
    MISCONFIG = "security_misconfiguration"    # A05:2021
    XSS = "cross_site_scripting"              # A03:2021
    INSECURE_DESER = "insecure_deserialization" # A08:2021
    VULNERABLE_DEPS = "vulnerable_dependencies" # A06:2021
    LOGGING = "insufficient_logging"           # A09:2021
    SSRF = "ssrf"                             # A10:2021
    CRYPTO = "cryptographic_failures"          # A02:2021
    OTHER = "other"


@dataclass
class Finding:
    """A security finding/vulnerability."""

    id: UUID = field(default_factory=uuid4)
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    category: VulnCategory = VulnCategory.OTHER

    # Location
    target: str = ""
    location: str = ""  # File path, URL path, etc.
    line_number: int | None = None
    column_number: int | None = None

    # Technical details
    evidence: str = ""
    request: str | None = None
    response: str | None = None

    # Remediation
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cwe_ids: list[int] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)

    # Metadata
    scanner: str = ""
    confidence: float = 1.0  # 0.0 to 1.0
    false_positive: bool = False
    verified: bool = False
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # CVSS
    cvss_score: float | None = None
    cvss_vector: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "target": self.target,
            "location": self.location,
            "line_number": self.line_number,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "cwe_ids": self.cwe_ids,
            "cve_ids": self.cve_ids,
            "scanner": self.scanner,
            "confidence": self.confidence,
            "cvss_score": self.cvss_score,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanResult:
    """Result of a scan operation."""

    scan_id: UUID = field(default_factory=uuid4)
    status: ScanStatus = ScanStatus.PENDING
    target: str = ""
    scan_type: str = ""

    # Findings
    findings: list[Finding] = field(default_factory=list)

    # Statistics
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration_seconds: float = 0.0

    # Summary
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    errors: list[str] = field(default_factory=list)

    def calculate_summary(self) -> None:
        """Calculate summary statistics."""
        self.total_findings = len(self.findings)
        self.critical_count = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        self.high_count = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        self.medium_count = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        self.low_count = sum(1 for f in self.findings if f.severity == Severity.LOW)
        self.info_count = sum(1 for f in self.findings if f.severity == Severity.INFO)

        if self.start_time and self.end_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()


class ScanTarget:
    """Represents a scan target with validation."""

    def __init__(self, target: str, target_type: str = "auto"):
        self.raw = target
        self.target_type = target_type if target_type != "auto" else self._detect_type()
        self._validate()

    def _detect_type(self) -> str:
        """Auto-detect target type."""
        import re

        if self.raw.startswith(("http://", "https://")):
            return "url"
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.raw):
            return "ip"
        if "/" in self.raw and any(c.isdigit() for c in self.raw.split("/")[-1]):
            return "cidr"
        if self.raw == "." or self.raw.startswith(("/", "./", "../")):
            return "path"
        if "@" in self.raw and ":" in self.raw:
            return "git"
        if "." in self.raw and " " not in self.raw:
            return "domain"
        return "unknown"

    def _validate(self) -> None:
        """Validate the target."""
        if not self.raw:
            raise ValueError("Target cannot be empty")

        if self.target_type == "ip":
            import ipaddress
            ipaddress.ip_address(self.raw)
        elif self.target_type == "cidr":
            import ipaddress
            ipaddress.ip_network(self.raw, strict=False)
        elif self.target_type == "url":
            from urllib.parse import urlparse
            parsed = urlparse(self.raw)
            if not parsed.netloc:
                raise ValueError(f"Invalid URL: {self.raw}")


class Scanner:
    """
    Main vulnerability scanner orchestrator.

    Coordinates scanning across multiple modules while respecting
    rate limits and authorization requirements.
    """

    def __init__(self, config: ShadowConfig):
        self.config = config
        self.throttler = Throttler(
            rate_limit=config.targets.requests_per_second,
            period=1.0
        )
        self._active_scans: dict[UUID, ScanResult] = {}
        self._scan_queue: asyncio.Queue[tuple[ScanTarget, str]] = asyncio.Queue()
        self._running = False

    async def scan(
        self,
        target: str | ScanTarget,
        scan_type: str = "full",
        options: dict[str, Any] | None = None
    ) -> ScanResult:
        """
        Execute a scan against a target.

        Args:
            target: The target to scan (must be authorized)
            scan_type: Type of scan (sast, dast, full, quick)
            options: Additional scan options

        Returns:
            ScanResult with findings
        """
        # Ensure authorization
        self.config.validate_authorization()

        # Normalize target
        if isinstance(target, str):
            target = ScanTarget(target)

        # Validate target is in authorized list
        self._validate_target_authorized(target)

        result = ScanResult(
            target=target.raw,
            scan_type=scan_type,
            status=ScanStatus.RUNNING,
            start_time=datetime.utcnow()
        )
        self._active_scans[result.scan_id] = result

        logger.info("scan_started", scan_id=str(result.scan_id), target=target.raw, type=scan_type)

        try:
            # Execute appropriate scan modules
            if scan_type in ("sast", "full"):
                await self._run_sast_scan(target, result, options or {})

            if scan_type in ("dast", "full"):
                await self._run_dast_scan(target, result, options or {})

            if scan_type == "quick":
                await self._run_quick_scan(target, result, options or {})

            result.status = ScanStatus.COMPLETED

        except asyncio.CancelledError:
            result.status = ScanStatus.CANCELLED
            raise
        except Exception as e:
            result.status = ScanStatus.FAILED
            result.errors.append(str(e))
            logger.error("scan_failed", scan_id=str(result.scan_id), error=str(e))
        finally:
            result.end_time = datetime.utcnow()
            result.calculate_summary()
            logger.info(
                "scan_completed",
                scan_id=str(result.scan_id),
                status=result.status.value,
                findings=result.total_findings,
                duration=result.duration_seconds
            )

        return result

    def _validate_target_authorized(self, target: ScanTarget) -> None:
        """Verify a network target is inside the configured allowlist.

        Local filesystem paths are operator-owned and do not require an allowlist.
        Every network target type fails closed, including CIDR ranges and names
        that could not be classified.
        """
        from pathlib import Path

        targets = self.config.targets

        if target.target_type == "path":
            return

        if target.target_type == "ip":
            if host_listed(target.raw, targets.hosts):
                return
            import ipaddress
            ip = ipaddress.ip_address(target.raw)
            for network in targets.networks:
                if ip in ipaddress.ip_network(network, strict=False):
                    return
            raise PermissionError(f"Target IP not authorized: {target.raw}")

        if target.target_type == "domain":
            if host_authorized(target.raw, targets.domains) or host_listed(target.raw, targets.hosts):
                return
            raise PermissionError(f"Target domain not authorized: {target.raw}")

        if target.target_type == "url":
            from urllib.parse import urlparse
            host = urlparse(target.raw).hostname or ""
            if host_authorized(host, targets.domains) or host_listed(host, targets.hosts):
                return
            raise PermissionError(f"Target URL host not authorized: {host}")

        if target.target_type == "cidr":
            import ipaddress
            network = ipaddress.ip_network(target.raw, strict=False)
            for allowed in targets.networks:
                allowed_net = ipaddress.ip_network(allowed, strict=False)
                if network.subnet_of(allowed_net):
                    return
            raise PermissionError(f"Target network is not inside an authorized range: {target.raw}")

        if target.target_type == "git":
            if target.raw in targets.repositories:
                return
            raise PermissionError(f"Repository not authorized: {target.raw}")

        # Unclassified names are local scans only when the path actually exists.
        if Path(target.raw).exists():
            return
        raise PermissionError(f"Target is not an authorized host, domain, or local path: {target.raw}")

    async def _run_sast_scan(
        self,
        target: ScanTarget,
        result: ScanResult,
        options: dict[str, Any]
    ) -> None:
        """Run static analysis scan."""
        if not self.config.sast.enabled:
            return

        from shadow_worker.scanners.sast import SASTScanner

        sast = SASTScanner(self.config.sast)
        findings = await sast.scan(target.raw)
        result.findings.extend(findings)

    async def _run_dast_scan(
        self,
        target: ScanTarget,
        result: ScanResult,
        options: dict[str, Any]
    ) -> None:
        """Run dynamic analysis scan."""
        if not self.config.dast.enabled:
            return

        if target.target_type not in ("url", "domain", "ip"):
            logger.info("dast_skipped", reason="Target type not suitable for DAST")
            return

        from shadow_worker.scanners.dast import DASTScanner

        async with self.throttler:
            dast = DASTScanner(self.config.dast)
            findings = await dast.scan(target.raw)
            result.findings.extend(findings)

    async def _run_quick_scan(
        self,
        target: ScanTarget,
        result: ScanResult,
        options: dict[str, Any]
    ) -> None:
        """Run a quick reconnaissance scan."""
        # Quick scan focuses on high-severity checks only
        from shadow_worker.scanners.quick import QuickScanner

        quick = QuickScanner(self.config)
        findings = await quick.scan(target.raw)
        result.findings.extend(findings)

    async def scan_multiple(
        self,
        targets: list[str],
        scan_type: str = "full",
        max_concurrent: int | None = None
    ) -> AsyncIterator[ScanResult]:
        """Scan multiple targets with concurrency control."""
        max_concurrent = max_concurrent or self.config.targets.max_concurrent_scans
        semaphore = asyncio.Semaphore(max_concurrent)

        async def scan_one(target: str) -> ScanResult:
            async with semaphore:
                return await self.scan(target, scan_type)

        tasks = [asyncio.create_task(scan_one(t)) for t in targets]

        for task in asyncio.as_completed(tasks):
            yield await task

    def get_scan_status(self, scan_id: UUID) -> ScanResult | None:
        """Get the status of a scan."""
        return self._active_scans.get(scan_id)

    def cancel_scan(self, scan_id: UUID) -> bool:
        """Cancel a running scan."""
        if scan_id in self._active_scans:
            self._active_scans[scan_id].status = ScanStatus.CANCELLED
            return True
        return False

    def list_active_scans(self) -> list[ScanResult]:
        """List all active scans."""
        return [
            s for s in self._active_scans.values()
            if s.status == ScanStatus.RUNNING
        ]
