"""Tests for Shadow Worker scanners."""

import pytest
from uuid import UUID

from shadow_worker.core.scanner import (
    Scanner,
    ScanTarget,
    Finding,
    ScanResult,
    Severity,
    VulnCategory,
    ScanStatus,
)
from shadow_worker.core.config import ShadowConfig


class TestScanTarget:
    """Tests for ScanTarget class."""

    def test_url_detection(self):
        """Test URL target type detection."""
        target = ScanTarget("https://example.com")
        assert target.target_type == "url"

        target = ScanTarget("http://localhost:8080")
        assert target.target_type == "url"

    def test_ip_detection(self):
        """Test IP address target type detection."""
        target = ScanTarget("192.168.1.1")
        assert target.target_type == "ip"

        target = ScanTarget("10.0.0.1")
        assert target.target_type == "ip"

    def test_domain_detection(self):
        """Test domain target type detection."""
        target = ScanTarget("example.com")
        assert target.target_type == "domain"

    def test_path_detection(self):
        """Test file path target type detection."""
        target = ScanTarget("/path/to/file")
        assert target.target_type == "path"

        target = ScanTarget("./relative/path")
        assert target.target_type == "path"

    def test_cidr_detection(self):
        """Test CIDR notation detection."""
        target = ScanTarget("192.168.1.0/24")
        assert target.target_type == "cidr"

    def test_empty_target_raises(self):
        """Test that empty target raises ValueError."""
        with pytest.raises(ValueError):
            ScanTarget("")

    def test_invalid_ip_raises(self):
        """Test that invalid IP raises ValueError."""
        with pytest.raises(ValueError):
            ScanTarget("999.999.999.999")


class TestFinding:
    """Tests for Finding class."""

    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            title="SQL Injection",
            description="SQL injection in login form",
            severity=Severity.CRITICAL,
            category=VulnCategory.INJECTION,
            target="https://example.com",
            location="/login",
            line_number=42,
            scanner="dast"
        )

        assert finding.title == "SQL Injection"
        assert finding.severity == Severity.CRITICAL
        assert finding.category == VulnCategory.INJECTION
        assert isinstance(finding.id, UUID)

    def test_finding_to_dict(self):
        """Test converting finding to dictionary."""
        finding = Finding(
            title="XSS Vulnerability",
            severity=Severity.HIGH,
            category=VulnCategory.XSS,
        )

        data = finding.to_dict()

        assert data["title"] == "XSS Vulnerability"
        assert data["severity"] == "high"
        assert data["category"] == "cross_site_scripting"
        assert "id" in data
        assert "timestamp" in data


class TestScanResult:
    """Tests for ScanResult class."""

    def test_result_creation(self):
        """Test creating a scan result."""
        result = ScanResult(
            target="https://example.com",
            scan_type="full",
            status=ScanStatus.COMPLETED,
        )

        assert result.target == "https://example.com"
        assert result.scan_type == "full"
        assert result.status == ScanStatus.COMPLETED
        assert isinstance(result.scan_id, UUID)

    def test_calculate_summary(self):
        """Test calculating finding summary."""
        result = ScanResult()
        result.findings = [
            Finding(severity=Severity.CRITICAL),
            Finding(severity=Severity.CRITICAL),
            Finding(severity=Severity.HIGH),
            Finding(severity=Severity.MEDIUM),
            Finding(severity=Severity.MEDIUM),
            Finding(severity=Severity.LOW),
            Finding(severity=Severity.INFO),
        ]

        result.calculate_summary()

        assert result.total_findings == 7
        assert result.critical_count == 2
        assert result.high_count == 1
        assert result.medium_count == 2
        assert result.low_count == 1
        assert result.info_count == 1


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.INFO.value == "info"
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_from_cvss(self):
        """Test severity from CVSS score."""
        assert Severity.from_cvss(0) == Severity.INFO
        assert Severity.from_cvss(2.5) == Severity.LOW
        assert Severity.from_cvss(5.5) == Severity.MEDIUM
        assert Severity.from_cvss(8.0) == Severity.HIGH
        assert Severity.from_cvss(9.5) == Severity.CRITICAL
