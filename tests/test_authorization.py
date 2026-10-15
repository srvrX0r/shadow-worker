"""Authorization boundary tests. Network targets fail closed."""

from pathlib import Path

import pytest

from shadow_worker.core.config import ShadowConfig
from shadow_worker.core.scanner import ScanTarget, Scanner, host_authorized


def _scanner(**kwargs: object) -> Scanner:
    config = ShadowConfig(authorization_confirmed=True)
    for key, value in kwargs.items():
        setattr(config.targets, key, value)
    return Scanner(config)


class TestHostAuthorized:
    def test_exact_and_subdomain(self):
        domains = ["example.com"]
        assert host_authorized("example.com", domains)
        assert host_authorized("API.Example.com.", domains)
        assert host_authorized("a.b.example.com", domains)

    def test_suffix_confusion_rejected(self):
        domains = ["example.com"]
        assert not host_authorized("notexample.com", domains)
        assert not host_authorized("example.com.evil.test", domains)
        assert not host_authorized("example.com", [""])


class TestScannerAuthorization:
    def test_domain_suffix_bypass_denied(self):
        scanner = _scanner(domains=["example.com"])
        with pytest.raises(PermissionError):
            scanner._validate_target_authorized(ScanTarget("notexample.com"))

    def test_subdomain_allowed(self):
        scanner = _scanner(domains=["example.com"])
        scanner._validate_target_authorized(ScanTarget("api.example.com"))

    def test_url_uses_hostname_not_port_suffix(self):
        scanner = _scanner(domains=["example.com"])
        scanner._validate_target_authorized(ScanTarget("https://api.example.com:8443/login"))
        with pytest.raises(PermissionError):
            scanner._validate_target_authorized(ScanTarget("https://notexample.com/login"))

    def test_ip_allowlist_and_network(self):
        scanner = _scanner(hosts=["10.0.0.5"], networks=["192.168.1.0/24"])
        scanner._validate_target_authorized(ScanTarget("10.0.0.5"))
        scanner._validate_target_authorized(ScanTarget("192.168.1.20"))
        with pytest.raises(PermissionError):
            scanner._validate_target_authorized(ScanTarget("10.0.0.6"))

    def test_cidr_must_be_subnet_of_allowlist(self):
        scanner = _scanner(networks=["10.0.0.0/8"])
        scanner._validate_target_authorized(ScanTarget("10.1.2.0/24"))
        with pytest.raises(PermissionError):
            scanner._validate_target_authorized(ScanTarget("11.0.0.0/8"))
        with pytest.raises(PermissionError):
            scanner._validate_target_authorized(ScanTarget("10.0.0.0/7"))

    def test_unknown_name_denied_unless_local_path(self, tmp_path: Path):
        scanner = _scanner()
        with pytest.raises(PermissionError):
            scanner._validate_target_authorized(ScanTarget("not-a-real-host"))
        local = tmp_path / "src"
        local.mkdir()
        scanner._validate_target_authorized(ScanTarget(str(local)))

    def test_relative_dot_is_a_path(self):
        assert ScanTarget(".").target_type == "path"
        assert ScanTarget("../other").target_type == "path"
