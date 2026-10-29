"""
Configuration management for Shadow Worker.

Handles loading, validation, and management of security scanning configurations.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator


class TargetConfig(BaseModel):
    """Configuration for scan targets - YOUR OWN infrastructure only."""

    # Authorized targets - must be infrastructure you own/control
    hosts: list[str] = Field(default_factory=list, description="Authorized IP addresses or hostnames")
    networks: list[str] = Field(default_factory=list, description="Authorized CIDR ranges")
    domains: list[str] = Field(default_factory=list, description="Authorized domains you own")
    repositories: list[str] = Field(default_factory=list, description="Source code repositories to scan")

    # Exclusions
    exclude_hosts: list[str] = Field(default_factory=list)
    exclude_paths: list[str] = Field(default_factory=list)

    # Rate limiting to be respectful
    max_concurrent_scans: int = Field(default=10, ge=1, le=100)
    requests_per_second: float = Field(default=10.0, ge=0.1, le=100.0)

    @field_validator("networks")
    @classmethod
    def validate_networks(cls, v: list[str]) -> list[str]:
        """Validate CIDR notation."""
        import ipaddress
        for network in v:
            try:
                ipaddress.ip_network(network, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid CIDR notation: {network}") from e
        return v


class SIEMConfig(BaseModel):
    """SIEM pipeline configuration."""

    enabled: bool = True
    log_sources: list[str] = Field(default_factory=list)
    log_formats: list[str] = Field(default_factory=lambda: ["json", "syslog", "cef", "leef"])

    # Storage
    storage_backend: Literal["sqlite", "postgresql", "elasticsearch"] = "sqlite"
    storage_path: str = "./data/siem.db"
    retention_days: int = Field(default=90, ge=1, le=365)

    # Correlation
    correlation_window_seconds: int = Field(default=300, ge=60, le=3600)
    alert_threshold: int = Field(default=5, ge=1, le=100)

    # External integrations
    elasticsearch_url: str | None = None
    splunk_hec_url: str | None = None
    splunk_hec_token: str | None = None


class DetectionConfig(BaseModel):
    """Threat detection configuration."""

    enabled: bool = True

    # YARA
    yara_rules_path: str = "./rules/yara"
    yara_scan_memory: bool = False

    # Suricata
    suricata_enabled: bool = False
    suricata_rules_path: str = "./rules/suricata"
    suricata_socket: str = "/var/run/suricata/suricata-command.socket"

    # Custom rules
    custom_rules_path: str = "./rules/custom"

    # Severity thresholds
    min_severity: Literal["info", "low", "medium", "high", "critical"] = "low"


class SASTConfig(BaseModel):
    """Static Application Security Testing configuration."""

    enabled: bool = True

    # Scanners
    semgrep_enabled: bool = True
    semgrep_rules: list[str] = Field(default_factory=lambda: ["p/security-audit", "p/owasp-top-ten"])
    bandit_enabled: bool = True

    # OWASP Noir for API discovery
    noir_enabled: bool = True
    noir_detect_endpoints: bool = True

    # Languages to scan
    languages: list[str] = Field(default_factory=lambda: ["python", "javascript", "typescript", "go", "rust", "java"])

    # Exclusions
    exclude_patterns: list[str] = Field(default_factory=lambda: ["**/node_modules/**", "**/vendor/**", "**/.git/**"])


class DASTConfig(BaseModel):
    """Dynamic Application Security Testing configuration."""

    enabled: bool = True

    # Scanner settings
    max_depth: int = Field(default=5, ge=1, le=20)
    max_pages: int = Field(default=1000, ge=1, le=10000)
    follow_redirects: bool = True

    # Authentication
    auth_type: Literal["none", "basic", "bearer", "cookie", "oauth2"] = "none"
    auth_credentials: dict[str, str] = Field(default_factory=dict)

    # Vulnerability checks
    check_sqli: bool = True
    check_xss: bool = True
    check_ssrf: bool = True
    check_lfi: bool = True
    check_rfi: bool = True
    check_command_injection: bool = True
    check_xxe: bool = True
    check_cors: bool = True
    check_headers: bool = True
    check_ssl: bool = True


class Web3Config(BaseModel):
    """Web3/Smart Contract security configuration."""

    enabled: bool = False

    # Networks (for reading contract state - no modification)
    networks: dict[str, str] = Field(default_factory=lambda: {
        "ethereum": "https://eth.llamarpc.com",
        "polygon": "https://polygon-rpc.com",
    })

    # Analysis tools
    slither_enabled: bool = True
    mythril_enabled: bool = True

    # Contract patterns to flag
    check_reentrancy: bool = True
    check_overflow: bool = True
    check_access_control: bool = True
    check_front_running: bool = True


class AlertingConfig(BaseModel):
    """Alerting and notification configuration."""

    enabled: bool = True

    # Channels
    slack_webhook: str | None = None
    discord_webhook: str | None = None
    email_smtp_host: str | None = None
    email_smtp_port: int = 587
    email_from: str | None = None
    email_to: list[str] = Field(default_factory=list)

    # PagerDuty / OpsGenie for critical alerts
    pagerduty_key: str | None = None
    opsgenie_key: str | None = None

    # Thresholds
    alert_on_severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    aggregate_window_seconds: int = Field(default=60, ge=10, le=600)
    max_alerts_per_hour: int = Field(default=100, ge=1, le=1000)


class ShadowConfig(BaseModel):
    """Main configuration for Shadow Worker."""

    # Metadata
    name: str = "shadow-worker"
    environment: Literal["development", "staging", "production"] = "development"

    # Authorization reminder
    authorization_confirmed: bool = Field(
        default=False,
        description="Confirm you are authorized to scan these targets"
    )

    # Component configs
    targets: TargetConfig = Field(default_factory=TargetConfig)
    siem: SIEMConfig = Field(default_factory=SIEMConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    sast: SASTConfig = Field(default_factory=SASTConfig)
    dast: DASTConfig = Field(default_factory=DASTConfig)
    web3: Web3Config = Field(default_factory=Web3Config)
    alerting: AlertingConfig = Field(default_factory=AlertingConfig)

    # Global settings
    data_dir: str = "./data"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    workers: int = Field(default=4, ge=1, le=32)

    @classmethod
    def load(cls, path: str | Path) -> ShadowConfig:
        """Load configuration from YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        with open(path) as f:
            data = yaml.safe_load(f)

        return cls.model_validate(data)

    @classmethod
    def load_from_env(cls) -> ShadowConfig:
        """Load configuration from environment or default locations.

        Environment variables win over file values so the container image can
        point the data directory at a mounted volume without editing config.
        """
        config_path = os.environ.get("SHADOW_CONFIG", "shadow-config.yaml")

        config: ShadowConfig | None = None
        if Path(config_path).exists():
            config = cls.load(config_path)
        else:
            # Check common locations
            for location in ["./shadow-config.yaml", "~/.shadow-worker/config.yaml", "/etc/shadow-worker/config.yaml"]:
                expanded = Path(location).expanduser()
                if expanded.exists():
                    config = cls.load(expanded)
                    break

        if config is None:
            config = cls()

        data_dir = os.environ.get("SHADOW_DATA_DIR")
        if data_dir:
            config.data_dir = data_dir

        log_level = os.environ.get("SHADOW_LOG_LEVEL")
        if log_level and log_level.upper() in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            config.log_level = log_level.upper()  # type: ignore[assignment]

        return config

    def save(self, path: str | Path) -> None:
        """Save configuration to YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False, sort_keys=False)

    def validate_authorization(self) -> None:
        """Ensure authorization is confirmed before scanning."""
        if not self.authorization_confirmed:
            raise ValueError(
                "Authorization not confirmed. Set 'authorization_confirmed: true' in config "
                "to confirm you are authorized to scan the specified targets."
            )
