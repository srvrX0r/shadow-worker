"""Tests for Shadow Worker configuration."""

import pytest
import tempfile
from pathlib import Path

from shadow_worker.core.config import ShadowConfig, TargetConfig, SIEMConfig


class TestShadowConfig:
    """Tests for ShadowConfig class."""

    def test_default_config(self):
        """Test creating default configuration."""
        config = ShadowConfig()

        assert config.name == "shadow-worker"
        assert config.environment == "development"
        assert config.authorization_confirmed is False
        assert config.siem.enabled is True
        assert config.sast.enabled is True
        assert config.dast.enabled is True

    def test_load_from_env_honors_data_dir(self, tmp_path, monkeypatch):
        """SHADOW_DATA_DIR must override the file/default data directory.

        The container image relies on this to write into a mounted volume.
        """
        config_file = tmp_path / "shadow-config.yaml"
        config_file.write_text("name: from-file\ndata_dir: ./data\n")
        monkeypatch.setenv("SHADOW_CONFIG", str(config_file))
        monkeypatch.setenv("SHADOW_DATA_DIR", "/var/lib/shadow-worker/data")

        config = ShadowConfig.load_from_env()

        assert config.name == "from-file"
        assert config.data_dir == "/var/lib/shadow-worker/data"

    def test_load_from_env_honors_log_level(self, tmp_path, monkeypatch):
        """SHADOW_LOG_LEVEL is normalized to the allowed enum values."""
        config_file = tmp_path / "shadow-config.yaml"
        config_file.write_text("name: from-file\n")
        monkeypatch.setenv("SHADOW_CONFIG", str(config_file))
        monkeypatch.setenv("SHADOW_LOG_LEVEL", "debug")

        config = ShadowConfig.load_from_env()

        assert config.log_level == "DEBUG"

    def test_load_from_env_ignores_invalid_log_level(self, tmp_path, monkeypatch):
        """An unusable SHADOW_LOG_LEVEL must not break startup."""
        config_file = tmp_path / "shadow-config.yaml"
        config_file.write_text("name: from-file\n")
        monkeypatch.setenv("SHADOW_CONFIG", str(config_file))
        monkeypatch.setenv("SHADOW_LOG_LEVEL", "verbose")

        config = ShadowConfig.load_from_env()

        assert config.log_level == "INFO"

    def test_load_from_env_without_config_file(self, tmp_path, monkeypatch):
        """Missing config files fall back to defaults, not an exception."""
        monkeypatch.setenv("SHADOW_CONFIG", str(tmp_path / "missing.yaml"))
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("SHADOW_DATA_DIR", raising=False)
        monkeypatch.delenv("SHADOW_LOG_LEVEL", raising=False)

        config = ShadowConfig.load_from_env()

        assert config.name == "shadow-worker"
        assert config.data_dir == "./data"

    def test_authorization_validation(self):
        """Test that authorization must be confirmed."""
        config = ShadowConfig()

        with pytest.raises(ValueError) as exc:
            config.validate_authorization()

        assert "Authorization not confirmed" in str(exc.value)

    def test_authorization_confirmed(self):
        """Test authorization when confirmed."""
        config = ShadowConfig(authorization_confirmed=True)
        config.validate_authorization()  # Should not raise

    def test_save_and_load(self):
        """Test saving and loading configuration."""
        config = ShadowConfig(
            name="test-config",
            environment="production",
        )
        config.targets.hosts = ["192.168.1.1"]
        config.targets.domains = ["example.com"]

        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            config_path = Path(f.name)

        try:
            config.save(config_path)
            loaded = ShadowConfig.load(config_path)

            assert loaded.name == "test-config"
            assert loaded.environment == "production"
            assert "192.168.1.1" in loaded.targets.hosts
            assert "example.com" in loaded.targets.domains
        finally:
            config_path.unlink()

    def test_target_network_validation(self):
        """Test CIDR network validation."""
        # Valid network
        targets = TargetConfig(networks=["192.168.1.0/24", "10.0.0.0/8"])
        assert len(targets.networks) == 2

        # Invalid network should raise
        with pytest.raises(ValueError):
            TargetConfig(networks=["invalid-network"])


class TestTargetConfig:
    """Tests for TargetConfig class."""

    def test_default_values(self):
        """Test default target configuration."""
        targets = TargetConfig()

        assert targets.hosts == []
        assert targets.networks == []
        assert targets.domains == []
        assert targets.max_concurrent_scans == 10
        assert targets.requests_per_second == 10.0

    def test_rate_limiting(self):
        """Test rate limiting configuration."""
        targets = TargetConfig(
            max_concurrent_scans=5,
            requests_per_second=5.0
        )

        assert targets.max_concurrent_scans == 5
        assert targets.requests_per_second == 5.0


class TestSIEMConfig:
    """Tests for SIEMConfig class."""

    def test_default_values(self):
        """Test default SIEM configuration."""
        siem = SIEMConfig()

        assert siem.enabled is True
        assert siem.storage_backend == "sqlite"
        assert siem.retention_days == 90

    def test_correlation_settings(self):
        """Test correlation window settings."""
        siem = SIEMConfig(
            correlation_window_seconds=600,
            alert_threshold=10
        )

        assert siem.correlation_window_seconds == 600
        assert siem.alert_threshold == 10
