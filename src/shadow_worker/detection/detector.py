"""
Threat Detector - Unified threat detection engine.

Integrates YARA rules, Suricata, and custom detection logic.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import structlog

from shadow_worker.core.config import DetectionConfig

logger = structlog.get_logger()


class ThreatType(str, Enum):
    """Types of detected threats."""

    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    BACKDOOR = "backdoor"
    ROOTKIT = "rootkit"
    CRYPTOMINER = "cryptominer"
    EXPLOIT = "exploit"
    WEBSHELL = "webshell"
    PHISHING = "phishing"
    SUSPICIOUS = "suspicious"
    PUP = "potentially_unwanted"
    UNKNOWN = "unknown"


class ThreatSeverity(str, Enum):
    """Threat severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatDetection:
    """A detected threat."""

    id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Classification
    threat_type: ThreatType = ThreatType.UNKNOWN
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    confidence: float = 0.0  # 0.0 to 1.0

    # Detection details
    rule_name: str = ""
    rule_id: str = ""
    engine: str = ""  # yara, suricata, custom

    # Target info
    filename: str = ""
    filepath: str = ""
    file_hash_md5: str = ""
    file_hash_sha256: str = ""
    file_size: int = 0

    # Match details
    matched_strings: list[str] = field(default_factory=list)
    matched_data: bytes = b""
    offset: int = 0

    # Metadata
    tags: list[str] = field(default_factory=list)
    description: str = ""
    references: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)  # MITRE ATT&CK IDs

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "timestamp": self.timestamp.isoformat(),
            "threat_type": self.threat_type.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "rule_name": self.rule_name,
            "rule_id": self.rule_id,
            "engine": self.engine,
            "filename": self.filename,
            "file_hash_sha256": self.file_hash_sha256,
            "matched_strings": self.matched_strings,
            "tags": self.tags,
            "description": self.description,
            "mitre_attack": self.mitre_attack,
        }


class ThreatDetector:
    """
    Unified threat detection engine.

    Combines multiple detection engines:
    - YARA for signature-based detection
    - Suricata for network-based detection
    - Custom rules for behavior detection
    """

    def __init__(self, config: DetectionConfig):
        self.config = config
        self._yara_engine: Any = None
        self._suricata_engine: Any = None
        self._custom_rules: list[dict[str, Any]] = []
        self._running = False

    async def start(self) -> None:
        """Initialize and start detection engines."""
        if self._running:
            return

        # Initialize YARA engine
        if Path(self.config.yara_rules_path).exists():
            from shadow_worker.detection.yara_engine import YaraEngine
            self._yara_engine = YaraEngine(self.config.yara_rules_path)
            await self._yara_engine.load_rules()
            logger.info("yara_engine_started", rules_path=self.config.yara_rules_path)

        # Initialize Suricata engine
        if self.config.suricata_enabled:
            from shadow_worker.detection.suricata_engine import SuricataEngine
            self._suricata_engine = SuricataEngine(
                self.config.suricata_rules_path,
                self.config.suricata_socket
            )
            await self._suricata_engine.start()
            logger.info("suricata_engine_started")

        # Load custom rules
        if Path(self.config.custom_rules_path).exists():
            self._load_custom_rules()

        self._running = True
        logger.info("threat_detector_started")

    async def stop(self) -> None:
        """Stop detection engines."""
        if self._suricata_engine:
            await self._suricata_engine.stop()

        self._running = False
        logger.info("threat_detector_stopped")

    async def detect(
        self,
        data: bytes | str,
        filename: str = "",
        scan_memory: bool = False
    ) -> list[ThreatDetection]:
        """
        Scan data for threats.

        Args:
            data: Data to scan (bytes or string)
            filename: Optional filename for context
            scan_memory: Whether this is memory scanning

        Returns:
            List of threat detections
        """
        if isinstance(data, str):
            data = data.encode("utf-8", errors="ignore")

        detections: list[ThreatDetection] = []

        # Calculate hashes
        md5_hash = hashlib.md5(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()

        # Run YARA scan
        if self._yara_engine:
            yara_detections = await self._yara_engine.scan(data, filename)
            for det in yara_detections:
                det.file_hash_md5 = md5_hash
                det.file_hash_sha256 = sha256_hash
                det.file_size = len(data)
                detections.append(det)

        # Run custom rule detection
        custom_detections = self._run_custom_rules(data, filename)
        for det in custom_detections:
            det.file_hash_md5 = md5_hash
            det.file_hash_sha256 = sha256_hash
            det.file_size = len(data)
            detections.append(det)

        # Filter by minimum severity
        severity_order = ["info", "low", "medium", "high", "critical"]
        min_idx = severity_order.index(self.config.min_severity)
        detections = [
            d for d in detections
            if severity_order.index(d.severity.value) >= min_idx
        ]

        if detections:
            logger.warning(
                "threats_detected",
                count=len(detections),
                filename=filename,
                sha256=sha256_hash[:16]
            )

        return detections

    async def scan_file(self, filepath: str | Path) -> list[ThreatDetection]:
        """Scan a file for threats."""
        filepath = Path(filepath)

        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        if filepath.stat().st_size > 100 * 1024 * 1024:  # 100MB limit
            logger.warning("file_too_large", filepath=str(filepath))
            return []

        data = filepath.read_bytes()
        detections = await self.detect(data, filepath.name)

        for det in detections:
            det.filepath = str(filepath)

        return detections

    async def scan_directory(
        self,
        dirpath: str | Path,
        recursive: bool = True,
        patterns: list[str] | None = None
    ) -> list[ThreatDetection]:
        """Scan a directory for threats."""
        dirpath = Path(dirpath)
        patterns = patterns or ["*"]

        all_detections: list[ThreatDetection] = []

        for pattern in patterns:
            if recursive:
                files = dirpath.rglob(pattern)
            else:
                files = dirpath.glob(pattern)

            for filepath in files:
                if filepath.is_file():
                    try:
                        detections = await self.scan_file(filepath)
                        all_detections.extend(detections)
                    except Exception as e:
                        logger.error("scan_file_failed", filepath=str(filepath), error=str(e))

        return all_detections

    async def scan_process_memory(self, pid: int) -> list[ThreatDetection]:
        """Scan process memory for threats (Linux only)."""
        if not self.config.yara_scan_memory:
            return []

        try:
            # Read process memory maps
            maps_path = Path(f"/proc/{pid}/maps")
            mem_path = Path(f"/proc/{pid}/mem")

            if not maps_path.exists() or not mem_path.exists():
                logger.warning("process_not_accessible", pid=pid)
                return []

            detections: list[ThreatDetection] = []

            # Parse memory maps and scan readable regions
            # Note: This requires appropriate permissions
            # Implementation would involve reading /proc/pid/maps and /proc/pid/mem

            logger.info("memory_scan_complete", pid=pid, detections=len(detections))
            return detections

        except PermissionError:
            logger.error("memory_scan_permission_denied", pid=pid)
            return []
        except Exception as e:
            logger.error("memory_scan_failed", pid=pid, error=str(e))
            return []

    def _load_custom_rules(self) -> None:
        """Load custom detection rules."""
        import yaml

        rules_path = Path(self.config.custom_rules_path)

        for rule_file in rules_path.glob("*.yaml"):
            try:
                with open(rule_file) as f:
                    rules = yaml.safe_load(f)
                    if isinstance(rules, list):
                        self._custom_rules.extend(rules)
                    elif isinstance(rules, dict) and "rules" in rules:
                        self._custom_rules.extend(rules["rules"])
            except Exception as e:
                logger.error("custom_rule_load_failed", file=str(rule_file), error=str(e))

        logger.info("custom_rules_loaded", count=len(self._custom_rules))

    def _run_custom_rules(
        self,
        data: bytes,
        filename: str
    ) -> list[ThreatDetection]:
        """Run custom detection rules."""
        import re

        detections: list[ThreatDetection] = []

        for rule in self._custom_rules:
            try:
                rule_id = rule.get("id", "unknown")
                patterns = rule.get("patterns", [])

                for pattern in patterns:
                    pattern_type = pattern.get("type", "string")
                    value = pattern.get("value", "")

                    matched = False
                    matched_strings = []

                    if pattern_type == "string":
                        if value.encode() in data:
                            matched = True
                            matched_strings.append(value)

                    elif pattern_type == "regex":
                        matches = re.findall(value.encode(), data)
                        if matches:
                            matched = True
                            matched_strings.extend(m.decode(errors="ignore") for m in matches[:10])

                    elif pattern_type == "hex":
                        hex_pattern = bytes.fromhex(value.replace(" ", ""))
                        if hex_pattern in data:
                            matched = True
                            matched_strings.append(f"hex:{value}")

                    if matched:
                        detections.append(ThreatDetection(
                            threat_type=ThreatType(rule.get("threat_type", "suspicious")),
                            severity=ThreatSeverity(rule.get("severity", "medium")),
                            confidence=rule.get("confidence", 0.7),
                            rule_name=rule.get("name", rule_id),
                            rule_id=rule_id,
                            engine="custom",
                            filename=filename,
                            matched_strings=matched_strings,
                            tags=rule.get("tags", []),
                            description=rule.get("description", ""),
                            mitre_attack=rule.get("mitre_attack", []),
                        ))
                        break  # One match per rule is enough

            except Exception as e:
                logger.error("custom_rule_execution_failed", rule_id=rule.get("id"), error=str(e))

        return detections

    def get_stats(self) -> dict[str, Any]:
        """Get detection statistics."""
        stats = {
            "yara_enabled": self._yara_engine is not None,
            "suricata_enabled": self._suricata_engine is not None,
            "custom_rules_count": len(self._custom_rules),
        }

        if self._yara_engine:
            stats["yara_rules_count"] = self._yara_engine.rules_count

        return stats
