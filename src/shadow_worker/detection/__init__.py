"""Threat Detection module - YARA, Suricata, and custom rule engines."""

from shadow_worker.detection.detector import ThreatDetector
from shadow_worker.detection.yara_engine import YaraEngine
from shadow_worker.detection.suricata_engine import SuricataEngine

__all__ = ["ThreatDetector", "YaraEngine", "SuricataEngine"]
