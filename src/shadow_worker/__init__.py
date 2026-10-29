"""
Shadow Worker - Comprehensive Defensive Security Operations Framework

A modular security platform for vulnerability scanning, SIEM operations,
and threat detection on YOUR OWN infrastructure.

Features:
- SAST/DAST vulnerability scanning
- SIEM log aggregation and correlation
- YARA rule-based threat detection
- Suricata network monitoring integration
- OWASP Noir API endpoint discovery
- Multi-platform support (Web, Mobile, Cloud, Web3)
- Real-time alerting and reporting
"""

__version__ = "1.2.0"
__author__ = "Rodrigo Coll"

from shadow_worker.core.engine import ShadowEngine
from shadow_worker.core.config import ShadowConfig
from shadow_worker.core.scanner import Scanner
from shadow_worker.siem.pipeline import SIEMPipeline
from shadow_worker.detection.detector import ThreatDetector

__all__ = [
    "ShadowEngine",
    "ShadowConfig",
    "Scanner",
    "SIEMPipeline",
    "ThreatDetector",
]
