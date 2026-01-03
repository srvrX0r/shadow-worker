"""
YARA Engine - Signature-based threat detection.

Provides YARA rule compilation and scanning capabilities.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import structlog

from shadow_worker.detection.detector import ThreatDetection, ThreatType, ThreatSeverity

logger = structlog.get_logger()


class YaraEngine:
    """
    YARA-based malware detection engine.

    Features:
    - Multi-file rule loading
    - Compiled rule caching
    - Async scanning support
    - Automatic rule reloading
    """

    def __init__(self, rules_path: str):
        self.rules_path = Path(rules_path)
        self._rules: Any = None
        self._rule_files: list[Path] = []
        self.rules_count = 0

    async def load_rules(self) -> int:
        """
        Load and compile YARA rules from directory.

        Returns:
            Number of rules loaded
        """
        try:
            import yara
        except ImportError:
            logger.warning("yara_not_installed", msg="Install yara-python for YARA support")
            return 0

        if not self.rules_path.exists():
            logger.warning("yara_rules_path_not_found", path=str(self.rules_path))
            return 0

        # Collect all rule files
        rule_files = {}
        self._rule_files = []

        for rule_file in self.rules_path.rglob("*.yar"):
            namespace = rule_file.stem
            rule_files[namespace] = str(rule_file)
            self._rule_files.append(rule_file)

        for rule_file in self.rules_path.rglob("*.yara"):
            namespace = rule_file.stem
            rule_files[namespace] = str(rule_file)
            self._rule_files.append(rule_file)

        if not rule_files:
            logger.warning("no_yara_rules_found", path=str(self.rules_path))
            return 0

        # Compile rules
        try:
            self._rules = yara.compile(filepaths=rule_files)
            self.rules_count = len(rule_files)
            logger.info("yara_rules_compiled", count=self.rules_count)
            return self.rules_count
        except yara.SyntaxError as e:
            logger.error("yara_syntax_error", error=str(e))
            return 0
        except Exception as e:
            logger.error("yara_compile_error", error=str(e))
            return 0

    async def scan(
        self,
        data: bytes,
        filename: str = ""
    ) -> list[ThreatDetection]:
        """
        Scan data with YARA rules.

        Args:
            data: Data to scan
            filename: Optional filename for context

        Returns:
            List of threat detections
        """
        if not self._rules:
            return []

        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        matches = await loop.run_in_executor(
            None,
            self._scan_sync,
            data
        )

        detections = []
        for match in matches:
            detection = self._match_to_detection(match, filename)
            detections.append(detection)

        return detections

    async def scan_file(self, filepath: str | Path) -> list[ThreatDetection]:
        """Scan a file with YARA rules."""
        if not self._rules:
            return []

        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        loop = asyncio.get_event_loop()
        matches = await loop.run_in_executor(
            None,
            lambda: self._rules.match(str(filepath))
        )

        detections = []
        for match in matches:
            detection = self._match_to_detection(match, filepath.name)
            detection.filepath = str(filepath)
            detections.append(detection)

        return detections

    def _scan_sync(self, data: bytes) -> list[Any]:
        """Synchronous scan for thread pool."""
        try:
            return self._rules.match(data=data)
        except Exception as e:
            logger.error("yara_scan_error", error=str(e))
            return []

    def _match_to_detection(self, match: Any, filename: str) -> ThreatDetection:
        """Convert YARA match to ThreatDetection."""
        # Extract matched strings
        matched_strings = []
        for string_match in match.strings:
            try:
                # YARA 4.x format
                identifier = string_match.identifier
                for instance in string_match.instances:
                    matched_strings.append(f"{identifier}: offset {instance.offset}")
            except AttributeError:
                # YARA 3.x format
                offset, identifier, data = string_match
                matched_strings.append(f"{identifier}: offset {offset}")

        # Determine threat type from rule tags
        threat_type = ThreatType.SUSPICIOUS
        tags = list(match.tags)

        tag_to_type = {
            "malware": ThreatType.MALWARE,
            "ransomware": ThreatType.RANSOMWARE,
            "trojan": ThreatType.TROJAN,
            "backdoor": ThreatType.BACKDOOR,
            "rootkit": ThreatType.ROOTKIT,
            "miner": ThreatType.CRYPTOMINER,
            "cryptominer": ThreatType.CRYPTOMINER,
            "exploit": ThreatType.EXPLOIT,
            "webshell": ThreatType.WEBSHELL,
            "phishing": ThreatType.PHISHING,
        }

        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in tag_to_type:
                threat_type = tag_to_type[tag_lower]
                break

        # Determine severity from meta
        severity = ThreatSeverity.MEDIUM
        meta = match.meta

        if "severity" in meta:
            try:
                severity = ThreatSeverity(meta["severity"].lower())
            except ValueError:
                pass

        # High severity for certain threat types
        if threat_type in (ThreatType.RANSOMWARE, ThreatType.ROOTKIT, ThreatType.BACKDOOR):
            severity = ThreatSeverity.CRITICAL

        return ThreatDetection(
            threat_type=threat_type,
            severity=severity,
            confidence=0.9,  # YARA matches are typically high confidence
            rule_name=match.rule,
            rule_id=f"yara:{match.namespace}:{match.rule}",
            engine="yara",
            filename=filename,
            matched_strings=matched_strings[:20],  # Limit matches
            tags=tags,
            description=meta.get("description", ""),
            references=self._parse_references(meta),
            mitre_attack=self._parse_mitre(meta),
        )

    def _parse_references(self, meta: dict) -> list[str]:
        """Extract references from rule metadata."""
        refs = []

        for key in ["reference", "url", "source"]:
            if key in meta:
                refs.append(meta[key])

        # Handle numbered references (reference1, reference2, etc.)
        for i in range(1, 10):
            key = f"reference{i}"
            if key in meta:
                refs.append(meta[key])

        return refs

    def _parse_mitre(self, meta: dict) -> list[str]:
        """Extract MITRE ATT&CK IDs from rule metadata."""
        mitre = []

        for key in ["mitre", "mitre_attack", "attack"]:
            if key in meta:
                value = meta[key]
                if isinstance(value, str):
                    mitre.extend(value.split(","))
                elif isinstance(value, list):
                    mitre.extend(value)

        return [m.strip() for m in mitre if m.strip()]


# Default YARA rules for common threats
DEFAULT_YARA_RULES = '''
rule Webshell_Generic {
    meta:
        description = "Detects generic webshell patterns"
        severity = "high"
        mitre = "T1505.003"
    strings:
        $php1 = "<?php eval(" ascii nocase
        $php2 = "<?php system(" ascii nocase
        $php3 = "<?php passthru(" ascii nocase
        $php4 = "<?php shell_exec(" ascii nocase
        $php5 = "<?php exec(" ascii nocase
        $php6 = "base64_decode($_" ascii nocase
        $asp1 = "<%eval request" ascii nocase
        $asp2 = "<%execute request" ascii nocase
        $jsp1 = "Runtime.getRuntime().exec" ascii
    condition:
        any of them
}

rule Suspicious_PowerShell {
    meta:
        description = "Detects suspicious PowerShell commands"
        severity = "medium"
        mitre = "T1059.001"
    strings:
        $enc = "-encodedcommand" ascii nocase
        $bypass = "-executionpolicy bypass" ascii nocase
        $hidden = "-windowstyle hidden" ascii nocase
        $download = "downloadstring" ascii nocase
        $iex = "iex(" ascii nocase
    condition:
        2 of them
}

rule Cryptominer_Strings {
    meta:
        description = "Detects cryptocurrency mining software"
        severity = "medium"
        mitre = "T1496"
    strings:
        $s1 = "stratum+tcp://" ascii
        $s2 = "stratum+ssl://" ascii
        $s3 = "xmrig" ascii nocase
        $s4 = "cryptonight" ascii nocase
        $s5 = "monero" ascii nocase
        $wallet = /[0-9A-Za-z]{95}/ ascii
    condition:
        2 of them
}

rule Ransomware_Note {
    meta:
        description = "Detects ransomware note patterns"
        severity = "critical"
        mitre = "T1486"
    strings:
        $s1 = "your files have been encrypted" ascii nocase
        $s2 = "bitcoin" ascii nocase
        $s3 = "decrypt" ascii nocase
        $s4 = "ransom" ascii nocase
        $s5 = "pay" ascii nocase
        $s6 = ".onion" ascii
    condition:
        3 of them
}

rule Suspicious_Base64_PE {
    meta:
        description = "Detects base64 encoded PE files"
        severity = "high"
        mitre = "T1027"
    strings:
        $mz_b64 = "TVqQAAMAAAA" ascii
        $mz_b64_2 = "TVpQAAIAAAA" ascii
    condition:
        any of them
}
'''


def create_default_rules(rules_path: str) -> None:
    """Create default YARA rules if none exist."""
    path = Path(rules_path)
    path.mkdir(parents=True, exist_ok=True)

    default_file = path / "default_rules.yar"
    if not default_file.exists():
        default_file.write_text(DEFAULT_YARA_RULES)
        logger.info("default_yara_rules_created", path=str(default_file))
