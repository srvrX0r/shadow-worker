"""
Suricata Engine - Network-based threat detection.

Integrates with Suricata IDS/IPS for network traffic analysis.
"""

from __future__ import annotations

import asyncio
import json
import socket
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator

import structlog

from shadow_worker.detection.detector import ThreatDetection, ThreatType, ThreatSeverity

logger = structlog.get_logger()


@dataclass
class SuricataAlert:
    """Alert from Suricata."""

    timestamp: datetime
    signature_id: int
    signature: str
    category: str
    severity: int
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    raw: dict


class SuricataEngine:
    """
    Suricata IDS/IPS integration.

    Features:
    - Unix socket communication with Suricata
    - EVE JSON log parsing
    - Real-time alert streaming
    - Rule management
    """

    def __init__(self, rules_path: str, socket_path: str):
        self.rules_path = Path(rules_path)
        self.socket_path = socket_path
        self._socket: socket.socket | None = None
        self._running = False
        self._alert_task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start Suricata engine connection."""
        if self._running:
            return

        # Try to connect to Suricata socket
        try:
            self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._socket.setblocking(False)

            loop = asyncio.get_event_loop()
            await loop.sock_connect(self._socket, self.socket_path)

            self._running = True
            logger.info("suricata_connected", socket=self.socket_path)

        except FileNotFoundError:
            logger.warning(
                "suricata_socket_not_found",
                socket=self.socket_path,
                msg="Suricata may not be running"
            )
            self._socket = None

        except Exception as e:
            logger.error("suricata_connect_failed", error=str(e))
            self._socket = None

    async def stop(self) -> None:
        """Stop Suricata engine connection."""
        self._running = False

        if self._alert_task:
            self._alert_task.cancel()
            try:
                await self._alert_task
            except asyncio.CancelledError:
                pass

        if self._socket:
            self._socket.close()
            self._socket = None

        logger.info("suricata_disconnected")

    async def send_command(self, command: str) -> dict[str, Any]:
        """Send command to Suricata via Unix socket."""
        if not self._socket:
            raise RuntimeError("Suricata not connected")

        cmd = json.dumps({"command": command}) + "\n"

        loop = asyncio.get_event_loop()
        await loop.sock_sendall(self._socket, cmd.encode())

        response = await loop.sock_recv(self._socket, 65536)
        return json.loads(response.decode())

    async def get_stats(self) -> dict[str, Any]:
        """Get Suricata statistics."""
        try:
            return await self.send_command("dump-counters")
        except Exception as e:
            logger.error("suricata_stats_failed", error=str(e))
            return {}

    async def reload_rules(self) -> bool:
        """Reload Suricata rules."""
        try:
            response = await self.send_command("reload-rules")
            return response.get("return") == "OK"
        except Exception as e:
            logger.error("suricata_reload_failed", error=str(e))
            return False

    async def parse_eve_log(
        self,
        eve_path: str,
        follow: bool = False
    ) -> AsyncIterator[SuricataAlert]:
        """
        Parse Suricata EVE JSON log file.

        Args:
            eve_path: Path to eve.json log file
            follow: If True, follow the log like tail -f

        Yields:
            SuricataAlert objects
        """
        eve_file = Path(eve_path)

        if not eve_file.exists():
            logger.warning("eve_log_not_found", path=eve_path)
            return

        async with asyncio.Lock():
            with open(eve_file) as f:
                if follow:
                    # Start from end of file
                    f.seek(0, 2)

                while self._running or not follow:
                    line = f.readline()

                    if not line:
                        if not follow:
                            break
                        await asyncio.sleep(0.1)
                        continue

                    try:
                        event = json.loads(line)

                        if event.get("event_type") == "alert":
                            yield self._parse_alert(event)

                    except json.JSONDecodeError:
                        continue

    def _parse_alert(self, event: dict) -> SuricataAlert:
        """Parse EVE JSON alert event."""
        alert_data = event.get("alert", {})

        return SuricataAlert(
            timestamp=datetime.fromisoformat(
                event.get("timestamp", "").replace("Z", "+00:00")
            ),
            signature_id=alert_data.get("signature_id", 0),
            signature=alert_data.get("signature", ""),
            category=alert_data.get("category", ""),
            severity=alert_data.get("severity", 3),
            src_ip=event.get("src_ip", ""),
            src_port=event.get("src_port", 0),
            dest_ip=event.get("dest_ip", ""),
            dest_port=event.get("dest_port", 0),
            protocol=event.get("proto", ""),
            raw=event,
        )

    def alert_to_detection(self, alert: SuricataAlert) -> ThreatDetection:
        """Convert Suricata alert to ThreatDetection."""
        # Map Suricata severity (1-3) to ThreatSeverity
        severity_map = {
            1: ThreatSeverity.CRITICAL,
            2: ThreatSeverity.HIGH,
            3: ThreatSeverity.MEDIUM,
        }
        severity = severity_map.get(alert.severity, ThreatSeverity.LOW)

        # Determine threat type from category
        threat_type = ThreatType.SUSPICIOUS
        category_lower = alert.category.lower()

        if "malware" in category_lower:
            threat_type = ThreatType.MALWARE
        elif "trojan" in category_lower:
            threat_type = ThreatType.TROJAN
        elif "exploit" in category_lower:
            threat_type = ThreatType.EXPLOIT
        elif "backdoor" in category_lower:
            threat_type = ThreatType.BACKDOOR
        elif "miner" in category_lower or "crypto" in category_lower:
            threat_type = ThreatType.CRYPTOMINER

        return ThreatDetection(
            timestamp=alert.timestamp,
            threat_type=threat_type,
            severity=severity,
            confidence=0.85,
            rule_name=alert.signature,
            rule_id=f"suricata:{alert.signature_id}",
            engine="suricata",
            tags=[alert.category, alert.protocol],
            description=f"Network alert: {alert.signature}",
        )


# Default Suricata rules for common threats
DEFAULT_SURICATA_RULES = '''
# Shadow Worker Default Suricata Rules
# These are example rules for common threats

# Detect potential C2 beaconing
alert http any any -> any any (msg:"Potential C2 Beacon - Regular Interval Request"; flow:established,to_server; detection_filter:track by_src, count 10, seconds 60; classtype:trojan-activity; sid:1000001; rev:1;)

# Detect cryptocurrency mining pool connections
alert tcp any any -> any any (msg:"Cryptocurrency Mining Pool Connection"; content:"stratum+tcp://"; classtype:policy-violation; sid:1000002; rev:1;)

# Detect potential data exfiltration via DNS
alert dns any any -> any any (msg:"Suspicious Long DNS Query - Potential Exfiltration"; dns_query; content:"|00|"; isdataat:100,relative; classtype:bad-unknown; sid:1000003; rev:1;)

# Detect PowerShell download cradle
alert http any any -> any any (msg:"PowerShell Download Cradle Detected"; flow:established,to_server; content:"powershell"; nocase; content:"downloadstring"; nocase; classtype:trojan-activity; sid:1000004; rev:1;)

# Detect potential webshell access
alert http any any -> any any (msg:"Potential Webshell Command Execution"; flow:established,to_server; content:"cmd="; content:"&"; within:100; classtype:web-application-attack; sid:1000005; rev:1;)
'''


def create_default_rules(rules_path: str) -> None:
    """Create default Suricata rules if none exist."""
    path = Path(rules_path)
    path.mkdir(parents=True, exist_ok=True)

    default_file = path / "shadow-worker.rules"
    if not default_file.exists():
        default_file.write_text(DEFAULT_SURICATA_RULES)
        logger.info("default_suricata_rules_created", path=str(default_file))
