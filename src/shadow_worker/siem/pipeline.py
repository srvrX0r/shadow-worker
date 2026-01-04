"""
SIEM Pipeline - Log aggregation, normalization, and correlation.

Provides centralized security event management for your infrastructure.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable
from uuid import UUID, uuid4

import structlog

from shadow_worker.core.config import SIEMConfig

logger = structlog.get_logger()


class EventSeverity(str, Enum):
    """Event severity levels."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventCategory(str, Enum):
    """Event categories for classification."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    FILE_SYSTEM = "file_system"
    PROCESS = "process"
    MALWARE = "malware"
    VULNERABILITY = "vulnerability"
    CONFIGURATION = "configuration"
    AUDIT = "audit"
    SYSTEM = "system"
    APPLICATION = "application"
    CUSTOM = "custom"


@dataclass
class SecurityEvent:
    """Normalized security event."""

    id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Classification
    category: EventCategory = EventCategory.CUSTOM
    severity: EventSeverity = EventSeverity.INFO
    event_type: str = ""

    # Source
    source: str = ""
    source_ip: str | None = None
    source_port: int | None = None
    source_user: str | None = None

    # Destination
    dest_ip: str | None = None
    dest_port: int | None = None
    dest_host: str | None = None

    # Content
    message: str = ""
    raw_log: str = ""

    # Context
    action: str | None = None  # e.g., "login", "file_read", "network_connect"
    outcome: str | None = None  # e.g., "success", "failure"
    reason: str | None = None

    # Additional fields
    fields: dict[str, Any] = field(default_factory=dict)

    # Correlation
    correlation_id: str | None = None
    related_events: list[UUID] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "timestamp": self.timestamp.isoformat(),
            "category": self.category.value,
            "severity": self.severity.value,
            "event_type": self.event_type,
            "source": self.source,
            "source_ip": self.source_ip,
            "source_user": self.source_user,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "message": self.message,
            "action": self.action,
            "outcome": self.outcome,
            "fields": self.fields,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityEvent:
        """Create from dictionary."""
        return cls(
            id=UUID(data["id"]) if "id" in data else uuid4(),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat())),
            category=EventCategory(data.get("category", "custom")),
            severity=EventSeverity(data.get("severity", "info")),
            event_type=data.get("event_type", ""),
            source=data.get("source", ""),
            source_ip=data.get("source_ip"),
            source_user=data.get("source_user"),
            dest_ip=data.get("dest_ip"),
            dest_port=data.get("dest_port"),
            message=data.get("message", ""),
            action=data.get("action"),
            outcome=data.get("outcome"),
            fields=data.get("fields", {}),
            correlation_id=data.get("correlation_id"),
        )


@dataclass
class CorrelationRule:
    """Rule for correlating events."""

    id: str
    name: str
    description: str
    severity: EventSeverity

    # Match conditions
    conditions: list[dict[str, Any]]  # List of field conditions
    window_seconds: int = 300  # Time window for correlation
    threshold: int = 1  # Number of matches required

    # Actions
    create_alert: bool = True
    alert_template: str = ""

    def matches(self, event: SecurityEvent) -> bool:
        """Check if an event matches this rule's conditions."""
        for condition in self.conditions:
            field_name = condition.get("field", "")
            operator = condition.get("operator", "equals")
            value = condition.get("value")

            event_value = getattr(event, field_name, None) or event.fields.get(field_name)

            if operator == "equals" and event_value != value:
                return False
            elif operator == "contains" and value not in str(event_value):
                return False
            elif operator == "regex" and not re.match(value, str(event_value)):
                return False
            elif operator == "in" and event_value not in value:
                return False

        return True


@dataclass
class Alert:
    """SIEM Alert."""

    id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    rule_id: str = ""
    rule_name: str = ""
    severity: EventSeverity = EventSeverity.WARNING

    title: str = ""
    description: str = ""

    # Related events
    event_ids: list[UUID] = field(default_factory=list)
    event_count: int = 0

    # Status
    acknowledged: bool = False
    resolved: bool = False
    assignee: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "timestamp": self.timestamp.isoformat(),
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "event_count": self.event_count,
            "acknowledged": self.acknowledged,
            "resolved": self.resolved,
        }


class LogParser:
    """Parses various log formats into normalized events."""

    # Common log patterns
    SYSLOG_PATTERN = re.compile(
        r"^(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.*)$"
    )

    JSON_PATTERN = re.compile(r"^\s*\{.*\}\s*$", re.DOTALL)

    CEF_PATTERN = re.compile(
        r"^CEF:(?P<version>\d+)\|"
        r"(?P<vendor>[^|]*)\|"
        r"(?P<product>[^|]*)\|"
        r"(?P<version2>[^|]*)\|"
        r"(?P<signature>[^|]*)\|"
        r"(?P<name>[^|]*)\|"
        r"(?P<severity>[^|]*)\|"
        r"(?P<extension>.*)$"
    )

    def parse(self, log_line: str, source: str = "unknown") -> SecurityEvent:
        """Parse a log line into a SecurityEvent."""
        # Try JSON first
        if self.JSON_PATTERN.match(log_line):
            return self._parse_json(log_line, source)

        # Try CEF
        if log_line.startswith("CEF:"):
            return self._parse_cef(log_line, source)

        # Try syslog
        match = self.SYSLOG_PATTERN.match(log_line)
        if match:
            return self._parse_syslog(match, log_line, source)

        # Fallback to raw event
        return SecurityEvent(
            source=source,
            message=log_line,
            raw_log=log_line,
            event_type="raw"
        )

    def _parse_json(self, log_line: str, source: str) -> SecurityEvent:
        """Parse JSON log."""
        try:
            data = json.loads(log_line)

            # Common field mappings
            return SecurityEvent(
                source=source,
                timestamp=self._parse_timestamp(data.get("timestamp", data.get("@timestamp", ""))),
                message=data.get("message", data.get("msg", "")),
                severity=self._map_severity(data.get("level", data.get("severity", "info"))),
                source_ip=data.get("source_ip", data.get("src_ip", data.get("client_ip"))),
                source_user=data.get("user", data.get("username")),
                dest_ip=data.get("dest_ip", data.get("dst_ip")),
                dest_port=data.get("dest_port", data.get("dst_port")),
                action=data.get("action", data.get("event_action")),
                outcome=data.get("outcome", data.get("result")),
                event_type=data.get("event_type", data.get("type", "json")),
                raw_log=log_line,
                fields=data
            )
        except json.JSONDecodeError:
            return SecurityEvent(source=source, message=log_line, raw_log=log_line)

    def _parse_cef(self, log_line: str, source: str) -> SecurityEvent:
        """Parse CEF (Common Event Format) log."""
        match = self.CEF_PATTERN.match(log_line)
        if not match:
            return SecurityEvent(source=source, message=log_line, raw_log=log_line)

        groups = match.groupdict()

        # Parse extension key=value pairs
        extension = {}
        for pair in groups.get("extension", "").split():
            if "=" in pair:
                key, value = pair.split("=", 1)
                extension[key] = value

        return SecurityEvent(
            source=source,
            message=groups.get("name", ""),
            severity=self._map_cef_severity(groups.get("severity", "5")),
            source_ip=extension.get("src"),
            dest_ip=extension.get("dst"),
            dest_port=int(extension.get("dpt", 0)) or None,
            source_user=extension.get("suser"),
            event_type="cef",
            raw_log=log_line,
            fields={
                "vendor": groups.get("vendor"),
                "product": groups.get("product"),
                "signature": groups.get("signature"),
                **extension
            }
        )

    def _parse_syslog(self, match: re.Match, log_line: str, source: str) -> SecurityEvent:
        """Parse syslog format."""
        groups = match.groupdict()

        return SecurityEvent(
            source=source,
            message=groups.get("message", ""),
            event_type="syslog",
            raw_log=log_line,
            fields={
                "host": groups.get("host"),
                "program": groups.get("program"),
                "pid": groups.get("pid"),
            }
        )

    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Parse various timestamp formats."""
        if not ts_str:
            return datetime.utcnow()

        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue

        return datetime.utcnow()

    def _map_severity(self, level: str) -> EventSeverity:
        """Map common log levels to severity."""
        level = level.lower()
        mapping = {
            "debug": EventSeverity.DEBUG,
            "info": EventSeverity.INFO,
            "information": EventSeverity.INFO,
            "warn": EventSeverity.WARNING,
            "warning": EventSeverity.WARNING,
            "error": EventSeverity.ERROR,
            "err": EventSeverity.ERROR,
            "critical": EventSeverity.CRITICAL,
            "fatal": EventSeverity.CRITICAL,
            "emergency": EventSeverity.CRITICAL,
        }
        return mapping.get(level, EventSeverity.INFO)

    def _map_cef_severity(self, severity: str) -> EventSeverity:
        """Map CEF severity (0-10) to EventSeverity."""
        try:
            sev = int(severity)
            if sev <= 3:
                return EventSeverity.INFO
            elif sev <= 5:
                return EventSeverity.WARNING
            elif sev <= 7:
                return EventSeverity.ERROR
            else:
                return EventSeverity.CRITICAL
        except ValueError:
            return EventSeverity.INFO


class SIEMPipeline:
    """
    SIEM Pipeline for log aggregation and correlation.

    Features:
    - Multi-format log parsing (JSON, syslog, CEF, LEEF)
    - Event normalization
    - Rule-based correlation
    - Real-time alerting
    - Event storage and retention
    """

    def __init__(self, config: SIEMConfig):
        self.config = config
        self.parser = LogParser()

        # Event storage
        self._events: list[SecurityEvent] = []
        self._alerts: list[Alert] = []
        self._event_buffer: asyncio.Queue[SecurityEvent] = asyncio.Queue(maxsize=10000)

        # Correlation
        self._rules: list[CorrelationRule] = []
        self._correlation_windows: dict[str, list[SecurityEvent]] = defaultdict(list)

        # Callbacks
        self._alert_callbacks: list[Callable[[Alert], Any]] = []

        # State
        self._running = False
        self._processor_task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the SIEM pipeline."""
        if self._running:
            return

        self._running = True
        self._processor_task = asyncio.create_task(self._event_processor())

        # Load default correlation rules
        self._load_default_rules()

        logger.info("siem_pipeline_started")

    async def stop(self) -> None:
        """Stop the SIEM pipeline."""
        self._running = False

        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass

        logger.info("siem_pipeline_stopped")

    async def ingest(
        self,
        logs: list[dict[str, Any]] | list[str],
        source: str = "unknown"
    ) -> int:
        """
        Ingest logs into the pipeline.

        Args:
            logs: List of log entries (dicts or strings)
            source: Source identifier

        Returns:
            Number of events ingested
        """
        count = 0

        for log in logs:
            try:
                if isinstance(log, dict):
                    event = SecurityEvent.from_dict({**log, "source": source})
                else:
                    event = self.parser.parse(str(log), source)

                await self._event_buffer.put(event)
                count += 1
            except Exception as e:
                logger.error("ingest_failed", error=str(e))

        return count

    async def ingest_event(self, event: SecurityEvent) -> None:
        """Ingest a single normalized event."""
        await self._event_buffer.put(event)

    def add_rule(self, rule: CorrelationRule) -> None:
        """Add a correlation rule."""
        self._rules.append(rule)
        logger.info("correlation_rule_added", rule_id=rule.id, name=rule.name)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a correlation rule."""
        for i, rule in enumerate(self._rules):
            if rule.id == rule_id:
                del self._rules[i]
                return True
        return False

    def on_alert(self, callback: Callable[[Alert], Any]) -> None:
        """Register a callback for alerts."""
        self._alert_callbacks.append(callback)

    def get_events(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        severity: EventSeverity | None = None,
        category: EventCategory | None = None,
        limit: int = 1000
    ) -> list[SecurityEvent]:
        """Query events with filters."""
        results = []

        for event in reversed(self._events):
            if len(results) >= limit:
                break

            if start_time and event.timestamp < start_time:
                continue
            if end_time and event.timestamp > end_time:
                continue
            if severity and event.severity != severity:
                continue
            if category and event.category != category:
                continue

            results.append(event)

        return results

    def get_alerts(
        self,
        unacknowledged_only: bool = False,
        limit: int = 100
    ) -> list[Alert]:
        """Get alerts."""
        alerts = self._alerts

        if unacknowledged_only:
            alerts = [a for a in alerts if not a.acknowledged]

        return alerts[-limit:]

    async def _event_processor(self) -> None:
        """Background task to process events."""
        while self._running:
            try:
                event = await asyncio.wait_for(
                    self._event_buffer.get(),
                    timeout=1.0
                )

                # Store event
                self._events.append(event)

                # Apply retention
                if len(self._events) > 100000:
                    self._events = self._events[-50000:]

                # Run correlation
                await self._correlate_event(event)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("event_processing_failed", error=str(e))

    async def _correlate_event(self, event: SecurityEvent) -> None:
        """Correlate an event against rules."""
        for rule in self._rules:
            if rule.matches(event):
                # Add to correlation window
                window_key = rule.id
                self._correlation_windows[window_key].append(event)

                # Clean old events from window
                cutoff = datetime.utcnow() - timedelta(seconds=rule.window_seconds)
                self._correlation_windows[window_key] = [
                    e for e in self._correlation_windows[window_key]
                    if e.timestamp > cutoff
                ]

                # Check if threshold reached
                if len(self._correlation_windows[window_key]) >= rule.threshold:
                    await self._create_alert(rule, self._correlation_windows[window_key])
                    self._correlation_windows[window_key] = []

    async def _create_alert(
        self,
        rule: CorrelationRule,
        events: list[SecurityEvent]
    ) -> None:
        """Create and dispatch an alert."""
        alert = Alert(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            title=f"[{rule.severity.value.upper()}] {rule.name}",
            description=rule.description,
            event_ids=[e.id for e in events],
            event_count=len(events)
        )

        self._alerts.append(alert)
        logger.warning(
            "alert_created",
            alert_id=str(alert.id),
            rule=rule.name,
            event_count=len(events)
        )

        # Dispatch to callbacks
        for callback in self._alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert)
                else:
                    callback(alert)
            except Exception as e:
                logger.error("alert_callback_failed", error=str(e))

    def _load_default_rules(self) -> None:
        """Load default correlation rules."""
        default_rules = [
            CorrelationRule(
                id="brute_force_login",
                name="Brute Force Login Attempt",
                description="Multiple failed login attempts detected",
                severity=EventSeverity.WARNING,
                conditions=[
                    {"field": "action", "operator": "equals", "value": "login"},
                    {"field": "outcome", "operator": "equals", "value": "failure"}
                ],
                window_seconds=300,
                threshold=5
            ),
            CorrelationRule(
                id="privilege_escalation",
                name="Privilege Escalation Attempt",
                description="Potential privilege escalation detected",
                severity=EventSeverity.CRITICAL,
                conditions=[
                    {"field": "category", "operator": "equals", "value": "authorization"},
                    {"field": "message", "operator": "contains", "value": "privilege"}
                ],
                window_seconds=60,
                threshold=1
            ),
            CorrelationRule(
                id="suspicious_network",
                name="Suspicious Network Activity",
                description="High volume of network connections from single source",
                severity=EventSeverity.WARNING,
                conditions=[
                    {"field": "category", "operator": "equals", "value": "network"}
                ],
                window_seconds=60,
                threshold=100
            ),
            CorrelationRule(
                id="malware_detected",
                name="Malware Detection",
                description="Malware or suspicious file detected",
                severity=EventSeverity.CRITICAL,
                conditions=[
                    {"field": "category", "operator": "equals", "value": "malware"}
                ],
                window_seconds=1,
                threshold=1
            ),
        ]

        for rule in default_rules:
            self.add_rule(rule)
