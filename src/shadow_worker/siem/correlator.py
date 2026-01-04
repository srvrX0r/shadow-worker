"""
Event Correlator - Advanced event correlation and pattern detection.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable
from uuid import UUID

import structlog

from shadow_worker.siem.pipeline import SecurityEvent, EventSeverity, Alert

logger = structlog.get_logger()


@dataclass
class PatternMatch:
    """A matched pattern in event stream."""

    pattern_id: str
    events: list[SecurityEvent]
    score: float
    timestamp: datetime = field(default_factory=datetime.utcnow)


class EventCorrelator:
    """
    Advanced event correlation engine.

    Supports:
    - Temporal correlation (events within time windows)
    - Behavioral patterns (sequences of events)
    - Statistical anomaly detection
    - Custom correlation functions
    """

    def __init__(self):
        self._patterns: dict[str, dict[str, Any]] = {}
        self._state: dict[str, Any] = {}
        self._baselines: dict[str, list[float]] = defaultdict(list)

    def register_pattern(
        self,
        pattern_id: str,
        name: str,
        sequence: list[dict[str, Any]],
        window_seconds: int = 300,
        severity: EventSeverity = EventSeverity.WARNING,
        description: str = ""
    ) -> None:
        """
        Register a behavioral pattern to detect.

        Args:
            pattern_id: Unique pattern identifier
            name: Human-readable name
            sequence: Ordered list of event conditions
            window_seconds: Time window for pattern matching
            severity: Alert severity when pattern is matched
            description: Pattern description
        """
        self._patterns[pattern_id] = {
            "id": pattern_id,
            "name": name,
            "sequence": sequence,
            "window_seconds": window_seconds,
            "severity": severity,
            "description": description,
        }
        self._state[pattern_id] = {
            "current_step": 0,
            "matched_events": [],
            "first_match_time": None,
        }
        logger.info("pattern_registered", pattern_id=pattern_id, name=name)

    def process_event(self, event: SecurityEvent) -> list[PatternMatch]:
        """
        Process an event and check for pattern matches.

        Returns list of matched patterns.
        """
        matches = []

        for pattern_id, pattern in self._patterns.items():
            state = self._state[pattern_id]
            sequence = pattern["sequence"]

            # Check if pattern window has expired
            if state["first_match_time"]:
                elapsed = (datetime.utcnow() - state["first_match_time"]).total_seconds()
                if elapsed > pattern["window_seconds"]:
                    self._reset_pattern_state(pattern_id)

            # Check if event matches current step
            current_step = state["current_step"]
            if current_step < len(sequence):
                step_conditions = sequence[current_step]

                if self._event_matches_conditions(event, step_conditions):
                    state["matched_events"].append(event)

                    if state["first_match_time"] is None:
                        state["first_match_time"] = datetime.utcnow()

                    state["current_step"] += 1

                    # Check if pattern is complete
                    if state["current_step"] >= len(sequence):
                        match = PatternMatch(
                            pattern_id=pattern_id,
                            events=state["matched_events"].copy(),
                            score=1.0
                        )
                        matches.append(match)
                        logger.warning(
                            "pattern_matched",
                            pattern_id=pattern_id,
                            name=pattern["name"],
                            event_count=len(match.events)
                        )
                        self._reset_pattern_state(pattern_id)

        return matches

    def detect_anomaly(
        self,
        metric_name: str,
        value: float,
        window_size: int = 100,
        std_threshold: float = 3.0
    ) -> bool:
        """
        Detect statistical anomaly using z-score.

        Args:
            metric_name: Name of the metric
            value: Current value
            window_size: Number of samples for baseline
            std_threshold: Number of standard deviations for anomaly

        Returns:
            True if anomaly detected
        """
        baseline = self._baselines[metric_name]
        baseline.append(value)

        # Keep only recent values
        if len(baseline) > window_size:
            baseline.pop(0)

        # Need minimum samples
        if len(baseline) < 10:
            return False

        # Calculate z-score
        import statistics
        mean = statistics.mean(baseline)
        std = statistics.stdev(baseline)

        if std == 0:
            return False

        z_score = abs(value - mean) / std

        if z_score > std_threshold:
            logger.warning(
                "anomaly_detected",
                metric=metric_name,
                value=value,
                mean=mean,
                std=std,
                z_score=z_score
            )
            return True

        return False

    def correlate_by_field(
        self,
        events: list[SecurityEvent],
        field: str,
        window_seconds: int = 300
    ) -> dict[str, list[SecurityEvent]]:
        """
        Group events by a common field within a time window.

        Useful for correlating events from same source, user, etc.
        """
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)

        groups: dict[str, list[SecurityEvent]] = defaultdict(list)

        for event in events:
            if event.timestamp < cutoff:
                continue

            value = getattr(event, field, None) or event.fields.get(field)
            if value:
                groups[str(value)].append(event)

        return dict(groups)

    def _event_matches_conditions(
        self,
        event: SecurityEvent,
        conditions: dict[str, Any]
    ) -> bool:
        """Check if event matches all conditions."""
        for field_name, expected in conditions.items():
            actual = getattr(event, field_name, None) or event.fields.get(field_name)

            if isinstance(expected, dict):
                operator = expected.get("op", "eq")
                value = expected.get("value")

                if operator == "eq" and actual != value:
                    return False
                elif operator == "ne" and actual == value:
                    return False
                elif operator == "contains" and value not in str(actual):
                    return False
                elif operator == "regex" and not re.match(value, str(actual)):
                    return False
                elif operator == "in" and actual not in value:
                    return False
                elif operator == "gt" and not (actual and actual > value):
                    return False
                elif operator == "lt" and not (actual and actual < value):
                    return False
            else:
                if actual != expected:
                    return False

        return True

    def _reset_pattern_state(self, pattern_id: str) -> None:
        """Reset pattern matching state."""
        self._state[pattern_id] = {
            "current_step": 0,
            "matched_events": [],
            "first_match_time": None,
        }


# Pre-defined attack patterns
ATTACK_PATTERNS = [
    {
        "id": "sql_injection_attempt",
        "name": "SQL Injection Attempt",
        "sequence": [
            {"message": {"op": "regex", "value": r"(?i)(union|select|insert|update|delete|drop).*"}},
        ],
        "window_seconds": 60,
        "severity": EventSeverity.WARNING,
    },
    {
        "id": "credential_stuffing",
        "name": "Credential Stuffing Attack",
        "sequence": [
            {"action": "login", "outcome": "failure"},
            {"action": "login", "outcome": "failure"},
            {"action": "login", "outcome": "failure"},
            {"action": "login", "outcome": "failure"},
            {"action": "login", "outcome": "failure"},
        ],
        "window_seconds": 300,
        "severity": EventSeverity.WARNING,
    },
    {
        "id": "lateral_movement",
        "name": "Lateral Movement Detected",
        "sequence": [
            {"action": "login", "outcome": "success"},
            {"category": "network", "action": {"op": "in", "value": ["connect", "ssh", "rdp"]}},
            {"action": "login", "outcome": "success"},
        ],
        "window_seconds": 3600,
        "severity": EventSeverity.CRITICAL,
    },
    {
        "id": "data_exfiltration",
        "name": "Potential Data Exfiltration",
        "sequence": [
            {"category": "file_system", "action": "read"},
            {"category": "network", "action": "upload"},
        ],
        "window_seconds": 600,
        "severity": EventSeverity.CRITICAL,
    },
]
