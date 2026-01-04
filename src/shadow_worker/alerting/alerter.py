"""
Alerter - Multi-channel security alert dispatcher.

Routes security findings and alerts to configured notification channels.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import structlog

from shadow_worker.core.config import AlertingConfig
from shadow_worker.core.scanner import Finding, Severity

logger = structlog.get_logger()


@dataclass
class Alert:
    """Security alert for dispatch."""

    id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Content
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM

    # Source
    source: str = ""  # scanner, siem, detection
    finding: Finding | None = None

    # Context
    target: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    # Status
    dispatched: bool = False
    dispatch_channels: list[str] = field(default_factory=list)
    acknowledged: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "timestamp": self.timestamp.isoformat(),
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "source": self.source,
            "target": self.target,
            "remediation": self.remediation,
            "dispatched": self.dispatched,
            "acknowledged": self.acknowledged,
        }


class AlertAggregator:
    """
    Aggregates similar alerts within a time window.

    Prevents alert fatigue by grouping related alerts.
    """

    def __init__(self, window_seconds: int = 60, threshold: int = 5):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self._buckets: dict[str, list[Alert]] = defaultdict(list)
        self._last_cleanup = datetime.utcnow()

    def add(self, alert: Alert) -> Alert | None:
        """
        Add an alert for aggregation.

        Returns:
            Alert if it should be dispatched, None if aggregated
        """
        self._cleanup_old_buckets()

        # Create aggregation key based on alert properties
        key = self._get_aggregation_key(alert)
        self._buckets[key].append(alert)

        bucket = self._buckets[key]

        # Dispatch on first alert or when threshold exceeded
        if len(bucket) == 1:
            return alert
        elif len(bucket) == self.threshold:
            # Create aggregated alert
            return self._create_aggregated_alert(bucket)

        return None

    def _get_aggregation_key(self, alert: Alert) -> str:
        """Generate aggregation key for an alert."""
        return f"{alert.source}:{alert.severity.value}:{alert.target}:{alert.title[:50]}"

    def _create_aggregated_alert(self, alerts: list[Alert]) -> Alert:
        """Create an aggregated alert from multiple alerts."""
        first = alerts[0]
        return Alert(
            title=f"[{len(alerts)}x] {first.title}",
            description=f"Aggregated alert: {len(alerts)} similar events\n\n{first.description}",
            severity=first.severity,
            source=first.source,
            target=first.target,
            remediation=first.remediation,
        )

    def _cleanup_old_buckets(self) -> None:
        """Remove old alert buckets."""
        now = datetime.utcnow()
        if (now - self._last_cleanup).total_seconds() < self.window_seconds:
            return

        cutoff = now - timedelta(seconds=self.window_seconds)
        keys_to_remove = []

        for key, alerts in self._buckets.items():
            self._buckets[key] = [a for a in alerts if a.timestamp > cutoff]
            if not self._buckets[key]:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self._buckets[key]

        self._last_cleanup = now


class Alerter:
    """
    Multi-channel alert dispatcher.

    Features:
    - Multiple notification channels (Slack, Discord, Email, Webhooks)
    - Alert aggregation to prevent fatigue
    - Rate limiting per channel
    - Severity-based routing
    """

    def __init__(self, config: AlertingConfig):
        self.config = config
        self._channels: dict[str, Any] = {}
        self._aggregator = AlertAggregator(
            window_seconds=config.aggregate_window_seconds,
            threshold=5
        )
        self._alert_count = 0
        self._hour_start = datetime.utcnow()

        self._setup_channels()

    def _setup_channels(self) -> None:
        """Initialize notification channels."""
        from shadow_worker.alerting.channels import (
            SlackChannel,
            DiscordChannel,
            EmailChannel,
            WebhookChannel,
        )

        if self.config.slack_webhook:
            self._channels["slack"] = SlackChannel(self.config.slack_webhook)

        if self.config.discord_webhook:
            self._channels["discord"] = DiscordChannel(self.config.discord_webhook)

        if self.config.email_smtp_host and self.config.email_to:
            self._channels["email"] = EmailChannel(
                smtp_host=self.config.email_smtp_host,
                smtp_port=self.config.email_smtp_port,
                from_addr=self.config.email_from or "security@shadow-worker.local",
                to_addrs=self.config.email_to,
            )

        if self.config.pagerduty_key:
            self._channels["pagerduty"] = WebhookChannel(
                url="https://events.pagerduty.com/v2/enqueue",
                headers={"Content-Type": "application/json"},
                transform=self._transform_pagerduty,
            )

        logger.info("alerter_initialized", channels=list(self._channels.keys()))

    async def send_alert(self, alert_or_finding: Alert | Finding) -> bool:
        """
        Send an alert to all configured channels.

        Args:
            alert_or_finding: Alert or Finding to dispatch

        Returns:
            True if dispatched successfully
        """
        if not self.config.enabled:
            return False

        # Convert Finding to Alert if needed
        if isinstance(alert_or_finding, Finding):
            alert = self._finding_to_alert(alert_or_finding)
        else:
            alert = alert_or_finding

        # Check severity threshold
        if not self._should_alert(alert):
            return False

        # Check rate limit
        if not self._check_rate_limit():
            logger.warning("alert_rate_limited")
            return False

        # Aggregate similar alerts
        aggregated = self._aggregator.add(alert)
        if aggregated is None:
            logger.debug("alert_aggregated", title=alert.title)
            return True

        # Dispatch to all channels
        success = await self._dispatch(aggregated)
        return success

    async def send_finding(self, finding: Finding) -> bool:
        """Send a security finding as an alert."""
        return await self.send_alert(finding)

    async def _dispatch(self, alert: Alert) -> bool:
        """Dispatch alert to all channels."""
        if not self._channels:
            logger.warning("no_alert_channels_configured")
            return False

        tasks = []
        for name, channel in self._channels.items():
            tasks.append(self._send_to_channel(name, channel, alert))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        successes = sum(1 for r in results if r is True)
        failures = sum(1 for r in results if r is False or isinstance(r, Exception))

        if successes > 0:
            alert.dispatched = True
            alert.dispatch_channels = list(self._channels.keys())
            logger.info(
                "alert_dispatched",
                alert_id=str(alert.id),
                title=alert.title,
                channels=successes
            )
            return True

        logger.error("alert_dispatch_failed", alert_id=str(alert.id), failures=failures)
        return False

    async def _send_to_channel(
        self,
        name: str,
        channel: Any,
        alert: Alert
    ) -> bool:
        """Send alert to a single channel."""
        try:
            await channel.send(alert)
            return True
        except Exception as e:
            logger.error("channel_send_failed", channel=name, error=str(e))
            return False

    def _finding_to_alert(self, finding: Finding) -> Alert:
        """Convert a Finding to an Alert."""
        return Alert(
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            source=finding.scanner,
            finding=finding,
            target=finding.target,
            remediation=finding.remediation,
            references=finding.references,
        )

    def _should_alert(self, alert: Alert) -> bool:
        """Check if alert meets severity threshold."""
        severity_order = ["info", "low", "medium", "high", "critical"]
        alert_idx = severity_order.index(alert.severity.value)
        threshold_idx = severity_order.index(self.config.alert_on_severity)
        return alert_idx >= threshold_idx

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits."""
        now = datetime.utcnow()

        # Reset hourly counter
        if (now - self._hour_start).total_seconds() > 3600:
            self._alert_count = 0
            self._hour_start = now

        if self._alert_count >= self.config.max_alerts_per_hour:
            return False

        self._alert_count += 1
        return True

    def _transform_pagerduty(self, alert: Alert) -> dict[str, Any]:
        """Transform alert to PagerDuty format."""
        severity_map = {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info",
            "info": "info",
        }

        return {
            "routing_key": self.config.pagerduty_key,
            "event_action": "trigger",
            "payload": {
                "summary": alert.title,
                "severity": severity_map.get(alert.severity.value, "info"),
                "source": "shadow-worker",
                "custom_details": {
                    "description": alert.description,
                    "target": alert.target,
                    "remediation": alert.remediation,
                },
            },
        }

    def get_stats(self) -> dict[str, Any]:
        """Get alerter statistics."""
        return {
            "enabled": self.config.enabled,
            "channels": list(self._channels.keys()),
            "alerts_this_hour": self._alert_count,
            "max_per_hour": self.config.max_alerts_per_hour,
        }
