"""
Alert Channels - Notification delivery implementations.

Supports multiple notification channels for security alerts.
"""

from __future__ import annotations

import html
import smtplib
from abc import ABC, abstractmethod
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Callable

import httpx
import structlog

from shadow_worker.core.scanner import Severity

logger = structlog.get_logger()


class AlertChannel(ABC):
    """Base class for alert channels."""

    @abstractmethod
    async def send(self, alert: Any) -> None:
        """Send an alert through this channel."""
        pass


class SlackChannel(AlertChannel):
    """Slack webhook notification channel."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    async def send(self, alert: Any) -> None:
        """Send alert to Slack."""
        color_map = {
            Severity.CRITICAL: "#dc3545",  # Red
            Severity.HIGH: "#fd7e14",      # Orange
            Severity.MEDIUM: "#ffc107",    # Yellow
            Severity.LOW: "#17a2b8",       # Teal
            Severity.INFO: "#6c757d",      # Gray
        }

        emoji_map = {
            Severity.CRITICAL: ":rotating_light:",
            Severity.HIGH: ":warning:",
            Severity.MEDIUM: ":large_orange_diamond:",
            Severity.LOW: ":information_source:",
            Severity.INFO: ":speech_balloon:",
        }

        payload = {
            "attachments": [
                {
                    "color": color_map.get(alert.severity, "#6c757d"),
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"{emoji_map.get(alert.severity, '')} {alert.title}",
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Severity:*\n{alert.severity.value.upper()}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Target:*\n{alert.target or 'N/A'}"
                                },
                            ]
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*Description:*\n{alert.description[:500]}"
                            }
                        },
                    ]
                }
            ]
        }

        if alert.remediation:
            payload["attachments"][0]["blocks"].append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Remediation:*\n{alert.remediation}"
                }
            })

        async with httpx.AsyncClient() as client:
            response = await client.post(self.webhook_url, json=payload)
            response.raise_for_status()


class DiscordChannel(AlertChannel):
    """Discord webhook notification channel."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    async def send(self, alert: Any) -> None:
        """Send alert to Discord."""
        color_map = {
            Severity.CRITICAL: 0xDC3545,
            Severity.HIGH: 0xFD7E14,
            Severity.MEDIUM: 0xFFC107,
            Severity.LOW: 0x17A2B8,
            Severity.INFO: 0x6C757D,
        }

        payload = {
            "embeds": [
                {
                    "title": f"🔒 {alert.title}",
                    "description": alert.description[:2000],
                    "color": color_map.get(alert.severity, 0x6C757D),
                    "fields": [
                        {
                            "name": "Severity",
                            "value": alert.severity.value.upper(),
                            "inline": True,
                        },
                        {
                            "name": "Target",
                            "value": alert.target or "N/A",
                            "inline": True,
                        },
                        {
                            "name": "Source",
                            "value": alert.source or "Shadow Worker",
                            "inline": True,
                        },
                    ],
                    "footer": {
                        "text": "Shadow Worker Security Alert"
                    },
                    "timestamp": alert.timestamp.isoformat(),
                }
            ]
        }

        if alert.remediation:
            payload["embeds"][0]["fields"].append({
                "name": "Remediation",
                "value": alert.remediation[:1000],
                "inline": False,
            })

        async with httpx.AsyncClient() as client:
            response = await client.post(self.webhook_url, json=payload)
            response.raise_for_status()


class EmailChannel(AlertChannel):
    """Email notification channel."""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        from_addr: str,
        to_addrs: list[str],
        username: str | None = None,
        password: str | None = None,
        use_tls: bool = True,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.username = username
        self.password = password
        self.use_tls = use_tls

    async def send(self, alert: Any) -> None:
        """Send alert via email."""
        import asyncio

        # Run SMTP in thread pool
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._send_sync, alert)

    def _render_email(self, alert: Any) -> tuple[str, str]:
        """Render plain and HTML bodies. HTML is escaped so findings cannot inject markup."""
        raw_severity = str(getattr(alert.severity, "value", alert.severity))
        title = html.escape(str(getattr(alert, "title", "")))
        severity = html.escape(raw_severity.upper())
        target = html.escape(str(getattr(alert, "target", None) or "N/A"))
        description = html.escape(str(getattr(alert, "description", "") or ""))
        remediation_raw = getattr(alert, "remediation", None) or ""
        remediation = html.escape(str(remediation_raw))
        timestamp = html.escape(str(alert.timestamp.isoformat()))

        text_content = (
            "Shadow Worker Security Alert\n"
            "============================\n\n"
            f"Title: {getattr(alert, 'title', '')}\n"
            f"Severity: {raw_severity.upper()}\n"
            f"Target: {getattr(alert, 'target', None) or 'N/A'}\n"
            f"Timestamp: {alert.timestamp.isoformat()}\n\n"
            "Description:\n"
            f"{getattr(alert, 'description', '')}\n\n"
            "Remediation:\n"
            f"{remediation_raw or 'N/A'}\n"
        )
        remediation_block = (
            f'<div class="remediation"><span class="label">Remediation:</span><br>{remediation}</div>'
            if remediation_raw
            else ""
        )
        html_content = f"""<!DOCTYPE html>
<html>
<body>
    <div class="alert {html.escape(raw_severity)}">
        <div class="header">{title}</div>
        <div class="field"><span class="label">Severity:</span> {severity}</div>
        <div class="field"><span class="label">Target:</span> {target}</div>
        <div class="field"><span class="label">Timestamp:</span> {timestamp}</div>
        <div class="field"><span class="label">Description:</span><br>{description}</div>
        {remediation_block}
    </div>
</body>
</html>
"""
        return text_content, html_content

    def _send_sync(self, alert: Any) -> None:
        """Synchronous email send."""
        msg = MIMEMultipart("alternative")
        severity = str(getattr(alert.severity, "value", alert.severity)).upper()
        msg["Subject"] = f"[{severity}] {alert.title}"
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)

        text_content, html_content = self._render_email(alert)
        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30) as server:
            if self.use_tls:
                server.starttls()
            if self.username and self.password:
                server.login(self.username, self.password)
            server.sendmail(self.from_addr, self.to_addrs, msg.as_string())


class WebhookChannel(AlertChannel):
    """Generic webhook notification channel."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        method: str = "POST",
        transform: Callable[[Any], dict] | None = None,
    ):
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}
        self.method = method
        self.transform = transform

    async def send(self, alert: Any) -> None:
        """Send alert to webhook."""
        if self.transform:
            payload = self.transform(alert)
        else:
            payload = alert.to_dict()

        async with httpx.AsyncClient() as client:
            if self.method == "POST":
                response = await client.post(
                    self.url,
                    json=payload,
                    headers=self.headers
                )
            elif self.method == "PUT":
                response = await client.put(
                    self.url,
                    json=payload,
                    headers=self.headers
                )
            else:
                raise ValueError(f"Unsupported method: {self.method}")

            response.raise_for_status()


class ConsoleChannel(AlertChannel):
    """Console output for alerts (development/debugging)."""

    def __init__(self, use_colors: bool = True):
        self.use_colors = use_colors

    async def send(self, alert: Any) -> None:
        """Print alert to console."""
        colors = {
            Severity.CRITICAL: "\033[91m",  # Red
            Severity.HIGH: "\033[93m",      # Yellow
            Severity.MEDIUM: "\033[94m",    # Blue
            Severity.LOW: "\033[96m",       # Cyan
            Severity.INFO: "\033[97m",      # White
        }
        reset = "\033[0m"

        if self.use_colors:
            color = colors.get(alert.severity, "")
            print(f"\n{color}{'='*60}")
            print(f"SECURITY ALERT: {alert.title}")
            print(f"{'='*60}{reset}")
            print(f"Severity: {color}{alert.severity.value.upper()}{reset}")
            print(f"Target: {alert.target or 'N/A'}")
            print(f"Description: {alert.description}")
            if alert.remediation:
                print(f"Remediation: {alert.remediation}")
            print(f"{color}{'='*60}{reset}\n")
        else:
            print(f"\n{'='*60}")
            print(f"SECURITY ALERT: {alert.title}")
            print(f"{'='*60}")
            print(f"Severity: {alert.severity.value.upper()}")
            print(f"Target: {alert.target or 'N/A'}")
            print(f"Description: {alert.description}")
            if alert.remediation:
                print(f"Remediation: {alert.remediation}")
            print(f"{'='*60}\n")
