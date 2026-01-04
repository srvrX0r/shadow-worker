"""Alerting module - Multi-channel alert dispatching."""

from shadow_worker.alerting.alerter import Alerter
from shadow_worker.alerting.channels import (
    AlertChannel,
    SlackChannel,
    DiscordChannel,
    EmailChannel,
    WebhookChannel,
)

__all__ = [
    "Alerter",
    "AlertChannel",
    "SlackChannel",
    "DiscordChannel",
    "EmailChannel",
    "WebhookChannel",
]
