"""Alert rendering must not treat findings as HTML."""

import html
from datetime import datetime, timezone
from types import SimpleNamespace

from shadow_worker.alerting.channels import EmailChannel
from shadow_worker.core.scanner import Severity


def test_email_html_escapes_finding_text():
    channel = EmailChannel(
        smtp_host="localhost",
        smtp_port=25,
        from_addr="alerts@example.com",
        to_addrs=["oncall@example.com"],
    )
    alert = SimpleNamespace(
        title="<script>alert(1)</script>",
        description='<img src=x onerror="alert(1)">',
        remediation="<b>patch</b>",
        target="https://app.example.com/?q=<x>",
        severity=Severity.HIGH,
        timestamp=datetime(2026, 10, 16, tzinfo=timezone.utc),
    )

    _text, html_body = channel._render_email(alert)

    assert "<script>" not in html_body
    assert "<img" not in html_body
    assert "<b>" not in html_body
    assert html.escape(alert.title) in html_body
    assert html.escape(alert.description) in html_body
    assert html.escape(alert.remediation) in html_body
    assert html.escape(alert.target) in html_body
