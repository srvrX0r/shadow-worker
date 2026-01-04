"""
Event Storage - Persistent storage for security events.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, AsyncIterator
from uuid import UUID

import aiosqlite
import structlog

from shadow_worker.siem.pipeline import SecurityEvent, EventSeverity, EventCategory, Alert

logger = structlog.get_logger()


class EventStorage:
    """
    Persistent storage for security events and alerts.

    Supports SQLite for local deployments and can be extended
    for Elasticsearch/PostgreSQL for production.
    """

    def __init__(self, db_path: str = "./data/siem.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Initialize database schema."""
        self._connection = await aiosqlite.connect(str(self.db_path))

        await self._connection.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                category TEXT,
                severity TEXT,
                event_type TEXT,
                source TEXT,
                source_ip TEXT,
                source_user TEXT,
                dest_ip TEXT,
                dest_port INTEGER,
                message TEXT,
                action TEXT,
                outcome TEXT,
                raw_log TEXT,
                fields TEXT,
                correlation_id TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
            CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
            CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
            CREATE INDEX IF NOT EXISTS idx_events_correlation ON events(correlation_id);

            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                rule_id TEXT,
                rule_name TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                event_ids TEXT,
                event_count INTEGER,
                acknowledged INTEGER DEFAULT 0,
                resolved INTEGER DEFAULT 0,
                assignee TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);
        """)

        await self._connection.commit()
        logger.info("event_storage_initialized", db_path=str(self.db_path))

    async def close(self) -> None:
        """Close database connection."""
        if self._connection:
            await self._connection.close()

    async def store_event(self, event: SecurityEvent) -> None:
        """Store a single event."""
        if not self._connection:
            raise RuntimeError("Storage not initialized")

        await self._connection.execute(
            """
            INSERT INTO events (
                id, timestamp, category, severity, event_type, source,
                source_ip, source_user, dest_ip, dest_port, message,
                action, outcome, raw_log, fields, correlation_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(event.id),
                event.timestamp.isoformat(),
                event.category.value,
                event.severity.value,
                event.event_type,
                event.source,
                event.source_ip,
                event.source_user,
                event.dest_ip,
                event.dest_port,
                event.message,
                event.action,
                event.outcome,
                event.raw_log,
                json.dumps(event.fields),
                event.correlation_id,
            )
        )
        await self._connection.commit()

    async def store_events_batch(self, events: list[SecurityEvent]) -> int:
        """Store multiple events in a batch."""
        if not self._connection:
            raise RuntimeError("Storage not initialized")

        await self._connection.executemany(
            """
            INSERT INTO events (
                id, timestamp, category, severity, event_type, source,
                source_ip, source_user, dest_ip, dest_port, message,
                action, outcome, raw_log, fields, correlation_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    str(e.id),
                    e.timestamp.isoformat(),
                    e.category.value,
                    e.severity.value,
                    e.event_type,
                    e.source,
                    e.source_ip,
                    e.source_user,
                    e.dest_ip,
                    e.dest_port,
                    e.message,
                    e.action,
                    e.outcome,
                    e.raw_log,
                    json.dumps(e.fields),
                    e.correlation_id,
                )
                for e in events
            ]
        )
        await self._connection.commit()
        return len(events)

    async def store_alert(self, alert: Alert) -> None:
        """Store an alert."""
        if not self._connection:
            raise RuntimeError("Storage not initialized")

        await self._connection.execute(
            """
            INSERT INTO alerts (
                id, timestamp, rule_id, rule_name, severity, title,
                description, event_ids, event_count, acknowledged, resolved, assignee
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(alert.id),
                alert.timestamp.isoformat(),
                alert.rule_id,
                alert.rule_name,
                alert.severity.value,
                alert.title,
                alert.description,
                json.dumps([str(eid) for eid in alert.event_ids]),
                alert.event_count,
                1 if alert.acknowledged else 0,
                1 if alert.resolved else 0,
                alert.assignee,
            )
        )
        await self._connection.commit()

    async def query_events(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        severity: EventSeverity | None = None,
        category: EventCategory | None = None,
        source_ip: str | None = None,
        search_text: str | None = None,
        limit: int = 1000,
        offset: int = 0
    ) -> list[SecurityEvent]:
        """Query events with filters."""
        if not self._connection:
            raise RuntimeError("Storage not initialized")

        query = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())

        if severity:
            query += " AND severity = ?"
            params.append(severity.value)

        if category:
            query += " AND category = ?"
            params.append(category.value)

        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)

        if search_text:
            query += " AND (message LIKE ? OR raw_log LIKE ?)"
            params.extend([f"%{search_text}%", f"%{search_text}%"])

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with self._connection.execute(query, params) as cursor:
            rows = await cursor.fetchall()

        events = []
        for row in rows:
            events.append(SecurityEvent(
                id=UUID(row[0]),
                timestamp=datetime.fromisoformat(row[1]),
                category=EventCategory(row[2]) if row[2] else EventCategory.CUSTOM,
                severity=EventSeverity(row[3]) if row[3] else EventSeverity.INFO,
                event_type=row[4] or "",
                source=row[5] or "",
                source_ip=row[6],
                source_user=row[7],
                dest_ip=row[8],
                dest_port=row[9],
                message=row[10] or "",
                action=row[11],
                outcome=row[12],
                raw_log=row[13] or "",
                fields=json.loads(row[14]) if row[14] else {},
                correlation_id=row[15],
            ))

        return events

    async def query_alerts(
        self,
        unacknowledged_only: bool = False,
        severity: EventSeverity | None = None,
        limit: int = 100,
        offset: int = 0
    ) -> list[Alert]:
        """Query alerts with filters."""
        if not self._connection:
            raise RuntimeError("Storage not initialized")

        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []

        if unacknowledged_only:
            query += " AND acknowledged = 0"

        if severity:
            query += " AND severity = ?"
            params.append(severity.value)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with self._connection.execute(query, params) as cursor:
            rows = await cursor.fetchall()

        alerts = []
        for row in rows:
            alerts.append(Alert(
                id=UUID(row[0]),
                timestamp=datetime.fromisoformat(row[1]),
                rule_id=row[2] or "",
                rule_name=row[3] or "",
                severity=EventSeverity(row[4]) if row[4] else EventSeverity.INFO,
                title=row[5] or "",
                description=row[6] or "",
                event_ids=[UUID(eid) for eid in json.loads(row[7])] if row[7] else [],
                event_count=row[8] or 0,
                acknowledged=bool(row[9]),
                resolved=bool(row[10]),
                assignee=row[11],
            ))

        return alerts

    async def acknowledge_alert(self, alert_id: UUID, assignee: str | None = None) -> bool:
        """Acknowledge an alert."""
        if not self._connection:
            raise RuntimeError("Storage not initialized")

        await self._connection.execute(
            "UPDATE alerts SET acknowledged = 1, assignee = ? WHERE id = ?",
            (assignee, str(alert_id))
        )
        await self._connection.commit()
        return True

    async def resolve_alert(self, alert_id: UUID) -> bool:
        """Resolve an alert."""
        if not self._connection:
            raise RuntimeError("Storage not initialized")

        await self._connection.execute(
            "UPDATE alerts SET resolved = 1 WHERE id = ?",
            (str(alert_id),)
        )
        await self._connection.commit()
        return True

    async def get_event_stats(
        self,
        window_hours: int = 24
    ) -> dict[str, Any]:
        """Get event statistics."""
        if not self._connection:
            raise RuntimeError("Storage not initialized")

        cutoff = (datetime.utcnow() - timedelta(hours=window_hours)).isoformat()

        stats: dict[str, Any] = {"window_hours": window_hours}

        # Total count
        async with self._connection.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ?",
            (cutoff,)
        ) as cursor:
            row = await cursor.fetchone()
            stats["total_events"] = row[0] if row else 0

        # By severity
        async with self._connection.execute(
            """
            SELECT severity, COUNT(*) FROM events
            WHERE timestamp >= ?
            GROUP BY severity
            """,
            (cutoff,)
        ) as cursor:
            rows = await cursor.fetchall()
            stats["by_severity"] = {row[0]: row[1] for row in rows}

        # By category
        async with self._connection.execute(
            """
            SELECT category, COUNT(*) FROM events
            WHERE timestamp >= ?
            GROUP BY category
            """,
            (cutoff,)
        ) as cursor:
            rows = await cursor.fetchall()
            stats["by_category"] = {row[0]: row[1] for row in rows}

        # Top source IPs
        async with self._connection.execute(
            """
            SELECT source_ip, COUNT(*) as cnt FROM events
            WHERE timestamp >= ? AND source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY cnt DESC
            LIMIT 10
            """,
            (cutoff,)
        ) as cursor:
            rows = await cursor.fetchall()
            stats["top_source_ips"] = [{"ip": row[0], "count": row[1]} for row in rows]

        return stats

    async def cleanup_old_events(self, retention_days: int = 90) -> int:
        """Delete events older than retention period."""
        if not self._connection:
            raise RuntimeError("Storage not initialized")

        cutoff = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()

        async with self._connection.execute(
            "DELETE FROM events WHERE timestamp < ?",
            (cutoff,)
        ) as cursor:
            deleted = cursor.rowcount

        await self._connection.commit()
        logger.info("old_events_cleaned", deleted=deleted, retention_days=retention_days)
        return deleted
