"""
Shadow Engine - Main orchestration engine for Shadow Worker.

Coordinates all security operations including scanning, detection,
SIEM operations, and alerting.
"""

from __future__ import annotations

import asyncio
import signal
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator
from uuid import UUID

import structlog

from shadow_worker.core.config import ShadowConfig
from shadow_worker.core.plugin import PluginManager, PluginType
from shadow_worker.core.scanner import Scanner, ScanResult, Finding

logger = structlog.get_logger()


@dataclass
class EngineStats:
    """Runtime statistics for the engine."""

    start_time: datetime = field(default_factory=datetime.utcnow)
    total_scans: int = 0
    total_findings: int = 0
    total_events_processed: int = 0
    total_alerts_sent: int = 0
    critical_findings: int = 0
    high_findings: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        uptime = (datetime.utcnow() - self.start_time).total_seconds()
        return {
            "uptime_seconds": uptime,
            "total_scans": self.total_scans,
            "total_findings": self.total_findings,
            "total_events_processed": self.total_events_processed,
            "total_alerts_sent": self.total_alerts_sent,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "findings_per_hour": (self.total_findings / uptime) * 3600 if uptime > 0 else 0,
        }


class ShadowEngine:
    """
    Main orchestration engine for Shadow Worker.

    Provides unified interface for:
    - Vulnerability scanning (SAST/DAST)
    - SIEM log aggregation and correlation
    - Threat detection (YARA, Suricata, custom rules)
    - Alerting and reporting
    """

    def __init__(self, config: ShadowConfig | None = None):
        self.config = config or ShadowConfig.load_from_env()
        self.plugin_manager = PluginManager()
        self.scanner = Scanner(self.config)
        self.stats = EngineStats()

        self._running = False
        self._shutdown_event = asyncio.Event()
        self._tasks: list[asyncio.Task] = []

        # Component references (lazy loaded)
        self._siem: Any = None
        self._detector: Any = None
        self._alerter: Any = None

    @asynccontextmanager
    async def run(self) -> AsyncIterator[ShadowEngine]:
        """
        Context manager for running the engine.

        Usage:
            async with engine.run():
                await engine.scan_target("https://myapp.example.com")
        """
        await self.start()
        try:
            yield self
        finally:
            await self.stop()

    async def start(self) -> None:
        """Start the engine and all components."""
        if self._running:
            logger.warning("engine_already_running")
            return

        logger.info("engine_starting", config=self.config.name, env=self.config.environment)

        # Ensure data directories exist
        Path(self.config.data_dir).mkdir(parents=True, exist_ok=True)

        # Initialize plugins
        await self._load_builtin_plugins()
        init_results = await self.plugin_manager.initialize_all()
        logger.info("plugins_initialized", results=init_results)

        # Start SIEM pipeline if enabled
        if self.config.siem.enabled:
            await self._start_siem()

        # Start detection engine if enabled
        if self.config.detection.enabled:
            await self._start_detection()

        # Setup signal handlers
        self._setup_signal_handlers()

        self._running = True
        self.stats.start_time = datetime.utcnow()
        logger.info("engine_started")

    async def stop(self) -> None:
        """Stop the engine and cleanup resources."""
        if not self._running:
            return

        logger.info("engine_stopping")
        self._running = False
        self._shutdown_event.set()

        # Cancel background tasks
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Cleanup plugins
        await self.plugin_manager.cleanup_all()

        # Stop components
        if self._siem:
            await self._siem.stop()
        if self._detector:
            await self._detector.stop()

        logger.info("engine_stopped", stats=self.stats.to_dict())

    async def scan(
        self,
        target: str,
        scan_type: str = "full",
        options: dict[str, Any] | None = None
    ) -> ScanResult:
        """
        Execute a security scan.

        Args:
            target: Target to scan (URL, IP, path, etc.)
            scan_type: Type of scan (sast, dast, full, quick)
            options: Additional scan options

        Returns:
            ScanResult containing findings
        """
        if not self._running:
            raise RuntimeError("Engine not running. Use 'async with engine.run():'")

        result = await self.scanner.scan(target, scan_type, options)

        # Update stats
        self.stats.total_scans += 1
        self.stats.total_findings += result.total_findings
        self.stats.critical_findings += result.critical_count
        self.stats.high_findings += result.high_count

        # Trigger alerts for high-severity findings
        if self.config.alerting.enabled:
            await self._process_findings_for_alerts(result.findings)

        return result

    async def scan_repository(
        self,
        repo_path: str,
        branch: str = "main",
        scan_type: str = "sast"
    ) -> ScanResult:
        """
        Scan a local or remote repository.

        Args:
            repo_path: Path to repository or git URL
            branch: Branch to scan
            scan_type: Type of scan

        Returns:
            ScanResult with findings
        """
        # Clone if remote
        if repo_path.startswith(("git@", "https://")) and repo_path.endswith(".git"):
            local_path = await self._clone_repository(repo_path, branch)
        else:
            local_path = repo_path

        return await self.scan(local_path, scan_type)

    async def continuous_monitor(
        self,
        targets: list[str],
        interval_seconds: int = 3600,
        scan_type: str = "quick"
    ) -> AsyncIterator[ScanResult]:
        """
        Continuously monitor targets at regular intervals.

        Args:
            targets: List of targets to monitor
            interval_seconds: Seconds between scan cycles
            scan_type: Type of scan to perform

        Yields:
            ScanResult for each completed scan
        """
        while self._running:
            for target in targets:
                if not self._running:
                    break

                try:
                    result = await self.scan(target, scan_type)
                    yield result
                except Exception as e:
                    logger.error("continuous_scan_failed", target=target, error=str(e))

            # Wait for next cycle
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=interval_seconds
                )
                break  # Shutdown requested
            except asyncio.TimeoutError:
                pass  # Continue to next cycle

    async def ingest_logs(
        self,
        logs: list[dict[str, Any]],
        source: str = "unknown"
    ) -> int:
        """
        Ingest logs into the SIEM pipeline.

        Args:
            logs: List of log entries
            source: Source identifier

        Returns:
            Number of logs processed
        """
        if not self._siem:
            logger.warning("siem_not_enabled")
            return 0

        count = await self._siem.ingest(logs, source)
        self.stats.total_events_processed += count
        return count

    async def detect_threats(
        self,
        data: bytes | str,
        filename: str = "",
        scan_memory: bool = False
    ) -> list[dict[str, Any]]:
        """
        Run threat detection on data.

        Args:
            data: Data to analyze
            filename: Optional filename for context
            scan_memory: Whether to scan process memory

        Returns:
            List of threat detections
        """
        if not self._detector:
            logger.warning("detection_not_enabled")
            return []

        return await self._detector.detect(data, filename, scan_memory)

    def get_stats(self) -> dict[str, Any]:
        """Get current engine statistics."""
        return self.stats.to_dict()

    def get_health(self) -> dict[str, Any]:
        """Get engine health status."""
        return {
            "status": "healthy" if self._running else "stopped",
            "uptime_seconds": (datetime.utcnow() - self.stats.start_time).total_seconds(),
            "plugins_loaded": len(self.plugin_manager.list_plugins()),
            "siem_enabled": self.config.siem.enabled and self._siem is not None,
            "detection_enabled": self.config.detection.enabled and self._detector is not None,
            "alerting_enabled": self.config.alerting.enabled,
        }

    async def _load_builtin_plugins(self) -> None:
        """Load built-in plugins."""
        from shadow_worker.plugins import get_builtin_plugins

        for plugin_cls in get_builtin_plugins():
            try:
                plugin = plugin_cls(self.config.model_dump())
                self.plugin_manager.register(plugin)
            except Exception as e:
                logger.error("plugin_load_failed", plugin=plugin_cls.__name__, error=str(e))

    async def _start_siem(self) -> None:
        """Start SIEM pipeline."""
        from shadow_worker.siem.pipeline import SIEMPipeline

        self._siem = SIEMPipeline(self.config.siem)
        await self._siem.start()
        logger.info("siem_started")

    async def _start_detection(self) -> None:
        """Start threat detection engine."""
        from shadow_worker.detection.detector import ThreatDetector

        self._detector = ThreatDetector(self.config.detection)
        await self._detector.start()
        logger.info("detection_started")

    async def _clone_repository(self, repo_url: str, branch: str) -> str:
        """Clone a remote repository."""
        import tempfile
        import subprocess

        temp_dir = tempfile.mkdtemp(prefix="shadow_scan_")
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", "--branch", branch, repo_url, temp_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.wait()

        if proc.returncode != 0:
            raise RuntimeError(f"Failed to clone repository: {repo_url}")

        return temp_dir

    async def _process_findings_for_alerts(self, findings: list[Finding]) -> None:
        """Process findings and send alerts as needed."""
        from shadow_worker.alerting.alerter import Alerter

        if not self._alerter:
            self._alerter = Alerter(self.config.alerting)

        severity_threshold = self.config.alerting.alert_on_severity

        for finding in findings:
            if self._should_alert(finding, severity_threshold):
                await self._alerter.send_alert(finding)
                self.stats.total_alerts_sent += 1

    def _should_alert(self, finding: Finding, threshold: str) -> bool:
        """Determine if a finding should trigger an alert."""
        severity_order = ["info", "low", "medium", "high", "critical"]
        finding_idx = severity_order.index(finding.severity.value)
        threshold_idx = severity_order.index(threshold)
        return finding_idx >= threshold_idx

    def _setup_signal_handlers(self) -> None:
        """Install graceful-shutdown handlers when the running loop allows it.

        ``add_signal_handler`` is main-thread and Unix-only. A scanner embedded
        in a worker thread, or running under a platform without the API, must
        still start.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.debug("signal_handler_skipped", reason="no_running_loop")
            return

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self._handle_shutdown()))
            except (NotImplementedError, RuntimeError) as exc:
                logger.debug("signal_handler_skipped", signal=getattr(sig, "name", str(sig)), error=str(exc))

    async def _handle_shutdown(self) -> None:
        """Handle shutdown signal."""
        logger.info("shutdown_signal_received")
        await self.stop()
