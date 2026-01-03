"""
Plugin architecture for Shadow Worker.

Enables extensible scanning, detection, and integration capabilities.
"""

from __future__ import annotations

import importlib
import inspect
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, TypeVar

import structlog

logger = structlog.get_logger()

T = TypeVar("T", bound="Plugin")


class PluginType(str, Enum):
    """Types of plugins available."""

    SCANNER = "scanner"          # Vulnerability scanners
    DETECTOR = "detector"        # Threat detection
    COLLECTOR = "collector"      # Log/data collection
    ANALYZER = "analyzer"        # Analysis engines
    REPORTER = "reporter"        # Report generation
    ALERTER = "alerter"          # Alert dispatching
    INTEGRATION = "integration"  # External tool integration


class PluginPriority(int, Enum):
    """Plugin execution priority."""

    CRITICAL = 0
    HIGH = 25
    NORMAL = 50
    LOW = 75
    BACKGROUND = 100


@dataclass
class PluginMetadata:
    """Metadata about a plugin."""

    name: str
    version: str
    description: str
    plugin_type: PluginType
    priority: PluginPriority = PluginPriority.NORMAL
    author: str = ""
    dependencies: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    enabled_by_default: bool = True


@dataclass
class PluginResult:
    """Result from plugin execution."""

    plugin_name: str
    success: bool
    data: Any = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    execution_time_ms: float = 0.0

    def merge(self, other: PluginResult) -> PluginResult:
        """Merge another result into this one."""
        return PluginResult(
            plugin_name=f"{self.plugin_name}+{other.plugin_name}",
            success=self.success and other.success,
            data={"left": self.data, "right": other.data},
            errors=self.errors + other.errors,
            warnings=self.warnings + other.warnings,
            execution_time_ms=self.execution_time_ms + other.execution_time_ms,
        )


class Plugin(ABC):
    """Base class for all Shadow Worker plugins."""

    metadata: PluginMetadata

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self._initialized = False

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the plugin. Called once before first use."""
        pass

    @abstractmethod
    async def execute(self, context: dict[str, Any]) -> PluginResult:
        """Execute the plugin's main functionality."""
        pass

    async def cleanup(self) -> None:
        """Cleanup resources. Called when plugin is unloaded."""
        pass

    def validate_config(self) -> list[str]:
        """Validate plugin configuration. Returns list of errors."""
        return []

    async def health_check(self) -> bool:
        """Check if the plugin is healthy and ready."""
        return True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.metadata.name} v{self.metadata.version}>"


class ScannerPlugin(Plugin):
    """Base class for vulnerability scanner plugins."""

    @abstractmethod
    async def scan(self, target: str, options: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Scan a target for vulnerabilities.

        Args:
            target: The target to scan (URL, IP, path, etc.)
            options: Scanner-specific options

        Returns:
            List of vulnerability findings
        """
        pass

    async def execute(self, context: dict[str, Any]) -> PluginResult:
        """Execute scanning."""
        import time
        start = time.time()

        target = context.get("target", "")
        options = context.get("options", {})

        try:
            findings = await self.scan(target, options)
            return PluginResult(
                plugin_name=self.metadata.name,
                success=True,
                data={"findings": findings, "target": target},
                execution_time_ms=(time.time() - start) * 1000,
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.metadata.name,
                success=False,
                errors=[str(e)],
                execution_time_ms=(time.time() - start) * 1000,
            )


class DetectorPlugin(Plugin):
    """Base class for threat detection plugins."""

    @abstractmethod
    async def detect(self, data: bytes | str, metadata: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Detect threats in data.

        Args:
            data: The data to analyze
            metadata: Context about the data (source, type, etc.)

        Returns:
            List of threat detections
        """
        pass

    async def execute(self, context: dict[str, Any]) -> PluginResult:
        """Execute detection."""
        import time
        start = time.time()

        data = context.get("data", b"")
        metadata = context.get("metadata", {})

        try:
            detections = await self.detect(data, metadata)
            return PluginResult(
                plugin_name=self.metadata.name,
                success=True,
                data={"detections": detections},
                execution_time_ms=(time.time() - start) * 1000,
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.metadata.name,
                success=False,
                errors=[str(e)],
                execution_time_ms=(time.time() - start) * 1000,
            )


class CollectorPlugin(Plugin):
    """Base class for log/data collector plugins."""

    @abstractmethod
    async def collect(self) -> list[dict[str, Any]]:
        """
        Collect logs or data.

        Returns:
            List of collected events/logs
        """
        pass

    async def execute(self, context: dict[str, Any]) -> PluginResult:
        """Execute collection."""
        import time
        start = time.time()

        try:
            events = await self.collect()
            return PluginResult(
                plugin_name=self.metadata.name,
                success=True,
                data={"events": events, "count": len(events)},
                execution_time_ms=(time.time() - start) * 1000,
            )
        except Exception as e:
            return PluginResult(
                plugin_name=self.metadata.name,
                success=False,
                errors=[str(e)],
                execution_time_ms=(time.time() - start) * 1000,
            )


class PluginManager:
    """Manages plugin discovery, loading, and execution."""

    def __init__(self):
        self._plugins: dict[str, Plugin] = {}
        self._hooks: dict[str, list[Callable]] = {}
        self._plugin_dirs: list[Path] = []

    def register(self, plugin: Plugin) -> None:
        """Register a plugin instance."""
        name = plugin.metadata.name
        if name in self._plugins:
            logger.warning("plugin_already_registered", name=name)
            return

        self._plugins[name] = plugin
        logger.info("plugin_registered", name=name, type=plugin.metadata.plugin_type.value)

    def unregister(self, name: str) -> None:
        """Unregister a plugin by name."""
        if name in self._plugins:
            del self._plugins[name]
            logger.info("plugin_unregistered", name=name)

    def get(self, name: str) -> Plugin | None:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def get_by_type(self, plugin_type: PluginType) -> list[Plugin]:
        """Get all plugins of a specific type."""
        return [
            p for p in self._plugins.values()
            if p.metadata.plugin_type == plugin_type
        ]

    def list_plugins(self) -> list[PluginMetadata]:
        """List all registered plugin metadata."""
        return [p.metadata for p in self._plugins.values()]

    async def initialize_all(self) -> dict[str, bool]:
        """Initialize all plugins. Returns success status per plugin."""
        results = {}

        # Sort by priority
        plugins = sorted(
            self._plugins.values(),
            key=lambda p: p.metadata.priority.value
        )

        for plugin in plugins:
            try:
                errors = plugin.validate_config()
                if errors:
                    logger.error("plugin_config_invalid", name=plugin.metadata.name, errors=errors)
                    results[plugin.metadata.name] = False
                    continue

                await plugin.initialize()
                plugin._initialized = True
                results[plugin.metadata.name] = True
                logger.info("plugin_initialized", name=plugin.metadata.name)
            except Exception as e:
                logger.error("plugin_init_failed", name=plugin.metadata.name, error=str(e))
                results[plugin.metadata.name] = False

        return results

    async def cleanup_all(self) -> None:
        """Cleanup all plugins."""
        for plugin in self._plugins.values():
            try:
                await plugin.cleanup()
            except Exception as e:
                logger.error("plugin_cleanup_failed", name=plugin.metadata.name, error=str(e))

    async def execute_plugins(
        self,
        plugin_type: PluginType,
        context: dict[str, Any],
        parallel: bool = True
    ) -> list[PluginResult]:
        """Execute all plugins of a type."""
        import asyncio

        plugins = self.get_by_type(plugin_type)
        plugins = [p for p in plugins if p._initialized]

        if not plugins:
            return []

        if parallel:
            results = await asyncio.gather(
                *[p.execute(context) for p in plugins],
                return_exceptions=True
            )
            return [
                r if isinstance(r, PluginResult) else PluginResult(
                    plugin_name="unknown",
                    success=False,
                    errors=[str(r)]
                )
                for r in results
            ]
        else:
            results = []
            for plugin in plugins:
                try:
                    result = await plugin.execute(context)
                    results.append(result)
                except Exception as e:
                    results.append(PluginResult(
                        plugin_name=plugin.metadata.name,
                        success=False,
                        errors=[str(e)]
                    ))
            return results

    def add_plugin_directory(self, path: Path) -> None:
        """Add a directory to search for plugins."""
        if path.is_dir():
            self._plugin_dirs.append(path)

    def discover_plugins(self) -> list[type[Plugin]]:
        """Discover plugins from registered directories."""
        discovered = []

        for plugin_dir in self._plugin_dirs:
            for py_file in plugin_dir.glob("*.py"):
                if py_file.name.startswith("_"):
                    continue

                try:
                    spec = importlib.util.spec_from_file_location(
                        py_file.stem, py_file
                    )
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)

                        for name, obj in inspect.getmembers(module):
                            if (
                                inspect.isclass(obj)
                                and issubclass(obj, Plugin)
                                and obj is not Plugin
                                and hasattr(obj, "metadata")
                            ):
                                discovered.append(obj)
                except Exception as e:
                    logger.error("plugin_discovery_failed", file=str(py_file), error=str(e))

        return discovered

    def register_hook(self, event: str, callback: Callable) -> None:
        """Register a hook for an event."""
        if event not in self._hooks:
            self._hooks[event] = []
        self._hooks[event].append(callback)

    async def trigger_hook(self, event: str, data: Any = None) -> list[Any]:
        """Trigger all hooks for an event."""
        import asyncio

        if event not in self._hooks:
            return []

        results = []
        for callback in self._hooks[event]:
            try:
                if asyncio.iscoroutinefunction(callback):
                    result = await callback(data)
                else:
                    result = callback(data)
                results.append(result)
            except Exception as e:
                logger.error("hook_failed", event=event, error=str(e))

        return results
