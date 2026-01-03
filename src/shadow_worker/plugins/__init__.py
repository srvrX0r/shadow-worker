"""Built-in plugins for Shadow Worker."""

from shadow_worker.core.plugin import (
    Plugin,
    PluginType,
    PluginMetadata,
    PluginPriority,
    ScannerPlugin,
    DetectorPlugin,
    CollectorPlugin,
)


def get_builtin_plugins() -> list[type[Plugin]]:
    """Get all built-in plugins."""
    return [
        # Add built-in plugins here as they are developed
    ]


__all__ = [
    "get_builtin_plugins",
    "Plugin",
    "PluginType",
    "PluginMetadata",
    "PluginPriority",
    "ScannerPlugin",
    "DetectorPlugin",
    "CollectorPlugin",
]
