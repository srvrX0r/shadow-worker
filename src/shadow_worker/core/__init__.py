"""Core engine and configuration for Shadow Worker."""

from shadow_worker.core.engine import ShadowEngine
from shadow_worker.core.config import ShadowConfig
from shadow_worker.core.scanner import Scanner
from shadow_worker.core.plugin import Plugin, PluginManager

__all__ = ["ShadowEngine", "ShadowConfig", "Scanner", "Plugin", "PluginManager"]
