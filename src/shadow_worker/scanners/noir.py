"""
OWASP Noir Integration - API Endpoint Discovery.

Noir is an attack surface detector that identifies API endpoints
from source code for security testing.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class APIEndpoint:
    """Discovered API endpoint."""

    url: str
    method: str
    params: list[dict[str, Any]] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)
    source_file: str = ""
    source_line: int = 0
    framework: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "headers": self.headers,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "framework": self.framework,
            "tags": self.tags,
        }


@dataclass
class NoirResult:
    """Result from Noir scan."""

    endpoints: list[APIEndpoint] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    total_endpoints: int = 0
    scan_duration_seconds: float = 0.0


class NoirScanner:
    """
    OWASP Noir API endpoint discovery scanner.

    Noir identifies API endpoints from source code without running
    the application, making it ideal for attack surface discovery.

    Supported frameworks:
    - Python: Django, Flask, FastAPI, Tornado
    - JavaScript: Express, Koa, Hapi, Fastify
    - Ruby: Rails, Sinatra
    - Go: Gin, Echo, Fiber
    - Java: Spring, JAX-RS
    - PHP: Laravel, Symfony
    - And many more...
    """

    def __init__(self):
        self._noir_available = self._check_noir()

    def _check_noir(self) -> bool:
        """Check if Noir is installed."""
        try:
            result = subprocess.run(
                ["noir", "--version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.warning(
                "noir_not_installed",
                msg="Install OWASP Noir: https://github.com/owasp-noir/noir"
            )
            return False

    async def scan(
        self,
        target_path: str | Path,
        base_url: str = "",
        options: dict[str, Any] | None = None
    ) -> NoirResult:
        """
        Scan source code to discover API endpoints.

        Args:
            target_path: Path to source code
            base_url: Base URL for endpoint construction
            options: Additional Noir options

        Returns:
            NoirResult with discovered endpoints
        """
        import time

        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"Target not found: {target_path}")

        result = NoirResult()
        start_time = time.time()

        if self._noir_available:
            result = await self._run_noir(target, base_url, options or {})
        else:
            # Fallback to basic framework detection
            result = await self._detect_endpoints_fallback(target)

        result.scan_duration_seconds = time.time() - start_time
        logger.info(
            "noir_scan_complete",
            target=str(target),
            endpoints=result.total_endpoints,
            duration=result.scan_duration_seconds
        )

        return result

    async def _run_noir(
        self,
        target: Path,
        base_url: str,
        options: dict[str, Any]
    ) -> NoirResult:
        """Run Noir CLI tool."""
        cmd = ["noir", "-b", str(target), "--format", "json"]

        if base_url:
            cmd.extend(["--url", base_url])

        # Add any custom options
        if options.get("include_techs"):
            cmd.append("--include-techs")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                logger.error("noir_failed", stderr=stderr.decode())
                return NoirResult()

            return self._parse_noir_output(stdout.decode())

        except Exception as e:
            logger.error("noir_execution_failed", error=str(e))
            return NoirResult()

    def _parse_noir_output(self, output: str) -> NoirResult:
        """Parse Noir JSON output."""
        result = NoirResult()

        try:
            data = json.loads(output)

            for endpoint in data.get("endpoints", []):
                result.endpoints.append(APIEndpoint(
                    url=endpoint.get("url", ""),
                    method=endpoint.get("method", "GET"),
                    params=[
                        {"name": p.get("name"), "type": p.get("param_type")}
                        for p in endpoint.get("params", [])
                    ],
                    headers=endpoint.get("headers", []),
                    source_file=endpoint.get("details", {}).get("file", ""),
                    source_line=endpoint.get("details", {}).get("line", 0),
                    framework=endpoint.get("details", {}).get("framework", ""),
                    tags=endpoint.get("tags", []),
                ))

            result.technologies = data.get("technologies", [])
            result.frameworks = data.get("frameworks", [])
            result.total_endpoints = len(result.endpoints)

        except json.JSONDecodeError as e:
            logger.error("noir_parse_failed", error=str(e))

        return result

    async def _detect_endpoints_fallback(self, target: Path) -> NoirResult:
        """Fallback endpoint detection without Noir."""
        import re

        result = NoirResult()
        endpoints = []

        # Framework detection patterns
        patterns = {
            "flask": {
                "files": ["*.py"],
                "route_pattern": r'@(?:app|blueprint)\.route\(["\']([^"\']+)["\'](?:.*methods=\[([^\]]+)\])?',
            },
            "fastapi": {
                "files": ["*.py"],
                "route_pattern": r'@(?:app|router)\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
            },
            "express": {
                "files": ["*.js", "*.ts"],
                "route_pattern": r'(?:app|router)\.(?:get|post|put|delete|patch|all)\(["\']([^"\']+)["\']',
            },
            "django": {
                "files": ["urls.py", "views.py"],
                "route_pattern": r'path\(["\']([^"\']+)["\']',
            },
            "spring": {
                "files": ["*.java"],
                "route_pattern": r'@(?:Get|Post|Put|Delete|Patch|Request)Mapping\(["\']?([^"\'\)]+)',
            },
            "gin": {
                "files": ["*.go"],
                "route_pattern": r'\.(?:GET|POST|PUT|DELETE|PATCH)\(["\']([^"\']+)["\']',
            },
        }

        for framework, config in patterns.items():
            for pattern in config["files"]:
                for filepath in target.rglob(pattern):
                    try:
                        content = filepath.read_text(errors="ignore")

                        for match in re.finditer(config["route_pattern"], content, re.IGNORECASE):
                            url = match.group(1)

                            # Extract method if available
                            method = "GET"
                            if "get" in match.group(0).lower():
                                method = "GET"
                            elif "post" in match.group(0).lower():
                                method = "POST"
                            elif "put" in match.group(0).lower():
                                method = "PUT"
                            elif "delete" in match.group(0).lower():
                                method = "DELETE"
                            elif "patch" in match.group(0).lower():
                                method = "PATCH"

                            # Get line number
                            line_num = content[:match.start()].count("\n") + 1

                            endpoints.append(APIEndpoint(
                                url=url,
                                method=method,
                                source_file=str(filepath.relative_to(target)),
                                source_line=line_num,
                                framework=framework,
                            ))

                            if framework not in result.frameworks:
                                result.frameworks.append(framework)

                    except Exception as e:
                        logger.debug("file_parse_failed", file=str(filepath), error=str(e))

        # Detect additional technologies
        result.technologies = self._detect_technologies(target)

        result.endpoints = endpoints
        result.total_endpoints = len(endpoints)

        return result

    def _detect_technologies(self, target: Path) -> list[str]:
        """Detect technologies used in the project."""
        technologies = []

        # Check for common files
        tech_indicators = {
            "package.json": "Node.js",
            "requirements.txt": "Python",
            "Pipfile": "Python",
            "pyproject.toml": "Python",
            "go.mod": "Go",
            "Cargo.toml": "Rust",
            "pom.xml": "Java/Maven",
            "build.gradle": "Java/Gradle",
            "Gemfile": "Ruby",
            "composer.json": "PHP",
            "docker-compose.yml": "Docker",
            "Dockerfile": "Docker",
            "kubernetes.yaml": "Kubernetes",
            ".env": "Environment Config",
        }

        for filename, tech in tech_indicators.items():
            if list(target.rglob(filename)):
                technologies.append(tech)

        return technologies

    async def generate_openapi_spec(
        self,
        endpoints: list[APIEndpoint],
        title: str = "Discovered API",
        version: str = "1.0.0"
    ) -> dict[str, Any]:
        """
        Generate OpenAPI specification from discovered endpoints.

        Useful for importing into security testing tools.
        """
        spec = {
            "openapi": "3.0.0",
            "info": {
                "title": title,
                "version": version,
                "description": "API specification generated by Shadow Worker Noir Scanner",
            },
            "paths": {},
        }

        for endpoint in endpoints:
            path = endpoint.url

            # Normalize path parameters
            path = re.sub(r':(\w+)', r'{\1}', path)  # Express style :id -> {id}
            path = re.sub(r'<(\w+)(?::\w+)?>', r'{\1}', path)  # Flask style <id:int> -> {id}

            if path not in spec["paths"]:
                spec["paths"][path] = {}

            method = endpoint.method.lower()
            spec["paths"][path][method] = {
                "summary": f"Discovered endpoint from {endpoint.source_file}",
                "responses": {
                    "200": {"description": "Successful response"},
                },
            }

            # Add parameters
            if endpoint.params:
                spec["paths"][path][method]["parameters"] = [
                    {
                        "name": p["name"],
                        "in": p.get("type", "query"),
                        "schema": {"type": "string"},
                    }
                    for p in endpoint.params
                    if p.get("name")
                ]

        return spec


# Convenience function for quick endpoint discovery
async def discover_endpoints(
    target_path: str,
    base_url: str = ""
) -> list[APIEndpoint]:
    """
    Quick endpoint discovery for a target path.

    Args:
        target_path: Path to source code
        base_url: Optional base URL

    Returns:
        List of discovered API endpoints
    """
    scanner = NoirScanner()
    result = await scanner.scan(target_path, base_url)
    return result.endpoints
