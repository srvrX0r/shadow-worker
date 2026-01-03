"""
SAST Scanner - Static Application Security Testing.

Integrates multiple static analysis tools for comprehensive code security.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

from shadow_worker.core.config import SASTConfig
from shadow_worker.core.scanner import Finding, Severity, VulnCategory

logger = structlog.get_logger()


@dataclass
class SemgrepFinding:
    """Finding from Semgrep."""

    rule_id: str
    path: str
    start_line: int
    end_line: int
    message: str
    severity: str
    metadata: dict


class SASTScanner:
    """
    Static Application Security Testing scanner.

    Integrates:
    - Semgrep for multi-language pattern matching
    - Bandit for Python security
    - OWASP Noir for API discovery
    - Custom regex patterns
    """

    def __init__(self, config: SASTConfig):
        self.config = config
        self._semgrep_available = self._check_tool("semgrep")
        self._bandit_available = self._check_tool("bandit")

    def _check_tool(self, tool: str) -> bool:
        """Check if a tool is available."""
        try:
            subprocess.run(
                [tool, "--version"],
                capture_output=True,
                timeout=10
            )
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    async def scan(self, target: str, options: dict[str, Any] | None = None) -> list[Finding]:
        """
        Run SAST scan on target path.

        Args:
            target: Path to scan (file or directory)
            options: Additional scan options

        Returns:
            List of security findings
        """
        target_path = Path(target)

        if not target_path.exists():
            raise FileNotFoundError(f"Target not found: {target}")

        findings: list[Finding] = []

        # Run enabled scanners concurrently
        tasks = []

        if self.config.semgrep_enabled and self._semgrep_available:
            tasks.append(self._run_semgrep(target_path))

        if self.config.bandit_enabled and self._bandit_available:
            if self._is_python_project(target_path):
                tasks.append(self._run_bandit(target_path))

        # Always run custom patterns
        tasks.append(self._run_custom_patterns(target_path))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error("sast_scanner_failed", error=str(result))
            elif isinstance(result, list):
                findings.extend(result)

        logger.info("sast_scan_complete", target=target, findings=len(findings))
        return findings

    async def _run_semgrep(self, target: Path) -> list[Finding]:
        """Run Semgrep scanner."""
        findings = []

        try:
            rules = " ".join(f"--config {r}" for r in self.config.semgrep_rules)
            excludes = " ".join(f"--exclude '{p}'" for p in self.config.exclude_patterns)

            cmd = f"semgrep {rules} {excludes} --json {target}"

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if stdout:
                result = json.loads(stdout.decode())
                for item in result.get("results", []):
                    findings.append(self._semgrep_to_finding(item))

        except Exception as e:
            logger.error("semgrep_failed", error=str(e))

        return findings

    async def _run_bandit(self, target: Path) -> list[Finding]:
        """Run Bandit Python security scanner."""
        findings = []

        try:
            excludes = ",".join(self.config.exclude_patterns)
            cmd = f"bandit -r {target} -f json --exclude {excludes}"

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if stdout:
                result = json.loads(stdout.decode())
                for item in result.get("results", []):
                    findings.append(self._bandit_to_finding(item))

        except Exception as e:
            logger.error("bandit_failed", error=str(e))

        return findings

    async def _run_custom_patterns(self, target: Path) -> list[Finding]:
        """Run custom security patterns."""
        import re

        findings = []

        # Security-sensitive patterns
        patterns = [
            {
                "id": "hardcoded-secret",
                "pattern": r'(?i)(password|secret|api_key|apikey|token|private_key)\s*[=:]\s*["\'][^"\']{8,}["\']',
                "severity": Severity.HIGH,
                "category": VulnCategory.SENSITIVE_DATA,
                "message": "Potential hardcoded secret detected",
                "cwe": 798
            },
            {
                "id": "sql-injection",
                "pattern": r'(?i)(execute|cursor\.execute|query)\s*\(\s*["\'].*%s.*["\']|f["\'].*\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE)',
                "severity": Severity.CRITICAL,
                "category": VulnCategory.INJECTION,
                "message": "Potential SQL injection vulnerability",
                "cwe": 89
            },
            {
                "id": "command-injection",
                "pattern": r'(?i)(os\.system|subprocess\.(?:call|run|Popen)|shell=True)',
                "severity": Severity.HIGH,
                "category": VulnCategory.INJECTION,
                "message": "Potential command injection vulnerability",
                "cwe": 78
            },
            {
                "id": "xss-vulnerability",
                "pattern": r'(?i)(innerHTML|outerHTML|document\.write|\.html\(|v-html)',
                "severity": Severity.MEDIUM,
                "category": VulnCategory.XSS,
                "message": "Potential XSS vulnerability - dynamic HTML insertion",
                "cwe": 79
            },
            {
                "id": "insecure-deserialization",
                "pattern": r'(?i)(pickle\.loads?|yaml\.(?:load|unsafe_load)|marshal\.loads?|eval\()',
                "severity": Severity.HIGH,
                "category": VulnCategory.INSECURE_DESER,
                "message": "Potential insecure deserialization",
                "cwe": 502
            },
            {
                "id": "weak-crypto",
                "pattern": r'(?i)(md5|sha1|DES|RC4|random\.random)',
                "severity": Severity.MEDIUM,
                "category": VulnCategory.CRYPTO,
                "message": "Use of weak cryptographic algorithm",
                "cwe": 327
            },
            {
                "id": "ssrf-vulnerability",
                "pattern": r'(?i)(requests\.get|urllib\.request\.urlopen|http\.client|fetch)\s*\([^)]*\+|(?:requests|urllib|http).*user.*input',
                "severity": Severity.HIGH,
                "category": VulnCategory.SSRF,
                "message": "Potential SSRF vulnerability",
                "cwe": 918
            },
            {
                "id": "path-traversal",
                "pattern": r'(?i)(open\(|os\.path\.join|Path\().*\+.*(?:request|input|param)',
                "severity": Severity.HIGH,
                "category": VulnCategory.INJECTION,
                "message": "Potential path traversal vulnerability",
                "cwe": 22
            },
            {
                "id": "jwt-none-algorithm",
                "pattern": r'(?i)algorithm\s*[=:]\s*["\']none["\']|verify\s*[=:]\s*False',
                "severity": Severity.CRITICAL,
                "category": VulnCategory.BROKEN_AUTH,
                "message": "JWT None algorithm or verification disabled",
                "cwe": 347
            },
            {
                "id": "debug-enabled",
                "pattern": r'(?i)(DEBUG\s*=\s*True|app\.debug\s*=\s*True|\.setLevel\(.*DEBUG)',
                "severity": Severity.LOW,
                "category": VulnCategory.MISCONFIG,
                "message": "Debug mode enabled",
                "cwe": 215
            },
        ]

        # Scan files
        if target.is_file():
            files = [target]
        else:
            files = list(target.rglob("*"))

        for filepath in files:
            if not filepath.is_file():
                continue

            # Skip excluded patterns
            if any(filepath.match(p) for p in self.config.exclude_patterns):
                continue

            # Skip binary files
            if self._is_binary(filepath):
                continue

            try:
                content = filepath.read_text(errors="ignore")
                lines = content.split("\n")

                for pattern_def in patterns:
                    for match in re.finditer(pattern_def["pattern"], content):
                        # Find line number
                        line_num = content[:match.start()].count("\n") + 1

                        findings.append(Finding(
                            title=pattern_def["message"],
                            description=f"Pattern '{pattern_def['id']}' matched",
                            severity=pattern_def["severity"],
                            category=pattern_def["category"],
                            target=str(target),
                            location=str(filepath.relative_to(target) if target.is_dir() else filepath.name),
                            line_number=line_num,
                            evidence=lines[line_num - 1].strip()[:200] if line_num <= len(lines) else "",
                            scanner="sast-custom",
                            cwe_ids=[pattern_def["cwe"]],
                            remediation=self._get_remediation(pattern_def["id"]),
                        ))

            except Exception as e:
                logger.debug("file_scan_failed", file=str(filepath), error=str(e))

        return findings

    def _semgrep_to_finding(self, item: dict) -> Finding:
        """Convert Semgrep result to Finding."""
        severity_map = {
            "ERROR": Severity.CRITICAL,
            "WARNING": Severity.HIGH,
            "INFO": Severity.MEDIUM,
        }

        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})

        return Finding(
            title=extra.get("message", item.get("check_id", "")),
            description=metadata.get("message", ""),
            severity=severity_map.get(extra.get("severity", "INFO"), Severity.MEDIUM),
            category=self._map_semgrep_category(metadata.get("category", "")),
            target=item.get("path", ""),
            location=item.get("path", ""),
            line_number=item.get("start", {}).get("line", 0),
            evidence=extra.get("lines", ""),
            scanner="semgrep",
            cwe_ids=metadata.get("cwe", []),
            references=metadata.get("references", []),
            remediation=metadata.get("fix", ""),
        )

    def _bandit_to_finding(self, item: dict) -> Finding:
        """Convert Bandit result to Finding."""
        severity_map = {
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }

        return Finding(
            title=item.get("issue_text", ""),
            description=f"Bandit {item.get('test_id', '')}: {item.get('issue_text', '')}",
            severity=severity_map.get(item.get("issue_severity", "MEDIUM"), Severity.MEDIUM),
            category=VulnCategory.OTHER,
            target=item.get("filename", ""),
            location=item.get("filename", ""),
            line_number=item.get("line_number", 0),
            evidence=item.get("code", ""),
            scanner="bandit",
            cwe_ids=[item.get("issue_cwe", {}).get("id")] if item.get("issue_cwe") else [],
            remediation=item.get("more_info", ""),
        )

    def _map_semgrep_category(self, category: str) -> VulnCategory:
        """Map Semgrep category to VulnCategory."""
        mapping = {
            "security": VulnCategory.OTHER,
            "injection": VulnCategory.INJECTION,
            "xss": VulnCategory.XSS,
            "auth": VulnCategory.BROKEN_AUTH,
            "crypto": VulnCategory.CRYPTO,
        }
        return mapping.get(category.lower(), VulnCategory.OTHER)

    def _is_python_project(self, path: Path) -> bool:
        """Check if path contains Python code."""
        if path.is_file():
            return path.suffix == ".py"
        return any(path.rglob("*.py"))

    def _is_binary(self, path: Path) -> bool:
        """Check if file is binary."""
        try:
            with open(path, "rb") as f:
                chunk = f.read(1024)
                return b"\x00" in chunk
        except Exception:
            return True

    def _get_remediation(self, pattern_id: str) -> str:
        """Get remediation advice for a pattern."""
        remediations = {
            "hardcoded-secret": "Move secrets to environment variables or a secrets manager",
            "sql-injection": "Use parameterized queries or an ORM",
            "command-injection": "Use subprocess with list arguments, avoid shell=True",
            "xss-vulnerability": "Sanitize user input and use Content-Security-Policy headers",
            "insecure-deserialization": "Use safe serialization formats like JSON",
            "weak-crypto": "Use strong algorithms: SHA-256+, AES, secrets.token_*",
            "ssrf-vulnerability": "Validate and whitelist URLs, use allowlists",
            "path-traversal": "Use os.path.realpath and validate paths",
            "jwt-none-algorithm": "Always specify algorithm and enable verification",
            "debug-enabled": "Disable debug mode in production",
        }
        return remediations.get(pattern_id, "Review and fix the security issue")
