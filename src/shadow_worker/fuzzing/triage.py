"""
Crash Triage - Analyze and classify fuzzing crashes.

Provides crash deduplication, exploitability analysis, and root cause identification.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ExploitabilityRating(str, Enum):
    """Exploitability classification."""

    EXPLOITABLE = "exploitable"
    PROBABLY_EXPLOITABLE = "probably_exploitable"
    PROBABLY_NOT_EXPLOITABLE = "probably_not_exploitable"
    NOT_EXPLOITABLE = "not_exploitable"
    UNKNOWN = "unknown"


class CrashType(str, Enum):
    """Crash classification types."""

    # Memory corruption
    STACK_BUFFER_OVERFLOW = "stack_buffer_overflow"
    HEAP_BUFFER_OVERFLOW = "heap_buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    NULL_DEREFERENCE = "null_dereference"
    UNINITIALIZED_MEMORY = "uninitialized_memory"
    INTEGER_OVERFLOW = "integer_overflow"

    # Control flow
    INVALID_INSTRUCTION = "invalid_instruction"
    STACK_EXHAUSTION = "stack_exhaustion"
    INFINITE_LOOP = "infinite_loop"

    # Application errors
    ASSERTION_FAILURE = "assertion_failure"
    UNCAUGHT_EXCEPTION = "uncaught_exception"
    TIMEOUT = "timeout"

    # Web-specific
    INJECTION = "injection"
    AUTH_BYPASS = "auth_bypass"
    INFORMATION_DISCLOSURE = "information_disclosure"

    UNKNOWN = "unknown"


@dataclass
class CrashInfo:
    """Detailed crash information."""

    # Basic info
    crash_type: CrashType = CrashType.UNKNOWN
    exploitability: ExploitabilityRating = ExploitabilityRating.UNKNOWN

    # Location
    crash_address: int = 0
    crash_instruction: str = ""
    faulting_module: str = ""
    faulting_function: str = ""

    # Stack trace
    stack_trace: list[str] = field(default_factory=list)
    stack_hash: str = ""

    # Registers (for native crashes)
    registers: dict[str, int] = field(default_factory=dict)

    # Memory state
    corrupted_memory: list[tuple[int, int]] = field(default_factory=list)

    # Input info
    input_hash: str = ""
    input_size: int = 0
    minimized_input: bytes = b""

    # Analysis
    root_cause: str = ""
    recommendations: list[str] = field(default_factory=list)
    cve_matches: list[str] = field(default_factory=list)
    similar_crashes: list[str] = field(default_factory=list)

    @property
    def signature(self) -> str:
        """Unique crash signature for deduplication."""
        return hashlib.md5(
            f"{self.crash_type.value}:{self.faulting_function}:{self.stack_hash}".encode()
        ).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "crash_type": self.crash_type.value,
            "exploitability": self.exploitability.value,
            "crash_address": hex(self.crash_address) if self.crash_address else None,
            "faulting_function": self.faulting_function,
            "stack_trace": self.stack_trace[:10],
            "stack_hash": self.stack_hash,
            "signature": self.signature,
            "root_cause": self.root_cause,
            "recommendations": self.recommendations,
        }


class CrashAnalyzer:
    """
    Analyze crashes to determine type and exploitability.

    Provides:
    - Crash classification
    - Stack trace analysis
    - Exploitability scoring
    - Root cause analysis
    - Crash deduplication
    """

    def __init__(self):
        self._known_crashes: dict[str, CrashInfo] = {}

    def analyze(
        self,
        exception: Exception | None = None,
        stack_trace: list[str] | None = None,
        input_data: bytes = b"",
        stderr: bytes = b"",
        exit_code: int = 0
    ) -> CrashInfo:
        """
        Analyze a crash and return detailed information.

        Args:
            exception: Python exception if available
            stack_trace: Stack trace lines
            input_data: Input that caused crash
            stderr: Standard error output
            exit_code: Process exit code

        Returns:
            CrashInfo with analysis results
        """
        info = CrashInfo(
            input_hash=hashlib.sha256(input_data).hexdigest()[:16],
            input_size=len(input_data),
            stack_trace=stack_trace or [],
        )

        # Analyze based on available information
        if exception:
            info = self._analyze_exception(exception, info)
        elif stack_trace:
            info = self._analyze_stack_trace(stack_trace, info)

        if stderr:
            info = self._analyze_stderr(stderr, info)

        # Calculate stack hash
        info.stack_hash = self._calculate_stack_hash(info.stack_trace)

        # Determine exploitability
        info.exploitability = self._assess_exploitability(info)

        # Generate recommendations
        info.recommendations = self._generate_recommendations(info)

        # Check for duplicates
        sig = info.signature
        if sig in self._known_crashes:
            info.similar_crashes.append(self._known_crashes[sig].input_hash)
        else:
            self._known_crashes[sig] = info

        return info

    def _analyze_exception(
        self,
        exception: Exception,
        info: CrashInfo
    ) -> CrashInfo:
        """Analyze Python exception."""
        exc_type = type(exception).__name__

        # Map exception types to crash types
        exception_map = {
            "MemoryError": CrashType.HEAP_BUFFER_OVERFLOW,
            "RecursionError": CrashType.STACK_EXHAUSTION,
            "OverflowError": CrashType.INTEGER_OVERFLOW,
            "AssertionError": CrashType.ASSERTION_FAILURE,
            "KeyError": CrashType.NULL_DEREFERENCE,
            "IndexError": CrashType.STACK_BUFFER_OVERFLOW,
            "TypeError": CrashType.UNKNOWN,
            "ValueError": CrashType.UNKNOWN,
        }

        info.crash_type = exception_map.get(exc_type, CrashType.UNCAUGHT_EXCEPTION)
        info.root_cause = str(exception)

        # Extract stack from exception
        import traceback
        info.stack_trace = traceback.format_exception(
            type(exception), exception, exception.__traceback__
        )

        if info.stack_trace:
            info.faulting_function = self._extract_function_from_trace(info.stack_trace)

        return info

    def _analyze_stack_trace(
        self,
        stack_trace: list[str],
        info: CrashInfo
    ) -> CrashInfo:
        """Analyze stack trace to classify crash."""
        trace_text = "\n".join(stack_trace).lower()

        # Pattern matching for crash types
        patterns = {
            CrashType.STACK_BUFFER_OVERFLOW: [
                r"stack.*overflow", r"stack.*smash", r"buffer.*overflow.*stack"
            ],
            CrashType.HEAP_BUFFER_OVERFLOW: [
                r"heap.*overflow", r"heap.*corruption", r"buffer.*overflow.*heap"
            ],
            CrashType.USE_AFTER_FREE: [
                r"use.*after.*free", r"uaf", r"freed.*memory"
            ],
            CrashType.DOUBLE_FREE: [
                r"double.*free", r"free.*already.*freed"
            ],
            CrashType.NULL_DEREFERENCE: [
                r"null.*pointer", r"nullptr", r"segfault.*0x0+",
                r"access.*null", r"dereference.*null"
            ],
            CrashType.INTEGER_OVERFLOW: [
                r"integer.*overflow", r"signed.*overflow", r"arithmetic.*overflow"
            ],
            CrashType.ASSERTION_FAILURE: [
                r"assertion.*fail", r"assert.*false"
            ],
        }

        for crash_type, regexes in patterns.items():
            for regex in regexes:
                if re.search(regex, trace_text):
                    info.crash_type = crash_type
                    break
            if info.crash_type != CrashType.UNKNOWN:
                break

        info.faulting_function = self._extract_function_from_trace(stack_trace)

        return info

    def _analyze_stderr(self, stderr: bytes, info: CrashInfo) -> CrashInfo:
        """Analyze stderr for crash indicators."""
        stderr_text = stderr.decode(errors="ignore").lower()

        # ASAN/MSAN/UBSAN patterns
        sanitizer_patterns = {
            "addresssanitizer: heap-buffer-overflow": CrashType.HEAP_BUFFER_OVERFLOW,
            "addresssanitizer: stack-buffer-overflow": CrashType.STACK_BUFFER_OVERFLOW,
            "addresssanitizer: use-after-free": CrashType.USE_AFTER_FREE,
            "addresssanitizer: double-free": CrashType.DOUBLE_FREE,
            "addresssanitizer: null-dereference": CrashType.NULL_DEREFERENCE,
            "memorysanitizer: use-of-uninitialized-value": CrashType.UNINITIALIZED_MEMORY,
            "ubsan: signed-integer-overflow": CrashType.INTEGER_OVERFLOW,
        }

        for pattern, crash_type in sanitizer_patterns.items():
            if pattern in stderr_text:
                info.crash_type = crash_type

                # Extract address from ASAN
                addr_match = re.search(r"0x([0-9a-f]+)", stderr_text)
                if addr_match:
                    info.crash_address = int(addr_match.group(1), 16)

                break

        return info

    def _calculate_stack_hash(self, stack_trace: list[str]) -> str:
        """Calculate hash of stack trace for deduplication."""
        # Use top 5 unique frames
        unique_frames = []
        seen = set()

        for frame in stack_trace:
            # Normalize frame (remove addresses, line numbers)
            normalized = re.sub(r'0x[0-9a-f]+', 'ADDR', frame)
            normalized = re.sub(r':\d+', ':LINE', normalized)
            normalized = re.sub(r'\s+', ' ', normalized).strip()

            if normalized and normalized not in seen:
                seen.add(normalized)
                unique_frames.append(normalized)

            if len(unique_frames) >= 5:
                break

        return hashlib.md5("\n".join(unique_frames).encode()).hexdigest()[:12]

    def _extract_function_from_trace(self, stack_trace: list[str]) -> str:
        """Extract faulting function from stack trace."""
        for frame in stack_trace:
            # Python-style: "in function_name"
            match = re.search(r'in\s+(\w+)', frame)
            if match:
                return match.group(1)

            # C-style: "function_name+0x"
            match = re.search(r'(\w+)\+0x', frame)
            if match:
                return match.group(1)

            # General: word before parenthesis
            match = re.search(r'(\w+)\s*\(', frame)
            if match:
                return match.group(1)

        return "unknown"

    def _assess_exploitability(self, info: CrashInfo) -> ExploitabilityRating:
        """Assess crash exploitability."""
        # High exploitability
        if info.crash_type in [
            CrashType.STACK_BUFFER_OVERFLOW,
            CrashType.USE_AFTER_FREE,
            CrashType.DOUBLE_FREE,
        ]:
            return ExploitabilityRating.EXPLOITABLE

        # Probably exploitable
        if info.crash_type in [
            CrashType.HEAP_BUFFER_OVERFLOW,
            CrashType.UNINITIALIZED_MEMORY,
        ]:
            return ExploitabilityRating.PROBABLY_EXPLOITABLE

        # Probably not exploitable
        if info.crash_type in [
            CrashType.INTEGER_OVERFLOW,
            CrashType.ASSERTION_FAILURE,
        ]:
            return ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE

        # Not exploitable
        if info.crash_type in [
            CrashType.NULL_DEREFERENCE,
            CrashType.TIMEOUT,
        ]:
            return ExploitabilityRating.NOT_EXPLOITABLE

        return ExploitabilityRating.UNKNOWN

    def _generate_recommendations(self, info: CrashInfo) -> list[str]:
        """Generate fix recommendations based on crash type."""
        recommendations = []

        if info.crash_type == CrashType.STACK_BUFFER_OVERFLOW:
            recommendations.extend([
                "Use bounds-checking functions (strncpy, snprintf)",
                "Enable stack canaries (-fstack-protector-strong)",
                "Consider using safe string libraries",
            ])

        elif info.crash_type == CrashType.HEAP_BUFFER_OVERFLOW:
            recommendations.extend([
                "Validate buffer sizes before allocation",
                "Use safe memory allocation wrappers",
                "Enable ASAN for debugging",
            ])

        elif info.crash_type == CrashType.USE_AFTER_FREE:
            recommendations.extend([
                "Set pointers to NULL after freeing",
                "Use smart pointers (C++) or ownership tracking",
                "Review object lifecycle management",
            ])

        elif info.crash_type == CrashType.NULL_DEREFERENCE:
            recommendations.extend([
                "Add null pointer checks before dereference",
                "Validate function return values",
                "Use optional types or defensive programming",
            ])

        elif info.crash_type == CrashType.INTEGER_OVERFLOW:
            recommendations.extend([
                "Use safe integer arithmetic functions",
                "Check for overflow before operations",
                "Use larger integer types if appropriate",
            ])

        elif info.crash_type == CrashType.INJECTION:
            recommendations.extend([
                "Use parameterized queries for SQL",
                "Sanitize and validate all user input",
                "Implement proper output encoding",
            ])

        return recommendations


class VulnerabilityClassifier:
    """
    Classify discovered issues into vulnerability categories.

    Maps fuzzing findings to CWE/CVE classifications.
    """

    # CWE mappings
    CWE_MAP = {
        CrashType.STACK_BUFFER_OVERFLOW: ("CWE-121", "Stack-based Buffer Overflow"),
        CrashType.HEAP_BUFFER_OVERFLOW: ("CWE-122", "Heap-based Buffer Overflow"),
        CrashType.USE_AFTER_FREE: ("CWE-416", "Use After Free"),
        CrashType.DOUBLE_FREE: ("CWE-415", "Double Free"),
        CrashType.NULL_DEREFERENCE: ("CWE-476", "NULL Pointer Dereference"),
        CrashType.INTEGER_OVERFLOW: ("CWE-190", "Integer Overflow"),
        CrashType.UNINITIALIZED_MEMORY: ("CWE-457", "Use of Uninitialized Variable"),
        CrashType.INJECTION: ("CWE-74", "Injection"),
    }

    def classify(self, info: CrashInfo) -> dict[str, Any]:
        """Classify crash into vulnerability category."""
        cwe_id, cwe_name = self.CWE_MAP.get(
            info.crash_type,
            ("CWE-Unknown", "Unknown Vulnerability")
        )

        severity = self._calculate_severity(info)

        return {
            "cwe_id": cwe_id,
            "cwe_name": cwe_name,
            "crash_type": info.crash_type.value,
            "exploitability": info.exploitability.value,
            "severity": severity,
            "cvss_estimate": self._estimate_cvss(info, severity),
        }

    def _calculate_severity(self, info: CrashInfo) -> str:
        """Calculate severity based on exploitability."""
        if info.exploitability == ExploitabilityRating.EXPLOITABLE:
            return "critical"
        elif info.exploitability == ExploitabilityRating.PROBABLY_EXPLOITABLE:
            return "high"
        elif info.exploitability == ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE:
            return "medium"
        else:
            return "low"

    def _estimate_cvss(self, info: CrashInfo, severity: str) -> float:
        """Estimate CVSS score."""
        base_scores = {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 3.0,
        }
        return base_scores.get(severity, 5.0)


class ExploitabilityScorer:
    """
    Score crash exploitability for prioritization.

    Uses multiple factors to determine likelihood of exploitation.
    """

    def score(self, info: CrashInfo) -> float:
        """
        Calculate exploitability score (0.0 - 10.0).

        Higher scores indicate more likely exploitability.
        """
        score = 0.0

        # Base score from crash type
        type_scores = {
            CrashType.USE_AFTER_FREE: 9.0,
            CrashType.DOUBLE_FREE: 8.5,
            CrashType.STACK_BUFFER_OVERFLOW: 8.0,
            CrashType.HEAP_BUFFER_OVERFLOW: 7.5,
            CrashType.UNINITIALIZED_MEMORY: 6.0,
            CrashType.INTEGER_OVERFLOW: 5.0,
            CrashType.NULL_DEREFERENCE: 3.0,
            CrashType.ASSERTION_FAILURE: 2.0,
        }

        score = type_scores.get(info.crash_type, 5.0)

        # Adjust based on crash location
        if info.faulting_function:
            # Functions handling user input are more concerning
            sensitive_functions = [
                "parse", "read", "input", "receive", "decode",
                "deserialize", "unpack", "load", "process"
            ]
            for func in sensitive_functions:
                if func in info.faulting_function.lower():
                    score = min(10.0, score + 0.5)
                    break

        # Adjust based on exploitability rating
        rating_adjustments = {
            ExploitabilityRating.EXPLOITABLE: 1.0,
            ExploitabilityRating.PROBABLY_EXPLOITABLE: 0.5,
            ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE: -0.5,
            ExploitabilityRating.NOT_EXPLOITABLE: -1.0,
        }

        score += rating_adjustments.get(info.exploitability, 0.0)

        return max(0.0, min(10.0, score))

    def prioritize(self, crashes: list[CrashInfo]) -> list[CrashInfo]:
        """Sort crashes by exploitability score (highest first)."""
        return sorted(crashes, key=lambda c: self.score(c), reverse=True)
