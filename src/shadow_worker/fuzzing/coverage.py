"""
Coverage Tracking - Code coverage instrumentation and analysis.

Provides coverage-guided fuzzing capabilities for maximum code exploration.
"""

from __future__ import annotations

import hashlib
import mmap
import os
import struct
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import structlog

logger = structlog.get_logger()


@dataclass
class CoverageData:
    """Coverage information for a single execution."""

    # Edge coverage (source -> dest)
    edges: set[tuple[int, int]] = field(default_factory=set)

    # Basic block coverage
    blocks: set[int] = field(default_factory=set)

    # Branch coverage
    branches: set[tuple[int, bool]] = field(default_factory=set)

    # Line coverage (file -> lines)
    lines: dict[str, set[int]] = field(default_factory=lambda: defaultdict(set))

    # Function coverage
    functions: set[str] = field(default_factory=set)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    @property
    def block_count(self) -> int:
        return len(self.blocks)

    @property
    def branch_count(self) -> int:
        return len(self.branches)

    @property
    def line_count(self) -> int:
        return sum(len(lines) for lines in self.lines.values())

    @property
    def function_count(self) -> int:
        return len(self.functions)

    def hash(self) -> str:
        """Generate hash of coverage state."""
        data = (
            frozenset(self.edges),
            frozenset(self.blocks),
            frozenset(self.branches),
        )
        return hashlib.md5(str(data).encode()).hexdigest()[:16]

    def merge(self, other: CoverageData) -> CoverageData:
        """Merge with another coverage dataset."""
        return CoverageData(
            edges=self.edges | other.edges,
            blocks=self.blocks | other.blocks,
            branches=self.branches | other.branches,
            lines={
                k: self.lines.get(k, set()) | other.lines.get(k, set())
                for k in set(self.lines) | set(other.lines)
            },
            functions=self.functions | other.functions,
        )

    def diff(self, other: CoverageData) -> CoverageData:
        """Get coverage unique to this dataset."""
        return CoverageData(
            edges=self.edges - other.edges,
            blocks=self.blocks - other.blocks,
            branches=self.branches - other.branches,
        )


class CoverageTracker(ABC):
    """Base class for coverage tracking."""

    @abstractmethod
    def reset(self) -> None:
        """Reset coverage counters."""
        pass

    @abstractmethod
    def get_coverage(self) -> CoverageData:
        """Get current coverage data."""
        pass

    @abstractmethod
    def get_edge_count(self) -> int:
        """Get number of unique edges covered."""
        pass


class ShmCoverageTracker(CoverageTracker):
    """
    Shared memory coverage tracker (AFL-style).

    Uses shared memory bitmap for high-performance coverage tracking.
    Compatible with AFL/AFL++ instrumented binaries.
    """

    MAP_SIZE = 65536  # 64KB coverage map

    def __init__(self, shm_id: int | None = None):
        self.shm_id = shm_id
        self._map: mmap.mmap | None = None
        self._virgin_map = bytearray(self.MAP_SIZE)
        self._trace_bits = bytearray(self.MAP_SIZE)

        if shm_id:
            self._attach_shm()

    def _attach_shm(self) -> None:
        """Attach to shared memory segment."""
        try:
            # Create or attach to shared memory
            self._map = mmap.mmap(-1, self.MAP_SIZE, f"afl_shm_{self.shm_id}")
        except Exception as e:
            logger.warning("shm_attach_failed", error=str(e))

    def reset(self) -> None:
        """Reset coverage bitmap."""
        if self._map:
            self._map.seek(0)
            self._map.write(b'\x00' * self.MAP_SIZE)
        self._trace_bits = bytearray(self.MAP_SIZE)

    def get_coverage(self) -> CoverageData:
        """Get coverage from shared memory."""
        if self._map:
            self._map.seek(0)
            self._trace_bits = bytearray(self._map.read(self.MAP_SIZE))

        coverage = CoverageData()

        for i, byte in enumerate(self._trace_bits):
            if byte:
                # Each byte represents an edge (simplified)
                coverage.edges.add((i, byte))
                coverage.blocks.add(i)

        return coverage

    def get_edge_count(self) -> int:
        """Count unique edges."""
        if self._map:
            self._map.seek(0)
            data = self._map.read(self.MAP_SIZE)
            return sum(1 for b in data if b)
        return sum(1 for b in self._trace_bits if b)

    def has_new_coverage(self) -> bool:
        """Check if execution found new coverage."""
        if self._map:
            self._map.seek(0)
            data = self._map.read(self.MAP_SIZE)

            for i, byte in enumerate(data):
                if byte and not self._virgin_map[i]:
                    self._virgin_map[i] = byte
                    return True

        return False

    def classify_coverage(self) -> tuple[int, int, int]:
        """
        Classify coverage into buckets.

        Returns:
            (new_edges, new_edge_hits, same_coverage)
        """
        new_edges = 0
        new_hits = 0
        same = 0

        if self._map:
            self._map.seek(0)
            data = self._map.read(self.MAP_SIZE)

            for i, byte in enumerate(data):
                if byte:
                    if not self._virgin_map[i]:
                        new_edges += 1
                        self._virgin_map[i] = byte
                    elif byte != self._virgin_map[i]:
                        new_hits += 1
                        self._virgin_map[i] = byte
                    else:
                        same += 1

        return new_edges, new_hits, same


class PythonCoverageTracker(CoverageTracker):
    """
    Python coverage tracker using sys.settrace.

    Tracks line, branch, and function coverage for Python code.
    """

    def __init__(self):
        self._coverage = CoverageData()
        self._last_location: tuple[str, int] | None = None
        self._active = False

    def reset(self) -> None:
        """Reset coverage data."""
        self._coverage = CoverageData()
        self._last_location = None

    def get_coverage(self) -> CoverageData:
        """Get current coverage."""
        return self._coverage

    def get_edge_count(self) -> int:
        """Get edge count."""
        return self._coverage.edge_count

    def start(self) -> None:
        """Start coverage tracking."""
        self._active = True
        sys.settrace(self._trace_callback)

    def stop(self) -> None:
        """Stop coverage tracking."""
        self._active = False
        sys.settrace(None)

    def _trace_callback(
        self,
        frame: Any,
        event: str,
        arg: Any
    ) -> Callable | None:
        """Trace callback for sys.settrace."""
        if not self._active:
            return None

        filename = frame.f_code.co_filename
        lineno = frame.f_lineno
        func_name = frame.f_code.co_name

        # Skip standard library
        if "site-packages" in filename or "lib/python" in filename:
            return self._trace_callback

        current = (filename, lineno)

        if event == "line":
            self._coverage.lines[filename].add(lineno)
            self._coverage.blocks.add(hash(current) & 0xFFFFFFFF)

            if self._last_location:
                edge = (
                    hash(self._last_location) & 0xFFFF,
                    hash(current) & 0xFFFF
                )
                self._coverage.edges.add(edge)

            self._last_location = current

        elif event == "call":
            self._coverage.functions.add(f"{filename}:{func_name}")

        elif event == "return":
            pass

        return self._trace_callback

    def __enter__(self) -> PythonCoverageTracker:
        self.start()
        return self

    def __exit__(self, *args) -> None:
        self.stop()


class CoverageGuided:
    """
    Coverage-guided fuzzing controller.

    Implements AFL-style coverage guidance with power scheduling.
    """

    def __init__(self, tracker: CoverageTracker | None = None):
        self.tracker = tracker or PythonCoverageTracker()
        self.global_coverage = CoverageData()
        self.inputs_by_coverage: dict[str, bytes] = {}

        # Statistics
        self.total_edges = 0
        self.total_blocks = 0
        self.total_executions = 0

    def reset(self) -> None:
        """Reset for new execution."""
        self.tracker.reset()

    def get_edge_count(self) -> int:
        """Get current global edge count."""
        return self.global_coverage.edge_count

    def record_execution(self, input_data: bytes) -> bool:
        """
        Record execution and check for new coverage.

        Returns:
            True if execution found new coverage
        """
        coverage = self.tracker.get_coverage()
        self.total_executions += 1

        # Check for new coverage
        new_coverage = coverage.diff(self.global_coverage)

        if new_coverage.edge_count > 0 or new_coverage.block_count > 0:
            # Merge into global coverage
            self.global_coverage = self.global_coverage.merge(coverage)

            # Store input
            cov_hash = coverage.hash()
            if cov_hash not in self.inputs_by_coverage:
                self.inputs_by_coverage[cov_hash] = input_data

            self.total_edges = self.global_coverage.edge_count
            self.total_blocks = self.global_coverage.block_count

            return True

        return False

    def get_coverage_bitmap(self) -> bytes:
        """Get coverage bitmap for visualization."""
        bitmap = bytearray(65536)

        for edge in self.global_coverage.edges:
            idx = hash(edge) % 65536
            bitmap[idx] = min(255, bitmap[idx] + 1)

        return bytes(bitmap)

    def get_stats(self) -> dict[str, Any]:
        """Get coverage statistics."""
        return {
            "total_edges": self.total_edges,
            "total_blocks": self.total_blocks,
            "total_executions": self.total_executions,
            "unique_inputs": len(self.inputs_by_coverage),
            "edges_per_exec": (
                self.total_edges / self.total_executions
                if self.total_executions > 0 else 0
            ),
        }


class InstrumentationEngine:
    """
    Code instrumentation for coverage tracking.

    Provides compile-time and runtime instrumentation options.
    """

    def __init__(self):
        self.instrumented_modules: set[str] = set()

    def instrument_function(
        self,
        func: Callable,
        tracker: CoverageTracker
    ) -> Callable:
        """
        Instrument a function for coverage tracking.

        Args:
            func: Function to instrument
            tracker: Coverage tracker to use

        Returns:
            Instrumented function
        """
        import functools

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if isinstance(tracker, PythonCoverageTracker):
                with tracker:
                    return func(*args, **kwargs)
            else:
                tracker.reset()
                try:
                    return func(*args, **kwargs)
                finally:
                    pass

        return wrapper

    def instrument_module(
        self,
        module_name: str,
        tracker: CoverageTracker
    ) -> None:
        """
        Instrument all functions in a module.

        Args:
            module_name: Name of module to instrument
            tracker: Coverage tracker to use
        """
        import importlib
        import types

        try:
            module = importlib.import_module(module_name)

            for name in dir(module):
                obj = getattr(module, name)
                if isinstance(obj, types.FunctionType):
                    setattr(module, name, self.instrument_function(obj, tracker))

            self.instrumented_modules.add(module_name)
            logger.info("module_instrumented", module=module_name)

        except Exception as e:
            logger.error("instrumentation_failed", module=module_name, error=str(e))

    @staticmethod
    def generate_afl_instrumentation(source_file: str, output_file: str) -> bool:
        """
        Generate AFL-compatible instrumentation for C/C++ source.

        This is a placeholder - actual implementation would use
        afl-gcc or afl-clang-fast.
        """
        # In practice, would invoke afl-gcc
        logger.info(
            "afl_instrumentation",
            source=source_file,
            output=output_file
        )
        return False


class CoverageReport:
    """Generate coverage reports."""

    def __init__(self, coverage: CoverageData):
        self.coverage = coverage

    def to_html(self) -> str:
        """Generate HTML coverage report."""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>Coverage Report</title>
    <style>
        body { font-family: monospace; margin: 20px; }
        .covered { background-color: #90EE90; }
        .uncovered { background-color: #FFB6C1; }
        .stats { margin-bottom: 20px; }
        .file { margin: 20px 0; border: 1px solid #ccc; padding: 10px; }
    </style>
</head>
<body>
    <h1>Coverage Report</h1>
    <div class="stats">
        <p>Edges: {edges}</p>
        <p>Blocks: {blocks}</p>
        <p>Lines: {lines}</p>
        <p>Functions: {functions}</p>
    </div>
    {file_reports}
</body>
</html>
        """.format(
            edges=self.coverage.edge_count,
            blocks=self.coverage.block_count,
            lines=self.coverage.line_count,
            functions=self.coverage.function_count,
            file_reports=self._generate_file_reports()
        )
        return html

    def _generate_file_reports(self) -> str:
        """Generate per-file coverage reports."""
        reports = []

        for filename, covered_lines in self.coverage.lines.items():
            try:
                with open(filename) as f:
                    source_lines = f.readlines()

                lines_html = []
                for i, line in enumerate(source_lines, 1):
                    css_class = "covered" if i in covered_lines else ""
                    lines_html.append(
                        f'<div class="{css_class}">{i:4d}: {line.rstrip()}</div>'
                    )

                reports.append(f"""
                    <div class="file">
                        <h3>{filename}</h3>
                        <pre>{''.join(lines_html)}</pre>
                    </div>
                """)
            except Exception:
                pass

        return "\n".join(reports)

    def to_lcov(self) -> str:
        """Generate LCOV format report."""
        lines = []

        for filename, covered_lines in self.coverage.lines.items():
            lines.append(f"SF:{filename}")

            for line_num in sorted(covered_lines):
                lines.append(f"DA:{line_num},1")

            lines.append(f"LF:{len(covered_lines)}")
            lines.append(f"LH:{len(covered_lines)}")
            lines.append("end_of_record")

        return "\n".join(lines)
