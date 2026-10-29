"""
Fuzzing Engine - Core orchestration for advanced security fuzzing.

Provides intelligent fuzzing with coverage guidance, corpus management,
and adaptive mutation strategies.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import pickle
import random
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, AsyncIterator, Callable, TypeVar
from uuid import UUID, uuid4

import structlog

logger = structlog.get_logger()

T = TypeVar("T")


class FuzzStrategy(str, Enum):
    """Fuzzing strategies."""

    RANDOM = "random"              # Pure random mutation
    MUTATION = "mutation"          # Corpus-based mutation
    GENERATION = "generation"      # Grammar-based generation
    COVERAGE = "coverage"          # Coverage-guided
    DIFFERENTIAL = "differential"  # Differential fuzzing
    DIRECTED = "directed"          # Target-directed fuzzing
    HYBRID = "hybrid"              # Combination of strategies
    EVOLUTIONARY = "evolutionary"  # Genetic algorithm based
    SMART = "smart"                # AI-assisted smart fuzzing


class VulnType(str, Enum):
    """Discovered vulnerability types."""

    CRASH = "crash"
    HANG = "hang"
    MEMORY_LEAK = "memory_leak"
    BUFFER_OVERFLOW = "buffer_overflow"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_DEREF = "null_dereference"
    USE_AFTER_FREE = "use_after_free"
    INJECTION = "injection"
    AUTH_BYPASS = "auth_bypass"
    INFO_DISCLOSURE = "info_disclosure"
    SSRF = "ssrf"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    RACE_CONDITION = "race_condition"
    LOGIC_FLAW = "logic_flaw"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Vulnerability severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class FuzzConfig:
    """Configuration for fuzzing session."""

    # Basic settings
    strategy: FuzzStrategy = FuzzStrategy.HYBRID
    max_iterations: int = 100000
    max_time_seconds: int = 3600
    parallel_workers: int = 4

    # Corpus settings
    corpus_dir: str = "./corpus"
    crashes_dir: str = "./crashes"
    minimize_corpus: bool = True
    corpus_size_limit: int = 10000

    # Mutation settings
    mutation_rate: float = 0.1
    max_mutations_per_input: int = 10
    dictionary_path: str | None = None

    # Coverage settings
    coverage_guided: bool = True
    coverage_threshold: float = 0.8
    track_edge_coverage: bool = True

    # Timeout settings
    input_timeout_ms: int = 5000
    hang_timeout_ms: int = 30000

    # Detection settings
    detect_crashes: bool = True
    detect_hangs: bool = True
    detect_leaks: bool = True
    detect_asan: bool = True
    detect_ubsan: bool = True

    # Reporting
    report_interval_seconds: int = 60
    save_all_inputs: bool = False

    # Smart fuzzing
    use_ai_guidance: bool = False
    learn_from_crashes: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "strategy": self.strategy.value,
            "max_iterations": self.max_iterations,
            "max_time_seconds": self.max_time_seconds,
            "parallel_workers": self.parallel_workers,
            "coverage_guided": self.coverage_guided,
        }


@dataclass
class FuzzInput:
    """A single fuzzing input."""

    id: UUID = field(default_factory=uuid4)
    data: bytes = b""
    metadata: dict[str, Any] = field(default_factory=dict)

    # Origin
    parent_id: UUID | None = None
    generation: int = 0
    mutations_applied: list[str] = field(default_factory=list)

    # Execution results
    executed: bool = False
    execution_time_ms: float = 0.0
    exit_code: int | None = None
    stdout: bytes = b""
    stderr: bytes = b""

    # Coverage
    coverage_hash: str = ""
    new_coverage: bool = False
    edge_count: int = 0

    # Crash info
    is_crash: bool = False
    crash_type: str = ""
    crash_address: str = ""
    crash_stack: list[str] = field(default_factory=list)

    @property
    def hash(self) -> str:
        """Get input hash."""
        return hashlib.sha256(self.data).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "hash": self.hash,
            "size": len(self.data),
            "generation": self.generation,
            "is_crash": self.is_crash,
            "new_coverage": self.new_coverage,
            "execution_time_ms": self.execution_time_ms,
        }


@dataclass
class FuzzResult:
    """Result of a fuzzing session."""

    session_id: UUID = field(default_factory=uuid4)
    target: str = ""
    strategy: FuzzStrategy = FuzzStrategy.HYBRID

    # Timing
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: datetime | None = None
    duration_seconds: float = 0.0

    # Statistics
    total_iterations: int = 0
    total_crashes: int = 0
    unique_crashes: int = 0
    total_hangs: int = 0
    total_coverage_increase: int = 0

    # Coverage
    edge_coverage: float = 0.0
    branch_coverage: float = 0.0
    line_coverage: float = 0.0

    # Findings
    crashes: list[FuzzInput] = field(default_factory=list)
    interesting_inputs: list[FuzzInput] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)

    # Performance
    executions_per_second: float = 0.0
    avg_execution_time_ms: float = 0.0

    def calculate_stats(self) -> None:
        """Calculate final statistics."""
        if self.start_time and self.end_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()
            if self.duration_seconds > 0:
                self.executions_per_second = self.total_iterations / self.duration_seconds

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": str(self.session_id),
            "target": self.target,
            "strategy": self.strategy.value,
            "duration_seconds": self.duration_seconds,
            "total_iterations": self.total_iterations,
            "total_crashes": self.total_crashes,
            "unique_crashes": self.unique_crashes,
            "edge_coverage": self.edge_coverage,
            "executions_per_second": self.executions_per_second,
            "vulnerabilities": self.vulnerabilities,
        }


@dataclass
class Corpus:
    """Manages fuzzing corpus (input seeds)."""

    inputs: list[FuzzInput] = field(default_factory=list)
    coverage_map: dict[str, FuzzInput] = field(default_factory=dict)
    size_limit: int = 10000

    @staticmethod
    def _key_for(input: FuzzInput) -> str:
        """Return the deduplication key for an input.

        Instrumented inputs are keyed by their coverage signature so that
        duplicate coverage is rejected. Seeds without instrumentation (for
        example user-supplied corpora or the built-in default seed) are keyed
        by content hash so they are retained but still deduplicated.
        """
        return input.coverage_hash or f"seed:{input.hash}"

    def add(self, input: FuzzInput) -> bool:
        """Add an input to the corpus.

        Inputs that provide new coverage are retained, and so are seeds that
        have not been executed yet (they have no coverage hash). Rejecting
        hashless inputs previously discarded every user-supplied seed and the
        default seed, leaving the corpus empty.
        """
        key = self._key_for(input)
        if key in self.coverage_map:
            return False

        self.coverage_map[key] = input
        self.inputs.append(input)

        # Enforce size limit
        if len(self.inputs) > self.size_limit:
            self._minimize()

        return True

    def get_random(self) -> FuzzInput | None:
        """Get random input from corpus."""
        if self.inputs:
            return random.choice(self.inputs)
        return None

    def get_weighted_random(self) -> FuzzInput | None:
        """Get random input weighted by coverage contribution."""
        if not self.inputs:
            return None

        # Weight by edge count
        weights = [max(1, inp.edge_count) for inp in self.inputs]
        return random.choices(self.inputs, weights=weights, k=1)[0]

    def _minimize(self) -> None:
        """Minimize corpus while preserving coverage."""
        # Sort by coverage contribution
        sorted_inputs = sorted(
            self.inputs,
            key=lambda x: x.edge_count,
            reverse=True
        )

        # Keep top inputs
        self.inputs = sorted_inputs[:self.size_limit // 2]

        # Rebuild coverage map
        self.coverage_map = {
            self._key_for(inp): inp
            for inp in self.inputs
        }

    def save(self, path: Path) -> None:
        """Save corpus to disk."""
        path.mkdir(parents=True, exist_ok=True)

        for input in self.inputs:
            input_path = path / f"{input.hash}.bin"
            input_path.write_bytes(input.data)

            meta_path = path / f"{input.hash}.json"
            meta_path.write_text(json.dumps(input.to_dict()))

    def load(self, path: Path) -> int:
        """Load corpus from disk."""
        if not path.exists():
            return 0

        count = 0
        for bin_file in path.glob("*.bin"):
            data = bin_file.read_bytes()
            input = FuzzInput(data=data)
            self.inputs.append(input)
            count += 1

        return count


class FuzzSession:
    """
    Manages a fuzzing session with state tracking.

    Supports pause/resume, checkpointing, and distributed fuzzing.
    """

    def __init__(self, config: FuzzConfig, target: str):
        self.config = config
        self.target = target
        self.session_id = uuid4()

        self.corpus = Corpus(size_limit=config.corpus_size_limit)
        self.result = FuzzResult(
            session_id=self.session_id,
            target=target,
            strategy=config.strategy
        )

        self._running = False
        self._paused = False
        self._crash_hashes: set[str] = set()
        self._start_time: datetime | None = None

    @property
    def is_running(self) -> bool:
        return self._running and not self._paused

    def save_checkpoint(self, path: Path) -> None:
        """Save session checkpoint."""
        path.mkdir(parents=True, exist_ok=True)

        checkpoint = {
            "session_id": str(self.session_id),
            "target": self.target,
            "config": self.config.to_dict(),
            "result": self.result.to_dict(),
            "crash_hashes": list(self._crash_hashes),
        }

        with open(path / "checkpoint.json", "w") as f:
            json.dump(checkpoint, f)

        self.corpus.save(path / "corpus")

    @classmethod
    def load_checkpoint(cls, path: Path) -> FuzzSession:
        """Load session from checkpoint."""
        with open(path / "checkpoint.json") as f:
            checkpoint = json.load(f)

        config = FuzzConfig(**checkpoint["config"])
        session = cls(config, checkpoint["target"])
        session.session_id = UUID(checkpoint["session_id"])
        session._crash_hashes = set(checkpoint["crash_hashes"])
        session.corpus.load(path / "corpus")

        return session


class FuzzEngine:
    """
    Core fuzzing engine with advanced capabilities.

    Features:
    - Multiple fuzzing strategies
    - Coverage-guided mutation
    - Intelligent corpus management
    - Crash deduplication and triage
    - Distributed fuzzing support
    - Real-time monitoring
    """

    def __init__(self, config: FuzzConfig | None = None):
        self.config = config or FuzzConfig()
        self._sessions: dict[UUID, FuzzSession] = {}
        self._mutators: list[Any] = []
        self._generators: list[Any] = []
        self._running = False

    async def fuzz(
        self,
        target: Callable[[bytes], Any],
        initial_corpus: list[bytes] | None = None,
        seeds: list[bytes] | None = None,
    ) -> FuzzResult:
        """
        Run fuzzing against a target function.

        Args:
            target: Function to fuzz (takes bytes, may crash)
            initial_corpus: Initial corpus of inputs
            seeds: Seed inputs for mutation

        Returns:
            FuzzResult with findings
        """
        session = FuzzSession(self.config, str(target))
        self._sessions[session.session_id] = session

        # Initialize corpus
        if initial_corpus:
            for data in initial_corpus:
                session.corpus.add(FuzzInput(data=data))

        if seeds:
            for data in seeds:
                session.corpus.add(FuzzInput(data=data))

        # Add default seed if corpus empty
        if not session.corpus.inputs:
            session.corpus.add(FuzzInput(data=b"FUZZ"))

        logger.info(
            "fuzzing_started",
            session_id=str(session.session_id),
            strategy=self.config.strategy.value,
            corpus_size=len(session.corpus.inputs)
        )

        session._running = True
        session._start_time = datetime.utcnow()
        session.result.start_time = session._start_time

        try:
            if self.config.strategy == FuzzStrategy.COVERAGE:
                await self._run_coverage_guided(session, target)
            elif self.config.strategy == FuzzStrategy.EVOLUTIONARY:
                await self._run_evolutionary(session, target)
            elif self.config.strategy == FuzzStrategy.SMART:
                await self._run_smart_fuzzing(session, target)
            else:
                await self._run_hybrid(session, target)

        except asyncio.CancelledError:
            logger.info("fuzzing_cancelled", session_id=str(session.session_id))
        finally:
            session._running = False
            session.result.end_time = datetime.utcnow()
            session.result.calculate_stats()

        logger.info(
            "fuzzing_completed",
            session_id=str(session.session_id),
            iterations=session.result.total_iterations,
            crashes=session.result.unique_crashes,
            coverage=session.result.edge_coverage
        )

        return session.result

    async def _run_hybrid(
        self,
        session: FuzzSession,
        target: Callable[[bytes], Any]
    ) -> None:
        """Run hybrid fuzzing strategy."""
        from shadow_worker.fuzzing.mutators import SmartMutator

        mutator = SmartMutator()
        iteration = 0
        start_time = time.time()

        while self._should_continue(session, iteration, start_time):
            # Get input from corpus
            base_input = session.corpus.get_weighted_random()
            if not base_input:
                base_input = FuzzInput(data=b"FUZZ")

            # Mutate
            mutated_data = mutator.mutate(base_input.data)
            fuzz_input = FuzzInput(
                data=mutated_data,
                parent_id=base_input.id,
                generation=base_input.generation + 1
            )

            # Execute
            await self._execute_input(session, fuzz_input, target)

            # Process result
            if fuzz_input.is_crash:
                await self._handle_crash(session, fuzz_input)
            elif fuzz_input.new_coverage:
                session.corpus.add(fuzz_input)
                session.result.total_coverage_increase += 1

            iteration += 1
            session.result.total_iterations = iteration

            # Periodic reporting
            if iteration % 1000 == 0:
                self._log_progress(session, iteration, start_time)

    async def _run_coverage_guided(
        self,
        session: FuzzSession,
        target: Callable[[bytes], Any]
    ) -> None:
        """Run coverage-guided fuzzing."""
        from shadow_worker.fuzzing.coverage import CoverageGuided
        from shadow_worker.fuzzing.mutators import SmartMutator

        coverage = CoverageGuided()
        mutator = SmartMutator()
        iteration = 0
        start_time = time.time()

        while self._should_continue(session, iteration, start_time):
            # Power schedule: prioritize inputs with more potential
            base_input = self._select_by_power_schedule(session.corpus)

            # Apply mutations based on coverage feedback
            mutation_count = self._calculate_mutation_count(base_input)

            for _ in range(mutation_count):
                mutated_data = mutator.mutate(base_input.data)
                fuzz_input = FuzzInput(
                    data=mutated_data,
                    parent_id=base_input.id,
                    generation=base_input.generation + 1
                )

                # Execute with coverage tracking
                cov_before = coverage.get_edge_count()
                await self._execute_input(session, fuzz_input, target)
                cov_after = coverage.get_edge_count()

                fuzz_input.new_coverage = cov_after > cov_before
                fuzz_input.edge_count = cov_after - cov_before

                if fuzz_input.is_crash:
                    await self._handle_crash(session, fuzz_input)
                elif fuzz_input.new_coverage:
                    session.corpus.add(fuzz_input)
                    session.result.total_coverage_increase += 1

                iteration += 1
                session.result.total_iterations = iteration

    async def _run_evolutionary(
        self,
        session: FuzzSession,
        target: Callable[[bytes], Any]
    ) -> None:
        """Run evolutionary/genetic algorithm fuzzing."""
        from shadow_worker.fuzzing.mutators import SmartMutator

        population_size = 50
        elite_size = 10
        mutator = SmartMutator()

        # Initialize population
        population: list[FuzzInput] = []
        for inp in session.corpus.inputs[:population_size]:
            population.append(inp)

        while len(population) < population_size:
            data = bytes([random.randint(0, 255) for _ in range(random.randint(1, 100))])
            population.append(FuzzInput(data=data))

        iteration = 0
        generation = 0
        start_time = time.time()

        while self._should_continue(session, iteration, start_time):
            # Evaluate fitness
            for individual in population:
                if not individual.executed:
                    await self._execute_input(session, individual, target)
                    iteration += 1
                    session.result.total_iterations = iteration

                    if individual.is_crash:
                        await self._handle_crash(session, individual)

            # Sort by fitness (edge count, execution time)
            population.sort(
                key=lambda x: (x.edge_count, -x.execution_time_ms),
                reverse=True
            )

            # Keep elite
            elite = population[:elite_size]

            # Generate new population
            new_population = elite.copy()

            while len(new_population) < population_size:
                # Tournament selection
                parent1 = self._tournament_select(population)
                parent2 = self._tournament_select(population)

                # Crossover
                child_data = self._crossover(parent1.data, parent2.data)

                # Mutation
                if random.random() < self.config.mutation_rate:
                    child_data = mutator.mutate(child_data)

                child = FuzzInput(
                    data=child_data,
                    generation=generation + 1
                )
                new_population.append(child)

            population = new_population
            generation += 1

            # Add best to corpus
            for inp in elite:
                if inp.new_coverage:
                    session.corpus.add(inp)

    async def _run_smart_fuzzing(
        self,
        session: FuzzSession,
        target: Callable[[bytes], Any]
    ) -> None:
        """Run AI-assisted smart fuzzing."""
        from shadow_worker.fuzzing.mutators import SmartMutator

        mutator = SmartMutator()
        iteration = 0
        start_time = time.time()

        # Track mutation effectiveness
        mutation_stats: dict[str, dict[str, int]] = defaultdict(
            lambda: {"attempts": 0, "successes": 0}
        )

        while self._should_continue(session, iteration, start_time):
            base_input = session.corpus.get_weighted_random()
            if not base_input:
                base_input = FuzzInput(data=b"FUZZ")

            # Select mutation strategy based on historical success
            mutation_type = self._select_mutation_strategy(mutation_stats)

            # Apply mutation
            mutated_data = mutator.mutate(
                base_input.data,
                strategy=mutation_type
            )

            fuzz_input = FuzzInput(
                data=mutated_data,
                parent_id=base_input.id,
                generation=base_input.generation + 1,
                mutations_applied=[mutation_type]
            )

            await self._execute_input(session, fuzz_input, target)

            # Update mutation statistics
            mutation_stats[mutation_type]["attempts"] += 1
            if fuzz_input.new_coverage or fuzz_input.is_crash:
                mutation_stats[mutation_type]["successes"] += 1

            if fuzz_input.is_crash:
                await self._handle_crash(session, fuzz_input)
            elif fuzz_input.new_coverage:
                session.corpus.add(fuzz_input)

            iteration += 1
            session.result.total_iterations = iteration

    async def _execute_input(
        self,
        session: FuzzSession,
        input: FuzzInput,
        target: Callable[[bytes], Any]
    ) -> None:
        """Execute a single fuzzing input."""
        start_time = time.time()

        try:
            # Run with timeout
            result = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None,
                    target,
                    input.data
                ),
                timeout=self.config.input_timeout_ms / 1000
            )
            input.exit_code = 0

        except asyncio.TimeoutError:
            input.exit_code = -1
            session.result.total_hangs += 1

        except Exception as e:
            input.is_crash = True
            input.crash_type = type(e).__name__
            input.exit_code = 1

            # Extract stack trace
            import traceback
            input.crash_stack = traceback.format_exc().split("\n")

        input.execution_time_ms = (time.time() - start_time) * 1000
        input.executed = True

        # Calculate coverage hash
        input.coverage_hash = self._calculate_coverage_hash(input)

        # Check for new coverage
        if input.coverage_hash not in session.corpus.coverage_map:
            input.new_coverage = True

    async def _handle_crash(
        self,
        session: FuzzSession,
        input: FuzzInput
    ) -> None:
        """Handle a crash-inducing input."""
        session.result.total_crashes += 1

        # Deduplicate by crash signature
        crash_sig = self._get_crash_signature(input)

        if crash_sig not in session._crash_hashes:
            session._crash_hashes.add(crash_sig)
            session.result.unique_crashes += 1
            session.result.crashes.append(input)

            # Save crash input
            crash_dir = Path(self.config.crashes_dir)
            crash_dir.mkdir(parents=True, exist_ok=True)

            crash_path = crash_dir / f"crash_{input.hash}.bin"
            crash_path.write_bytes(input.data)

            # Save crash metadata
            meta_path = crash_dir / f"crash_{input.hash}.json"
            meta_path.write_text(json.dumps({
                "id": str(input.id),
                "hash": input.hash,
                "crash_type": input.crash_type,
                "crash_stack": input.crash_stack,
                "generation": input.generation,
                "mutations": input.mutations_applied,
            }, indent=2))

            logger.warning(
                "crash_found",
                hash=input.hash,
                type=input.crash_type,
                unique=session.result.unique_crashes
            )

            # Classify vulnerability
            vuln = self._classify_crash(input)
            if vuln:
                session.result.vulnerabilities.append(vuln)

    def _get_crash_signature(self, input: FuzzInput) -> str:
        """Generate unique signature for crash deduplication."""
        # Use crash type + top 3 stack frames
        sig_parts = [input.crash_type]
        sig_parts.extend(input.crash_stack[:3])
        return hashlib.md5("|".join(sig_parts).encode()).hexdigest()

    def _classify_crash(self, input: FuzzInput) -> dict[str, Any] | None:
        """Classify crash as vulnerability type."""
        vuln_type = VulnType.UNKNOWN
        severity = Severity.MEDIUM

        crash_type = input.crash_type.lower()
        stack_str = " ".join(input.crash_stack).lower()

        # Memory safety issues
        if "segfault" in crash_type or "sigsegv" in crash_type:
            vuln_type = VulnType.BUFFER_OVERFLOW
            severity = Severity.HIGH
        elif "overflow" in crash_type:
            if "integer" in crash_type or "int" in crash_type:
                vuln_type = VulnType.INTEGER_OVERFLOW
                severity = Severity.MEDIUM
            else:
                vuln_type = VulnType.BUFFER_OVERFLOW
                severity = Severity.HIGH
        elif "null" in crash_type or "nullptr" in crash_type:
            vuln_type = VulnType.NULL_DEREF
            severity = Severity.MEDIUM
        elif "free" in crash_type:
            vuln_type = VulnType.USE_AFTER_FREE
            severity = Severity.CRITICAL

        # Injection patterns
        elif "sql" in stack_str:
            vuln_type = VulnType.INJECTION
            severity = Severity.CRITICAL
        elif "command" in stack_str or "exec" in stack_str:
            vuln_type = VulnType.INJECTION
            severity = Severity.CRITICAL

        return {
            "type": vuln_type.value,
            "severity": severity.value,
            "crash_hash": input.hash,
            "crash_type": input.crash_type,
            "input_size": len(input.data),
            "generation": input.generation,
        }

    def _should_continue(
        self,
        session: FuzzSession,
        iteration: int,
        start_time: float
    ) -> bool:
        """Check if fuzzing should continue."""
        if not session._running:
            return False

        if iteration >= self.config.max_iterations:
            return False

        elapsed = time.time() - start_time
        if elapsed >= self.config.max_time_seconds:
            return False

        return True

    def _select_by_power_schedule(self, corpus: Corpus) -> FuzzInput:
        """Select input using power schedule (AFL-style)."""
        if not corpus.inputs:
            return FuzzInput(data=b"FUZZ")

        # Calculate power for each input
        powers = []
        for inp in corpus.inputs:
            # More power to:
            # - Smaller inputs (encourage minimization)
            # - Inputs with more coverage
            # - Newer inputs (explore recent discoveries)
            size_factor = 1.0 / (1 + len(inp.data) / 1000)
            coverage_factor = 1 + inp.edge_count / 10
            age_factor = 1.0 / (1 + inp.generation / 100)

            power = size_factor * coverage_factor * age_factor
            powers.append(power)

        return random.choices(corpus.inputs, weights=powers, k=1)[0]

    def _calculate_mutation_count(self, input: FuzzInput) -> int:
        """Calculate number of mutations to apply."""
        # More mutations for smaller inputs
        base = self.config.max_mutations_per_input
        size_factor = max(1, 100 / (1 + len(input.data)))
        return max(1, int(base * size_factor))

    def _tournament_select(
        self,
        population: list[FuzzInput],
        tournament_size: int = 3
    ) -> FuzzInput:
        """Tournament selection for evolutionary fuzzing."""
        tournament = random.sample(population, min(tournament_size, len(population)))
        return max(tournament, key=lambda x: x.edge_count)

    def _crossover(self, parent1: bytes, parent2: bytes) -> bytes:
        """Crossover two parent inputs."""
        if not parent1 or not parent2:
            return parent1 or parent2 or b""

        # Single-point crossover
        point1 = random.randint(0, len(parent1))
        point2 = random.randint(0, len(parent2))

        return parent1[:point1] + parent2[point2:]

    def _select_mutation_strategy(
        self,
        stats: dict[str, dict[str, int]]
    ) -> str:
        """Select mutation strategy based on historical success."""
        strategies = ["bitflip", "byte", "arithmetic", "dictionary", "splice"]

        if not stats:
            return random.choice(strategies)

        # Calculate success rates
        weights = []
        for strategy in strategies:
            s = stats.get(strategy, {"attempts": 0, "successes": 0})
            if s["attempts"] > 0:
                rate = s["successes"] / s["attempts"]
            else:
                rate = 0.5  # Default for unexplored
            weights.append(rate + 0.1)  # Ensure non-zero

        return random.choices(strategies, weights=weights, k=1)[0]

    def _calculate_coverage_hash(self, input: FuzzInput) -> str:
        """Calculate hash representing code coverage."""
        # In real implementation, this would use actual coverage data
        # For now, use input hash as proxy
        return hashlib.md5(input.data).hexdigest()[:8]

    def _log_progress(
        self,
        session: FuzzSession,
        iteration: int,
        start_time: float
    ) -> None:
        """Log fuzzing progress."""
        elapsed = time.time() - start_time
        exec_per_sec = iteration / elapsed if elapsed > 0 else 0

        logger.info(
            "fuzzing_progress",
            iterations=iteration,
            crashes=session.result.unique_crashes,
            corpus_size=len(session.corpus.inputs),
            exec_per_sec=f"{exec_per_sec:.1f}"
        )
