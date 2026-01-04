"""
Differential and Stateful Fuzzing - Advanced fuzzing techniques.

Provides differential testing across implementations and stateful
protocol fuzzing for complex systems.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Sequence
from uuid import UUID, uuid4

import structlog

from shadow_worker.fuzzing.engine import FuzzInput, FuzzResult, FuzzConfig

logger = structlog.get_logger()


class DifferentialResult(str, Enum):
    """Result of differential comparison."""

    MATCH = "match"
    MISMATCH = "mismatch"
    CRASH_DIFF = "crash_diff"
    TIMEOUT_DIFF = "timeout_diff"
    SEMANTIC_DIFF = "semantic_diff"


@dataclass
class DifferentialFinding:
    """A difference found between implementations."""

    id: UUID = field(default_factory=uuid4)
    input_data: bytes = b""
    result_type: DifferentialResult = DifferentialResult.MISMATCH

    # Results from each implementation
    results: dict[str, Any] = field(default_factory=dict)

    # Analysis
    description: str = ""
    severity: str = "medium"
    potential_bug: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": str(self.id),
            "input_hash": hashlib.sha256(self.input_data).hexdigest()[:16],
            "result_type": self.result_type.value,
            "description": self.description,
            "severity": self.severity,
            "potential_bug": self.potential_bug,
        }


class DifferentialFuzzer:
    """
    Differential fuzzer for comparing multiple implementations.

    Finds bugs by detecting differences in behavior between:
    - Multiple implementations of the same spec
    - Different versions of the same software
    - Reference vs optimized implementations
    - Different configurations
    """

    def __init__(
        self,
        implementations: dict[str, Callable[[bytes], Any]],
        config: FuzzConfig | None = None
    ):
        """
        Initialize differential fuzzer.

        Args:
            implementations: Named implementations to compare
            config: Fuzzing configuration
        """
        if len(implementations) < 2:
            raise ValueError("Need at least 2 implementations for differential fuzzing")

        self.implementations = implementations
        self.config = config or FuzzConfig()
        self.findings: list[DifferentialFinding] = []
        self._reference_impl: str | None = None

    def set_reference(self, name: str) -> None:
        """Set reference implementation for comparison."""
        if name not in self.implementations:
            raise ValueError(f"Unknown implementation: {name}")
        self._reference_impl = name

    async def fuzz(
        self,
        initial_corpus: list[bytes] | None = None,
        max_iterations: int | None = None
    ) -> list[DifferentialFinding]:
        """
        Run differential fuzzing.

        Args:
            initial_corpus: Initial seed inputs
            max_iterations: Maximum fuzzing iterations

        Returns:
            List of differential findings
        """
        from shadow_worker.fuzzing.mutators import SmartMutator

        max_iter = max_iterations or self.config.max_iterations
        mutator = SmartMutator()

        # Initialize corpus
        corpus = initial_corpus or [b"FUZZ", b"", b"\x00", b"\xff" * 100]

        logger.info(
            "differential_fuzzing_started",
            implementations=list(self.implementations.keys()),
            corpus_size=len(corpus)
        )

        iteration = 0
        start_time = time.time()

        while iteration < max_iter:
            elapsed = time.time() - start_time
            if elapsed >= self.config.max_time_seconds:
                break

            # Select and mutate input
            base_input = random.choice(corpus)
            test_input = mutator.mutate(base_input)

            # Execute on all implementations
            results = await self._execute_all(test_input)

            # Compare results
            finding = self._compare_results(test_input, results)

            if finding:
                self.findings.append(finding)
                logger.warning(
                    "differential_finding",
                    type=finding.result_type.value,
                    description=finding.description
                )

                # Add interesting input to corpus
                corpus.append(test_input)

            iteration += 1

            if iteration % 1000 == 0:
                logger.info(
                    "differential_progress",
                    iterations=iteration,
                    findings=len(self.findings)
                )

        logger.info(
            "differential_fuzzing_complete",
            iterations=iteration,
            findings=len(self.findings)
        )

        return self.findings

    async def _execute_all(
        self,
        input_data: bytes
    ) -> dict[str, dict[str, Any]]:
        """Execute input on all implementations."""
        results = {}

        for name, impl in self.implementations.items():
            result = {
                "output": None,
                "exception": None,
                "crashed": False,
                "timed_out": False,
                "execution_time": 0.0,
            }

            start_time = time.time()

            try:
                output = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, impl, input_data
                    ),
                    timeout=self.config.input_timeout_ms / 1000
                )
                result["output"] = output

            except asyncio.TimeoutError:
                result["timed_out"] = True

            except Exception as e:
                result["crashed"] = True
                result["exception"] = str(e)

            result["execution_time"] = time.time() - start_time
            results[name] = result

        return results

    def _compare_results(
        self,
        input_data: bytes,
        results: dict[str, dict[str, Any]]
    ) -> DifferentialFinding | None:
        """Compare results from all implementations."""
        impl_names = list(results.keys())

        # Check for crash differences
        crashed = {n for n, r in results.items() if r["crashed"]}
        not_crashed = set(impl_names) - crashed

        if crashed and not_crashed:
            return DifferentialFinding(
                input_data=input_data,
                result_type=DifferentialResult.CRASH_DIFF,
                results=results,
                description=f"Crash in {crashed}, success in {not_crashed}",
                severity="high",
                potential_bug=True,
            )

        # Check for timeout differences
        timed_out = {n for n, r in results.items() if r["timed_out"]}
        not_timed_out = set(impl_names) - timed_out

        if timed_out and not_timed_out:
            return DifferentialFinding(
                input_data=input_data,
                result_type=DifferentialResult.TIMEOUT_DIFF,
                results=results,
                description=f"Timeout in {timed_out}, completed in {not_timed_out}",
                severity="medium",
                potential_bug=True,
            )

        # Compare outputs
        if self._reference_impl:
            ref_output = results[self._reference_impl]["output"]
            for name, result in results.items():
                if name == self._reference_impl:
                    continue
                if not self._outputs_equal(ref_output, result["output"]):
                    return DifferentialFinding(
                        input_data=input_data,
                        result_type=DifferentialResult.MISMATCH,
                        results=results,
                        description=f"Output mismatch: {self._reference_impl} vs {name}",
                        severity="medium",
                        potential_bug=True,
                    )
        else:
            # Compare all pairs
            outputs = [(n, r["output"]) for n, r in results.items() if r["output"] is not None]
            if len(outputs) >= 2:
                first_name, first_output = outputs[0]
                for name, output in outputs[1:]:
                    if not self._outputs_equal(first_output, output):
                        return DifferentialFinding(
                            input_data=input_data,
                            result_type=DifferentialResult.MISMATCH,
                            results=results,
                            description=f"Output mismatch between {first_name} and {name}",
                            severity="medium",
                            potential_bug=True,
                        )

        return None

    def _outputs_equal(self, output1: Any, output2: Any) -> bool:
        """Compare two outputs for equality."""
        # Handle bytes
        if isinstance(output1, bytes) and isinstance(output2, bytes):
            return output1 == output2

        # Handle JSON-serializable
        try:
            return json.dumps(output1, sort_keys=True) == json.dumps(output2, sort_keys=True)
        except (TypeError, ValueError):
            pass

        # Direct comparison
        return output1 == output2


class StateTransition:
    """Represents a state transition in stateful fuzzing."""

    def __init__(
        self,
        action: str,
        params: dict[str, Any] | None = None,
        expected_state: str | None = None
    ):
        self.action = action
        self.params = params or {}
        self.expected_state = expected_state

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "params": self.params,
            "expected_state": self.expected_state,
        }


@dataclass
class StateModel:
    """State machine model for stateful fuzzing."""

    states: set[str] = field(default_factory=set)
    initial_state: str = "init"
    transitions: dict[str, list[StateTransition]] = field(default_factory=dict)

    def add_state(self, state: str) -> None:
        """Add a state to the model."""
        self.states.add(state)

    def add_transition(
        self,
        from_state: str,
        action: str,
        to_state: str,
        params: dict[str, Any] | None = None
    ) -> None:
        """Add a transition between states."""
        self.states.add(from_state)
        self.states.add(to_state)

        if from_state not in self.transitions:
            self.transitions[from_state] = []

        self.transitions[from_state].append(
            StateTransition(action, params, to_state)
        )

    def get_valid_transitions(self, state: str) -> list[StateTransition]:
        """Get valid transitions from a state."""
        return self.transitions.get(state, [])

    def get_random_transition(self, state: str) -> StateTransition | None:
        """Get a random valid transition from a state."""
        transitions = self.get_valid_transitions(state)
        if transitions:
            return random.choice(transitions)
        return None


@dataclass
class StatefulTestCase:
    """A sequence of actions for stateful testing."""

    id: UUID = field(default_factory=uuid4)
    actions: list[StateTransition] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)

    current_state: str = "init"
    is_valid: bool = True
    found_bug: bool = False
    bug_description: str = ""

    def add_action(self, action: StateTransition) -> None:
        """Add an action to the test case."""
        self.actions.append(action)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "actions": [a.to_dict() for a in self.actions],
            "current_state": self.current_state,
            "found_bug": self.found_bug,
            "bug_description": self.bug_description,
        }


class StatefulFuzzer:
    """
    Stateful protocol fuzzer for complex systems.

    Tests sequences of operations to find:
    - State machine violations
    - Race conditions
    - Resource leaks
    - Authentication bypasses
    - Transaction inconsistencies
    """

    def __init__(
        self,
        model: StateModel,
        executor: Callable[[StateTransition, str], tuple[bool, str, Any]],
        config: FuzzConfig | None = None
    ):
        """
        Initialize stateful fuzzer.

        Args:
            model: State machine model
            executor: Function to execute transitions
                      Takes (transition, current_state)
                      Returns (success, new_state, result)
            config: Fuzzing configuration
        """
        self.model = model
        self.executor = executor
        self.config = config or FuzzConfig()
        self.findings: list[StatefulTestCase] = []
        self._state_coverage: dict[str, int] = {}
        self._transition_coverage: dict[str, int] = {}

    async def fuzz(
        self,
        max_iterations: int | None = None,
        max_sequence_length: int = 20
    ) -> list[StatefulTestCase]:
        """
        Run stateful fuzzing.

        Args:
            max_iterations: Maximum number of test sequences
            max_sequence_length: Maximum length of each sequence

        Returns:
            List of bug-finding test cases
        """
        max_iter = max_iterations or self.config.max_iterations

        logger.info(
            "stateful_fuzzing_started",
            states=len(self.model.states),
            initial_state=self.model.initial_state
        )

        iteration = 0
        start_time = time.time()

        while iteration < max_iter:
            elapsed = time.time() - start_time
            if elapsed >= self.config.max_time_seconds:
                break

            # Generate test case
            test_case = await self._generate_test_case(max_sequence_length)

            # Execute test case
            await self._execute_test_case(test_case)

            if test_case.found_bug:
                self.findings.append(test_case)
                logger.warning(
                    "stateful_bug_found",
                    description=test_case.bug_description,
                    sequence_length=len(test_case.actions)
                )

            iteration += 1

            if iteration % 100 == 0:
                logger.info(
                    "stateful_progress",
                    iterations=iteration,
                    findings=len(self.findings),
                    state_coverage=len(self._state_coverage)
                )

        logger.info(
            "stateful_fuzzing_complete",
            iterations=iteration,
            findings=len(self.findings),
            state_coverage=f"{len(self._state_coverage)}/{len(self.model.states)}"
        )

        return self.findings

    async def _generate_test_case(
        self,
        max_length: int
    ) -> StatefulTestCase:
        """Generate a test case using various strategies."""
        strategy = random.choice([
            "random_walk",
            "coverage_guided",
            "targeted",
            "mutation"
        ])

        if strategy == "random_walk":
            return self._generate_random_walk(max_length)
        elif strategy == "coverage_guided":
            return self._generate_coverage_guided(max_length)
        elif strategy == "targeted":
            return self._generate_targeted(max_length)
        else:
            return self._generate_mutation(max_length)

    def _generate_random_walk(self, max_length: int) -> StatefulTestCase:
        """Generate random walk through state machine."""
        test_case = StatefulTestCase(current_state=self.model.initial_state)

        for _ in range(random.randint(1, max_length)):
            transition = self.model.get_random_transition(test_case.current_state)
            if transition:
                # Mutate parameters
                mutated_transition = self._mutate_transition(transition)
                test_case.add_action(mutated_transition)

                if transition.expected_state:
                    test_case.current_state = transition.expected_state
            else:
                break

        return test_case

    def _generate_coverage_guided(self, max_length: int) -> StatefulTestCase:
        """Generate test case prioritizing uncovered states/transitions."""
        test_case = StatefulTestCase(current_state=self.model.initial_state)

        for _ in range(random.randint(1, max_length)):
            transitions = self.model.get_valid_transitions(test_case.current_state)

            if not transitions:
                break

            # Prioritize uncovered transitions
            uncovered = [
                t for t in transitions
                if self._get_transition_key(test_case.current_state, t)
                   not in self._transition_coverage
            ]

            if uncovered:
                transition = random.choice(uncovered)
            else:
                # Weight by inverse coverage
                weights = [
                    1.0 / (1 + self._transition_coverage.get(
                        self._get_transition_key(test_case.current_state, t), 0
                    ))
                    for t in transitions
                ]
                transition = random.choices(transitions, weights=weights, k=1)[0]

            mutated = self._mutate_transition(transition)
            test_case.add_action(mutated)

            if transition.expected_state:
                test_case.current_state = transition.expected_state

        return test_case

    def _generate_targeted(self, max_length: int) -> StatefulTestCase:
        """Generate test case targeting specific vulnerability patterns."""
        test_case = StatefulTestCase(current_state=self.model.initial_state)

        # Target patterns
        patterns = [
            self._pattern_auth_bypass,
            self._pattern_double_action,
            self._pattern_out_of_order,
            self._pattern_resource_exhaustion,
        ]

        pattern = random.choice(patterns)
        return pattern(test_case, max_length)

    def _generate_mutation(self, max_length: int) -> StatefulTestCase:
        """Mutate an existing successful test case."""
        if not self.findings:
            return self._generate_random_walk(max_length)

        # Clone a previous finding
        base = random.choice(self.findings)
        test_case = StatefulTestCase(current_state=self.model.initial_state)

        for action in base.actions:
            if random.random() < 0.3:
                # Mutate this action
                test_case.add_action(self._mutate_transition(action))
            elif random.random() < 0.1:
                # Skip this action
                pass
            elif random.random() < 0.1:
                # Duplicate this action
                test_case.add_action(action)
                test_case.add_action(action)
            else:
                test_case.add_action(action)

        return test_case

    def _mutate_transition(self, transition: StateTransition) -> StateTransition:
        """Mutate a transition's parameters."""
        from shadow_worker.fuzzing.mutators import SmartMutator

        mutator = SmartMutator()
        mutated_params = {}

        for key, value in transition.params.items():
            if random.random() < 0.3:  # 30% chance to mutate each param
                if isinstance(value, bytes):
                    mutated_params[key] = mutator.mutate(value)
                elif isinstance(value, str):
                    mutated_bytes = mutator.mutate(value.encode())
                    mutated_params[key] = mutated_bytes.decode('utf-8', errors='replace')
                elif isinstance(value, int):
                    mutated_params[key] = value + random.randint(-1000, 1000)
                elif isinstance(value, bool):
                    mutated_params[key] = not value
                else:
                    mutated_params[key] = value
            else:
                mutated_params[key] = value

        return StateTransition(
            action=transition.action,
            params=mutated_params,
            expected_state=transition.expected_state
        )

    def _pattern_auth_bypass(
        self,
        test_case: StatefulTestCase,
        max_length: int
    ) -> StatefulTestCase:
        """Generate test case targeting auth bypass."""
        # Try to reach authenticated states without authentication
        auth_actions = {"login", "authenticate", "auth", "signin"}
        protected_actions = {"admin", "delete", "update", "create", "write"}

        # Skip auth and go directly to protected actions
        for state in self.model.states:
            transitions = self.model.get_valid_transitions(state)
            for t in transitions:
                if any(p in t.action.lower() for p in protected_actions):
                    test_case.add_action(self._mutate_transition(t))
                    if len(test_case.actions) >= max_length:
                        return test_case

        return test_case

    def _pattern_double_action(
        self,
        test_case: StatefulTestCase,
        max_length: int
    ) -> StatefulTestCase:
        """Generate test case with repeated actions (double-spend, etc.)."""
        # Execute same action multiple times
        transitions = self.model.get_valid_transitions(test_case.current_state)

        if transitions:
            action = random.choice(transitions)
            repeat_count = random.randint(2, 5)

            for _ in range(repeat_count):
                test_case.add_action(self._mutate_transition(action))

        return test_case

    def _pattern_out_of_order(
        self,
        test_case: StatefulTestCase,
        max_length: int
    ) -> StatefulTestCase:
        """Generate test case with out-of-order actions."""
        # Collect some valid actions
        all_actions = []
        for state in self.model.states:
            all_actions.extend(self.model.get_valid_transitions(state))

        # Execute in random order
        random.shuffle(all_actions)

        for action in all_actions[:max_length]:
            test_case.add_action(self._mutate_transition(action))

        return test_case

    def _pattern_resource_exhaustion(
        self,
        test_case: StatefulTestCase,
        max_length: int
    ) -> StatefulTestCase:
        """Generate test case for resource exhaustion."""
        # Find create/allocate actions and repeat many times
        create_keywords = {"create", "new", "allocate", "open", "start"}

        transitions = self.model.get_valid_transitions(test_case.current_state)
        create_actions = [
            t for t in transitions
            if any(k in t.action.lower() for k in create_keywords)
        ]

        if create_actions:
            action = random.choice(create_actions)
            for _ in range(max_length):
                test_case.add_action(self._mutate_transition(action))

        return test_case

    async def _execute_test_case(self, test_case: StatefulTestCase) -> None:
        """Execute a test case and check for bugs."""
        current_state = self.model.initial_state

        for i, action in enumerate(test_case.actions):
            try:
                success, new_state, result = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None,
                        self.executor,
                        action,
                        current_state
                    ),
                    timeout=self.config.input_timeout_ms / 1000
                )

                test_case.results.append({
                    "action": action.action,
                    "success": success,
                    "state": new_state,
                    "result": str(result)[:200],
                })

                # Track coverage
                self._state_coverage[new_state] = \
                    self._state_coverage.get(new_state, 0) + 1

                trans_key = self._get_transition_key(current_state, action)
                self._transition_coverage[trans_key] = \
                    self._transition_coverage.get(trans_key, 0) + 1

                # Check for violations
                if action.expected_state and new_state != action.expected_state:
                    test_case.found_bug = True
                    test_case.bug_description = (
                        f"State violation: expected {action.expected_state}, "
                        f"got {new_state} after {action.action}"
                    )
                    return

                current_state = new_state

            except asyncio.TimeoutError:
                test_case.found_bug = True
                test_case.bug_description = f"Timeout during {action.action}"
                return

            except Exception as e:
                test_case.found_bug = True
                test_case.bug_description = f"Crash during {action.action}: {e}"
                return

        test_case.current_state = current_state

    def _get_transition_key(
        self,
        from_state: str,
        transition: StateTransition
    ) -> str:
        """Get unique key for a transition."""
        return f"{from_state}->{transition.action}"

    def get_coverage_report(self) -> dict[str, Any]:
        """Get coverage statistics."""
        total_states = len(self.model.states)
        covered_states = len(self._state_coverage)

        total_transitions = sum(
            len(t) for t in self.model.transitions.values()
        )
        covered_transitions = len(self._transition_coverage)

        return {
            "state_coverage": f"{covered_states}/{total_states}",
            "state_coverage_pct": covered_states / total_states * 100 if total_states > 0 else 0,
            "transition_coverage": f"{covered_transitions}/{total_transitions}",
            "transition_coverage_pct": (
                covered_transitions / total_transitions * 100
                if total_transitions > 0 else 0
            ),
            "most_visited_states": sorted(
                self._state_coverage.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "findings": len(self.findings),
        }


class AFLNetFuzzer:
    """
    Network protocol fuzzer inspired by AFLNet.

    Combines coverage guidance with stateful protocol fuzzing
    for finding bugs in network servers.
    """

    def __init__(
        self,
        host: str,
        port: int,
        protocol: str = "tcp",
        config: FuzzConfig | None = None
    ):
        """
        Initialize network fuzzer.

        Args:
            host: Target host
            port: Target port
            protocol: Protocol type (tcp/udp)
            config: Fuzzing configuration
        """
        self.host = host
        self.port = port
        self.protocol = protocol
        self.config = config or FuzzConfig()

        self._state_sequence: list[bytes] = []
        self._response_map: dict[str, bytes] = {}
        self._findings: list[dict[str, Any]] = []

    async def fuzz(
        self,
        seed_sequences: list[list[bytes]] | None = None,
        max_iterations: int | None = None
    ) -> list[dict[str, Any]]:
        """
        Run network protocol fuzzing.

        Args:
            seed_sequences: Seed message sequences
            max_iterations: Maximum iterations

        Returns:
            List of findings
        """
        from shadow_worker.fuzzing.mutators import SmartMutator

        max_iter = max_iterations or self.config.max_iterations
        mutator = SmartMutator()

        # Initialize with seed sequences
        corpus: list[list[bytes]] = seed_sequences or [[b"HELLO\r\n"]]

        logger.info(
            "aflnet_fuzzing_started",
            host=self.host,
            port=self.port,
            protocol=self.protocol
        )

        iteration = 0
        start_time = time.time()

        while iteration < max_iter:
            elapsed = time.time() - start_time
            if elapsed >= self.config.max_time_seconds:
                break

            # Select sequence from corpus
            sequence = random.choice(corpus)

            # Mutate sequence
            mutated_sequence = self._mutate_sequence(sequence, mutator)

            # Execute
            result = await self._execute_sequence(mutated_sequence)

            if result["crashed"] or result["new_state"]:
                if result["crashed"]:
                    self._findings.append({
                        "type": "crash",
                        "sequence": [m.hex() for m in mutated_sequence],
                        "response": result.get("last_response", b"").hex(),
                    })
                    logger.warning("aflnet_crash_found")

                if result["new_state"]:
                    corpus.append(mutated_sequence)

            iteration += 1

            if iteration % 100 == 0:
                logger.info(
                    "aflnet_progress",
                    iterations=iteration,
                    corpus_size=len(corpus),
                    findings=len(self._findings)
                )

        return self._findings

    def _mutate_sequence(
        self,
        sequence: list[bytes],
        mutator: Any
    ) -> list[bytes]:
        """Mutate a message sequence."""
        result = []

        for msg in sequence:
            if random.random() < 0.3:
                # Mutate message
                result.append(mutator.mutate(msg))
            elif random.random() < 0.1:
                # Duplicate message
                result.append(msg)
                result.append(msg)
            elif random.random() < 0.05:
                # Skip message
                pass
            else:
                result.append(msg)

        # Maybe add a new message
        if random.random() < 0.2:
            new_msg = mutator.mutate(random.choice(sequence) if sequence else b"FUZZ")
            insert_pos = random.randint(0, len(result))
            result.insert(insert_pos, new_msg)

        return result if result else [b"FUZZ"]

    async def _execute_sequence(
        self,
        sequence: list[bytes]
    ) -> dict[str, Any]:
        """Execute message sequence against target."""
        result = {
            "crashed": False,
            "new_state": False,
            "responses": [],
            "last_response": b"",
        }

        try:
            if self.protocol == "tcp":
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port),
                    timeout=5.0
                )

                try:
                    for msg in sequence:
                        writer.write(msg)
                        await writer.drain()

                        try:
                            response = await asyncio.wait_for(
                                reader.read(4096),
                                timeout=1.0
                            )
                            result["responses"].append(response)
                            result["last_response"] = response

                            # Check for new state
                            resp_hash = hashlib.md5(response).hexdigest()[:8]
                            if resp_hash not in self._response_map:
                                self._response_map[resp_hash] = response
                                result["new_state"] = True

                        except asyncio.TimeoutError:
                            pass

                finally:
                    writer.close()
                    await writer.wait_closed()

        except ConnectionRefusedError:
            result["crashed"] = True
        except Exception as e:
            if "Connection reset" in str(e) or "Broken pipe" in str(e):
                result["crashed"] = True

        return result
