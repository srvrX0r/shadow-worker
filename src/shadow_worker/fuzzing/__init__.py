"""
Advanced Fuzzing Module - Comprehensive security fuzzing capabilities.

Enterprise-grade fuzzing framework for vulnerability discovery across
all platforms, protocols, and input formats.
"""

from shadow_worker.fuzzing.engine import (
    FuzzConfig,
    FuzzEngine,
    FuzzResult,
    FuzzSession,
    FuzzStrategy,
)
from shadow_worker.fuzzing.mutators import (
    Mutator,
    BitFlipMutator,
    ByteMutator,
    ArithmeticMutator,
    DictionaryMutator,
    StructureMutator,
    GrammarMutator,
    SmartMutator,
)
from shadow_worker.fuzzing.generators import (
    InputGenerator,
    RandomGenerator,
    TemplateGenerator,
    GrammarGenerator,
    CorpusGenerator,
)
from shadow_worker.fuzzing.protocols import (
    HTTPFuzzer,
    WebSocketFuzzer,
    GraphQLFuzzer,
    GRPCFuzzer,
    RESTFuzzer,
)
from shadow_worker.fuzzing.coverage import (
    CoverageTracker,
    CoverageGuided,
    InstrumentationEngine,
)
from shadow_worker.fuzzing.triage import (
    CrashAnalyzer,
    VulnerabilityClassifier,
    ExploitabilityScorer,
)
from shadow_worker.fuzzing.differential import (
    DifferentialFuzzer,
    DifferentialFinding,
    StatefulFuzzer,
    StateModel,
    StatefulTestCase,
    AFLNetFuzzer,
)

__all__ = [
    # Engine
    "FuzzEngine",
    "FuzzConfig",
    "FuzzResult",
    "FuzzSession",
    "FuzzStrategy",
    # Mutators
    "Mutator",
    "BitFlipMutator",
    "ByteMutator",
    "ArithmeticMutator",
    "DictionaryMutator",
    "StructureMutator",
    "GrammarMutator",
    "SmartMutator",
    # Generators
    "InputGenerator",
    "RandomGenerator",
    "TemplateGenerator",
    "GrammarGenerator",
    "CorpusGenerator",
    # Protocol Fuzzers
    "HTTPFuzzer",
    "WebSocketFuzzer",
    "GraphQLFuzzer",
    "GRPCFuzzer",
    "RESTFuzzer",
    # Coverage
    "CoverageTracker",
    "CoverageGuided",
    "InstrumentationEngine",
    # Triage
    "CrashAnalyzer",
    "VulnerabilityClassifier",
    "ExploitabilityScorer",
    # Differential & Stateful
    "DifferentialFuzzer",
    "DifferentialFinding",
    "StatefulFuzzer",
    "StateModel",
    "StatefulTestCase",
    "AFLNetFuzzer",
]
