"""Regression tests for the fuzzing engine corpus and coverage tracker."""

import asyncio

from shadow_worker.fuzzing.coverage import ShmCoverageTracker
from shadow_worker.fuzzing.engine import (
    Corpus,
    FuzzConfig,
    FuzzEngine,
    FuzzInput,
    FuzzStrategy,
)


class TestCorpusSeeding:
    """Seeds without coverage must still enter the corpus."""

    def test_seed_inputs_without_coverage_are_retained(self):
        corpus = Corpus(size_limit=100)

        assert corpus.add(FuzzInput(data=b"seed-a")) is True
        assert corpus.add(FuzzInput(data=b"seed-b")) is True
        assert len(corpus.inputs) == 2

    def test_identical_seeds_are_deduplicated(self):
        corpus = Corpus(size_limit=100)

        assert corpus.add(FuzzInput(data=b"seed")) is True
        assert corpus.add(FuzzInput(data=b"seed")) is False
        assert len(corpus.inputs) == 1

    def test_inputs_sharing_coverage_are_deduplicated(self):
        corpus = Corpus(size_limit=100)

        first = FuzzInput(data=b"one")
        first.coverage_hash = "cov-1"
        second = FuzzInput(data=b"two")
        second.coverage_hash = "cov-1"

        assert corpus.add(first) is True
        assert corpus.add(second) is False
        assert len(corpus.inputs) == 1

    def test_weighted_random_returns_a_seed(self):
        corpus = Corpus(size_limit=100)
        corpus.add(FuzzInput(data=b"seed"))

        selected = corpus.get_weighted_random()

        assert selected is not None
        assert selected.data == b"seed"


class TestShmCoverageTracker:
    """The shared-memory coverage map must attach instead of raising."""

    def test_attaches_and_reports_zero_coverage(self):
        tracker = ShmCoverageTracker(shm_id=1)

        assert tracker._map is not None
        tracker.reset()
        assert tracker.get_edge_count() == 0


class TestFuzzEngineSeeds:
    """``FuzzEngine.fuzz`` must exercise the supplied initial corpus."""

    def test_initial_corpus_is_executed(self, monkeypatch):
        seen: list[bytes] = []

        def target(data: bytes) -> None:
            seen.append(data)

        # Use an identity mutation so the executed input equals the selected
        # seed; this isolates corpus seeding from mutation behaviour.
        monkeypatch.setattr(
            "shadow_worker.fuzzing.mutators.SmartMutator.mutate",
            lambda self, data, **kwargs: data,
        )

        engine = FuzzEngine(
            FuzzConfig(max_iterations=4, strategy=FuzzStrategy.RANDOM)
        )
        result = asyncio.run(
            engine.fuzz(target, initial_corpus=[b"alpha", b"beta"])
        )

        assert result.total_iterations > 0
        assert set(seen) & {b"alpha", b"beta"}
