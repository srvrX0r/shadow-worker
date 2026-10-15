"""The console script must import."""

from shadow_worker.cli import main


def test_cli_entrypoint_imports():
    assert callable(main)
