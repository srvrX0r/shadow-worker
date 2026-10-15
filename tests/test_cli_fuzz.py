"""The fuzzing CLI commands must drive the real protocol fuzzer API.

These commands previously called an imagined API (``base_url=`` constructor
arguments and ``fuzz_endpoint``/``introspect``/``fuzz_all_endpoints`` methods)
that does not exist, so every invocation raised ``TypeError``/``AttributeError``.
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadow_worker import cli
from shadow_worker.fuzzing.protocols import ProtocolFuzzResult


class _RecordingFuzzer:
    """Stand-in for a protocol fuzzer that records how it was driven."""

    instances: list["_RecordingFuzzer"] = []

    def __init__(self, config):
        self.config = config
        self.calls: list[dict] = []
        _RecordingFuzzer.instances.append(self)

    async def fuzz(self, **kwargs) -> ProtocolFuzzResult:
        self.calls.append(kwargs)
        result = ProtocolFuzzResult(target=kwargs.get("target", ""), protocol="recording")
        result.requests_sent = 1
        return result


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    path = tmp_path / "shadow-config.yaml"
    path.write_text(
        "authorization_confirmed: true\n"
        "targets:\n"
        "  domains: ['example.com']\n"
    )
    return path


def _invoke(config_file: Path, monkeypatch, *args: str):
    _RecordingFuzzer.instances = []
    for name in ("HTTPFuzzer", "GraphQLFuzzer", "RESTFuzzer"):
        monkeypatch.setattr(cli, name, _RecordingFuzzer)
    runner = CliRunner()
    return runner.invoke(cli.main, ["-c", str(config_file), *args])


def test_fuzz_http_uses_real_api(config_file, monkeypatch):
    result = _invoke(
        config_file, monkeypatch,
        "fuzz", "http", "https://example.com/api/users",
        "-i", "7", "-d", "3", "-t", "1500",
    )

    assert result.exit_code == 0, result.output
    fuzzer = _RecordingFuzzer.instances[-1]
    assert fuzzer.config.max_iterations == 7
    assert fuzzer.config.input_timeout_ms == 1500

    call = fuzzer.calls[-1]
    assert call["target"] == "https://example.com"
    assert call["endpoints"] == ["/api/users"]
    assert call["duration_seconds"] == 3
    assert call["method"] == "GET"


def test_fuzz_graphql_uses_real_api(config_file, monkeypatch):
    result = _invoke(
        config_file, monkeypatch,
        "fuzz", "graphql", "https://example.com/graphql",
        "-d", "2", "--no-introspect", "--dos-test",
    )

    assert result.exit_code == 0, result.output
    call = _RecordingFuzzer.instances[-1].calls[-1]
    assert call["target"] == "https://example.com/graphql"
    assert call["duration_seconds"] == 2
    assert call["introspect"] is False
    assert call["test_dos"] is True


def test_fuzz_api_uses_real_api(config_file, monkeypatch, tmp_path):
    spec = tmp_path / "openapi.json"
    spec.write_text(json.dumps({"paths": {"/api/users": {"get": {}}}}))

    result = _invoke(
        config_file, monkeypatch,
        "fuzz", "api", str(spec),
        "-u", "https://example.com", "-d", "2", "--idor-test",
    )

    assert result.exit_code == 0, result.output
    call = _RecordingFuzzer.instances[-1].calls[-1]
    assert call["target"] == "https://example.com"
    assert call["duration_seconds"] == 2
    assert "/api/users" in call["openapi_spec"]["paths"]
    assert call["test_idor"] is True
