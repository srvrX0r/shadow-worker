"""Scanner command construction must stay argv-based."""

from pathlib import Path

from shadow_worker.core.config import SASTConfig
from shadow_worker.scanners.sast import SASTScanner


def test_external_scanners_are_not_shell_strings():
    hostile = Path("/tmp/app; rm -rf /")
    scanner = SASTScanner(
        SASTConfig(
            semgrep_rules=["p/security-audit", "p/owasp-top-ten"],
            exclude_patterns=["**/node_modules/**", "vendor;id"],
        )
    )

    semgrep = scanner._semgrep_argv(hostile)
    bandit = scanner._bandit_argv(hostile)

    assert semgrep[0] == "semgrep"
    assert bandit[0] == "bandit"
    assert semgrep[-1] == str(hostile)
    assert str(hostile) in bandit
    assert all(";" not in part or part.endswith("id") or part == str(hostile) for part in semgrep)
    assert "--config" in semgrep
    assert "p/owasp-top-ten" in semgrep
    joined = " ".join(semgrep)
    assert "rm -rf" not in joined.replace(str(hostile), "")
