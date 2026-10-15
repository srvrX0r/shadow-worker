"""Regression tests for protocol fuzzer detection precision."""

from shadow_worker.fuzzing.protocols import GraphQLFuzzer, HTTPFuzzer


class TestXxeDetectionPrecision:
    """Benign HTML must not be reported as XXE."""

    def test_benign_html_is_not_flagged(self):
        fuzzer = HTTPFuzzer()
        response = b"<!DOCTYPE html><html><body>Hello</body></html>"

        assert fuzzer._check_for_vulnerability(b"GET /", response, 200, 5.0) is None

    def test_leaked_file_contents_are_still_detected(self):
        fuzzer = HTTPFuzzer()
        response = b"[fonts]\r\n[extensions]\r\n"

        vuln = fuzzer._check_for_vulnerability(b"GET /", response, 200, 5.0)

        assert vuln is not None
        assert vuln["type"] == "xxe"


class TestGraphQLQueryGeneration:
    """DoS templates must be opt-in via ``include_dos``."""

    def _template_pool(self, monkeypatch, include_dos):
        fuzzer = GraphQLFuzzer()
        captured: dict[str, list[str]] = {}

        def fake_choice(seq):
            captured["seq"] = list(seq)
            return seq[0]

        monkeypatch.setattr(
            "shadow_worker.fuzzing.protocols.random.choice", fake_choice
        )
        fuzzer._generate_query(None, None, include_dos=include_dos)
        return captured["seq"]

    def test_dos_templates_excluded_when_disabled(self, monkeypatch):
        pool = self._template_pool(monkeypatch, include_dos=False)

        assert not any("friends { friends" in q for q in pool)

    def test_dos_templates_included_when_enabled(self, monkeypatch):
        pool = self._template_pool(monkeypatch, include_dos=True)

        assert any("friends { friends" in q for q in pool)
