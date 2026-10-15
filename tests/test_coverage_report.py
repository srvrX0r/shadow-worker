"""Coverage HTML must survive CSS braces in str.format."""

from shadow_worker.fuzzing.coverage import CoverageData, CoverageReport


def test_coverage_html_renders_counts():
    data = CoverageData()
    data.edges.add((1, 2))
    data.blocks.add(1)
    data.functions.add("main")

    html = CoverageReport(data).to_html()

    assert "Edges: 1" in html
    assert "Blocks: 1" in html
    assert "Functions: 1" in html
    assert "font-family: monospace" in html
