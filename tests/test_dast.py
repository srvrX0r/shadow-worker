"""Regression tests for DAST form parsing."""

from shadow_worker.scanners.dast import FormParser


def test_form_parser_handles_valueless_attributes():
    """HTML attributes without a value must not crash the parser."""
    parser = FormParser()
    parser.feed("<form method action><input name type value></form>")

    assert len(parser.forms) == 1
    form = parser.forms[0]
    assert form["method"] == "GET"
    assert form["action"] == ""
    assert form["inputs"][0] == {"name": "", "type": "text", "value": ""}


def test_form_parser_reads_normal_attributes():
    parser = FormParser()
    parser.feed(
        '<form method="post" action="/login">'
        '<input name="user" type="text" value="x"></form>'
    )

    form = parser.forms[0]
    assert form["method"] == "POST"
    assert form["action"] == "/login"
    assert form["inputs"][0] == {"name": "user", "type": "text", "value": "x"}


def test_form_parser_handles_valueless_links_and_scripts():
    parser = FormParser()
    parser.feed('<a href><script src></script>')

    assert parser.links == []
    assert parser.scripts == []
