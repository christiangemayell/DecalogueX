"""
Tests for the engine's fix safety check.
"""

from decaloguex import engine
from decaloguex.models import Finding, Fix, TextEdit


def test_patch_that_breaks_syntax_is_rejected(tmp_path):
    path = tmp_path / "app.js"
    original = b"const a = 1;\n"
    path.write_bytes(original)

    # A deliberately bad patch: replace "1" with an unclosed bracket.
    bad = Finding(
        rule_id="TEST",
        title="bad patch",
        path=path,
        line=1,
        impact="",
        fix=Fix(edits=[TextEdit(path, 10, 11, b"(")]),
    )

    result = engine.apply_fixes([bad])

    assert result.rejected == [bad]
    assert path.read_bytes() == original  # the file was never touched


def test_good_patch_is_saved(tmp_path):
    path = tmp_path / "app.js"
    path.write_bytes(b"const a = 1;\n")

    good = Finding(rule_id="TEST", title="good patch", path=path, line=1, impact="",
                   fix=Fix(edits=[TextEdit(path, 10, 11, b"2")]))

    result = engine.apply_fixes([good])

    assert result.applied == [good]
    assert path.read_bytes() == b"const a = 2;\n"
