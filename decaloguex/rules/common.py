"""
common.py: small editing helpers that several rules share.

Nothing in here knows about secrets, SQL or errors. These are the
"carpentry" jobs: find where a line starts, copy a line's indentation,
add an `import` to a Python file, and so on.

JAVA COMPARISON: think of this as a utility class full of static methods
(like java.util.Collections). Python doesn't need the class: a module's
top-level functions already work that way.
"""

from __future__ import annotations

import re

from tree_sitter import Node

from decaloguex.languages import SourceFile, text
from decaloguex.models import TextEdit

# What visitors see instead of a raw error message.
GENERIC_ERROR_MESSAGE = "Something went wrong. Please try again."


def short(code: str, limit: int = 60) -> str:
    """Squash code onto one line and cut it down for the terminal preview."""
    one_line = " ".join(code.split())  # split() with no argument splits on any whitespace
    if len(one_line) <= limit:
        return one_line
    return one_line[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Lines and indentation
# ---------------------------------------------------------------------------

def line_start(source: bytes, offset: int) -> int:
    """The byte position where the line containing `offset` begins.

    rfind returns -1 when there's no newline before `offset` (we're on the
    first line), and -1 + 1 = 0 is exactly the start of the file.
    """
    return source.rfind(b"\n", 0, offset) + 1


def indent_at(source: bytes, offset: int) -> str:
    """The spaces/tabs at the start of the line containing `offset`."""
    start = line_start(source, offset)
    end = start
    # source[end:end + 1] is a one-byte slice. (source[end] on its own gives
    # an int, because indexing bytes returns the byte's number.)
    while source[end:end + 1] in (b" ", b"\t"):
        end += 1
    return source[start:end].decode("utf-8", errors="replace")


def starts_line(source: bytes, node: Node) -> bool:
    """True if only whitespace comes before the node on its line."""
    before = source[line_start(source, node.start_byte):node.start_byte]
    return before.strip() == b""


def newline_of(source: bytes) -> str:
    """Windows files often end lines with \\r\\n. Match whatever the file uses."""
    return "\r\n" if b"\r\n" in source else "\n"


def insert_line_before(file: SourceFile, statement: Node, code: str) -> TextEdit | None:
    """An edit that puts `code` on its own line just above `statement`.

    The new line copies the statement's indentation. That matters in Python,
    where indentation decides which block the line belongs to.

    Returns None when the statement shares its line with other code, as in
    `except Exception as e: return str(e)`. Adding a line there could move
    code out of its block, so the rule should report instead of fixing.
    """
    if not starts_line(file.source, statement):
        return None
    indent = indent_at(file.source, statement.start_byte)
    # Inserting "code\n<indent>" right before the statement turns
    #     <indent>statement
    # into
    #     <indent>code
    #     <indent>statement
    new_text = code + newline_of(file.source) + indent
    return TextEdit(file.path, statement.start_byte, statement.start_byte, new_text.encode("utf-8"))


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

def python_import_edit(file: SourceFile, module: str) -> TextEdit | None:
    """An edit that adds `import <module>` to a Python file, or None if it's there.

    The import goes after the module's docstring, comments and any
    `from __future__ import` lines, because Python requires __future__
    imports to come first.
    """
    for child in file.root.children:
        if child.type == "import_statement":
            # `import os, sys` holds one dotted_name per module.
            names = [text(part) for part in child.named_children if part.type == "dotted_name"]
            if module in names:
                return None  # already imported

    new_line = f"import {module}{newline_of(file.source)}".encode("utf-8")

    for child in file.root.children:
        is_docstring = child.type == "expression_statement" and child.children[0].type == "string"
        if child.type in ("comment", "future_import_statement") or is_docstring:
            continue  # skip past these
        return TextEdit(file.path, child.start_byte, child.start_byte, new_line)

    # The file has nothing but comments and docstrings: add it at the end.
    end = file.root.end_byte
    needs_newline = file.source and not file.source.endswith(b"\n")
    prefix = newline_of(file.source).encode("utf-8") if needs_newline else b""
    return TextEdit(file.path, end, end, prefix + new_line)


# Matches   require("pg")   from "pg"   import "pg"   and captures the name.
_JS_IMPORT = re.compile(rb"""(?:require\(\s*|\bfrom\s+|\bimport\s+)['"]([^'"\n]+)['"]""")


def js_imported_modules(file: SourceFile) -> set[str]:
    """Every module a JavaScript/TypeScript file loads, e.g. {"express", "pg", "./db"}.

    A regex is good enough here: module names always appear as a quoted
    string right after require( / from / import.
    """
    return {name.decode("utf-8", errors="replace") for name in _JS_IMPORT.findall(file.source)}
