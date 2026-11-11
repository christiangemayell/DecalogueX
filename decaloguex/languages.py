"""
languages.py: which languages DecalogueX understands, and how to read them.

Tree-sitter turns source code into a syntax tree. For example
`const key = "abc";` becomes roughly:

    program
    └── lexical_declaration
        └── variable_declarator
            ├── name: identifier         "key"
            └── value: string            "\"abc\""

Every node knows its type ("string", "identifier", ...), its children, and
its exact start/end byte position in the file. The rules search this tree
instead of the raw text, so they aren't fooled by comments, or by a quote
character inside a string.

JAVA COMPARISON: a Tree-sitter tree is like the AST from JavaParser, except
one library covers all three languages.
"""

from __future__ import annotations

from collections.abc import Iterator  # like java.util.Iterator
from dataclasses import dataclass
from pathlib import Path

import tree_sitter
import tree_sitter_javascript
import tree_sitter_python
import tree_sitter_typescript


# ---------------------------------------------------------------------------
# The languages
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LanguageInfo:
    """A language DecalogueX can scan."""

    name: str    # "javascript", "typescript", "tsx" or "python"
    # Most rules only care about the family: JavaScript and TypeScript are
    # fixed the same way, Python another way.
    family: str  # "js" or "python"
    grammar: tree_sitter.Language


# These are module-level constants, like `static final` fields in Java.
JAVASCRIPT = LanguageInfo("javascript", "js", tree_sitter.Language(tree_sitter_javascript.language()))
TYPESCRIPT = LanguageInfo("typescript", "js", tree_sitter.Language(tree_sitter_typescript.language_typescript()))
TSX = LanguageInfo("tsx", "js", tree_sitter.Language(tree_sitter_typescript.language_tsx()))  # TypeScript + React tags
PYTHON = LanguageInfo("python", "python", tree_sitter.Language(tree_sitter_python.language()))

# File extension -> language. A dict is Python's HashMap, written as {key: value}.
EXTENSIONS: dict[str, LanguageInfo] = {
    ".js": JAVASCRIPT,
    ".jsx": JAVASCRIPT,  # the JavaScript grammar already understands React tags
    ".mjs": JAVASCRIPT,
    ".cjs": JAVASCRIPT,
    ".ts": TYPESCRIPT,
    ".mts": TYPESCRIPT,
    ".cts": TYPESCRIPT,
    ".tsx": TSX,
    ".py": PYTHON,
}


def detect(path: Path) -> LanguageInfo | None:
    """The language of a file, or None if DecalogueX doesn't scan it."""
    # dict.get(key) returns None when the key is missing, instead of throwing.
    return EXTENSIONS.get(path.suffix.lower())


def parse(language: LanguageInfo, source: bytes) -> tree_sitter.Tree:
    """Parse source code (raw bytes) into a syntax tree."""
    return tree_sitter.Parser(language.grammar).parse(source)


def has_syntax_errors(language: LanguageInfo, source: bytes) -> bool:
    """True if the code doesn't parse cleanly.

    This is the "fix safety check": after patching a file, the engine
    re-parses it, and if the patch broke the code it isn't saved.

    Tree-sitter never throws on bad code. It marks broken parts with ERROR
    nodes and sets the root node's has_error flag.
    """
    return parse(language, source).root_node.has_error


# ---------------------------------------------------------------------------
# One file, ready for the rules
# ---------------------------------------------------------------------------

@dataclass
class SourceFile:
    """A source file that has been read and parsed.

    The engine makes ONE of these per file and gives the same object to
    every rule. That way each file is read and parsed only once, and each
    rule takes a single argument instead of four.
    """

    path: Path
    source: bytes        # the raw file contents
    lang: LanguageInfo
    tree: tree_sitter.Tree

    # @property turns a method into something you read like a field:
    # `file.is_python`, no brackets. Like a getter in Java.
    @property
    def is_python(self) -> bool:
        return self.lang.family == "python"

    @property
    def is_typescript(self) -> bool:
        return self.lang.name in ("typescript", "tsx")

    @property
    def root(self) -> tree_sitter.Node:
        return self.tree.root_node


def load(path: Path) -> SourceFile | None:
    """Read and parse a file, or return None if it isn't a supported language."""
    lang = detect(path)
    if lang is None:
        return None
    source = path.read_bytes()
    return SourceFile(path, source, lang, parse(lang, source))


# ---------------------------------------------------------------------------
# Reading the tree
# ---------------------------------------------------------------------------

def walk(root: tree_sitter.Node | None) -> Iterator[tree_sitter.Node]:
    """Visit every node under `root`, parents before children.

    This is a GENERATOR: `yield` hands back one node at a time, and the
    caller just writes `for node in walk(root):`. In Java you'd write a
    whole Iterator class with hasNext()/next().

    It uses a stack instead of recursion because Python only allows about
    1000 nested calls, and deeply nested code could hit that limit.

    walk(None) visits nothing, which saves an `if` wherever a child is optional.
    """
    if root is None:
        return
    stack = [root]
    while stack:  # an empty list counts as False
        node = stack.pop()
        yield node
        # Push children in reverse so the first child comes off the stack first.
        stack.extend(reversed(node.children))


def ancestors(node: tree_sitter.Node) -> Iterator[tree_sitter.Node]:
    """The node's parent, then grandparent, and so on up to the root."""
    current = node.parent
    while current is not None:
        yield current
        current = current.parent


def text(node: tree_sitter.Node | None) -> str:
    """The source code a node covers, as a string ("" for None)."""
    if node is None:
        return ""
    return node.text.decode("utf-8", errors="replace")


def line_of(node: tree_sitter.Node) -> int:
    """The 1-based line number a node starts on (Tree-sitter counts from 0)."""
    return node.start_point.row + 1


def field(node: tree_sitter.Node | None, name: str) -> tree_sitter.Node | None:
    """A labelled child of a node, or None.

    Tree-sitter labels important children with "field names". For a call
    such as db.query(x), field(call, "function") is `db.query` and
    field(call, "arguments") is `(x)`. Unlike node.child_by_field_name(),
    this also accepts None, which saves an `if` at every call site.
    """
    return node.child_by_field_name(name) if node is not None else None


def items(node: tree_sitter.Node | None) -> list[tree_sitter.Node]:
    """The real items inside brackets, without the ( , ) punctuation or comments.

    Works for argument lists (a, b), parameter lists (req, res) and tuples.
    Tree-sitter keeps punctuation as children too. "Named" children are the
    meaningful ones, so filtering on them drops the commas and brackets.
    """
    if node is None:
        return []
    return [child for child in node.named_children if child.type != "comment"]


def arguments(call: tree_sitter.Node | None) -> list[tree_sitter.Node]:
    """The arguments of a call:  db.query(sql, [id])  ->  [sql, [id]]."""
    return items(field(call, "arguments"))


def method_name(call: tree_sitter.Node) -> str:
    """The name being called:  db.query(...) -> "query",  print(...) -> "print"."""
    function = field(call, "function")
    if function is None:
        return ""
    if function.type == "member_expression":      # JavaScript: obj.name
        return text(field(function, "property"))
    if function.type == "attribute":              # Python: obj.name
        return text(field(function, "attribute"))
    return text(function)
