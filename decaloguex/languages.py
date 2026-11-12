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
from functools import cached_property
from pathlib import Path

import re

import tree_sitter
import tree_sitter_c_sharp
import tree_sitter_go
import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_kotlin
import tree_sitter_php
import tree_sitter_python
import tree_sitter_ruby
import tree_sitter_swift
import tree_sitter_typescript


# ---------------------------------------------------------------------------
# The languages
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LanguageInfo:
    """A language DecalogueX can scan."""

    name: str      # "javascript", "php", "vue", ...
    # The "family" decides which rules run:
    #   "js" and "python"  have their own detailed rules (secrets.py, sql.py, ...)
    #   every other family  uses the shared rules in rules/other_languages.py
    family: str
    grammar: tree_sitter.Language
    label: str = ""          # the name people know, e.g. "C#" (shown in reports)
    # True for HTML, Vue and Svelte files: the JavaScript lives inside
    # <script> tags, surrounded by page markup. See parse() below.
    embedded: bool = False


def _grammar(language_function) -> tree_sitter.Language:
    return tree_sitter.Language(language_function())


# These are module-level constants, like `static final` fields in Java.
JAVASCRIPT = LanguageInfo("javascript", "js", _grammar(tree_sitter_javascript.language), "JavaScript")
TYPESCRIPT = LanguageInfo("typescript", "js", _grammar(tree_sitter_typescript.language_typescript), "TypeScript")
TSX = LanguageInfo("tsx", "js", _grammar(tree_sitter_typescript.language_tsx), "TypeScript")  # TypeScript + React tags
PYTHON = LanguageInfo("python", "python", _grammar(tree_sitter_python.language), "Python")
PHP = LanguageInfo("php", "php", _grammar(tree_sitter_php.language_php), "PHP")
JAVA = LanguageInfo("java", "java", _grammar(tree_sitter_java.language), "Java")
CSHARP = LanguageInfo("csharp", "csharp", _grammar(tree_sitter_c_sharp.language), "C#")
GO = LanguageInfo("go", "go", _grammar(tree_sitter_go.language), "Go")
RUBY = LanguageInfo("ruby", "ruby", _grammar(tree_sitter_ruby.language), "Ruby")
KOTLIN = LanguageInfo("kotlin", "kotlin", _grammar(tree_sitter_kotlin.language), "Kotlin")
SWIFT = LanguageInfo("swift", "swift", _grammar(tree_sitter_swift.language), "Swift")
# Web pages: the JavaScript inside <script> tags is checked with the JavaScript rules.
HTML = LanguageInfo("html", "js", JAVASCRIPT.grammar, "HTML", embedded=True)
VUE = LanguageInfo("vue", "js", JAVASCRIPT.grammar, "Vue", embedded=True)
SVELTE = LanguageInfo("svelte", "js", JAVASCRIPT.grammar, "Svelte", embedded=True)

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
    ".php": PHP,
    ".java": JAVA,
    ".cs": CSHARP,
    ".go": GO,
    ".rb": RUBY,
    ".kt": KOTLIN,
    ".kts": KOTLIN,
    ".swift": SWIFT,
    ".html": HTML,
    ".htm": HTML,
    ".vue": VUE,
    ".svelte": SVELTE,
}


def detect(path: Path) -> LanguageInfo | None:
    """The language of a file, or None if DecalogueX doesn't scan it."""
    # dict.get(key) returns None when the key is missing, instead of throwing.
    return EXTENSIONS.get(path.suffix.lower())


def parse(language: LanguageInfo, source: bytes) -> tree_sitter.Tree:
    """Parse source code (raw bytes) into a syntax tree.

    For web pages (HTML, Vue, Svelte), only the code inside <script> tags
    is JavaScript. See script_only() for how that's handled.
    """
    if language.embedded:
        grammar = TYPESCRIPT.grammar if _uses_typescript(source) else JAVASCRIPT.grammar
        return tree_sitter.Parser(grammar).parse(script_only(source))
    return tree_sitter.Parser(language.grammar).parse(source)


# <script ...> CONTENT </script>. (?is) means: ignore case, and let . match newlines.
_SCRIPT_TAG = re.compile(rb"(?is)<script\b([^>]*)>(.*?)</script\s*>")


def script_only(source: bytes) -> bytes:
    """Blank out everything that isn't inside a <script> tag.

    Every other character becomes a space (newlines are kept), so the
    result is EXACTLY as long as the original, with every line in the same
    place. That's the trick: the JavaScript rules see plain JavaScript, yet
    every position they report still points at the right spot in the real
    file, so fixes land in the right place.
    """
    keep = bytearray(b" " * len(source))  # bytearray is a changeable byte[]
    for newline in re.finditer(rb"\n", source):
        keep[newline.start()] = ord("\n")
    for match in _SCRIPT_TAG.finditer(source):
        attributes = match.group(1).lower()
        if b"src=" in attributes:
            continue  # <script src="..."> loads a file; there's no code here
        if b"type=" in attributes and not re.search(rb"type=[\"']?(?:text/javascript|module)", attributes):
            continue  # e.g. type="application/ld+json" is data, not code
        start, end = match.span(2)  # where the code inside the tag starts and ends
        keep[start:end] = source[start:end]
    return bytes(keep)


def _uses_typescript(source: bytes) -> bool:
    """Vue and Svelte mark TypeScript with <script lang="ts">."""
    return bool(re.search(rb"(?i)<script\b[^>]*\blang=[\"']?(?:ts|typescript)\b", source))


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

    # @cached_property works out the value the FIRST time it's read, then
    # remembers it. Every rule needs the file's nodes, so listing them once
    # and sharing the list makes scans several times faster.
    @cached_property
    def _listing(self) -> tuple[list[tree_sitter.Node], dict[str, list[int]]]:
        """One walk over the tree that builds two things:

        nodes      every NAMED node, parents before children
        positions  node type -> where nodes of that type sit in `nodes`
                   (an index, like the one at the back of a book)
        """
        nodes: list[tree_sitter.Node] = []
        positions: dict[str, list[int]] = {}
        stack = [self.root]
        while stack:
            node = stack.pop()
            # setdefault returns the list for this type, creating it if needed
            # (Java: computeIfAbsent).
            positions.setdefault(node.type, []).append(len(nodes))
            nodes.append(node)
            stack.extend(reversed(node.named_children))
        return nodes, positions

    @property
    def nodes(self) -> list[tree_sitter.Node]:
        """Every NAMED node in the file, parents before children.

        "Named" nodes are the meaningful ones: strings, calls, statements.
        Punctuation such as ( , ; is left out. No rule looks for it, and
        it makes up about half of all the nodes in a file.
        """
        return self._listing[0]

    @property
    def _positions_by_type(self) -> dict[str, list[int]]:
        return self._listing[1]

    def node_types(self) -> list[str]:
        """Every node type that appears in this file, e.g. ["module", "string", "call"]."""
        return list(self._positions_by_type)

    def nodes_of(self, *types: str) -> list[tree_sitter.Node]:
        """The nodes of the given types, in the order they appear in the file.

        Most rules only care about a few kinds of node. A rule about
        strings asks for file.nodes_of("string") and gets just those,
        instead of checking every node in the file one by one.
        """
        positions = [p for kind in types for p in self._positions_by_type.get(kind, ())]
        if len(types) > 1:
            positions.sort()  # put the different types back into file order
        return [self.nodes[p] for p in positions]


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
