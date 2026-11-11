"""
sql.py: SQL Query Parameterization (rules SQL-001, SQL-002).

THE PROBLEM
    AI tools often build SQL by gluing user input into the text:

        db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`);
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

    If someone types   ' OR '1'='1   into the email box, the query becomes
    "...WHERE email = '' OR '1'='1'", which matches EVERY user. This is
    "SQL injection", one of the oldest and most damaging web bugs.

THE FIX
    Send the SQL and the values separately. The query gets a placeholder,
    and the database library passes the value on its own, so the value can
    never be read as SQL:

        db.query("SELECT * FROM users WHERE email = ?", [req.body.email]);
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

THE RULES
    SQL-001  A query built from variables is passed straight to a database call.
    SQL-002  The query is stored in a variable first:
                 sql = f"..."
                 cursor.execute(sql)
             Fixed when the variable is used exactly once, in the same block.

WHEN THERE'S NO AUTOMATIC FIX (a "manual step" is shown instead)
    * A table or column name comes from a variable (ORDER BY ${column}).
      Placeholders only hold VALUES, so the name must be checked against a
      fixed list of allowed names. That needs a human.
    * The value is only PART of a quoted string ('%${search}%').
    * We can't tell which database library is used, so we don't know which
      placeholder to write (? or $1 or %s).

HOW IT WORKS, IN 4 STEPS
    1. SPLIT:  break a built-up string into fixed text and variables:
               `... id = ${id}`  ->  ["... id = ", <id>]
    2. CHECK:  is the fixed text SQL? Is it passed to a database call?
    3. REBUILD: put a placeholder where each variable was:
               "... id = ?"  and the values  [id]
    4. EDIT:   replace the string, and add the values to the call.

JAVA COMPARISON: this is the move from Statement to PreparedStatement:
    "SELECT ... WHERE id = " + id   ->   "SELECT ... WHERE id = ?" + stmt.setInt(1, id)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from tree_sitter import Node

from decaloguex.languages import SourceFile, arguments, field, items, line_of, method_name, text, walk
from decaloguex.models import Finding, Fix, Severity, TextEdit
from decaloguex.project import ProjectInfo, normalize_py_name
from decaloguex.rules.common import js_imported_modules, short

IMPACT = "Attackers can't rewrite this query by typing SQL into a form. Values now travel separately from the SQL."


class CannotFix(Exception):
    """Raised when a query is unsafe but can't be rewritten automatically.

    The message becomes the "manual step" shown to the user.

    JAVA COMPARISON: a custom exception. Python has no checked exceptions,
    so nothing forces callers to catch it; the rule just does.
    """


# ===========================================================================
# THE RULE
# ===========================================================================

def check(file: SourceFile, info: ProjectInfo) -> list[Finding]:
    """Scan one file for SQL built from variables. Returns findings; writes nothing."""
    drivers = drivers_in_use(file, info)
    findings = []
    for node in walk(file.root):
        built = sql_string(node, file)          # steps 1 and 2a
        if built is None:
            continue
        finding = query_finding(file, built, drivers)
        if finding is not None:
            findings.append(finding)
    return findings


def query_finding(file: SourceFile, built: Built, drivers: list[Driver]) -> Finding | None:
    line = line_of(built.node)

    # --- SQL-001: the query goes straight into a database call ---------------
    call = query_call(built.node, file)       # step 2b
    if call is not None:
        title = f"SQL injection risk in .{method_name(call)}()"
        try:
            fix = plan_fix(file, built, call, drivers)
        except CannotFix as reason:
            return Finding("SQL-001", title, file.path, line, IMPACT, Severity.CRITICAL, note=str(reason))
        return Finding("SQL-001", title, file.path, line, IMPACT, Severity.CRITICAL, fix=fix)

    # --- SQL-002: the query is stored in a variable first --------------------
    variable = assigned_variable(built.node, file)
    if variable is None:
        return None  # a SQL-looking string that isn't used as a query
    title = f"SQL injection risk in '{variable}'"
    try:
        call = only_query_using(variable, built, file)
        fix = plan_fix(file, built, call, drivers)
    except CannotFix as reason:
        return Finding("SQL-002", title, file.path, line, IMPACT, Severity.CRITICAL, note=str(reason))
    return Finding("SQL-002", title, file.path, line, IMPACT, Severity.CRITICAL, fix=fix)


def plan_fix(file: SourceFile, built: Built, call: Node, drivers: list[Driver]) -> Fix:
    """Steps 3 and 4: build the Fix, or raise CannotFix explaining why not.

    The SQL text is replaced where it's BUILT (built.node), and the values
    are added where it's RUN (after the call's first argument). For SQL-001
    those are the same place; for SQL-002 they're two different lines.
    """
    if built.problem:
        raise CannotFix(built.problem)
    if any(part.text is not None and "\\" in part.text for part in built.parts):
        # Escape sequences like \n or \' mean different things in different
        # kinds of string. Rather than risk changing the query, stop.
        raise CannotFix("The query contains escape sequences. Rewrite it with placeholders by hand.")

    # Check the query's shape first (with ? as a stand-in). "A variable is a
    # table name" is more useful to hear than "unknown library".
    parameterize(built.parts, "?")

    driver = driver_for(method_name(call), drivers)
    if driver is None:
        raise CannotFix(f"Couldn't tell which database library runs .{method_name(call)}(). "
                        "Use its placeholders (? or $1 or %s) and pass the values separately.")

    sql, values = parameterize(built.parts, driver.style)                    # step 3
    literal = python_literal(sql) if file.is_python else js_literal(sql)
    values_code = [text(value) for value in values]

    replace_sql = TextEdit(file.path, built.node.start_byte, built.node.end_byte, literal.encode("utf-8"))
    add_values = values_edit(file, call, driver, values_code)                 # step 4

    # The preview shows the new arguments, e.g.   "... id = ?", [id]
    preview = literal + add_values.replacement.decode("utf-8")
    if driver.shape == "prepare":
        preview = f"{literal} … .{text(field(call.parent, 'property'))}({add_values.replacement.decode()})"
    return Fix(edits=[replace_sql, add_values],
               preview_before=short(text(built.node), 50),
               preview_after=short(preview, 60))


# ===========================================================================
# STEP 1: SPLITTING A BUILT-UP STRING INTO PARTS
# ===========================================================================

@dataclass
class Part:
    """One piece of a string built at runtime. Exactly one field is set:

    text  fixed SQL text, e.g. "SELECT * FROM users WHERE id = "
    expr  a variable or expression, e.g. the node for `req.params.id`
    """

    text: str | None = None
    expr: Node | None = None


@dataclass
class Built:
    """A string-building expression, split into its parts."""

    node: Node           # the whole expression, e.g. the template string
    parts: list[Part]
    problem: str = ""    # set when we can detect it but not rewrite it

    def has_variables(self) -> bool:
        return any(part.expr is not None for part in self.parts)

    def preview_sql(self) -> str:
        """The fixed text with each variable shown as ?, for the "is it SQL?" test."""
        return "".join(part.text if part.text is not None else "?" for part in self.parts)


# The node types that can BUILD a string, per language.
JS_BUILDERS = {"template_string", "binary_expression"}
PY_BUILDERS = {"string", "binary_operator", "concatenated_string", "call"}


def split(node: Node, file: SourceFile) -> Built | None:
    """Split any string-building expression, in either language."""
    if file.is_python:
        return split_python(node, file) if node.type in PY_BUILDERS else None
    return split_js(node, file) if node.type in JS_BUILDERS else None


def source_between(file: SourceFile, start: int, end: int) -> str:
    return file.source[start:end].decode("utf-8", errors="replace")


# --- JavaScript / TypeScript ----------------------------------------------

def split_js(node: Node, file: SourceFile) -> Built | None:
    """Split  `... ${x} ...`  or  "..." + x + "..."  into parts."""
    if node.type == "string":
        return Built(node, [Part(text=source_between(file, node.start_byte + 1, node.end_byte - 1))])

    if node.type == "template_string":
        parts = []
        position = node.start_byte + 1  # just after the opening backtick
        for child in node.children:
            if child.type != "template_substitution":
                continue
            parts.append(Part(text=source_between(file, position, child.start_byte)))  # text before ${
            if not child.named_children:
                return None
            parts.append(Part(expr=child.named_children[0]))  # the expression inside ${ }
            position = child.end_byte
        parts.append(Part(text=source_between(file, position, node.end_byte - 1)))  # text after the last }
        return Built(node, parts)

    if node.type == "binary_expression" and text(field(node, "operator")) == "+":
        parts = []
        for side in (field(node, "left"), field(node, "right")):
            is_stringy = side.type in ("string", "template_string", "binary_expression")
            piece = split_js(side, file) if is_stringy else None
            # A side that isn't a string (a variable, a call...) is one expression part.
            parts += piece.parts if piece else [Part(expr=side)]
        return Built(node, parts)

    return None


# --- Python -----------------------------------------------------------------

def split_python(node: Node, file: SourceFile) -> Built | None:
    """Split a Python string expression into parts.

    Handles the four ways Python code glues strings together:
        f"... {x} ..."            f-strings
        "..." + x                 concatenation
        "... %s ..." % (x,)       old-style % formatting
        "... {} ...".format(x)    str.format
    """
    if node.type == "string":
        return split_python_string(node, file)

    if node.type == "concatenated_string":
        # "SELECT ... " f"WHERE id = {x}"  (two strings side by side are joined)
        pieces = [split_python_string(child, file) for child in node.named_children]
        if None in pieces:
            return None
        parts = [part for piece in pieces for part in piece.parts]  # flatten the lists
        problem = next((piece.problem for piece in pieces if piece.problem), "")
        return Built(node, parts, problem)

    if node.type == "binary_operator":
        operator = text(field(node, "operator"))
        left, right = field(node, "left"), field(node, "right")
        if operator == "+":
            parts, problem = [], ""
            for side in (left, right):
                piece = split_python(side, file) if side.type in PY_BUILDERS else None
                parts += piece.parts if piece else [Part(expr=side)]
                problem = problem or (piece.problem if piece else "")
            return Built(node, parts, problem)
        if operator == "%" and left.type == "string":
            return split_percent_format(node, left, right, file)
        return None

    if node.type == "call":
        # "...".format(a, b): calling .format on a string.
        function = field(node, "function")
        target = field(function, "object")
        if function.type == "attribute" and text(field(function, "attribute")) == "format" \
                and target is not None and target.type == "string":
            return split_str_format(node, target, file)

    return None


def string_prefix(node: Node) -> str | None:
    """A Python string's prefix letters: f"..." -> "f",  rb'...' -> "rb",  "..." -> "".

    Returns None if the node isn't a normal string literal.
    """
    if node.type != "string" or node.child_count < 2:
        return None
    start, end = node.children[0], node.children[-1]
    if start.type != "string_start" or end.type != "string_end":
        return None
    return text(start).lower().rstrip("'\"")


def string_inside(node: Node, file: SourceFile) -> str:
    """The raw source between a Python string's quotes."""
    return source_between(file, node.children[0].end_byte, node.children[-1].start_byte)


def split_python_string(node: Node, file: SourceFile) -> Built | None:
    prefix = string_prefix(node)
    if prefix is None or "b" in prefix:
        return None  # not a string, or bytes (b"...") which isn't a query
    is_f_string = "f" in prefix
    parts = []
    problem = ""

    def add_text(start: int, end: int) -> None:
        # In an f-string, {{ and }} mean a literal { and }. Once it's a plain
        # string again, they go back to single braces.
        value = source_between(file, start, end)
        if is_f_string:
            value = value.replace("{{", "{").replace("}}", "}")
        parts.append(Part(text=value))

    position = node.children[0].end_byte  # just after the opening quote
    for child in node.children[1:-1]:
        if child.type != "interpolation":
            continue
        add_text(position, child.start_byte)
        expression = field(child, "expression")
        if expression is None:
            return None
        if field(child, "type_conversion") or field(child, "format_specifier"):
            # {x!r} or {x:>5} changes how the value is written. A placeholder
            # would pass the raw value instead, so leave it to a human.
            problem = "The query formats a value with !r or :spec. Rewrite it with placeholders by hand."
        parts.append(Part(expr=expression))
        position = child.end_byte
    add_text(position, node.children[-1].start_byte)
    return Built(node, parts, problem)


# %s, %d, %i and %f are positional. %(name)s is named, which we don't rewrite.
PERCENT_SPEC = re.compile(r"%%|%\([^)]*\)[a-z]|%[sdif]|%.?")


def split_percent_format(node: Node, template: Node, values: Node, file: SourceFile) -> Built | None:
    """ "SELECT ... %s" % (a,)   ->   parts """
    prefix = string_prefix(template)
    if prefix is None or "f" in prefix or "b" in prefix:
        return None
    raw = string_inside(template, file)
    # The values: a tuple (a, b) holds several; anything else is one value.
    value_nodes = items(values) if values.type == "tuple" else [values]

    parts = []
    position = 0
    used = 0
    problem = ""
    for match in PERCENT_SPEC.finditer(raw):
        spec = match.group(0)
        if spec == "%%":
            continue  # a literal %, unescaped when the text is copied below
        parts.append(Part(text=raw[position : match.start()].replace("%%", "%")))
        if spec in ("%s", "%d", "%i", "%f") and used < len(value_nodes):
            parts.append(Part(expr=value_nodes[used]))
            used += 1
        else:
            problem = "The query uses named or unusual % placeholders. Rewrite it by hand."
            parts.append(Part(expr=values))
        position = match.end()
    parts.append(Part(text=raw[position:].replace("%%", "%")))

    if used != len(value_nodes) and not problem:
        problem = "The number of % placeholders doesn't match the values. Rewrite it by hand."
    return Built(node, parts, problem)


# {} and {0} are positional; {name} is named, which we don't rewrite.
FORMAT_FIELD = re.compile(r"\{\{|\}\}|\{([^{}]*)\}")


def split_str_format(node: Node, template: Node, file: SourceFile) -> Built | None:
    """ "SELECT ... {}".format(a)   ->   parts """
    prefix = string_prefix(template)
    if prefix is None or "f" in prefix or "b" in prefix:
        return None
    raw = string_inside(template, file)
    args = arguments(node)
    has_keywords = any(arg.type == "keyword_argument" for arg in args)

    def unescape(value: str) -> str:
        return value.replace("{{", "{").replace("}}", "}")

    parts = []
    position = 0
    next_index = 0
    problem = "The query uses .format() with named values. Rewrite it by hand." if has_keywords else ""
    for match in FORMAT_FIELD.finditer(raw):
        if match.group(0) in ("{{", "}}"):
            continue
        parts.append(Part(text=unescape(raw[position : match.start()])))
        name = match.group(1)
        if name == "":                    # {}  -> the next value
            index = next_index
            next_index += 1
        elif name.isdigit():              # {0} -> that value
            index = int(name)
        else:                             # {name}
            index = -1
        if 0 <= index < len(args) and args[index].type != "keyword_argument":
            parts.append(Part(expr=args[index]))
        else:
            problem = problem or "The query uses named .format() fields. Rewrite it by hand."
            parts.append(Part(expr=node))
        position = match.end()
    parts.append(Part(text=unescape(raw[position:])))
    return Built(node, parts, problem)


# ===========================================================================
# STEP 2: IS IT SQL, AND IS IT A QUERY?
# ===========================================================================

# A query must START with a SQL keyword AND have the shape of a real
# statement. Needing both avoids false alarms on ordinary sentences.
SQL_START = re.compile(r"^\s*\(?\s*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|WITH)\b", re.IGNORECASE)
SQL_SHAPE = re.compile(
    r"\bSELECT\b[\s\S]+\bFROM\b"       # [\s\S] means "any character, newlines too"
    r"|\bINSERT\s+INTO\b"
    r"|\bREPLACE\s+INTO\b"
    r"|\bUPDATE\b[\s\S]+\bSET\b"
    r"|\bDELETE\s+FROM\b",
    re.IGNORECASE,
)

# Call names that run SQL, in any library. Dynamic SQL passed to one of
# these is always reported, even when only some libraries can be fixed.
JS_QUERY_METHODS = {"query", "execute", "raw", "all", "get", "run", "each", "exec", "prepare",
                    "unsafe", "$queryRawUnsafe", "$executeRawUnsafe"}
PY_QUERY_METHODS = {"execute", "executemany", "executescript", "raw", "fetch", "fetchrow", "fetchval",
                    "text", "read_sql", "read_sql_query", "exec_driver_sql"}


def looks_like_sql(sql_text: str) -> bool:
    start = SQL_START.search(sql_text)
    if not start or not SQL_SHAPE.search(sql_text):
        return False
    # Real SQL writes keywords as SELECT or select. A capital first letter
    # only ("Select 3 items from the list") is an English sentence.
    keyword = start.group(0).strip(" \t\r\n(")
    return keyword.isupper() or keyword.islower()


def sql_string(node: Node, file: SourceFile) -> Built | None:
    """If `node` is the OUTERMOST expression building a SQL string, split it.

    "Outermost" matters for  "SELECT " + a + " FROM t",  which parses as
    ("SELECT " + a) + " FROM t". Only the outer one should be reported.
    """
    builders = PY_BUILDERS if file.is_python else JS_BUILDERS
    if node.type not in builders:
        return None  # quick exit: most nodes can't build a string at all
    parent = node.parent
    if parent is not None and split(parent, file) is not None:
        return None  # the parent is a bigger piece of the same string
    if node.type == "template_string" and parent is not None and parent.type == "call_expression":
        return None  # a TAGGED template, sql`...${id}`, is the SAFE way to write SQL
    built = split(node, file)
    if built is None or not built.has_variables() or not looks_like_sql(built.preview_sql()):
        return None
    return built


def query_call(arg: Node, file: SourceFile) -> Node | None:
    """If `arg` is the FIRST argument of a database call, return the call."""
    arg_list = arg.parent
    if arg_list is None or arg_list.type not in ("arguments", "argument_list"):
        return None
    args = items(arg_list)
    call = arg_list.parent
    if not args or args[0] != arg:
        return None
    methods = PY_QUERY_METHODS if file.is_python else JS_QUERY_METHODS
    return call if method_name(call) in methods else None


# ===========================================================================
# STEP 3: REBUILDING THE QUERY WITH PLACEHOLDERS
# ===========================================================================

# A placeholder is only allowed where SQL expects a VALUE: right after
# =, <, >, LIKE, LIMIT, OFFSET or BETWEEN. Anywhere else (FROM ${table},
# ORDER BY ${column}) the variable is a NAME, and placeholders can't hold names.
VALUE_BEFORE = re.compile(r"(?:[=<>]|\bLIKE|\bILIKE|\bLIMIT|\bOFFSET|\bBETWEEN)$", re.IGNORECASE)
BETWEEN_AND = re.compile(r"\bBETWEEN\s+(?:\?|\$\d+|%s)\s+AND$", re.IGNORECASE)   # BETWEEN ? AND <here>
VALUES_LIST = re.compile(r"\bVALUES\s*\((?:[^()]*,)?$", re.IGNORECASE)           # VALUES (?, <here>

QUOTED_PART = ("A variable is only part of a quoted SQL string (like '%${x}%'). "
               "Build that value in code first, then pass it as a placeholder.")


def is_value_position(sql_so_far: str) -> bool:
    before = sql_so_far.rstrip()
    return bool(VALUE_BEFORE.search(before) or BETWEEN_AND.search(before) or VALUES_LIST.search(before))


def parameterize(parts: list[Part], style: str) -> tuple[str, list[Node]]:
    """Rebuild the query with placeholders. Returns (sql, values).

    For example the parts of
        `SELECT * FROM users WHERE name = '${name}' AND age > ${age}`
    become
        ("SELECT * FROM users WHERE name = ? AND age > ?", [name, age])

    The quotes around '${name}' disappear: the database quotes a
    placeholder's value itself, so keeping them would search for the
    literal text "?".

    Raises CannotFix if any variable isn't in a value position.
    """
    texts = [part.text for part in parts]  # a copy we can trim quotes from
    sql = ""
    values = []

    for index, part in enumerate(parts):  # enumerate gives (index, item) pairs
        # --- fixed text: copy it across ---
        if part.text is not None:
            piece = texts[index]
            if (style == "?" and "?" in piece) or (style == "$n" and re.search(r"\$\d", piece)):
                raise CannotFix("The query already mixes placeholders with variables. Finish it by hand.")
            # With %s placeholders, a real % must be written %% (psycopg2's rule).
            sql += piece.replace("%", "%%") if style == "%s" else piece
            continue

        # --- a variable: turn it into a placeholder ---
        has_next_text = index + 1 < len(parts) and texts[index + 1] is not None
        following = texts[index + 1] if has_next_text else ""

        # Remove quotes wrapped round the variable:  '${name}'  ->  ?
        if sql.endswith(("'", '"')):
            if not following.startswith(sql[-1]):
                raise CannotFix(QUOTED_PART)
            sql = sql[:-1]
            following = following[1:]
            texts[index + 1] = following
        elif following.startswith(("'", '"')):
            raise CannotFix(QUOTED_PART)

        # An odd number of ' before the variable means we're INSIDE a quoted
        # SQL string, as in  LIKE '%${q}%'. (% here is remainder, like Java's %.)
        if sql.count("'") % 2 == 1:
            raise CannotFix(QUOTED_PART)
        if not is_value_position(sql):
            raise CannotFix("A table or column name comes from a variable. Placeholders can't hold names, "
                            "so check the name against a fixed list of allowed names.")
        if following[:1].isalnum() or following[:1] in ("_", "."):
            raise CannotFix("A variable is glued to other SQL text. Rewrite it by hand.")

        values.append(part.expr)
        if style == "$n":
            sql += f"${len(values)}"  # $1, $2, $3 ...
        else:
            sql += style              # ? or %s
    return sql, values


def js_literal(value: str) -> str:
    """Write `value` as a JavaScript string literal."""
    if "\n" in value:
        # Multi-line SQL stays a template literal, with no ${} left inside.
        return "`" + value.replace("`", "\\`").replace("${", "\\${") + "`"
    return '"' + value.replace('"', '\\"') + '"'


def python_literal(value: str) -> str:
    """Write `value` as a Python string literal."""
    if "\n" not in value:
        return '"' + value.replace('"', '\\"') + '"'
    # Multi-line SQL needs triple quotes that don't clash with the text.
    for quote in ('"""', "'''"):
        if quote not in value and not value.endswith(quote[0]):
            return quote + value + quote
    raise CannotFix("The query text has awkward quotes. Rewrite it by hand.")


# ===========================================================================
# STEP 4: ADDING THE VALUES TO THE CALL
# ===========================================================================

def values_edit(file: SourceFile, call: Node, driver: Driver, values_code: list[str]) -> TextEdit:
    """The edit that passes the values to the database call.

    Raises CannotFix if the call has a shape we don't recognise, for
    example when it already passes some values.
    """
    args = arguments(call)
    joined = ", ".join(values_code)
    extra_args = args[1:]

    if driver.shape == "prepare":
        return prepare_values_edit(file, call, args, joined)

    if driver.shape == "array":
        # A callback function may follow:  db.query(sql, [a], (err, rows) => ...)
        is_callback = len(extra_args) == 1 and extra_args[0].type in ("arrow_function", "function_expression", "function")
        if extra_args and not is_callback:
            raise CannotFix("The call already passes extra arguments. Add the values by hand.")
        added = f", [{joined}]"
    elif extra_args:
        raise CannotFix("The call already passes extra arguments. Add the values by hand.")
    elif driver.shape == "tuple":
        # A one-item tuple needs a trailing comma: (x,) is a tuple, (x) is just x.
        added = f", ({joined},)" if len(values_code) == 1 else f", ({joined})"
    elif driver.shape == "spread":
        added = f", {joined}"
    else:  # "replacements"
        added = f", {{ replacements: [{joined}] }}"  # {{ in an f-string is a literal {

    sql_arg = args[0]
    return TextEdit(file.path, sql_arg.end_byte, sql_arg.end_byte, added.encode("utf-8"))


def prepare_values_edit(file: SourceFile, call: Node, args: list[Node], joined: str) -> TextEdit:
    """better-sqlite3:  db.prepare(sql).get()  ->  db.prepare(sql).get(a, b)"""
    member = call.parent        # db.prepare(sql).get
    runner = member.parent if member is not None else None  # db.prepare(sql).get()
    looks_right = (
        len(args) == 1
        and member is not None and member.type == "member_expression"
        and runner is not None and runner.type == "call_expression"
        and not arguments(runner)
        and text(field(member, "property")) in ("get", "all", "run", "iterate")
    )
    if not looks_right:
        raise CannotFix("Pass the values to .get()/.all()/.run() with ? placeholders.")
    inside_brackets = field(runner, "arguments").start_byte + 1
    return TextEdit(file.path, inside_brackets, inside_brackets, joined.encode("utf-8"))


# ===========================================================================
# DATABASE LIBRARIES AND THEIR PLACEHOLDERS
# ===========================================================================

@dataclass(frozen=True)
class Driver:
    """How one database library wants its values.

    style:  "?"   ->  WHERE id = ?             (MySQL, SQLite, Knex, Sequelize)
            "$n"  ->  WHERE id = $1 AND x = $2  (PostgreSQL, Prisma, asyncpg)
            "%s"  ->  WHERE id = %s            (psycopg2, PyMySQL, Django)

    shape:  where the values go in the call:
            "array"         db.query(sql, [a, b])
            "tuple"         cursor.execute(sql, (a, b))
            "spread"        prisma.$queryRawUnsafe(sql, a, b)
            "replacements"  sequelize.query(sql, { replacements: [a, b] })
            "prepare"       db.prepare(sql).get(a, b)
    """

    label: str
    style: str
    shape: str
    methods: frozenset[str]  # the call names this library uses for queries


# JavaScript/TypeScript, by npm package name.
JS_DRIVERS = {
    "pg": Driver("pg", "$n", "array", frozenset({"query"})),
    "pg-pool": Driver("pg", "$n", "array", frozenset({"query"})),
    "@neondatabase/serverless": Driver("Neon", "$n", "array", frozenset({"query"})),
    "@vercel/postgres": Driver("Vercel Postgres", "$n", "array", frozenset({"query"})),
    "postgres": Driver("postgres.js", "$n", "array", frozenset({"unsafe"})),
    "mysql": Driver("mysql", "?", "array", frozenset({"query"})),
    "mysql2": Driver("mysql2", "?", "array", frozenset({"query", "execute"})),
    "sqlite3": Driver("sqlite3", "?", "array", frozenset({"all", "get", "run", "each"})),
    "better-sqlite3": Driver("better-sqlite3", "?", "prepare", frozenset({"prepare"})),
    "knex": Driver("Knex", "?", "array", frozenset({"raw"})),
    "sequelize": Driver("Sequelize", "?", "replacements", frozenset({"query"})),
    "@prisma/client": Driver("Prisma", "$n", "spread", frozenset({"$queryRawUnsafe", "$executeRawUnsafe"})),
}

# Python, by the module name you `import`.
PY_DRIVERS = {
    "sqlite3": Driver("sqlite3", "?", "tuple", frozenset({"execute"})),
    "aiosqlite": Driver("aiosqlite", "?", "tuple", frozenset({"execute"})),
    "psycopg2": Driver("psycopg2", "%s", "tuple", frozenset({"execute"})),
    "psycopg": Driver("psycopg", "%s", "tuple", frozenset({"execute"})),
    "pymysql": Driver("PyMySQL", "%s", "tuple", frozenset({"execute"})),
    "MySQLdb": Driver("mysqlclient", "%s", "tuple", frozenset({"execute"})),
    "mysql": Driver("mysql-connector", "%s", "tuple", frozenset({"execute"})),
    "aiomysql": Driver("aiomysql", "%s", "tuple", frozenset({"execute"})),
    "django": Driver("Django", "%s", "tuple", frozenset({"execute", "raw"})),
    "asyncpg": Driver("asyncpg", "$n", "spread", frozenset({"execute", "fetch", "fetchrow", "fetchval"})),
}

# requirements.txt names that differ from the module you import.
PY_PACKAGE_TO_MODULE = {
    "psycopg2-binary": "psycopg2",
    "psycopg-binary": "psycopg",
    "mysqlclient": "MySQLdb",
    "mysql-connector-python": "mysql",
}


def drivers_in_use(file: SourceFile, info: ProjectInfo) -> list[Driver]:
    """The database libraries this file uses. If the file doesn't import any
    (a routes file importing your own ./db.js, say), fall back to the
    project's dependency list.
    """
    if file.is_python:
        return python_drivers(file, info)

    packages = set()
    for module in js_imported_modules(file):
        # "mysql2/promise" is still the mysql2 package. Scoped packages like
        # "@prisma/client" keep their first two parts.
        pieces = module.split("/")
        packages.add("/".join(pieces[:2]) if module.startswith("@") else pieces[0])
    found = [JS_DRIVERS[name] for name in sorted(packages) if name in JS_DRIVERS]
    if not found:
        found = [JS_DRIVERS[name] for name in sorted(info.js_dependencies) if name in JS_DRIVERS]
    return found


def python_drivers(file: SourceFile, info: ProjectInfo) -> list[Driver]:
    # `import psycopg2` or `from django.db import connection` -> "psycopg2", "django".
    # (?m) is MULTILINE mode, so ^ matches at the start of every line.
    imported = {m.decode() for m in re.findall(rb"(?m)^\s*(?:import|from)\s+([A-Za-z_]\w*)", file.source)}
    found = [PY_DRIVERS[name] for name in sorted(imported) if name in PY_DRIVERS]
    if found:
        return found

    for package in sorted(info.py_dependencies):
        module = PY_PACKAGE_TO_MODULE.get(package, package)
        for key, driver in PY_DRIVERS.items():
            if normalize_py_name(key) == normalize_py_name(module):
                found.append(driver)
    return found


def driver_for(method: str, drivers: list[Driver]) -> Driver | None:
    """Pick the one library this call belongs to, or None if unsure.

    If a project uses two libraries that both have .query() but different
    placeholders, guessing wrong would break the query, so we don't guess.
    """
    if method in ("$queryRawUnsafe", "$executeRawUnsafe"):
        return JS_DRIVERS["@prisma/client"]  # only Prisma has these names
    matches = [d for d in drivers if method in d.methods]
    # Two libraries that take values the SAME way are fine (pg and Neon, say).
    if len({(d.style, d.shape) for d in matches}) != 1:
        return None
    return matches[0]


# ===========================================================================
# SQL-002: FOLLOWING A QUERY STORED IN A VARIABLE
# ===========================================================================

BLOCKS = {"statement_block", "program", "block", "module"}
ASSIGNMENTS = {"assignment", "augmented_assignment", "assignment_expression",
               "augmented_assignment_expression", "update_expression"}
BUILD_IT_YOURSELF = "Build '{name}' with placeholders and pass the values to the query call."


def assigned_variable(node: Node, file: SourceFile) -> str | None:
    """The variable a built query is stored in:  const sql = `...`  ->  "sql"."""
    parent = node.parent
    if parent is None:
        return None
    # Which kind of parent stores a value, and in which field is the name?
    if file.is_python:
        storing = {"assignment": "left"}
    else:
        storing = {"variable_declarator": "name", "assignment_expression": "left"}
    if parent.type not in storing:
        return None
    if field(parent, "value") != node and field(parent, "right") != node:
        return None
    name = field(parent, storing[parent.type])
    return text(name) if name is not None and name.type == "identifier" else None


def only_query_using(name: str, built: Built, file: SourceFile) -> Node:
    """Find the ONE database call that uses the variable, or raise CannotFix.

    The fix moves the variables from where the query is built to where it's
    run. That's only safe when:
      * both are in the same block, with the call coming after;
      * the variable is used nowhere else (not logged, not changed);
      * nothing in between changes the values being moved.
    """
    found = statement_in_block(built.node)
    if found is None:
        raise CannotFix(BUILD_IT_YOURSELF.format(name=name))
    block, declaration = found

    declared = field(built.node.parent, "name") or field(built.node.parent, "left")
    uses = [use for use in variable_uses(block, name) if use != declared]
    if len(uses) != 1:
        raise CannotFix(f"'{name}' is used in more than one place. "
                        "Build it with placeholders and pass the values to the query call.")

    call = query_call(uses[0], file)
    if call is None:
        raise CannotFix(BUILD_IT_YOURSELF.format(name=name))
    found_call = statement_in_block(call)
    if found_call is None or found_call[0] != block or found_call[1].start_byte <= declaration.start_byte:
        raise CannotFix(BUILD_IT_YOURSELF.format(name=name))

    # Check that nothing between the two statements changes the moved values.
    # {... for ...} builds a set, like a list comprehension does a list.
    moved = {root_variable(part.expr) for part in built.parts if part.expr is not None}
    moved.discard("")  # "" means "not a plain variable"
    for statement in block.named_children:
        between = declaration.end_byte <= statement.start_byte < found_call[1].start_byte
        if not between:
            continue
        for node in walk(statement):
            if node.type in ASSIGNMENTS:
                target = field(node, "left") or field(node, "argument")
                if root_variable(target) in moved:
                    raise CannotFix("A value in the query changes before the query runs. "
                                    "Rewrite it with placeholders by hand.")
    return call


def statement_in_block(node: Node) -> tuple[Node, Node] | None:
    """Climb from `node` to the statement that sits directly in a block.

    Returns (block, statement), or None if there's no such block.
    """
    child = node
    while child.parent is not None:
        if child.parent.type in BLOCKS:
            return child.parent, child
        child = child.parent
    return None


def variable_uses(scope: Node, name: str) -> list[Node]:
    """Every place `name` is used as a variable inside `scope`."""
    uses = []
    for node in walk(scope):
        if node.type not in ("identifier", "shorthand_property_identifier") or text(node) != name:
            continue
        parent = node.parent
        # Python's  obj.sql  contains an identifier `sql`, but it's an attribute, not our variable.
        if parent.type == "attribute" and field(parent, "attribute") == node:
            continue
        if parent.type == "keyword_argument" and field(parent, "name") == node:
            continue
        uses.append(node)
    return uses


def root_variable(node: Node | None) -> str:
    """req.body.email -> "req",   user_id -> "user_id",   str(x) -> "" """
    while node is not None and node.type in ("member_expression", "attribute", "subscript", "subscript_expression"):
        node = field(node, "object") or field(node, "value")
    return text(node) if node is not None and node.type == "identifier" else ""
