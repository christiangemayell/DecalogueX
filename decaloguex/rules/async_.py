"""
async_.py: Unhandled Async Error Boundaries (rules ASYNC-001 to ASYNC-004).

(The file is called async_.py because `async` is a reserved word in Python,
so `import async` would be a syntax error. A trailing _ is the usual way
around that.)

"Async" code runs in the background and finishes later. When it fails, the
error needs somewhere to go. AI tools often forget to give it one:

ASYNC-001  JavaScript: an Express route marked `async` with no try/catch.
           If the database call inside fails, Express 4 never hears about
           it. The visitor's page hangs forever, and on Node 15+ the error
           CRASHES THE WHOLE SERVER for everyone.
           Fix: wrap the body in try/catch and pass the error to next(),
           which hands it to Express's error handler.

ASYNC-002  JavaScript: a promise chain with .then() but no .catch():
               fetch(url).then(r => r.json()).then(show);
           If the request fails, nothing handles it.
           Fix: add .catch((err) => console.error(err)) to the end.

ASYNC-003  Python: an `async def` function called WITHOUT `await`:
               send_welcome_email(user)
           This doesn't run the function at all! It only creates a
           "coroutine" object, which Python throws away with a warning.
           Fix: add `await` (or asyncio.run() at the top level of a script).

ASYNC-004  Python: asyncio.create_task(...) whose result is thrown away.
           Python only keeps a weak reference to running tasks, so the task
           can be garbage-collected and vanish halfway through.
           Fix: keep the task in a set until it finishes (the pattern from
           Python's own asyncio documentation).

JAVA COMPARISON: a JavaScript promise or Python coroutine is like a
CompletableFuture. Forgetting .catch() is like never calling
.exceptionally(), and forgetting `await` is like never calling .join().
"""

from __future__ import annotations

import re

from tree_sitter import Node

from decaloguex.languages import SourceFile, ancestors, arguments, field, items, line_of, text, walk
from decaloguex.models import Finding, Fix, Severity, TextEdit
from decaloguex.project import ProjectInfo
from decaloguex.rules import secrets
from decaloguex.rules.common import (
    indent_at,
    js_imported_modules,
    line_start,
    newline_of,
    python_import_edit,
    short,
    starts_line,
)


# ===========================================================================
# THE RULE
# ===========================================================================

def check(file: SourceFile, info: ProjectInfo) -> list[Finding]:
    """Scan one file for unhandled async errors. Returns findings; writes nothing."""
    if file.is_python:
        return check_missing_await(file) + check_lost_tasks(file)
    return check_express_routes(file, info) + check_missing_catch(file)


def is_async(function: Node) -> bool:
    """True if a function was declared with the `async` keyword."""
    return any(child.type == "async" for child in function.children)


def is_whole_statement(node: Node) -> tuple[Node, Node] | None:
    """If `node` is a statement made of a single expression, return (statement, expression).

    For the line  `send(email);`  that's the statement and the `send(email)` call.
    A call that is a statement on its own has its result thrown away, which
    is exactly what ASYNC-002/003/004 look for.
    """
    if node.type != "expression_statement" or not node.named_children:
        return None
    return node, node.named_children[0]


# ===========================================================================
# ASYNC-001: Express async routes with no try/catch
# ===========================================================================

ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "all", "use", "options", "head"}
JS_FUNCTIONS = {"arrow_function", "function_expression", "function_declaration", "function",
                "method_definition", "generator_function", "generator_function_declaration"}
ASYNC_001_IMPACT = "An error in this route now reaches Express's error handler instead of crashing the whole server."
ASYNC_001_NOTE = "Wrap the body in try { ... } catch (err) { next(err); }."


def check_express_routes(file: SourceFile, info: ProjectInfo) -> list[Finding]:
    modules = js_imported_modules(file)
    if "express" not in modules and not any(m.startswith("express/") for m in modules):
        return []  # only Express has this problem; Fastify, Koa and Hono catch async errors
    if express_catches_async_errors(file, info):
        return []

    findings = []
    for handler in route_handlers(file):
        body = field(handler, "body")
        if can_fail(body) and not fully_guarded(body):
            findings.append(route_finding(file, handler, body))
    return findings


def express_catches_async_errors(file: SourceFile, info: ProjectInfo) -> bool:
    """True if this project's Express already handles async errors itself.

    * Express 5 catches errors from async routes on its own.
    * The express-async-errors package teaches Express 4 to do the same.
    """
    version = info.js_dependencies.get("express", "")
    # "^5.0.1", "~5.1", ">=5": the first number in the range is the major version.
    major = re.search(r"\d+", version)
    if major and int(major.group(0)) >= 5:
        return True
    return "express-async-errors" in info.js_dependencies or "express-async-errors" in js_imported_modules(file)


def route_handlers(file: SourceFile) -> list[Node]:
    """Async functions passed to app.get(...), router.post(...) and so on."""
    handlers = []
    for call in file.nodes_of("call_expression"):
        function = field(call, "function")
        if function is None or function.type != "member_expression":
            continue
        method = text(field(function, "property"))
        if method not in ROUTE_METHODS:
            continue
        args = arguments(call)
        # Routes start with a path: app.get("/users", ...). app.use() may not.
        starts_with_path = bool(args) and args[0].type in ("string", "template_string")
        if not starts_with_path and method != "use":
            continue
        for arg in args:
            is_function = arg.type in ("arrow_function", "function_expression", "function")
            body = field(arg, "body")
            if is_function and is_async(arg) and body is not None and body.type == "statement_block":
                handlers.append(arg)
    return handlers


def can_fail(node: Node) -> bool:
    """Does this code `await` something or `throw`? (Not counting nested functions.)"""
    failing = ("await_expression", "throw_statement")
    if node.type in failing:
        return True
    return any(n.type in failing for n in own_nodes(node, JS_FUNCTIONS))


def fully_guarded(body: Node) -> bool:
    """True if every statement that can fail is already inside a try/catch."""
    for statement in body.named_children:
        if not can_fail(statement):
            continue
        has_catch = statement.type == "try_statement" and field(statement, "handler") is not None
        if not has_catch:
            return False
    return True


def route_finding(file: SourceFile, handler: Node, body: Node) -> Finding:
    line = line_of(handler)
    title = "Async route can crash the server (no try/catch)"
    params_node = field(handler, "parameters")
    params = items(params_node)
    if params_node is None or len(params) < 2:
        return Finding("ASYNC-001", title, file.path, line, ASYNC_001_IMPACT, note=ASYNC_001_NOTE)

    # Make sure the handler receives `next`.
    edits = []
    if len(params) == 2:
        # (req, res)  ->  (req, res, next)
        if any(node.type == "identifier" and text(node) == "next" for node in walk(handler)):
            # The route already has something called `next` (const next = ...).
            # A second `next` is a "already declared" error when the app starts.
            return Finding("ASYNC-001", title, file.path, line, ASYNC_001_IMPACT,
                           note=ASYNC_001_NOTE + " This route already uses the name `next` for something "
                                                 "else, so give the new third parameter a different name.")
        next_name = "next"
        # TypeScript wants a type on a new parameter. This one needs no import.
        addition = ", next: (err?: unknown) => void" if file.is_typescript else ", next"
        edits.append(TextEdit(file.path, params[-1].end_byte, params[-1].end_byte, addition.encode()))
    else:
        # (req, res, next) or (err, req, res, next): use the last parameter's name.
        last = params[-1]
        name_node = last if last.type == "identifier" else field(last, "pattern")
        if name_node is None or name_node.type != "identifier":
            return Finding("ASYNC-001", title, file.path, line, ASYNC_001_IMPACT, note=ASYNC_001_NOTE)
        next_name = text(name_node)

    edits.extend(wrap_in_try(file, body, next_name))
    fix = Fix(edits=edits, preview_before="async (req, res) => { ... }",
              preview_after=f"try {{ ... }} catch (err) {{ {next_name}(err); }}")
    return Finding("ASYNC-001", title, file.path, line, ASYNC_001_IMPACT, Severity.CRITICAL, fix=fix)


def wrap_in_try(file: SourceFile, body: Node, next_name: str) -> list[TextEdit]:
    """Edits that turn  { a; b; }  into  { try { a; b; } catch (err) { next(err); } }.

    A body on several lines also gets every line indented one level deeper,
    so the result looks hand-written:

        async (req, res, next) => {
          try {
            const user = await db.find(req.params.id);
            res.json(user);
          } catch (err) {
            next(err);
          }
        }
    """
    source = file.source
    nl = newline_of(source)
    open_brace = body.start_byte       # position of the {
    close_brace = body.end_byte - 1    # position of the }
    closing_line = line_start(source, close_brace)
    first_line_end = source.find(b"\n", open_brace)

    # Multi-line means: nothing after the { on its line, and nothing before the } on its line.
    multi_line = (
        first_line_end != -1
        and first_line_end < close_brace
        and source[open_brace + 1 : first_line_end].strip() == b""
        and source[closing_line:close_brace].strip() == b""
    )
    if not multi_line:
        # A short body all on one line gets a one-line wrapper.
        catch = f" }} catch (err) {{ {next_name}(err); }} "  # {{ in an f-string is a literal {
        return [
            TextEdit(file.path, open_brace + 1, open_brace + 1, b" try {"),
            TextEdit(file.path, close_brace, close_brace, catch.encode()),
        ]

    # Work out the indentation: `outer` is the closing }'s, `unit` is one level.
    outer = indent_at(source, close_brace)
    first = body.named_children[0] if body.named_children else None
    inner = indent_at(source, first.start_byte) if first is not None else outer + "  "
    unit = inner[len(outer):] if inner.startswith(outer) and len(inner) > len(outer) else "  "

    edits = [TextEdit(file.path, open_brace + 1, open_brace + 1, f"{nl}{outer}{unit}try {{".encode())]
    edits += indent_lines(file, body, open_brace, closing_line, unit)
    catch = f"{outer}{unit}}} catch (err) {{{nl}{outer}{unit}{unit}{next_name}(err);{nl}{outer}{unit}}}{nl}"
    edits.append(TextEdit(file.path, closing_line, closing_line, catch.encode()))
    return edits


def indent_lines(file: SourceFile, body: Node, start: int, stop: int, unit: str) -> list[TextEdit]:
    """Edits adding `unit` to the start of every line between `start` and `stop`.

    Blank lines are skipped, and so are lines that begin INSIDE a multi-line
    string: adding spaces there would change the string's value (a
    multi-line SQL query, say).
    """
    strings = [(n.start_byte, n.end_byte) for n in walk(body)
               if n.type in ("template_string", "string") and b"\n" in n.text]
    edits = []
    newline = file.source.find(b"\n", start, stop)
    while newline != -1 and newline + 1 < stop:
        line_begins = newline + 1
        is_blank = file.source[line_begins:line_begins + 1] in (b"\n", b"\r")
        in_string = any(s < line_begins < e for s, e in strings)
        if not is_blank and not in_string:
            edits.append(TextEdit(file.path, line_begins, line_begins, unit.encode()))
        newline = file.source.find(b"\n", line_begins, stop)
    return edits


def own_nodes(root: Node, function_types: set[str]):
    """Walk the code under `root` without going inside nested functions."""
    stack = list(reversed(root.children))
    while stack:
        node = stack.pop()
        yield node
        if node.type not in function_types:
            stack.extend(reversed(node.children))


# ===========================================================================
# ASYNC-002: .then() with no .catch()
# ===========================================================================

# Signs that a JavaScript file runs on a SERVER (Node.js), not in a browser:
# loading Node's own modules or server libraries, reading process.env, or
# a Next.js API route (export async function GET).
SERVER_SIGNS = re.compile(
    rb"""\brequire\(\s*['"]"""
    rb"""|\bfrom\s+['"](?:node:|fs|path|os|http|https|child_process|express|fastify|koa|hono|"""
    rb"""@nestjs/|mongoose|pg|mysql2?|@prisma/|sqlite3|better-sqlite3|redis|ioredis)['"/]"""
    rb"""|\bprocess\.(?:env|exit|on|argv)\b|\bmodule\.exports\b"""
    rb"""|\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b"""
)


def runs_on_server(file: SourceFile) -> bool:
    """Does this JavaScript run on a server, where an unhandled error can crash it?

    In a visitor's browser, a promise without .catch() only prints a
    warning in the browser's console. Testing on real projects found
    over a hundred such "problems" in one website's front end, so the
    rule only applies where it really matters: on the server.
    """
    if file.lang.embedded:
        return False  # a <script> in a web page
    if secrets.USE_CLIENT.search(file.source) or secrets.BROWSER_ONLY.search(file.source):
        return False  # marked as browser code, or uses things only a browser has
    return bool(SERVER_SIGNS.search(file.source))


def check_missing_catch(file: SourceFile) -> list[Finding]:
    if not runs_on_server(file):
        return []
    handler = ".catch((err) => console.error(err))"
    findings = []
    for node in file.nodes_of("expression_statement"):
        # Only a promise chain that is a whole statement on its own. If it's
        # returned, awaited or stored, someone else may still handle errors.
        found = is_whole_statement(node)
        if found is None:
            continue
        statement, call = found
        if not unhandled_chain(call):
            continue
        fix = Fix(edits=[TextEdit(file.path, call.end_byte, call.end_byte, handler.encode())],
                  preview_before=short(text(call), 40), preview_after="… " + handler)
        findings.append(Finding(
            "ASYNC-002", "Promise chain has no .catch()", file.path, line_of(statement),
            "If this fails, the error is logged instead of going unhandled (which crashes Node servers).",
            Severity.WARNING, fix=fix,
        ))
    return findings


def unhandled_chain(call: Node) -> bool:
    """True for a .then() chain that nothing catches errors from.

    a.then(f).then(g)          -> True
    a.then(f).catch(h)         -> False   (has .catch)
    a.then(f, onError)         -> False   (the second function handles errors)
    cy.get(x).then(f)          -> False   (Cypress test commands: see below)
    """
    # Walk back along the chain:  a.then(f).finally(g)  ->  ["finally", "then"]
    chain = []
    node = call
    while node is not None and node.type == "call_expression":
        function = field(node, "function")
        if function is None or function.type != "member_expression":
            break
        chain.append((text(field(function, "property")), node))
        node = field(function, "object")

    names = [name for name, _ in chain]
    if not names or names[0] not in ("then", "finally") or "then" not in names:
        return False
    # After the loop, `node` is whatever the chain starts from. Cypress test
    # commands (cy.get(...).then(...)) have .then() but NO .catch(), so
    # adding one would crash the test.
    if text(node) in ("cy", "Cypress"):
        return False
    if "catch" in names:
        return False
    has_error_callback = any(name == "then" and len(arguments(link)) >= 2 for name, link in chain)
    return not has_error_callback


# ===========================================================================
# ASYNC-003: Python async functions called without await
# ===========================================================================

AWAIT_IMPACT = "The code inside this function now actually runs, and its errors are no longer lost."


def check_missing_await(file: SourceFile) -> list[Finding]:
    if not file.nodes_of("function_definition"):
        return []  # no functions at all, so nothing to forget to await

    findings = []
    known: dict = {}  # remembers each scope's functions, so they're only listed once
    for node in file.nodes_of("expression_statement"):
        found = is_whole_statement(node)
        if found is None:
            continue
        statement, call = found
        if call.type != "call":
            continue
        target = async_function_called(file, call, known)
        if target is None or is_generator(target):
            continue
        findings.append(missing_await_finding(file, statement, call, target))
    return findings


def functions_in(scope: Node, known: dict) -> dict[str, list[Node]]:
    """Function name -> the functions with that name directly inside `scope`.

    `known` is a notebook shared across the whole file: a scope (the file,
    or one class) is only searched the first time it's asked about.
    """
    if scope.id not in known:
        by_name: dict[str, list[Node]] = {}
        for child in scope.named_children:
            definition = field(child, "definition") if child.type == "decorated_definition" else child
            if definition is not None and definition.type == "function_definition":
                by_name.setdefault(text(field(definition, "name")), []).append(definition)
        known[scope.id] = by_name
    return known[scope.id]


def async_function_called(file: SourceFile, call: Node, known: dict) -> Node | None:
    """The `async def` that this call runs, or None if we can't be sure.

    Two kinds of call are understood:
        send(x)        a function defined at the top level of this file
        self.send(x)   a method of the class the call is written in

    "The class the call is written in" matters: two classes can each have
    a method called run(), one async and one not. Adding `await` to the
    normal one would crash the program.
    """
    callee = field(call, "function")
    if callee.type == "identifier":
        scope = file.root                                         # the whole file
        name = text(callee)
    elif callee.type == "attribute" and text(field(callee, "object")) == "self":
        owner = next((a for a in ancestors(call) if a.type == "class_definition"), None)
        scope = field(owner, "body")                              # that class's body
        name = text(field(callee, "attribute"))
    else:
        return None
    if scope is None:
        return None

    # Every function with that name in the scope. More than one (the name is
    # defined twice) means we can't tell which one runs.
    matches = functions_in(scope, known).get(name, [])
    if len(matches) == 1 and is_async(matches[0]):
        return matches[0]
    return None


def is_generator(function: Node) -> bool:
    """An `async def` that uses `yield` is an async GENERATOR.

    Calling it hands back a stream of values to loop over with `async for`.
    `await` on it is an error, so it must never be "fixed" that way.
    """
    return any(node.type == "yield" for node in own_nodes(field(function, "body"), {"function_definition", "lambda"}))


def missing_await_finding(file: SourceFile, statement: Node, call: Node, target: Node) -> Finding:
    name = text(field(call, "function"))
    title = f"{name}() is async but isn't awaited, so it never runs"
    line = line_of(statement)
    function = next((a for a in ancestors(statement) if a.type in ("function_definition", "lambda")), None)

    if target.parent is not None and target.parent.type == "decorated_definition":
        # A decorator (the @something line above a function) can swap the
        # function for something else entirely, such as a background-job
        # launcher that must NOT be awaited. Only a person can tell.
        return Finding("ASYNC-003", title, file.path, line, AWAIT_IMPACT, Severity.CRITICAL,
                       note=f"{name}() has a decorator (an @ line above it), which can change how it "
                            "must be called. If it's still a normal async function, add `await` in "
                            "front of this call.")

    if function is not None and function.type == "function_definition" and is_async(function):
        # Inside an async function: just add `await`.
        fix = Fix(edits=[TextEdit(file.path, call.start_byte, call.start_byte, b"await ")],
                  preview_before=short(text(call), 40), preview_after="await " + short(text(call), 40))
        return Finding("ASYNC-003", title, file.path, line, AWAIT_IMPACT, Severity.CRITICAL, fix=fix)

    if function is None:
        # At the top level of a script, asyncio.run() starts the async machinery.
        edits = [
            TextEdit(file.path, call.start_byte, call.start_byte, b"asyncio.run("),
            TextEdit(file.path, call.end_byte, call.end_byte, b")"),
        ]
        import_edit = python_import_edit(file, "asyncio")
        if import_edit is not None:
            edits.append(import_edit)
        fix = Fix(edits=edits, preview_before=short(text(call), 40),
                  preview_after=f"asyncio.run({short(text(call), 40)})")
        return Finding("ASYNC-003", title, file.path, line, AWAIT_IMPACT, Severity.CRITICAL, fix=fix)

    # Inside a normal (non-async) function, `await` isn't allowed.
    return Finding("ASYNC-003", title, file.path, line, AWAIT_IMPACT, Severity.CRITICAL,
                   note="This function isn't async, so it can't use await. Make it `async def` "
                        "(and await it), or call asyncio.run() at the program's entry point.")


# ===========================================================================
# ASYNC-004: Python fire-and-forget tasks
# ===========================================================================

TASK_SET = "_background_tasks"
TASK_IMPACT = "The task is kept alive until it finishes, instead of being garbage-collected halfway through."


def check_lost_tasks(file: SourceFile) -> list[Finding]:
    findings = []
    for node in file.nodes_of("expression_statement"):
        found = is_whole_statement(node)
        if found is None:
            continue
        statement, call = found
        if call.type == "call" and starts_a_task(call):
            findings.append(lost_task_finding(file, statement, call))
    return findings


def starts_a_task(call: Node) -> bool:
    """asyncio.create_task(...), asyncio.ensure_future(...), loop.create_task(...).

    A TaskGroup's tg.create_task() is NOT included: the group holds on to
    its tasks itself, which is exactly the safe pattern.
    """
    function = field(call, "function")
    if function is None or function.type != "attribute":
        return False
    owner = text(field(function, "object"))
    method = text(field(function, "attribute"))
    if owner == "asyncio" and method in ("create_task", "ensure_future"):
        return True
    return method == "create_task" and "loop" in owner.lower()


def lost_task_finding(file: SourceFile, statement: Node, call: Node) -> Finding:
    title = "Background task can disappear before it finishes"
    line = line_of(statement)
    already_defined = any(text(c).startswith(TASK_SET) for c in file.root.children)
    set_edit = None if already_defined else task_set_edit(file)

    if not starts_line(file.source, statement) or (set_edit is None and not already_defined):
        return Finding("ASYNC-004", title, file.path, line, TASK_IMPACT, Severity.WARNING,
                       note="Keep a reference: tasks = set(); t = asyncio.create_task(...); "
                            "tasks.add(t); t.add_done_callback(tasks.discard)")

    # Replace the line with three lines that keep the task in the set.
    nl = newline_of(file.source)
    indent = indent_at(file.source, statement.start_byte)
    replacement = (
        f"_task = {text(call)}{nl}"
        f"{indent}{TASK_SET}.add(_task){nl}"
        f"{indent}_task.add_done_callback({TASK_SET}.discard)"
    )
    edits = [TextEdit(file.path, statement.start_byte, statement.end_byte, replacement.encode())]
    if set_edit is not None:
        edits.append(set_edit)  # identical in every finding, so the engine adds it once
    fix = Fix(edits=edits, preview_before=short(text(call), 40), preview_after=f"_task = … ; {TASK_SET}.add(_task)")
    return Finding("ASYNC-004", title, file.path, line, TASK_IMPACT, Severity.WARNING, fix=fix)


def task_set_edit(file: SourceFile) -> TextEdit | None:
    """An edit that defines the task set just after the imports, or None if there are no imports."""
    imports = [c for c in file.root.children
               if c.type in ("import_statement", "import_from_statement", "future_import_statement")]
    if not imports:
        return None
    nl = newline_of(file.source)
    definition = (
        f"{nl}{nl}"
        f"# Keeps background tasks alive until they finish (added by DecalogueX).{nl}"
        f"# asyncio only holds a weak reference to tasks, so an unreferenced task{nl}"
        f"# can be garbage-collected before it completes.{nl}"
        f"{TASK_SET}: set = set()"
    )
    end = imports[-1].end_byte
    return TextEdit(file.path, end, end, definition.encode())
