"""
errors.py: Safe Error Masking, the "PII Shield" (rule ERR-001).

THE PROBLEM
    AI tools love sending the raw error back to the browser:

        } catch (err) {
          res.status(500).json({ error: err.message });
        }

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    Error messages leak far more than people expect: SQL queries, table
    names, file paths on the server, and often the personal data (emails,
    names) that was being processed when things broke. ("PII" means
    Personally Identifiable Information.)

THE FIX
    Show visitors a friendly, generic sentence, and log the real error on
    the server, where only you can see it:

        } catch (err) {
          console.error(err);
          res.status(500).json({ error: "Something went wrong. Please try again." });
        }

        except Exception as e:
            logging.exception("Unhandled error")
            return jsonify({"error": "Something went wrong. Please try again."}), 500

    (logging.exception automatically includes the full error details.)

WHAT IS NOT FLAGGED
    * Responses with a 4xx status (400, 404, ...). Those are usually
      deliberate messages for the user, like "Email already taken".
    * (Reported, but not changed:) responses whose status is worked out
      while the app runs, like res.status(err.status || 500). Those send
      the deliberate 404s too, so swapping the message would hide them.
    * Python `except ValueError as e:` and other SPECIFIC error types,
      unless the response is a 5xx. Showing a specific error's message is
      usually on purpose. `except Exception` catches everything, including
      the dangerous surprises.

HOW IT WORKS, IN 4 STEPS
    1. Find a call that sends a response (res.json, jsonify, ...).
    2. Find the error variable it might leak (the `err` in catch (err)).
    3. Find every place the response uses that variable, and grow each one
       to the whole leaking expression: err -> err.message -> `Oops: ${err.message}`.
    4. Replace those with the generic message, and add a log line.
"""

from __future__ import annotations

import re

from tree_sitter import Node

from decaloguex.languages import SourceFile, ancestors, arguments, field, items, line_of, text, walk
from decaloguex.models import Finding, Fix, Severity, TextEdit
from decaloguex.rules.common import GENERIC_ERROR_MESSAGE, insert_line_before, python_import_edit, short

IMPACT = "Visitors no longer see error details, file paths or personal data. The real error is logged on your server."
MESSAGE = '"' + GENERIC_ERROR_MESSAGE + '"'  # the message as code, with its quotes


# ===========================================================================
# THE RULE
# ===========================================================================

def check(file: SourceFile) -> list[Finding]:
    """Scan one file for errors shown to visitors. Returns findings; writes nothing."""
    if file.is_python:
        return check_python(file)
    return check_javascript(file)


def manual(file: SourceFile, line: int, title: str, note: str) -> Finding:
    """A finding we report but can't fix automatically."""
    return Finding("ERR-001", title, file.path, line, IMPACT, Severity.WARNING, note=note)


# Returned by the status helpers when a status IS set, but not as a plain
# number: res.status(err.status || 500). Its value is only known when the
# app runs, so we can't tell a deliberate 404 from a real server error.
DYNAMIC = -1
DYNAMIC_STATUS_NOTE = ("The status code is chosen while the app runs, so this may also send deliberate "
                       "messages like 404 \"Not found\". Send a generic message when the status is 500 "
                       "or more, and log the real error.")


def mentions(code: str, name: str) -> bool:
    """Does this code use the variable `name`? (As a whole word: `e` isn't in `email`.)"""
    return re.search(rf"\b{re.escape(name)}\b", code) is not None


def outermost_only(nodes: list[Node]) -> list[Node]:
    """Drop duplicates, and nodes that sit inside another node in the list.

    If both `err.message` and the template around it are in the list,
    replacing the template already covers the inner one.
    """
    result = []
    for node in nodes:
        inside_another = any(
            other.start_byte <= node.start_byte and node.end_byte <= other.end_byte
            and (other.start_byte, other.end_byte) != (node.start_byte, node.end_byte)
            for other in nodes
        )
        already_added = any((n.start_byte, n.end_byte) == (node.start_byte, node.end_byte) for n in result)
        if not inside_another and not already_added:
            result.append(node)
    return result


# ===========================================================================
# JAVASCRIPT / TYPESCRIPT
# ===========================================================================

# res.send(...), res.json(...), reply.send(...) and friends.
JS_RESPONSE_METHODS = {"send", "json", "jsonp", "end", "write"}
JS_RESPONSE_OBJECTS = {"res", "response", "reply"}
# Next.js and web-standard responses:  NextResponse.json(...), new Response(...)
JS_STATIC_RESPONSES = {"NextResponse", "Response"}
# Wrappers that still show the error:  String(err), JSON.stringify(err)
JS_STRINGIFIERS = {"String", "JSON.stringify"}
# Already logged?  console.error(err), logger.error(err) ...
JS_LOGGER = re.compile(r"^(?:console|logger|log|winston|pino|Sentry)\.")
JS_FUNCTIONS = ("arrow_function", "function_expression", "function_declaration", "function")


def check_javascript(file: SourceFile) -> list[Finding]:
    findings = []
    for call in file.nodes_of("call_expression", "new_expression"):
        # Step 1: a call that sends a response...
        if not is_js_response(call):
            continue
        status = js_status(call)
        if status is not None and 400 <= status < 500:
            continue  # a deliberate message for the user
        # Step 2: ...inside code that has caught an error...
        found = js_error_variable(call)
        if found is None:
            continue
        error_name, handler = found
        # Step 3: ...and the response uses that error.
        uses = [
            node for node in walk(field(call, "arguments"))
            if node.type in ("identifier", "shorthand_property_identifier") and text(node) == error_name
        ]
        if not uses:
            continue
        if status == DYNAMIC and status_comes_from_error(call, error_name):
            continue
        if status == DYNAMIC:
            findings.append(manual(file, line_of(call), f"Error details sent to visitors ({error_name})",
                                   DYNAMIC_STATUS_NOTE))
        else:
            findings.append(js_finding(file, call, error_name, handler, uses))
    return findings


def js_finding(file: SourceFile, call: Node, error_name: str, handler: Node, uses: list[Node]) -> Finding:
    """Step 4: replace the leaks and add console.error(err)."""
    line = line_of(call)
    title = f"Error details sent to visitors ({error_name})"
    edits = js_mask_edits(file, call, uses)

    if not js_already_logged(handler, error_name):
        log = f"console.error({error_name});"
        statement = js_statement(call)
        if statement is not None:
            insert = insert_line_before(file, statement, log)
            if insert is None:
                return manual(file, line, title,
                              f"Log the error with console.error({error_name}) and send a generic message instead.")
            edits.append(insert)
        else:
            # An arrow function with no { } body:  err => res.json(err.message)
            # Give it a body so there's room for the log line:
            #   err => { console.error(err); return res.json("..."); }
            # next(iterator, None) gives the first match, or None if there isn't one.
            arrow = next((a for a in ancestors(call) if a.type == "arrow_function"), None)
            body = field(arrow, "body")
            if body is None:
                return manual(file, line, title,
                              f"Log the error with console.error({error_name}) and send a generic message instead.")
            edits.append(TextEdit(file.path, body.start_byte, body.start_byte, f"{{ {log} return ".encode()))
            edits.append(TextEdit(file.path, body.end_byte, body.end_byte, b"; }"))

    fix = Fix(edits=edits, preview_before=short(text(call), 45),
              preview_after=f"generic message + console.error({error_name})")
    return Finding("ERR-001", title, file.path, line, IMPACT, Severity.WARNING, fix=fix)


def js_mask_edits(file: SourceFile, call: Node, uses: list[Node]) -> list[TextEdit]:
    """Edits that swap each leaking expression for the generic message."""
    edits = []
    # { err } is short for { err: err }. Written out in full it becomes
    # { err: "..." }: the SAME key, because the code reading the response
    # looks for that name.
    for use in uses:
        if use.type == "shorthand_property_identifier":
            edits.append(TextEdit(file.path, use.start_byte, use.end_byte, f"{text(use)}: {MESSAGE}".encode()))

    leaks = outermost_only([js_grow_leak(use) for use in uses if use.type == "identifier"])
    first_arg = (arguments(call) or [None])[0]
    sends_json = text(field(call, "function")).endswith(".json")
    for leak in leaks:
        # res.json(err) needs an object, not a bare string.
        replacement = f"{{ error: {MESSAGE} }}" if sends_json and leak == first_arg else MESSAGE
        edits.append(TextEdit(file.path, leak.start_byte, leak.end_byte, replacement.encode()))
    return edits


def js_grow_leak(use: Node) -> Node:
    """Grow a use of `err` into the whole expression that shows it.

    err          ->  err.message                (reading a property)
    err.message  ->  `Failed: ${err.message}`   (inside a template)
    err          ->  String(err)                (turned into text)
    err.message  ->  err.message || "Error"     (with a fallback)
    """
    node = use
    while node.parent is not None:
        parent = node.parent
        grandparent = parent.parent
        if parent.type == "member_expression" and field(parent, "object") == node:
            node = parent                    # err.message
        elif parent.type == "call_expression" and field(parent, "function") == node:
            node = parent                    # err.toString()
        elif parent.type == "arguments" and text(field(grandparent, "function")) in JS_STRINGIFIERS:
            node = grandparent               # String(err)
        elif parent.type == "template_substitution" and grandparent is not None:
            node = grandparent               # `...${err}...`
        elif parent.type == "binary_expression" and text(field(parent, "operator")) in ("+", "||", "??"):
            node = parent                    # "Error: " + err
        elif parent.type == "parenthesized_expression":
            node = parent
        else:
            return node
    return node


def is_js_response(node: Node) -> bool:
    """Does this call send something to the visitor?"""
    if node.type == "new_expression":
        return text(field(node, "constructor")) in JS_STATIC_RESPONSES   # new Response(...)
    if node.type != "call_expression":
        return False
    function = field(node, "function")
    if function is None or function.type != "member_expression":
        return False
    method = text(field(function, "property"))
    target = field(function, "object")
    if target.type == "identifier" and text(target) in JS_STATIC_RESPONSES:
        return method == "json"                                          # NextResponse.json(...)
    root = js_chain_start(function)
    return method in JS_RESPONSE_METHODS and text(root) in JS_RESPONSE_OBJECTS  # res.status(500).json(...)


def js_chain_start(node: Node) -> Node:
    """res.status(500).json  ->  the `res` at the very start of the chain."""
    while node.type in ("member_expression", "call_expression"):
        inner = field(node, "object") or field(node, "function")
        if inner is None:
            break
        node = inner
    return node


def status_comes_from_error(call: Node, error_name: str) -> bool:
    """Is the status read straight from the error, with no fallback?

        res.status(err.errorCode).json(err.message)

    An error that carries its own status code was made on purpose by the
    app (like HttpException(404, "Not found")), so its message is meant for
    the visitor. With a fallback, res.status(err.status || 500), unknown
    errors land on 500 and still leak, so those are still reported.
    """
    name = re.escape(error_name)
    return re.search(rf"\.(?:status|code)\(\s*{name}\.\w+\s*\)", text(call)) is not None


def js_status(call: Node) -> int | None:
    """The HTTP status in  res.status(404).json(...).

    Returns the number, None if no status is set, or DYNAMIC if it's set
    to something that isn't a plain number.
    """
    # Walk back along the chain looking for .status(...) or .code(...).
    node = field(call, "function")
    while node is not None and node.type in ("member_expression", "call_expression"):
        if node.type == "call_expression":
            function = field(node, "function")
            is_status_call = text(field(function, "property")) in ("status", "code")
            args = arguments(node)
            if is_status_call and args:
                return int(text(args[0])) if text(args[0]).isdigit() else DYNAMIC
            node = function
        else:
            node = field(node, "object")

    # NextResponse.json(body, { status: 500 })
    args = arguments(call)
    if len(args) > 1 and args[1].type == "object":
        match = re.search(r"\bstatus\s*:\s*(\d{3}\b)?", text(args[1]))
        if match:
            return int(match.group(1)) if match.group(1) else DYNAMIC
    return None


def js_error_variable(call: Node) -> tuple[str, Node] | None:
    """Which variable holds the error, and the code that handles it.

    An error can come from three places:
      try { } catch (err) { ...here... }
      app.use((err, req, res, next) => { ...here... })     Express error handler
      promise.catch((err) => ...here...)
    """
    for ancestor in ancestors(call):
        if ancestor.type == "catch_clause":
            name = param_name(field(ancestor, "parameter"))
            if name:
                return name, field(ancestor, "body")

        if ancestor.type in JS_FUNCTIONS:
            params = function_params(ancestor)
            first = param_name(params[0]) if params else None
            # Express recognises an error handler by its FOUR parameters.
            if len(params) == 4 and first:
                return first, ancestor
            # .catch(err => ...): the function is the argument of a .catch call.
            holder = ancestor.parent.parent if ancestor.parent is not None else None
            if first and holder is not None and holder.type == "call_expression" and method_is(holder, "catch"):
                return first, ancestor
            return None  # don't look past the nearest function
    return None


def method_is(call: Node, name: str) -> bool:
    function = field(call, "function")
    return function is not None and function.type == "member_expression" and text(field(function, "property")) == name


def function_params(function: Node) -> list[Node]:
    params = field(function, "parameters")
    if params is None:
        single = field(function, "parameter")  # x => ...  (no brackets)
        return [single] if single is not None else []
    return items(params)


def param_name(param: Node | None) -> str | None:
    """`err`, or for TypeScript's `err: Error`, just the name part."""
    if param is None:
        return None
    if param.type == "identifier":
        return text(param)
    pattern = field(param, "pattern")
    if pattern is not None and pattern.type == "identifier":
        return text(pattern)
    return None


def js_already_logged(handler: Node, error_name: str) -> bool:
    """Is the ERROR ITSELF already being logged?

    console.log("save failed") doesn't count: it leaves out what went
    wrong. Once the response stops showing the error too, a log line that
    includes it is the only place left to find the cause.
    """
    for node in walk(handler):
        if node.type != "call_expression" or not JS_LOGGER.match(text(field(node, "function"))):
            continue
        if mentions(text(field(node, "arguments")), error_name):
            return True
    return False


def js_statement(call: Node) -> Node | None:
    """The statement holding the call, if it sits directly in a { } block.

    Returns None for an arrow function's expression body, such as
    `err => res.json(err.message)`, which has no statements at all.
    """
    node = call
    while node.parent is not None:
        if node.parent.type == "statement_block":
            return node
        if node.parent.type in ("arrow_function", "function_expression"):
            return None
        node = node.parent
    return None


# ===========================================================================
# PYTHON
# ===========================================================================

# Calls that send a response to the visitor (Flask, Django, FastAPI, Starlette).
PY_RESPONSE_CALLS = {
    "jsonify", "make_response", "Response", "JsonResponse", "HttpResponse",
    "HttpResponseServerError", "JSONResponse", "PlainTextResponse", "HTMLResponse",
    "HTTPException", "abort",
}
# Decorators that mark a function as a web route:  @app.route, @router.get ...
PY_ROUTE_DECORATOR = re.compile(r"\.(?:route|get|post|put|patch|delete|api_route)\(|\bapi_view\b")
# Already logged?  logging.exception(...), logger.error(...), print(e) ...
PY_LOGGER = re.compile(r"^(?:logging|logger|log|_logger|LOGGER|sentry_sdk|traceback)\.|^print$")
# Calls that return the error's details all by themselves.
PY_TRACEBACK_CALLS = {"traceback.format_exc", "traceback.format_exception", "sys.exc_info"}
BROAD_EXCEPTIONS = {"Exception", "BaseException"}
PY_STRINGIFIERS = {"str", "repr", "format"}


def check_python(file: SourceFile) -> list[Finding]:
    findings = []
    for clause in file.nodes_of("except_clause"):
        error_name, catches_everything = except_details(clause)
        block = next((child for child in clause.children if child.type == "block"), None)
        if block is None:
            continue
        for statement in block.named_children:
            finding = python_statement_finding(file, statement, block, error_name, catches_everything)
            if finding is not None:
                findings.append(finding)
    return findings


def python_statement_finding(file: SourceFile, statement: Node, block: Node,
                             error_name: str | None, catches_everything: bool) -> Finding | None:
    # Steps 1 and 3: does this statement send the error to the visitor?
    uses = []
    for sink in python_sinks(statement):
        for use in python_error_uses(sink, error_name):
            if use not in uses:
                uses.append(use)
    if not uses:
        return None

    statuses = status_codes(statement)
    if any(400 <= code < 500 for code in statuses):
        return None  # a deliberate message for the user
    if not catches_everything and not any(code >= 500 for code in statuses):
        return None  # a specific error, shown on purpose

    line = line_of(statement)
    title = f"Error details sent to visitors ({error_name or 'traceback'})"
    if python_status_is_dynamic(statement):
        return manual(file, line, title, DYNAMIC_STATUS_NOTE)

    # Step 4: replace the leaks and add logging.exception(...).
    leaks = outermost_only([python_grow_leak(use) for use in uses])
    edits = [TextEdit(file.path, leak.start_byte, leak.end_byte, MESSAGE.encode()) for leak in leaks]

    if not python_already_logged(block, error_name):
        insert = insert_line_before(file, statement, 'logging.exception("Unhandled error")')
        if insert is None:
            return manual(file, line, title, "Put the except body on its own line, log with "
                                             "logging.exception(), and return a generic message.")
        edits.append(insert)
        import_edit = python_import_edit(file, "logging")
        if import_edit is not None:
            edits.append(import_edit)

    fix = Fix(edits=edits, preview_before=short(text(statement), 45),
              preview_after="generic message + logging.exception()")
    return Finding("ERR-001", title, file.path, line, IMPACT, Severity.WARNING, fix=fix)


def except_details(clause: Node) -> tuple[str | None, bool]:
    """(the error's variable name, does it catch every kind of error?)

    except Exception as e:     ->  ("e", True)
    except ValueError as e:    ->  ("e", False)
    except:                    ->  (None, True)
    """
    value = field(clause, "value")
    if value is None:
        return None, True  # a bare `except:` catches everything

    name = None
    types = value
    if value.type == "as_pattern":
        alias = field(value, "alias")
        if alias is not None and alias.named_children:
            name = text(alias.named_children[0])
        types = value.named_children[0]
    # `except (ValueError, Exception)` lists several types in a tuple.
    type_names = [text(t) for t in types.named_children] if types.type == "tuple" else [text(types)]
    # "builtins.Exception" -> "Exception": compare the last part only.
    broad = any(name_.split(".")[-1] in BROAD_EXCEPTIONS for name_ in type_names)
    return name, broad


def python_sinks(statement: Node) -> list[Node]:
    """The parts of a statement that send something to the visitor."""
    sinks = [
        node for node in own_nodes(statement)
        if node.type == "call" and text(field(node, "function")).split(".")[-1] in PY_RESPONSE_CALLS
    ]
    # In a web route, whatever you `return` IS the response.
    if statement.type == "return_statement" and in_route(statement):
        sinks.append(statement)
    return sinks


def python_error_uses(node: Node, error_name: str | None) -> list[Node]:
    """Places inside `node` that read the error: e, str(e), traceback.format_exc()."""
    found = []
    for child in walk(node):
        if child.type == "call" and text(field(child, "function")) in PY_TRACEBACK_CALLS:
            found.append(child)
            continue
        if error_name is None or child.type != "identifier" or text(child) != error_name:
            continue
        parent = child.parent
        if parent.type == "attribute" and field(parent, "attribute") == child:
            continue  # obj.e is not our variable
        if parent.type == "keyword_argument" and field(parent, "name") == child:
            continue  # f(e=1) isn't either
        found.append(child)
    return found


def python_grow_leak(use: Node) -> Node:
    """Grow a use of `e` into the whole expression that shows it.

    e  ->  e.args[0]  ->  str(e)  ->  f"Failed: {e}"  ->  "Error: " + str(e)
    """
    node = use
    while node.parent is not None:
        parent = node.parent
        grandparent = parent.parent
        called = text(field(grandparent, "function"))
        if parent.type == "attribute" and field(parent, "object") == node:
            node = parent                    # e.args
        elif parent.type == "subscript" and field(parent, "value") == node:
            node = parent                    # e.args[0]
        elif parent.type == "call" and field(parent, "function") == node:
            node = parent                    # e.with_traceback()
        elif parent.type == "argument_list" and (called in PY_STRINGIFIERS or called.endswith(".format")):
            node = grandparent               # str(e), "{}".format(e)
        elif parent.type == "interpolation" and grandparent is not None:
            node = grandparent               # f"...{e}..."
        elif parent.type == "binary_operator" and text(field(parent, "operator")) in ("+", "%"):
            node = parent                    # "Error: " + str(e)
        elif parent.type in ("parenthesized_expression", "boolean_operator"):
            node = parent                    # (str(e) or "Error")
        else:
            return node
    return node


def own_nodes(root: Node):
    """Walk `root`, but don't go inside nested functions, classes or lambdas.

    Code in a nested function runs later, maybe long after the except block
    finished, so it isn't "responding with this error".
    """
    stack = list(reversed(root.children))
    while stack:
        node = stack.pop()
        yield node
        if node.type not in ("function_definition", "class_definition", "lambda"):
            stack.extend(reversed(node.children))


def in_route(node: Node) -> bool:
    """True if `node` is inside a function decorated as a web route."""
    function = next((a for a in ancestors(node) if a.type == "function_definition"), None)
    if function is None or function.parent is None or function.parent.type != "decorated_definition":
        return False
    decorators = [d for d in function.parent.children if d.type == "decorator"]
    return any(PY_ROUTE_DECORATOR.search(text(d)) for d in decorators)


def status_codes(node: Node) -> list[int]:
    """Every HTTP-status-like number in a statement, e.g. the 500 in `return x, 500`."""
    return [int(text(n)) for n in walk(node) if n.type == "integer" and re.fullmatch(r"[1-5]\d\d", text(n))]


def python_status_is_dynamic(statement: Node) -> bool:
    """Is the status worked out while the app runs?

    return jsonify(...), e.code                     (Flask)
    raise HTTPException(status_code=e.status_code)  (FastAPI)
    """
    if statement.type == "return_statement" and statement.named_children:
        returned = statement.named_children[0]
        # `return body, status` is an expression_list of two or more parts.
        if returned.type == "expression_list" and len(returned.named_children) >= 2 \
                and returned.named_children[1].type != "integer":
            return True
    for node in own_nodes(statement):
        if node.type == "keyword_argument" and text(field(node, "name")) in ("status", "status_code", "code"):
            value = field(node, "value")
            if value is not None and value.type != "integer":
                return True
    return False


def python_already_logged(block: Node, error_name: str | None) -> bool:
    """Is the ERROR ITSELF already being logged? (print("failed") doesn't count.)"""
    for node in own_nodes(block):
        if node.type != "call":
            continue
        function = text(field(node, "function"))
        if not PY_LOGGER.match(function):
            continue
        whole_call = text(node)
        # These record the error by themselves, without being handed it:
        # logging.exception(...), traceback.print_exc(), exc_info=True.
        records_it = function.endswith(".exception") or function.startswith(("traceback.", "sentry_sdk.")) \
            or "exc_info" in whole_call
        if records_it or (error_name is not None and mentions(text(field(node, "arguments")), error_name)):
            return True
    return False
