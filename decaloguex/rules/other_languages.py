"""
other_languages.py: the rules for PHP, Java, C#, Go, Ruby, Kotlin and Swift.

JavaScript/TypeScript and Python each have their own detailed rule files
(secrets.py, sql.py, errors.py, async_.py). Writing all of those again for
seven more languages would mean thousands of nearly identical lines, so the
other languages SHARE the rules in this file instead.

THE IDEA: A PROFILE PER LANGUAGE
    Every language does the same jobs with different words:

        job                  PHP                Java                    Go
        a string             "..." or '...'     "..."                   "..." or `...`
        read an env var      getenv('KEY')      System.getenv("KEY")    os.Getenv("KEY")
        catch an error       catch (E $e)       catch (E e)             if err != nil
        log an error         error_log($e)      e.printStackTrace()     log.Println(err)

    A Profile (below) is a small card listing one language's words. The
    rules are written once and read the card for each language.

WHAT EACH RULE DOES HERE
    Secrets  (SEC-001/002)  found and FIXED in all seven languages.
    SQL      (SQL-001/002)  found in all seven. FIXED in Go, Ruby (ActiveRecord)
                            and PHP (PDO). The others get clear instructions.
    Errors   (ERR-001)      found and FIXED in all seven.
    Async    (ASYNC-005..9) one rule per language where the problem exists:
                            C# async void, Go goroutines, Java
                            CompletableFuture, Kotlin GlobalScope, Swift Task.
                            (PHP and Ruby code is mostly not async.)

A rule that can't be SURE its fix is safe reports the problem with
instructions (a "manual step") instead of changing the code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from tree_sitter import Node

from decaloguex.languages import SourceFile, ancestors, line_of, text, walk
from decaloguex.models import AppendEdit, Finding, Fix, Severity, TextEdit
from decaloguex.project import ProjectInfo
from decaloguex.rules import secrets
from decaloguex.rules.common import (
    GENERIC_ERROR_MESSAGE,
    indent_at,
    insert_line_before,
    line_start,
    newline_of,
    short,
    starts_line,
)
from decaloguex.rules.sql import CannotFix, Part, looks_like_sql, only_names_inserted, parameterize


# ===========================================================================
# THE PROFILES
# ===========================================================================

@dataclass(frozen=True)
class Profile:
    """One language's words for the jobs the rules do."""

    family: str                       # matches LanguageInfo.family, e.g. "php"
    string_types: frozenset[str]      # node types that are string literals
    # Child node types inside a string that mean "a value is pasted in here",
    # like ${x} or #{x}. Their presence means the string is built at runtime.
    interpolation_types: frozenset[str]
    env_lookup: str                   # code that reads an environment variable; {name} is filled in
    env_needs: str                    # regex the file must match for env_lookup to work ("" = always works)
    log_line: str                     # code that logs an error; {error} is filled in
    already_logs: str                 # regex: is the error already being logged?
    response_call: str                # regex on a call's name: does it send a response to the visitor?
    response_statements: frozenset[str] = frozenset()  # statements that print to the visitor (PHP echo)
    quote: str = '"'                  # quote mark for the generic message
    sql_advice: str = ""              # what to do about SQL injection, in this language
    catch_types: frozenset[str] = frozenset()
    broad_errors: frozenset[str] = frozenset({"Exception", "Throwable", "Error"})


PROFILES = {
    "php": Profile(
        family="php",
        string_types=frozenset({"string", "encapsed_string"}),
        interpolation_types=frozenset({"variable_name", "member_access_expression", "subscript_expression",
                                       "member_call_expression"}),
        env_lookup="getenv('{name}')",
        env_needs="",
        log_line="error_log((string) {error});",
        already_logs=r"error_log|Log::|logger\(|->error\(|->critical\(",
        response_call=r"(?:->json|^response|->send|^abort|->setContent|->write|->withJson)$",
        response_statements=frozenset({"echo_statement", "print_intrinsic", "exit_statement"}),
        quote="'",
        sql_advice="Use a prepared statement: $stmt = $pdo->prepare('... WHERE id = ?'); $stmt->execute([$id]);",
        catch_types=frozenset({"catch_clause"}),
    ),
    "java": Profile(
        family="java",
        string_types=frozenset({"string_literal"}),
        interpolation_types=frozenset(),
        env_lookup='System.getenv("{name}")',
        env_needs="",
        log_line="{error}.printStackTrace();",
        already_logs=r"printStackTrace|\blog(?:ger)?\.|\bLOG(?:GER)?\.",
        response_call=r"(?:\.body|\bok|getWriter\(\)\.(?:print|println|write)|\.sendError|\.entity)$",
        sql_advice="Use a PreparedStatement: put ? in the SQL and set each value with stmt.setString(1, value).",
        catch_types=frozenset({"catch_clause"}),
        broad_errors=frozenset({"Exception", "Throwable", "RuntimeException", "Error"}),
    ),
    "csharp": Profile(
        family="csharp",
        string_types=frozenset({"string_literal", "verbatim_string_literal", "interpolated_string_expression"}),
        interpolation_types=frozenset({"interpolation"}),
        env_lookup='System.Environment.GetEnvironmentVariable("{name}")',
        env_needs="",
        log_line="System.Console.Error.WriteLine({error});",
        already_logs=r"_?[lL]ogger\.|\bLog\.|Console\.Error",
        response_call=r"(?:StatusCode|Problem|Content|\bOk|Json|InternalServerError|\.WriteAsync)$",
        sql_advice='Use parameters: put @id in the SQL and add cmd.Parameters.AddWithValue("@id", id).',
        catch_types=frozenset({"catch_clause"}),
    ),
    "go": Profile(
        family="go",
        string_types=frozenset({"interpreted_string_literal", "raw_string_literal"}),
        interpolation_types=frozenset(),
        env_lookup='os.Getenv("{name}")',
        env_needs=r'"os"',  # Go only allows os.Getenv if the file imports "os"
        log_line="log.Println({error})",
        already_logs=r"\blog\.|\blogger\.|\bslog\.|zap\.|logrus",
        response_call=r"(?:http\.Error|\.JSON|\.String|\.AbortWithStatusJSON|\.SendString|\.Write|"
                      r"fmt\.Fprint(?:f|ln)?|\.WriteString)$",
        sql_advice='Pass values separately: db.Query("... WHERE id = ?", id). Use $1 instead of ? for PostgreSQL.',
        broad_errors=frozenset(),  # Go has no error types to catch: every err is checked the same way
    ),
    "ruby": Profile(
        family="ruby",
        string_types=frozenset({"string"}),
        interpolation_types=frozenset({"interpolation"}),
        env_lookup='ENV["{name}"]',
        env_needs="",
        log_line="warn {error}.full_message",
        already_logs=r"logger\.|\bwarn\b|Rails\.logger|puts\s+\w+\.(?:full_message|backtrace)",
        response_call=r"(?:render|halt|send_data|json|body)$",
        sql_advice='Use placeholders: where("name = ?", name).',
        catch_types=frozenset({"rescue"}),
        broad_errors=frozenset({"StandardError", "Exception"}),
    ),
    "kotlin": Profile(
        family="kotlin",
        string_types=frozenset({"string_literal", "multiline_string_literal"}),
        interpolation_types=frozenset({"interpolation"}),
        env_lookup='System.getenv("{name}")',
        env_needs="",
        log_line="{error}.printStackTrace()",
        already_logs=r"printStackTrace|\blog(?:ger)?\.|\bLOG(?:GER)?\.",
        response_call=r"(?:respond|respondText|\.body|\bok)$",
        sql_advice="Use a PreparedStatement: put ? in the SQL and set each value with stmt.setString(1, value).",
        catch_types=frozenset({"catch_block"}),
        broad_errors=frozenset({"Exception", "Throwable", "RuntimeException", "Error"}),
    ),
    "swift": Profile(
        family="swift",
        string_types=frozenset({"line_string_literal", "multi_line_string_literal"}),
        interpolation_types=frozenset({"interpolated_expression"}),
        env_lookup='(ProcessInfo.processInfo.environment["{name}"] ?? "")',
        env_needs=r"import\s+(?:Foundation|UIKit|SwiftUI|AppKit|Vapor)",  # ProcessInfo comes from Foundation
        log_line="print({error})",
        already_logs=r"\bprint\(|logger\.|os_log|Logger\(",
        response_call=r"(?:Abort|Response|\.send|\.json)$",
        sql_advice="Use your database library's bound parameters (? or $1) instead of putting values in the SQL text.",
        catch_types=frozenset({"catch_block"}),
        broad_errors=frozenset({"Error"}),
    ),
}


# ===========================================================================
# THE RULES
# ===========================================================================

def check(file: SourceFile, planner: secrets.EnvPlanner, info: ProjectInfo) -> list[Finding]:
    """Run every rule on one file. Returns findings; writes nothing."""
    profile = PROFILES.get(file.lang.family)
    if profile is None:
        return []
    return (
        check_secrets(file, profile, planner)
        + check_sql(file, profile, info)
        + check_errors(file, profile)
        + check_async(file)
    )


def code_of(node: Node | str) -> str:
    """The source code of a node (or the text itself, if it's already text)."""
    return node if isinstance(node, str) else text(node)


# Node types that hold a name: a variable, a property, a hash key...
NAME_TYPES = {"identifier", "simple_identifier", "name", "field_identifier", "hash_key_symbol",
              "instance_variable", "class_variable", "simple_symbol",
              "constant", "property_identifier", "variable_name"}
# Node types where code waits its turn: nothing inside runs "right now".
FUNCTION_TYPES = {"lambda_expression", "lambda_literal", "func_literal", "anonymous_function",
                  "anonymous_function_creation_expression", "lambda", "block_argument",
                  "function_declaration", "method_declaration", "closure_expression"}


# ===========================================================================
# SECRETS (SEC-001, SEC-002)
# ===========================================================================

def check_secrets(file: SourceFile, profile: Profile, planner: secrets.EnvPlanner) -> list[Finding]:
    findings = []
    for node in file.nodes_of(*profile.string_types):
        if is_struct_tag(node):
            continue
        found = string_value(node, profile)
        if found is None:
            continue
        value, rewritable = found
        finding = known_key(file, profile, planner, node, value, rewritable) \
            or secret_named(file, profile, planner, node, value, rewritable)
        if finding is not None:
            findings.append(finding)
    return findings


# A string's quotes and any prefix letters: @"...", $"...", '...', `...`, """...""".
STRING_SHAPE = re.compile(r'^[@$]*("""|\'\'\'|"|\'|`)(.*)\1$', re.DOTALL)


def is_struct_tag(node: Node) -> bool:
    """Go only: the `json:"password"` note after a struct field.

        type User struct {
            Password string `json:"password"`
        }

    It's an instruction to Go ("call this field password in JSON"), not a
    value, so it can never be a secret.
    """
    parent = node.parent
    return parent is not None and parent.type == "field_declaration" and parent.child_by_field_name("tag") == node


def string_value(node: Node, profile: Profile) -> tuple[str, bool] | None:
    """(the text inside the quotes, is it safe to replace?) or None."""
    match = STRING_SHAPE.match(text(node))
    if match is None:
        return None
    quote, value = match.group(1), match.group(2)
    rewritable = (
        not is_built_at_runtime(node, profile)
        and "\\" not in value          # escape sequences: leave to a human
        and len(quote) == 1            # not a multi-line """ string
        and "\n" not in value
        and not in_constant(node, profile.family)
    )
    return value, rewritable


def is_built_at_runtime(node: Node, profile: Profile) -> bool:
    """Does the string have values pasted into it, like "Hi ${name}"?"""
    if any(child.type in profile.interpolation_types for child in walk(node) if child != node):
        return True
    if node.type == "interpolated_string_expression":
        return True  # C# $"..."
    # Kotlin's parser reads "$name" as plain text, so check the text itself.
    return profile.family == "kotlin" and bool(re.search(r"\$\{|\$[A-Za-z_]", text(node)))


# Places that only accept a FIXED value, by language. Code like getenv(...)
# isn't allowed there: PHP stops with a fatal error, C# refuses to build.
#   PHP   private $key = "...";        a property's starting value
#         function pay($key = "...")   a parameter's default
#         static $cache = "...";       a static variable
#   C#    void Pay(string key = "...") a parameter's default
MUST_BE_FIXED = {
    "php": {"property_element", "simple_parameter", "property_promotion_parameter",
            "static_variable_declaration", "enum_case"},
    "csharp": {"parameter", "enum_member_declaration"},
}


def in_constant(node: Node, family: str = "") -> bool:
    """Is this string somewhere that only accepts a fixed value?

    That means a constant (const), an annotation or attribute, or one of
    the language-specific places in MUST_BE_FIXED. Those are settled when
    the program is BUILT, so they can't read an environment variable,
    which only exists when the program RUNS.
    """
    must_be_fixed = MUST_BE_FIXED.get(family, set())
    for ancestor in ancestors(node):
        kind = ancestor.type
        if "const" in kind or "annotation" in kind or kind == "attribute" or kind in must_be_fixed:
            return True
        if re.match(r"(?:\w+\s+)*const\b", text(ancestor)[:80]):
            return True
        # Stop at the edge of the surrounding block or class: anything further
        # out belongs to other code.
        if kind in ("block", "class_body", "declaration_list", "compound_statement", "statement_list",
                    "statements", "program", "source_file", "module") or "body" in kind:
            return False
    return False


def known_key(file, profile, planner, node, value, rewritable) -> Finding | None:
    """SEC-001: the string matches a known key format (Stripe, AWS, ...)."""
    for pattern in secrets.KNOWN_PATTERNS:
        match = pattern.regex.search(value)
        if match is None or secrets.obviously_fake(match.group(0)):
            continue
        title = f"Exposed {pattern.label}"
        if not pattern.fixable:
            return manual("SEC-003", title, file, node, "Anyone who sees this file can impersonate your server.",
                          "Move it into a file outside your project and load it at startup.")
        if match.group(0) != value.strip() or not rewritable:
            return manual("SEC-001", title, file, node, secrets.IMPACT, why_not_moved(node, profile))
        return secret_fix(file, profile, planner, node, value, "SEC-001", title,
                          pattern.env_name, secrets.mask(value, reveal=True))
    return None


def secret_named(file, profile, planner, node, value, rewritable) -> Finding | None:
    """SEC-002: the string is stored under a secret-sounding name."""
    name = assigned_name(node, profile)
    if name is None or not secrets.SECRET_NAME.search(name):
        return None
    if secrets.to_env_name(name).split("_")[-1].lower() in secrets.NOT_SECRET_LAST_WORDS:
        return None
    if not secrets.looks_like_secret(value):
        return None
    if is_built_at_runtime(node, profile):
        return None  # "1!aA#{SecureRandom.hex(12)}": made fresh each time, not a fixed secret
    kind = "password" if re.search(r"passw|pwd", name, re.IGNORECASE) else "secret"
    title = f"Hard-coded {kind} in '{name}'"
    if not rewritable:
        card = manual("SEC-002", title, file, node, secrets.IMPACT, why_not_moved(node, profile))
        card.same_as = secrets.fingerprint_of(value)
        return card
    return secret_fix(file, profile, planner, node, value, "SEC-002", title,
                      secrets.to_env_name(name), secrets.mask(value, reveal=False))


def why_not_moved(node: Node, profile: Profile) -> str:
    if in_constant(node, profile.family):
        return "It's in a spot that only accepts a fixed value (a constant, a default or a starting " \
               "value), which can't read settings at run time. Set it in code that runs instead, " \
               f"using {profile.env_lookup.format(name='NAME')}, and put the value in .env."
    return f"The key sits inside a longer or special string. Move it to .env by hand and read it " \
           f"with {profile.env_lookup.format(name='NAME')}."


def secret_fix(file, profile, planner, node, value, rule_id, title, env_name, shown) -> Finding:
    """Swap the string for an environment lookup, and add the value to .env."""
    if profile.env_needs and not re.search(profile.env_needs, file.source.decode("utf-8", "replace")):
        needed = {"go": 'import "os"', "swift": "import Foundation"}.get(profile.family, "the right import")
        return manual(rule_id, title, file, node, secrets.IMPACT,
                      f"Add {needed} to this file, then replace the value with "
                      f"{profile.env_lookup.format(name=env_name)} and put it in .env.")

    env_name, needs_append = planner.reserve(env_name, value)
    replacement = profile.env_lookup.format(name=env_name)
    appends = []
    if needs_append:
        appends.append(AppendEdit(planner.env_path, secrets.env_line(env_name, value), header=secrets.ENV_HEADER))
    fix = Fix(edits=[TextEdit(file.path, node.start_byte, node.end_byte, replacement.encode())],
              appends=appends, preview_before=f'"{shown}"', preview_after=replacement)
    return Finding(rule_id, title, file.path, line_of(node), secrets.IMPACT, Severity.CRITICAL, fix=fix)


# Node types that STORE a value under a name, in the seven languages:
#   PHP     $apiKey = "..."    'password' => '...'    private $key = "..."
#   Java    String apiKey = "..."          C#   var apiKey = "..."
#   Go      apiKey := "..."    var apiKey = "..."     Password: "..." (in a struct)
#   Ruby    api_key = "..."    password: "..."        Kotlin/Swift  val apiKey = "..."
HOLDERS = {
    "assignment_expression", "assignment", "operator_assignment", "assignment_statement",
    "variable_declarator", "short_var_declaration", "var_spec", "const_spec", "const_element",
    "pair", "array_element_initializer", "keyed_element",
    "property_declaration", "property_element", "static_variable_declaration",
    "simple_parameter", "property_promotion_parameter", "parameter",
    "enum_case", "enum_member_declaration", "element_value_pair",
}
# Nodes that just wrap a single value on its way to a holder: the right-hand
# side of  a, b := ...  in Go, a function argument, brackets...
WRAPPERS = {"expression_list", "literal_element", "argument", "value_argument",
            "parenthesized_expression", "equals_value_clause"}


def assigned_name(node: Node, profile: Profile) -> str | None:
    """The name a string is stored under:  $apiKey = "..."  ->  "apiKey".

    This is strict on purpose. The string must be THE value being stored,
    and the name must be the thing it's stored in. Being merely NEAR a
    secret-sounding word isn't enough. A looser version (looking at any
    name nearby) flagged things like these during testing:
        "gitea.dev/modules/auth/password"            an import line
        '...apiKey=' . $user->api_key . '&f=json'    ordinary text
        x.Exec("UPDATE access_token SET ...", "all") a database command
    """
    value = node
    parent = node.parent
    # Step through wrappers, as long as each one holds ONLY this value.
    while parent is not None and parent.type in WRAPPERS:
        label = argument_label(parent)
        if label is not None:
            return label                          # a named argument: connect(password: "...")
        if len([c for c in parent.named_children if c.type != "comment"]) != 1:
            return None                           # one of several values, like f("a", "b")
        value, parent = parent, parent.parent
    if parent is None or parent.type not in HOLDERS:
        return None

    parts = [c for c in parent.named_children if c.type != "comment"]
    if not parts or parts[-1] != value:
        return None                               # our string isn't the stored value
    for part in parts[:-1]:
        if is_modifier_or_type(part):
            continue                              # skip "private", "String", "let"...
        return name_of(part, profile)
    return None


def argument_label(argument: Node) -> str | None:
    """The label of a named argument, like `password` in f(password: "..."), or None."""
    if argument.type not in ("argument", "value_argument"):
        return None
    named = argument.child_by_field_name("name")              # PHP, Swift
    if named is None:
        named = next((c for c in argument.named_children
                      if c.type in ("name_colon", "simple_identifier", "value_argument_label")), None)
        if named is None or len(argument.named_children) < 2:  # a lone value has no label
            return None
    leaves = [n for n in walk(named) if n.type in NAME_TYPES]
    return text(leaves[0]) if leaves else None


def is_modifier_or_type(node: Node) -> bool:
    kind = node.type
    return "type" in kind or "modifier" in kind or kind in ("value_binding_pattern", "attribute_list")


def name_of(node: Node, profile: Profile) -> str | None:
    """The name inside the "name side" of an assignment.

    $apiKey -> apiKey,  this.apiKey -> apiKey,  'password' -> password,
    val apiKey: String -> apiKey
    """
    if node.type in profile.string_types:
        match = STRING_SHAPE.match(text(node))
        return match.group(2) if match else None   # a quoted key, like 'password' => '...'
    if node.type in NAME_TYPES and node.named_child_count == 0:
        return text(node).lstrip("$:@")
    named = [c for c in node.named_children if c.type != "comment"]
    if node.type in ("expression_list", "literal_element"):
        return name_of(named[0], profile) if len(named) == 1 else None
    leaves = [n for n in walk(node) if n.type in NAME_TYPES and n.named_child_count == 0]
    if not leaves:
        return None
    # A declaration names the variable FIRST (val apiKey: String); member
    # access names it LAST (this.config.apiKey).
    first = node.type in ("variable_declaration", "pattern", "variable_name")
    return text(leaves[0] if first else leaves[-1]).lstrip("$:@")


def manual(rule_id: str, title: str, file: SourceFile, node: Node, impact: str, note: str,
           severity: Severity = Severity.CRITICAL) -> Finding:
    """A finding we report with instructions but don't fix automatically."""
    return Finding(rule_id, title, file.path, line_of(node), impact, severity, note=note)


# ===========================================================================
# SQL (SQL-001, SQL-002)
# ===========================================================================

SQL_IMPACT = "Attackers can't rewrite this query by typing SQL into a form. Values now travel separately from the SQL."
FORMAT_CALL = re.compile(r"(?:fmt\.Sprintf|String\.format|string\.Format|\bsprintf|\.format|\bformat)$")


def check_sql(file: SourceFile, profile: Profile, info: ProjectInfo) -> list[Finding]:
    findings = []
    # Only strings, joins ("a" + b) and calls can build a query.
    kinds = [kind for kind in file.node_types()
             if kind in profile.string_types or kind in CALL_TYPES or "binary" in kind or "additive" in kind]
    for node in file.nodes_of(*kinds):
        if is_joined_to_more(node):
            continue  # only look at the outermost piece of a  "a" + b + "c"  chain
        parts = sql_parts(node, file, profile)
        if parts is None or not any(p.expr is not None for p in parts):
            continue
        preview = "".join(p.text if p.text is not None else "?" for p in parts)
        if not looks_like_sql(preview) and not is_where_clause(node, preview):
            continue
        if only_names_inserted(parts, text):
            continue  # "DELETE FROM " + tableName: a name from the app, not a visitor
        finding = sql_finding(file, profile, info, node, parts)
        if finding is not None:
            findings.append(finding)
    return findings


def is_joined_to_more(node: Node) -> bool:
    """Is `node` one side of a join like  "a" + b  (or  "a" . $b  in PHP)?

    Then its parent is the bigger expression, and that's the one to check.
    (Checking every inner piece as well made long chains very slow.)
    """
    parent = node.parent
    if parent is None or not ("binary" in parent.type or "additive" in parent.type):
        return False
    return any(not child.is_named and text(child) in ("+", ".") for child in parent.children)


def is_where_clause(node: Node, preview: str) -> bool:
    """Ruby's  where("name = '#{x}'")  holds only PART of a query (the bit
    after WHERE), so it doesn't start with SELECT. Count it as SQL when it's
    passed to where/having and compares something."""
    call = query_call_of(node)
    return call is not None and callee_name(call) in ("where", "having") \
        and is_first_argument(node) and bool(re.search(r"[=<>]|\bLIKE\b|\bIN\b", preview, re.IGNORECASE))


def is_first_argument(node: Node) -> bool:
    """where("tags ~ ?", "#{tag}"): the second string is the VALUE for ?, not SQL."""
    current = node
    while current.parent is not None and not current.parent.type.endswith(("argument_list", "arguments")):
        current = current.parent
    if current.parent is None:
        return True
    named = current.parent.named_children
    return bool(named) and named[0] == current


def sql_finding(file, profile, info, node, parts) -> Finding | None:
    call = query_call_of(node)
    stored = call is None and storing(node)
    if call is None and not stored:
        return None  # SQL-looking text that isn't used as a query

    rule_id = "SQL-001" if call is not None else "SQL-002"
    title = "SQL injection risk" + (f" in {callee_name(call)}()" if call is not None else "")
    try:
        if call is None:
            raise CannotFix(profile.sql_advice)
        fix = sql_fix(file, profile, info, node, parts, call)
    except CannotFix as reason:
        return manual(rule_id, title, file, node, SQL_IMPACT, str(reason))
    return Finding(rule_id, title, file.path, line_of(node), SQL_IMPACT, Severity.CRITICAL, fix=fix)


def sql_parts(node: Node, file: SourceFile, profile: Profile) -> list[Part] | None:
    """Split a string-building expression into fixed text and values.

    Handles the three ways these languages build strings:
        "SELECT ... " + id           joining with + (or . in PHP)
        "SELECT ... $id"             pasting values into the string
        fmt.Sprintf("... %s", id)    format functions
    Returns None if `node` doesn't build a string.
    """
    if node.type in profile.string_types:
        return string_parts(node, profile)

    if "binary" in node.type or "additive" in node.type:
        operator = next((text(c) for c in node.children if not c.is_named), "")
        if operator not in ("+", "."):
            return None
        sides = [c for c in node.named_children if c.type != "comment"]
        if len(sides) != 2:
            return None
        parts = []
        for side in sides:
            inner = sql_parts(side, file, profile)
            parts += inner if inner is not None else [Part(expr=side)]
        if not any(p.text is not None for p in parts):
            return None  # adding numbers, not building a string
        return parts

    if is_call(node) and FORMAT_CALL.search(callee_text(node)):
        args = call_arguments(node)
        if not args or args[0].type not in profile.string_types:
            return None
        return format_parts(args[0], args[1:], profile)
    return None


# Pieces of a ${...} that are punctuation, not the value (C# counts them as pieces).
INTERPOLATION_PUNCTUATION = {"interpolation_brace", "interpolation_start", "interpolation_alignment_clause",
                             "interpolation_format_clause"}


def string_parts(node: Node, profile: Profile) -> list[Part] | None:
    """The pieces of one string literal: fixed text, and any pasted-in values."""
    match = STRING_SHAPE.match(text(node))
    if match is None:
        return None
    if profile.family == "kotlin":
        # Kotlin's parser reads $name as text; split it ourselves.
        pieces = re.split(r"\$\{([^}]*)\}|\$([A-Za-z_]\w*)", match.group(2))
        parts = []
        for index, piece in enumerate(pieces):
            if index % 3 == 0:
                parts.append(Part(text=piece))
            elif piece:
                parts.append(Part(expr=piece))
        return parts

    parts = []
    quote_length = len(match.group(1)) + (len(text(node)) - len(text(node).lstrip("@$")))
    position = node.start_byte + quote_length
    end = node.end_byte - len(match.group(1))
    for child in node.named_children:
        if child.type in profile.interpolation_types:
            before, after = child.start_byte, child.end_byte
            # PHP also allows curly brackets round a value: "id = {$row['id']}".
            # They belong to the value, not to the SQL text.
            if node_source(node, before - 1, before) == "{" and node_source(node, after, after + 1) == "}":
                before, after = before - 1, after + 1
            parts.append(Part(text=node_source(node, position, before)))
            # The value inside ${...} or {...}. (C#'s code reader counts the { }
            # braces as pieces too, so they're skipped to reach the value itself.)
            values = [c for c in child.named_children if c.type not in INTERPOLATION_PUNCTUATION]
            inner = child if profile.family == "php" or not values else values[0]
            parts.append(Part(expr=inner))
            position = after
    parts.append(Part(text=node_source(node, position, end)))
    return parts


def node_source(node: Node, start: int, end: int) -> str:
    """The source between two byte positions inside `node`."""
    return node.text[start - node.start_byte : end - node.start_byte].decode("utf-8", errors="replace")


def format_parts(template: Node, values: list[Node], profile: Profile) -> list[Part] | None:
    """fmt.Sprintf("... %s ...", x)  or  String.format("... {0} ...", x)  ->  parts."""
    found = STRING_SHAPE.match(text(template))
    if found is None:
        return None
    raw = found.group(2)
    parts = []
    position = 0
    used = 0
    for spec in re.finditer(r"%%|%[-+ #0-9.]*[sdvifq]|\{\d*\}", raw):
        if spec.group(0) == "%%":
            continue
        parts.append(Part(text=raw[position : spec.start()].replace("%%", "%")))
        if used < len(values) and not spec.group(0).endswith("q"):
            parts.append(Part(expr=values[used]))
        else:
            return None  # an unusual format; don't guess
        used += 1
        position = spec.end()
    parts.append(Part(text=raw[position:].replace("%%", "%")))
    return parts


def storing(node: Node) -> bool:
    """Is this value being stored in a variable (q := "..." + id)?"""
    parent = node.parent
    for _ in range(3):
        if parent is None:
            return False
        if any(word in parent.type for word in ("assignment", "declarator", "declaration", "binding")):
            return True
        if parent.type in ("expression_list", "value_argument"):
            parent = parent.parent
            continue
        return False
    return False


QUERY_NAMES = re.compile(
    r"(?:query|Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|execute|executeQuery|"
    r"executeUpdate|exec|prepare|prepareStatement|raw|rawQuery|where|having|find_by_sql|select_all|"
    r"FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|ExecuteReader|ExecuteNonQuery|SqlCommand|createQuery|"
    r"createNativeQuery|mysqli_query|pg_query|run|fetch|fetchAll|"
    # Spring's JdbcTemplate (Java and Kotlin)
    r"queryForObject|queryForList|queryForMap|queryForRowSet|queryForStream|update|batchUpdate|"
    # Dapper (C#)
    r"QueryAsync|QueryFirst|QueryFirstAsync|QueryFirstOrDefault|QueryFirstOrDefaultAsync|QuerySingle|"
    r"QuerySingleAsync|QuerySingleOrDefault|QuerySingleOrDefaultAsync|Execute|ExecuteAsync|ExecuteScalar|"
    r"ExecuteScalarAsync)$"
)


def query_call_of(node: Node) -> Node | None:
    """If `node` is passed straight into a database call, return the call."""
    current = node
    for _ in range(5):  # climb past wrappers like (argument) and (value_argument)
        parent = current.parent
        if parent is None:
            return None
        if is_call(parent) and current != call_callee(parent):
            return parent if QUERY_NAMES.search(callee_name(parent)) else None
        if parent.type.endswith(("argument", "arguments", "argument_list", "value_arguments", "call_suffix")):
            current = parent
            continue
        if parent.type in ("object_creation_expression",):  # new SqlCommand("...")
            return parent if "SqlCommand" in text(parent)[:40] else None
        return None
    return None


def sql_fix(file, profile, info, node, parts, call) -> Fix:
    """Rewrite the query with placeholders.

    Go, Ruby (ActiveRecord), PHP (PDO), C# (Entity Framework and Dapper),
    and Java/Kotlin (Spring's JdbcTemplate). Other database libraries get
    instructions instead.
    """
    if profile.family == "csharp" and callee_name(call) in EF_INTERPOLATED:
        return csharp_ef_fix(file, node, call)  # (escape codes are fine here: nothing is rewritten)
    if any(part.text is not None and "\\" in part.text for part in parts):
        # Escape codes (a backslash followed by a letter) mean different things
        # in different kinds of string, so leave those queries to a human.
        raise CannotFix("The query contains escape codes. " + profile.sql_advice)
    if profile.family == "go":
        return go_sql_fix(file, info, node, parts, call)
    if profile.family == "ruby":
        return ruby_sql_fix(file, node, parts, call)
    if profile.family == "php":
        return php_sql_fix(file, node, parts, call)
    if profile.family == "csharp":
        return csharp_dapper_fix(file, node, parts, call)
    if profile.family in ("java", "kotlin"):
        return jdbc_template_fix(file, profile, node, parts, call)
    raise CannotFix(profile.sql_advice)


# --- C#: Entity Framework ---------------------------------------------------------

# Entity Framework's "Raw" methods take SQL text as-is. Their "Interpolated"
# twins take the SAME $"...{x}..." string, but turn every {x} into a safe
# value first. So the fix is just a change of name.
EF_INTERPOLATED = {
    "FromSqlRaw": "FromSqlInterpolated",
    "ExecuteSqlRaw": "ExecuteSqlInterpolated",
    "ExecuteSqlRawAsync": "ExecuteSqlInterpolatedAsync",
}


def csharp_ef_fix(file, node, call) -> Fix:
    """db.Users.FromSqlRaw($"... {id}")  ->  db.Users.FromSqlInterpolated($"... {id}")"""
    advice = PROFILES["csharp"].sql_advice
    args = call_arguments(call)
    # Only for a single $"..." string: the Interpolated methods need exactly that.
    if node.type != "interpolated_string_expression" or args != [node]:
        raise CannotFix("Use FromSqlInterpolated with a $\"...\" string, or pass values as parameters.")
    name_node = call_name_node(call)
    if name_node is None:
        raise CannotFix(advice)
    new_name = EF_INTERPOLATED[text(name_node)]
    return Fix(edits=[TextEdit(file.path, name_node.start_byte, name_node.end_byte, new_name.encode())],
               preview_before=f"{text(name_node)}($\"…{{…}}\")", preview_after=f"{new_name}($\"…{{…}}\")")


def call_name_node(call: Node) -> Node | None:
    """The node holding the method's NAME, e.g. FromSqlRaw in db.Users.FromSqlRaw(...)."""
    function = call.child_by_field_name("function")
    if function is None:
        return None
    if function.type == "member_access_expression":
        return function.child_by_field_name("name")
    if function.type == "identifier":
        return function
    return None


# --- C#: Dapper ----------------------------------------------------------------------

DAPPER_METHODS = {"Query", "QueryAsync", "QueryFirst", "QueryFirstAsync", "QueryFirstOrDefault",
                  "QueryFirstOrDefaultAsync", "QuerySingle", "QuerySingleAsync", "QuerySingleOrDefault",
                  "QuerySingleOrDefaultAsync", "Execute", "ExecuteAsync", "ExecuteScalar", "ExecuteScalarAsync"}


def csharp_dapper_fix(file, node, parts, call) -> Fix:
    """conn.Query<User>($"... {id}")  ->  conn.Query<User>("... @p0", new { p0 = id })

    Dapper reads @p0 from the object passed after the SQL.
    """
    advice = PROFILES["csharp"].sql_advice
    if not re.search(rb"using\s+Dapper\s*;", file.source) or callee_name(call) not in DAPPER_METHODS:
        raise CannotFix(advice)
    if call_arguments(call) != [node]:
        raise CannotFix(advice)  # already passes parameters: leave it to a human
    sql, values = parameterize(parts, "@p")
    literal = '"' + sql.replace('"', '\\"') + '"'
    members = ", ".join(f"p{number} = {code_of(value)}" for number, value in enumerate(values))
    replacement = f"{literal}, new {{ {members} }}"
    return Fix(edits=[TextEdit(file.path, node.start_byte, node.end_byte, replacement.encode())],
               preview_before=short(text(node), 45), preview_after=short(replacement, 55))


# --- Java and Kotlin: Spring's JdbcTemplate ------------------------------------------

# JdbcTemplate methods whose LAST parameter is "Object... args": the values
# for the ? placeholders, in order.
JDBC_TEMPLATE_METHODS = {"query", "queryForObject", "queryForList", "queryForMap", "queryForRowSet",
                         "queryForStream", "update"}


def jdbc_template_fix(file, profile, node, parts, call) -> Fix:
    """jdbcTemplate.query("... = " + id, mapper)  ->  jdbcTemplate.query("... = ?", mapper, id)"""
    advice = profile.sql_advice
    receiver = callee_text(call).split(".")[-2] if "." in callee_text(call) else ""
    uses_jdbc_template = re.search(rb"JdbcTemplate", file.source) and "jdbc" in receiver.lower()
    args = call_arguments(call)
    if not uses_jdbc_template or callee_name(call) not in JDBC_TEMPLATE_METHODS or not args or args[0] != node:
        raise CannotFix(advice)
    sql, values = parameterize(parts, "?")
    escaped = sql.replace("\\", "\\\\").replace('"', '\\"')
    if profile.family == "kotlin":
        escaped = escaped.replace("$", "\\$")  # in Kotlin, $ starts a pasted-in value
    added = "".join(", " + code_of(value) for value in values)
    holder = argument_holder(call)
    closing = holder.end_byte - 1  # the ) at the end of the call: the values go just before it
    return Fix(edits=[TextEdit(file.path, node.start_byte, node.end_byte, f'"{escaped}"'.encode()),
                      TextEdit(file.path, closing, closing, added.encode())],
               preview_before=short(text(node), 45), preview_after=short(f'"{escaped}"…{added}', 55))


def go_sql_fix(file, info, node, parts, call) -> Fix:
    """db.Query("... = " + id)  ->  db.Query("... = ?", id)"""
    name = callee_name(call)
    args = call_arguments(call)
    takes_context = name.endswith("Context")
    expected_position = 1 if takes_context else 0
    if name not in ("Query", "QueryRow", "Exec", "QueryContext", "QueryRowContext", "ExecContext") \
            or len(args) != expected_position + 1 or args[expected_position] != node:
        raise CannotFix(PROFILES["go"].sql_advice)

    parameterize(parts, "?")  # check the query's shape first: a table name is the more useful thing to hear
    style = go_placeholder_style(file, info)
    sql, values = parameterize(parts, style)
    literal = go_literal(sql)
    replacement = literal + "".join(", " + code_of(v) for v in values)
    return Fix(edits=[TextEdit(file.path, node.start_byte, node.end_byte, replacement.encode())],
               preview_before=short(text(node), 45), preview_after=short(replacement, 55))


def go_placeholder_style(file: SourceFile, info: ProjectInfo) -> str:
    """? for MySQL and SQLite, $1 for PostgreSQL. Looks at imports, then go.mod."""
    everything = file.source.decode("utf-8", "replace") + " " + " ".join(info.go_modules)
    postgres = re.search(r"lib/pq|jackc/pgx", everything)
    question = re.search(r"go-sql-driver/mysql|mattn/go-sqlite3|modernc\.org/sqlite", everything)
    if bool(postgres) == bool(question):  # neither, or both: can't tell
        raise CannotFix("Couldn't tell which database driver is used. " + PROFILES["go"].sql_advice)
    return "$n" if postgres else "?"


def go_literal(value: str) -> str:
    if "\n" in value and "`" not in value:
        return "`" + value + "`"
    return '"' + value.replace('"', '\\"').replace("\n", "\\n") + '"'


def ruby_sql_fix(file, node, parts, call) -> Fix:
    """User.where("name = '#{name}'")  ->  User.where("name = ?", name)"""
    name = callee_name(call)
    args = call_arguments(call)
    if name not in ("where", "having", "find_by_sql") or args != [node]:
        raise CannotFix(PROFILES["ruby"].sql_advice)
    sql, values = parameterize(parts, "?")
    literal = ruby_literal(sql)
    inside = literal + "".join(", " + code_of(v) for v in values)
    replacement = f"[{inside}]" if name == "find_by_sql" else inside
    return Fix(edits=[TextEdit(file.path, node.start_byte, node.end_byte, replacement.encode())],
               preview_before=short(text(node), 45), preview_after=short(replacement, 55))


def ruby_literal(value: str) -> str:
    if "'" not in value:
        return "'" + value + "'"
    return '"' + value.replace('"', '\\"').replace("#{", "\\#{") + '"'


def php_sql_fix(file, node, parts, call) -> Fix:
    """$result = $pdo->query("... $id");
         ->
       $result = $pdo->prepare('... ?');
       $result->execute([$id]);

    Only for PDO, whose prepared statements work exactly like query results.
    """
    advice = PROFILES["php"].sql_advice
    if not re.search(rb"\bPDO\b", file.source) or re.search(rb"mysqli", file.source):
        # No PDO here, or mysqli as well (its prepared statements work
        # differently, and we can't tell which kind of connection this is).
        raise CannotFix(advice)
    statement = call.parent.parent if call.parent is not None else None
    assignment = call.parent
    is_simple = (
        callee_name(call) == "query"
        and call.type == "member_call_expression"
        and call_arguments(call) == [node]
        and assignment is not None and assignment.type == "assignment_expression"
        and statement is not None and statement.type == "expression_statement"
        and starts_line(file.source, statement)
    )
    if not is_simple:
        raise CannotFix(advice)

    sql, values = parameterize(parts, "?")
    variable = text(assignment.child_by_field_name("left"))
    connection = text(call.child_by_field_name("object"))
    literal = "'" + sql.replace("'", "\\'") + "'"
    indent = indent_at(file.source, statement.start_byte)
    nl = newline_of(file.source)
    values_code = ", ".join(code_of(v) for v in values)
    replacement = (f"{variable} = {connection}->prepare({literal});{nl}"
                   f"{indent}{variable}->execute([{values_code}]);")
    return Fix(edits=[TextEdit(file.path, statement.start_byte, statement.end_byte, replacement.encode())],
               preview_before=short(text(statement), 45), preview_after=short(replacement, 55))


# ---------------------------------------------------------------------------
# Reading calls in any of the languages
# ---------------------------------------------------------------------------

CALL_TYPES = {"call_expression", "method_invocation", "member_call_expression", "function_call_expression",
              "invocation_expression", "call", "scoped_call_expression", "object_creation_expression"}
ARGUMENT_HOLDERS = {"arguments", "argument_list", "value_arguments", "call_suffix"}


def is_call(node: Node) -> bool:
    return node.type in CALL_TYPES


def argument_holder(call: Node) -> Node | None:
    """The (...) part of a call."""
    for child in call.children:
        if child.type in ARGUMENT_HOLDERS:
            return child
    return None


def call_arguments(call: Node) -> list[Node]:
    """The values passed to a call, without wrappers like (argument) or (value_argument)."""
    holder = argument_holder(call)
    if holder is None:
        return []
    if holder.type == "call_suffix":  # Swift: call_suffix > value_arguments
        holder = next((c for c in holder.named_children if c.type == "value_arguments"), None)
        if holder is None:
            return []
    values = []
    for child in holder.named_children:
        if child.type == "comment":
            continue
        if child.type in ("argument", "value_argument") and child.named_children:
            child = child.named_children[-1]  # the value, after any  name:  label
        values.append(child)
    return values


def call_callee(call: Node) -> Node | None:
    holder = argument_holder(call)
    return call.named_children[0] if call.named_children and call.named_children[0] != holder else None


def callee_text(call: Node) -> str:
    """Everything before the (...): for res.status(500).json(x) that's 'res.status(500).json'."""
    holder = argument_holder(call)
    end = holder.start_byte if holder is not None else call.end_byte
    return node_source(call, call.start_byte, end).strip()


def callee_name(call: Node) -> str:
    """The last word of the callee: res.status(500).json -> json.

    Types in angle brackets are skipped first: in C#'s conn.Query<User>(...),
    the method is Query, not User.
    """
    callee = re.sub(r"<[^<>()]*>", "", callee_text(call))
    words = re.findall(r"[A-Za-z_$][\w$]*", callee)
    return words[-1] if words else ""


# ===========================================================================
# ERRORS SHOWN TO VISITORS (ERR-001)
# ===========================================================================

ERR_IMPACT = "Visitors no longer see error details, file paths or personal data. The real error is logged on your server."
CLIENT_ERROR = re.compile(r"\b4\d\d\b|BadRequest|NotFound|Unauthorized|Forbid|Conflict|Unprocessable|"
                          r"bad_request|not_found|unauthorized|forbidden")
# Status codes written as NAMES: Go's http.StatusTeapot, Kotlin's HttpStatusCode.Gone...
STATUS_NAME = re.compile(r"(?:http\.Status|HttpStatusCode\.|StatusCodes\.Status)(\w+)")
# The names that mean a SERVER error (5xx). Every other status name is a
# deliberate message: "not found", "range not satisfiable", and so on.
SERVER_STATUS_NAMES = {
    "InternalServerError", "NotImplemented", "BadGateway", "ServiceUnavailable", "GatewayTimeout",
    "HTTPVersionNotSupported", "VariantAlsoNegotiates", "InsufficientStorage", "LoopDetected",
    "NotExtended", "NetworkAuthenticationRequired",
}


# Ruby on Rails writes statuses as names:  status: :unprocessable_entity
RUBY_STATUS = re.compile(r"status:\s*:(\w+)")
RUBY_SERVER_STATUSES = {"internal_server_error", "not_implemented", "bad_gateway", "service_unavailable",
                        "gateway_timeout", "http_version_not_supported", "insufficient_storage", "loop_detected"}


def is_client_error(code: str) -> bool:
    """Does this response use a 4xx (or other non-server-error) status on purpose?"""
    if CLIENT_ERROR.search(code):
        return True
    ruby = RUBY_STATUS.findall(code)
    if ruby:
        return not any(name in RUBY_SERVER_STATUSES for name in ruby)
    names = STATUS_NAME.findall(code)
    # StatusCodes.Status404NotFound (C#) -> "404NotFound": strip the number first.
    names = [re.sub(r"^\d+", "", name) for name in names]
    return bool(names) and not any(name in SERVER_STATUS_NAMES for name in names)
SERVER_ERROR = re.compile(r"\b5\d\d\b|InternalServerError|internal_server_error")
STATEMENT_HOLDERS = {"block", "compound_statement", "statement_list", "then", "statements", "body_statement"}


def check_errors(file: SourceFile, profile: Profile) -> list[Finding]:
    findings = []
    handler_types = ("if_statement",) if profile.family == "go" else tuple(profile.catch_types)
    for handler in file.nodes_of(*handler_types):
        found = error_handler(handler, profile)
        if found is None:
            continue
        error_name, body, catches_everything = found
        for sink in sinks_in(body, profile):
            finding = error_finding(file, profile, sink, body, error_name, catches_everything)
            if finding is not None:
                findings.append(finding)
    return findings


def error_handler(node: Node, profile: Profile) -> tuple[str, Node, bool] | None:
    """If `node` handles an error, return (its variable name, the code that runs, catches everything?).

    Each language says "something went wrong" differently:
        PHP, Java, C#   catch (Exception e) { ... }
        Ruby            rescue => e
        Kotlin          catch (e: Exception) { ... }
        Swift           catch { ... }              (the error is called `error`)
        Go              if err != nil { ... }
    """
    family = profile.family
    if family == "go":
        if node.type != "if_statement":
            return None
        condition = re.fullmatch(r"\(?\s*(\w+)\s*!=\s*nil\s*\)?", text(node.child_by_field_name("condition")))
        body = node.child_by_field_name("consequence")
        if condition is None or body is None:
            return None
        return condition.group(1), body, True

    if node.type not in profile.catch_types:
        return None
    if family == "php":
        name, body = text(node.child_by_field_name("name")), node.child_by_field_name("body")
        types = text(node.child_by_field_name("type"))
    elif family == "java":
        parameter = next((c for c in node.named_children if c.type == "catch_formal_parameter"), None)
        name, body = text(parameter.child_by_field_name("name")) if parameter else "", node.child_by_field_name("body")
        types = text(parameter)
    elif family == "csharp":
        declaration = next((c for c in node.named_children if c.type == "catch_declaration"), None)
        name = text(declaration.child_by_field_name("name")) if declaration else ""
        body, types = node.child_by_field_name("body"), text(declaration) if declaration else ""
    elif family == "ruby":
        variable = node.child_by_field_name("variable")
        name = text(variable.named_children[0]) if variable and variable.named_children else ""
        body, types = node.child_by_field_name("body"), text(node.child_by_field_name("exceptions"))
    elif family == "kotlin":
        name = text(next((c for c in node.named_children if c.type == "identifier"), None))
        body = next((c for c in node.named_children if c.type == "block"), None)
        types = text(next((c for c in node.named_children if c.type == "user_type"), None))
    else:  # swift
        pattern = node.child_by_field_name("error")
        identifier = next((n for n in walk(pattern) if n.type == "simple_identifier"), None) if pattern else None
        name = text(identifier) if identifier else "error"  # Swift's built-in name
        body = next((c for c in node.named_children if c.type == "statements"), None)
        types = text(pattern) if pattern and " as " in text(pattern) else ""

    if not name or body is None:
        return None
    type_names = re.findall(r"[A-Za-z_]\w*", types)
    catches_everything = not types or any(t.split(".")[-1] in profile.broad_errors for t in type_names)
    return name, body, catches_everything


def own_nodes(root: Node):
    """Walk `root` without going inside functions defined within it."""
    stack = list(reversed(root.children))
    while stack:
        node = stack.pop()
        yield node
        if node.type not in FUNCTION_TYPES:
            stack.extend(reversed(node.children))


def sinks_in(body: Node, profile: Profile) -> list[Node]:
    """The places in the error handler that send something to the visitor."""
    sinks = []
    for node in own_nodes(body):
        if node.type in profile.response_statements:
            sinks.append(node)
        elif is_call(node) and call_arguments(node) and re.search(profile.response_call, callee_text(node)):
            if profile.family == "go" and not go_writes_to_visitor(node):
                continue
            sinks.append(node)
    return sinks


def go_handler_names(node: Node) -> tuple[list[str], list[str]]:
    """The response-writer and context names of the web handler `node` is in.

        func show(w http.ResponseWriter, r *http.Request)   ->  (["w"], [])
        func show(c *gin.Context)                            ->  ([], ["c"])

    Both lists are empty when `node` isn't inside a web handler.
    """
    function = next((a for a in ancestors(node)
                     if a.type in ("function_declaration", "method_declaration", "func_literal")), None)
    if function is None:
        return [], []
    parameters = text(function.child_by_field_name("parameters"))
    writers = re.findall(r"(\w+)\s+http\.ResponseWriter", parameters)
    contexts = re.findall(r"(\w+)\s+\*?(?:gin\.Context|echo\.Context|fiber\.Ctx)", parameters)
    if not writers and not contexts and function.type == "func_literal":
        return go_handler_names(function)  # a function inside a handler counts too
    return writers, contexts


def inside_go_web_handler(node: Node) -> bool:
    writers, contexts = go_handler_names(node)
    return bool(writers or contexts)


def go_writes_to_visitor(call: Node) -> bool:
    """Go only: does this call write to the web response?

    `if err != nil` is on nearly every other line of a Go program, and
    most of them have nothing to do with the web. So a call only counts
    when the function it's in is a web handler, and the call writes to
    that handler's response:

        func show(w http.ResponseWriter, r *http.Request)   ->  w.Write, http.Error(w, ...), fmt.Fprint(w, ...)
        func show(c *gin.Context)                            ->  c.JSON, c.String, ...
    """
    writers, contexts = go_handler_names(call)
    if not writers and not contexts:
        return False

    callee = callee_text(call)
    receiver = callee.split(".")[0]                 # the `w` in w.Write
    first_argument = text(call_arguments(call)[0])  # the `w` in http.Error(w, ...)
    if receiver in contexts:
        return True
    if receiver in writers:
        return callee_name(call) in ("Write", "WriteString")
    return receiver in ("http", "fmt", "io") and first_argument in writers


def error_finding(file, profile, sink, body, error_name, catches_everything) -> Finding | None:
    sink_text = text(sink)
    if is_client_error(sink_text):
        return None  # a deliberate message for the user, like 400 Bad Request
    if not catches_everything and not SERVER_ERROR.search(sink_text):
        return None  # a specific error, shown on purpose
    uses = error_uses(sink, error_name)
    if not uses:
        return None

    line = line_of(sink)
    title = f"Error details sent to visitors ({error_name})"
    message = profile.quote + GENERIC_ERROR_MESSAGE + profile.quote
    leaks = outermost([grow_leak(use, profile) for use in uses])
    edits = [TextEdit(file.path, leak.start_byte, leak.end_byte, message.encode()) for leak in leaks]

    if not already_logs_error(profile, body, error_name):
        statement = statement_of(sink)
        log = log_line(file, profile, error_name)
        insert = insert_line_before(file, statement, log) if statement is not None else None
        if insert is None:
            return manual("ERR-001", title, file, sink, ERR_IMPACT,
                          f"Log the error with {log} and send a generic message instead.", Severity.WARNING)
        edits.append(insert)

    fix = Fix(edits=edits, preview_before=short(sink_text, 45), preview_after="generic message + log the error")
    return Finding("ERR-001", title, file.path, line, ERR_IMPACT, Severity.WARNING, fix=fix)


def already_logs_error(profile: Profile, body: Node, error_name: str) -> bool:
    """Is the ERROR ITSELF already being logged in this handler?

    A log line that leaves the error out ("save failed") doesn't count:
    once the response stops showing the error too, nobody could find the
    cause. So the same line must mention the error, or be one of the
    calls that record it by themselves (printStackTrace).
    """
    name = re.escape(error_name.lstrip("$"))
    for line in text(body).splitlines():
        if re.search(profile.already_logs, line) and re.search(rf"\b{name}\b|printStackTrace", line):
            return True
    return False


def error_uses(sink: Node, error_name: str) -> list[Node]:
    """Places in the sink that read the error variable."""
    uses = []
    for node in walk(sink):
        if node.named_child_count == 0 and text(node) == error_name.lstrip("$") and node.type in NAME_TYPES:
            # PHP: the name node sits inside a variable_name ($e); use the whole $e.
            if node.parent is not None and node.parent.type == "variable_name":
                node = node.parent
            if not is_property_name(node):
                uses.append(node)
    return uses


def is_property_name(node: Node) -> bool:
    """True for the `e` in  obj.e  (a property that happens to share the name)."""
    parent = node.parent
    return bool(parent is not None and is_access(parent) and parent.named_children
                and parent.named_children[0] != node)


ACCESS_TYPES = {"member_call_expression", "member_access_expression", "method_invocation", "selector_expression",
                "call", "navigation_expression", "field_access", "invocation_expression", "call_expression",
                "nullsafe_member_access_expression", "nullsafe_member_call_expression", "navigation_suffix"}


def is_access(node: Node) -> bool:
    return node.type in ACCESS_TYPES


def grow_leak(use: Node, profile: Profile) -> Node:
    """Grow a use of the error into the whole expression that shows it.

    e  ->  e.getMessage()  ->  "Failed: " . e.getMessage()  ->  "Failed: ${e.message}"
    """
    node = use
    while node.parent is not None:
        parent = node.parent
        if is_access(parent) and parent.named_children and parent.named_children[0] == node:
            node = parent                                   # e.message, e.getMessage()
        elif parent.type in profile.string_types or "interpolat" in parent.type:
            string = parent if parent.type in profile.string_types else \
                next((a for a in ancestors(parent) if a.type in profile.string_types), None)
            if string is None:
                return node
            node = string                                   # "Failed: $e"
        elif ("binary" in parent.type or "additive" in parent.type) and \
                any(not c.is_named and text(c) in ("+", ".") for c in parent.children):
            node = parent                                   # "Failed: " . $e
        elif "cast" in parent.type or parent.type == "parenthesized_expression":
            node = parent                                   # (string) $e
        elif parent.type in ARGUMENT_HOLDERS | {"argument", "value_argument"} and parent.parent is not None \
                and is_call(parent.parent) and makes_text(parent.parent):
            node = parent.parent                            # fmt.Sprintf("%v", err)
        elif parent.type == "call_suffix" and parent.parent is not None:
            node = parent.parent
        else:
            return node
    return node


# Functions that turn a value into text. Only THESE may be swallowed whole
# when a leak is replaced: fmt.Sprintf("%v", err) becomes "Something went wrong".
TEXT_MAKERS = {"Sprintf", "Sprint", "sprintf", "format", "Format", "valueOf", "strval", "toString", "to_s"}


def makes_text(call: Node) -> bool:
    """Is this call just turning a value into text, like fmt.Sprintf(...)?

    The check is on the exact name. A looser check once matched
    c.String(500, err.Error()) and buf.WriteString(err.Error()) because
    their names END in "String", and the whole call (the response itself!)
    was replaced by a bare piece of text.
    """
    return callee_name(call) in TEXT_MAKERS or callee_text(call) == "String"  # Swift: String(describing: error)


def outermost(nodes: list[Node]) -> list[Node]:
    """Drop duplicates, and nodes that sit inside another node in the list."""
    result = []
    for node in nodes:
        span = (node.start_byte, node.end_byte)
        inside = any(o.start_byte <= span[0] and span[1] <= o.end_byte and (o.start_byte, o.end_byte) != span
                     for o in nodes)
        if not inside and all((n.start_byte, n.end_byte) != span for n in result):
            result.append(node)
    return result


def statement_of(node: Node) -> Node | None:
    """The whole statement containing `node`, if it sits directly in a block."""
    current = node
    while current.parent is not None:
        if current.parent.type in STATEMENT_HOLDERS:
            return current
        current = current.parent
    return None


def log_line(file: SourceFile, profile: Profile, error_name: str) -> str:
    if profile.family == "go" and not re.search(rb'"log"', file.source):
        return f"println({error_name}.Error())"  # Go's built-in println needs no import
    return profile.log_line.format(error=error_name)


# ===========================================================================
# ASYNC (ASYNC-005 to ASYNC-009)
# ===========================================================================

def check_async(file: SourceFile) -> list[Finding]:
    checkers = {
        "csharp": csharp_async_void,
        "go": go_unprotected_goroutines,
        "java": java_unhandled_futures,
        "kotlin": kotlin_global_scope,
        "swift": swift_unhandled_tasks,
    }
    checker = checkers.get(file.lang.family)
    return checker(file) if checker else []


def csharp_async_void(file: SourceFile) -> list[Finding]:
    """ASYNC-005: `async void` methods.

    If an `async void` method throws, nothing can catch the error and the
    whole program crashes. `async Task` lets the caller catch it.
    (Event handlers, like button clicks, must stay void, so they're skipped.)
    """
    findings = []
    source_text = file.source.decode("utf-8", "replace")
    # The short name Task only works if the file says  using System.Threading.Tasks;
    # Otherwise the full name is used, which always works. (A build test caught
    # an older version guessing "Task" just because the word appeared somewhere.)
    task = "Task" if re.search(r"using\s+System\.Threading\.Tasks\s*;", source_text) else \
        "System.Threading.Tasks.Task"
    for method in file.nodes_of("method_declaration", "local_function_statement"):
        modifiers = {text(child) for child in method.children if child.type == "modifier"}
        returns = method.child_by_field_name("returns") or method.child_by_field_name("type")
        if "async" not in modifiers or returns is None or text(returns) != "void":
            continue
        if "EventArgs" in text(method.child_by_field_name("parameters")):
            continue  # an event handler: void is required here
        name_node = method.child_by_field_name("name")
        name = text(name_node)
        title = f"async void method '{name}' can crash the app"
        impact = "Errors in this method can now be caught, instead of crashing the whole program."

        if not csharp_void_can_change(file, method, name_node, modifiers):
            findings.append(manual(
                "ASYNC-005", title, file, method, impact,
                "Change `async void` to `async Task` and add `await` where it's called. I left it alone "
                "because other code may rely on it returning nothing (a base class, an event, or "
                "another file).",
            ))
            continue
        fix = Fix(edits=[TextEdit(file.path, returns.start_byte, returns.end_byte, task.encode())],
                  preview_before=f"async void {name}(…)", preview_after=f"async {task} {name}(…)")
        findings.append(Finding("ASYNC-005", title, file.path, line_of(method), impact, Severity.CRITICAL, fix=fix))
    return findings


def csharp_void_can_change(file: SourceFile, method: Node, name_node: Node, modifiers: set[str]) -> bool:
    """Is it safe to change this method from `void` to `Task`?

    Only when nothing else can depend on it returning nothing:
      * it's private, so no other file uses it (C# methods are private
        unless marked public, protected or internal);
      * it isn't `override`, `virtual` or `abstract`, where the return
        type must match another class;
      * everywhere this file mentions it, it's CALLED:  Refresh();
        and never handed over as a value:  timer.Elapsed += Refresh;
        (an event expects a method that returns nothing).
    """
    if modifiers & {"public", "protected", "internal", "override", "virtual", "abstract", "new"}:
        return False
    if any(child.type == "explicit_interface_specifier" for child in method.children):
        return False
    name = text(name_node)
    for node in file.nodes_of("identifier"):
        if text(node) != name or node == name_node:
            continue
        after = file.source[node.end_byte : node.end_byte + 20].lstrip()
        if not after.startswith(b"("):
            return False  # mentioned without being called
    return True


def go_unprotected_goroutines(file: SourceFile) -> list[Finding]:
    """ASYNC-006: `go func() { ... }()` with no recover(), inside a web handler.

    A panic inside a goroutine crashes the ENTIRE program, even if main()
    is fine. A deferred recover() catches it.

    Only goroutines started from a WEB HANDLER are reported. Go's web server
    already catches crashes in the handler itself, but not in background
    tasks it starts, so one bad request can take the whole site down. Most
    other goroutines are part of a program's own design, and experienced Go
    developers deliberately leave them alone: testing on a large real Go
    project found over a hundred, nearly all of them fine.
    """
    findings = []
    for statement in file.nodes_of("go_statement"):
        if not statement.named_children or not inside_go_web_handler(statement):
            continue
        call = statement.named_children[0]
        function = call.child_by_field_name("function") if call.type == "call_expression" else None
        title = "Background task (goroutine) can crash the whole program"
        impact = "A crash inside this background task is now caught, instead of taking down the whole program."
        if function is None or function.type != "func_literal":
            findings.append(manual("ASYNC-006", title, file, statement, impact,
                                   "Add  defer func() { if r := recover(); r != nil { log.Println(r) } }()  "
                                   "at the top of the function this starts."))
            continue
        body = function.child_by_field_name("body")
        if body is None or "recover()" in text(body):
            continue
        findings.append(Finding("ASYNC-006", title, file.path, line_of(statement), impact, Severity.CRITICAL,
                                fix=go_recover_fix(file, body)))
    return findings


def go_recover_fix(file: SourceFile, body: Node) -> Fix:
    source_text = file.source.decode("utf-8", "replace")
    if re.search(r'"log"', source_text):
        report = 'log.Println("recovered from panic:", rec)'
    elif re.search(r'"fmt"', source_text):
        report = 'fmt.Println("recovered from panic:", rec)'
    else:
        report = 'println("recovered from a panic in a background task")'
    open_brace = body.start_byte + 1
    statements = [c for c in body.named_children if c.type != "comment"]
    multi_line = statements and file.source[open_brace:statements[0].start_byte].count(b"\n") > 0
    if multi_line:
        nl = newline_of(file.source)
        inner = indent_at(file.source, statements[0].start_byte)
        tab = "\t" if inner.startswith("\t") else "    "
        code = (f"{nl}{inner}defer func() {{{nl}{inner}{tab}if rec := recover(); rec != nil {{{nl}"
                f"{inner}{tab}{tab}{report}{nl}{inner}{tab}}}{nl}{inner}}}()")
    else:
        code = f" defer func() {{ if rec := recover(); rec != nil {{ {report} }} }}();"
    return Fix(edits=[TextEdit(file.path, open_brace, open_brace, code.encode())],
               preview_before="go func() { … }()", preview_after="go func() { defer recover() … }()")


def java_unhandled_futures(file: SourceFile) -> list[Finding]:
    """ASYNC-007: CompletableFuture.runAsync/supplyAsync with nothing handling errors.

    If the background work fails, the error is stored inside the future
    and nobody ever looks at it: it disappears without a trace.
    """
    findings = []
    # The handler's parameter gets a name nobody else uses. Java refuses to
    # build if it's called the same as a variable nearby, and `e` is what
    # almost everyone calls a caught exception.
    handler = ".exceptionally(asyncError -> { asyncError.printStackTrace(); return null; })"
    for statement in file.nodes_of("expression_statement"):
        if not statement.named_children:
            continue
        expression = statement.named_children[0]
        code = text(expression)
        if not re.match(r"CompletableFuture\s*\.\s*(?:runAsync|supplyAsync)\b", code):
            continue
        if re.search(r"\.(?:exceptionally|handle|whenComplete|join|get)\s*\(", code):
            continue
        fix = Fix(edits=[TextEdit(file.path, expression.end_byte, expression.end_byte, handler.encode())],
                  preview_before=short(code, 40), preview_after="… " + handler)
        findings.append(Finding(
            "ASYNC-007", "Background task errors disappear silently", file.path, line_of(statement),
            "If this background work fails, the error is now printed instead of vanishing.",
            Severity.WARNING, fix=fix,
        ))
    return findings


# Prints the error instead of crashing. Written with its full name
# (kotlinx.coroutines....) so no import line is needed.
KOTLIN_HANDLER = "kotlinx.coroutines.CoroutineExceptionHandler { _, throwable -> throwable.printStackTrace() }"


KOTLIN_BROWSER_CODE = re.compile(r"/(?:js|frontend|wasmJs|browser)Main/")


def kotlin_global_scope(file: SourceFile) -> list[Finding]:
    """ASYNC-008: GlobalScope.launch { } with no error handler.

    FIX: give launch an error handler, which prints the error:
        GlobalScope.launch { ... }
          -> GlobalScope.launch(kotlinx.coroutines.CoroutineExceptionHandler { _, throwable -> ... }) { ... }
        GlobalScope.launch(Dispatchers.IO) { ... }
          -> GlobalScope.launch(Dispatchers.IO + kotlinx.coroutines.CoroutineExceptionHandler { ... }) { ... }
    (In Kotlin, + combines settings like Dispatchers.IO with a handler.)
    GlobalScope.async keeps its errors for whoever reads the result, where a
    handler does nothing, so async only gets instructions.

    Not reported for Kotlin that runs in a web browser (Kotlin/JS: the
    jsMain, frontendMain or wasmJsMain folders). There an error is printed
    to the browser's console and nothing crashes.
    """
    if KOTLIN_BROWSER_CODE.search(file.path.as_posix()):
        return []
    findings = []
    for call in file.nodes_of("call_expression"):
        if not re.match(r"GlobalScope\s*\.\s*(?:launch|async)\b", text(call)):
            continue
        # GlobalScope.launch(Dispatchers.IO) { } is a call INSIDE a call: the
        # outer one (with the { } block) is reported, the inner one skipped.
        if call.parent is not None and call.parent.type == "call_expression" \
                and re.match(r"GlobalScope\s*\.\s*(?:launch|async)\b", text(call.parent)):
            continue
        if "CoroutineExceptionHandler" in text(call) or "try" in text(call):
            continue
        title = "Background coroutine can crash the app"
        impact = "Errors in this background work are now caught instead of crashing the app."
        fix = kotlin_handler_fix(file, call)
        if fix is None:
            findings.append(manual(
                "ASYNC-008", title, file, call, impact,
                "Run it in a scope you control (like viewModelScope or a CoroutineScope), or pass a "
                "CoroutineExceptionHandler { _, e -> e.printStackTrace() } to launch().",
                Severity.WARNING,
            ))
        else:
            findings.append(Finding("ASYNC-008", title, file.path, line_of(call), impact, Severity.WARNING, fix=fix))
    return findings


def kotlin_handler_fix(file: SourceFile, call: Node) -> Fix | None:
    """The edit that adds an error handler to GlobalScope.launch, or None if unsure."""
    target = next((n for n in walk(call) if n.type == "navigation_expression"
                   and re.fullmatch(r"GlobalScope\s*\.\s*launch", text(n))), None)
    if target is None:
        return None  # GlobalScope.async, or a shape we don't recognise
    arguments = target.next_named_sibling
    if arguments is not None and arguments.type == "value_arguments":
        closing = arguments.end_byte - 1  # the )
        joiner = " + " if arguments.named_children else ""
        edit = TextEdit(file.path, closing, closing, (joiner + KOTLIN_HANDLER).encode())
    else:
        edit = TextEdit(file.path, target.end_byte, target.end_byte, f"({KOTLIN_HANDLER})".encode())
    return Fix(edits=[edit], preview_before="GlobalScope.launch { … }",
               preview_after="GlobalScope.launch(CoroutineExceptionHandler { … }) { … }")


def swift_unhandled_tasks(file: SourceFile) -> list[Finding]:
    """ASYNC-009: Task { try ... } with no do/catch.

    Errors thrown inside a Task are stored and, if nobody awaits the task,
    silently thrown away.

    FIX (for a Task that stands on its own line): wrap its work in
        do { ... } catch { print(error) }
    A Task whose result is kept (let t = Task { ... }) gets instructions
    instead: wrapping it would change what the task hands back.
    """
    findings = []
    for call in file.nodes_of("call_expression"):
        if not call.named_children or text(call.named_children[0]) not in ("Task", "Task.detached"):
            continue
        body = text(call)
        if not re.search(r"\btry\b(?!\?)", body) or "catch" in body:
            continue
        if result_read_later(file, call):
            continue  # let task = Task { ... } ... try await task.value: the error is passed on
        title = "Background task errors disappear silently"
        impact = "Errors in this background work are now printed instead of vanishing."
        fix = swift_do_catch_fix(file, call)
        if fix is None:
            findings.append(manual("ASYNC-009", title, file, call, impact,
                                   "Wrap the work in  do { ... } catch { print(error) }  inside the Task.",
                                   Severity.WARNING))
        else:
            findings.append(Finding("ASYNC-009", title, file.path, line_of(call), impact, Severity.WARNING, fix=fix))
    return findings


def result_read_later(file: SourceFile, call: Node) -> bool:
    """Is the Task stored in a variable whose .value is read somewhere in the file?

        let task = Task { try await compute() }
        ...
        return try await task.value      <- the error comes out here
    """
    before = file.source[line_start(file.source, call.start_byte):call.start_byte].decode("utf-8", "replace")
    stored = re.search(r"(?:let|var)?\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*$", before)
    if stored is None:
        return False
    name = re.escape(stored.group(1))
    return re.search(rf"\b{name}\s*\.\s*value\b".encode(), file.source) is not None


def swift_do_catch_fix(file: SourceFile, call: Node) -> Fix | None:
    stands_alone = call.parent is not None and call.parent.type in ("statements", "source_file")
    statements = next((n for n in walk(call) if n.type == "statements"), None)
    if not stands_alone or statements is None:
        return None
    source = file.source
    first_line = line_start(source, statements.start_byte)
    on_own_lines = source[first_line:statements.start_byte].strip() == b"" and \
        b"\n" in source[statements.end_byte:call.end_byte]
    if not on_own_lines:
        # Task { try await work() }  ->  Task { do { try await work() } catch { print(error) } }
        return Fix(edits=[TextEdit(file.path, statements.start_byte, statements.start_byte, b"do { "),
                          TextEdit(file.path, statements.end_byte, statements.end_byte,
                                   b" } catch { print(error) }")],
                   preview_before="Task { try … }", preview_after="Task { do { try … } catch { print(error) } }")
    # Several lines: indent the work one level, inside do { ... }.
    nl = newline_of(source)
    indent = indent_at(source, statements.start_byte)
    unit = "    "
    edits = [TextEdit(file.path, first_line, first_line, f"{indent}do {{{nl}".encode())]
    position = first_line
    while position != -1 and position < statements.end_byte:
        if source[position:position + 1] not in (b"\n", b"\r"):
            edits.append(TextEdit(file.path, position, position, unit.encode()))
        next_newline = source.find(b"\n", position, statements.end_byte)
        position = next_newline + 1 if next_newline != -1 else -1
    edits.append(TextEdit(file.path, statements.end_byte, statements.end_byte,
                          f"{nl}{indent}}} catch {{{nl}{indent}{unit}print(error){nl}{indent}}}".encode()))
    return Fix(edits=edits, preview_before="Task { try … }", preview_after="Task { do { try … } catch { print(error) } }")
