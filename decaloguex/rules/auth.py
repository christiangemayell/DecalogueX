"""
auth.py: AUTH-001, an ownership check that lets logged-out visitors through.

THE PROBLEM
    const session = await getServerSession(authOptions)
    await db.post.count({ where: { id: postId, authorId: session?.user.id } })

    This asks "is there a post with this ID, written by YOU?". But when
    nobody is logged in, session?.user.id is undefined, and the database
    libraries (Prisma, and Mongoose by default) quietly SKIP any filter set
    to undefined. The question becomes "is there a post with this ID?", the
    answer is yes, and a logged-out visitor can edit or delete anyone's post.

    Like a bouncer who asks "is your name on the list?", and lets you in
    when you don't give a name.

    Found in a popular Next.js template during testing (js-3-nextjs-taxonomy).

WHAT COUNTS
    A database filter whose value might be empty because of ?. :
        where: { authorId: session?.user.id }          (Prisma)
        Post.findOne({ _id: id, owner: req.user?._id }) (Mongoose)
    ...unless the code already checks for a login first, like
        if (!session) return ...

WHAT TO DO
    A "What to do" card: check that someone is logged in BEFORE the query.
    Not fixed automatically: the right answer for a logged-out visitor (a
    login page, 401 or 403) depends on the app.
"""

from __future__ import annotations

import re

from tree_sitter import Node

from decaloguex.languages import SourceFile, ancestors, field, line_of, text
from decaloguex.models import Finding, Severity

TITLE = "Owner check lets logged-out visitors through"
IMPACT = "Visitors who aren't logged in can't read, change or delete other people's data."
NOTE = ("When nobody is logged in, {value} is undefined, and the database skips filters set to undefined, "
        "so this matches EVERYONE's data. Check for a login first, before this query, for example: "
        "if (!{root}) return new Response(null, {{ status: 401 }})")

# The last part of a login value: session?.user.id, req.user?._id, currentUser?.email
ID_ENDING = re.compile(r"(?:\.|\?\.)(?:id|_id|userId|uid|sub|email)$")

# Where the logged-in user lives in Express, Koa, SvelteKit, Fastify...
LOGIN_OBJECTS = re.compile(r"^(?:req|request|ctx|context|event)\.(?:user|session|auth|locals\.user|state\.user)$"
                           r"|^(?:locals|ctx\.state)\.user$")
# Functions that return the logged-in user: getServerSession(), auth(), currentUser()...
LOGIN_FUNCTIONS = (r"(?:getServerSession|getSession|auth|currentUser|getCurrentUser|getUser|getAuth|"
                   r"getToken|validateRequest|requireUser|getLoggedInUser|useSession)")


def comes_from_login(file: SourceFile, root: str) -> bool:
    """Is `root` the logged-in user, not just something NAMED like it?

    In a Stripe webhook, "session" is a payment (a Checkout Session), not a
    login. So the variable must come from a login function:
        const session = await getServerSession(authOptions)
        const { user } = await validateRequest()
    or be where frameworks keep the user: req.user, ctx.state.user...
    """
    if LOGIN_OBJECTS.match(root):
        return True
    name = re.escape(root.split(".")[0])
    source = file.source.decode("utf-8", "replace")
    assigned = rf"(?:\b{name}\b|\{{[^}}]*\b{name}\b[^}}]*\}})\s*=\s*(?:await\s+)?[\w.]*\b{LOGIN_FUNCTIONS}\s*\("
    return re.search(assigned, source) is not None

# Mongoose calls whose first argument is a filter.
MONGOOSE_FILTERS = {
    "find", "findOne", "findById", "countDocuments", "exists", "deleteOne", "deleteMany", "updateOne",
    "updateMany", "findOneAndUpdate", "findOneAndDelete", "findOneAndRemove", "findOneAndReplace", "replaceOne",
}
FUNCTIONS = ("arrow_function", "function_expression", "function_declaration", "method_definition", "function")


def check(file: SourceFile) -> list[Finding]:
    """Check one JavaScript/TypeScript or Python file. Returns findings; writes nothing."""
    findings = missing_owner_checks(file)  # AUTH-002 (see the bottom of this file)
    if file.lang.family != "js":
        return findings
    seen = set()
    for pair in file.nodes_of("pair"):
        value = field(pair, "value")
        if value is None or value.type != "member_expression":
            continue
        written = text(value)
        if "?." not in written or not ID_ENDING.search(written):
            continue  # no ?. means it can't quietly be undefined
        root = written.split("?.")[0]  # session?.user.id -> session,  req.user?._id -> req.user
        if not comes_from_login(file, root) or not in_database_filter(pair):
            continue
        if checked_first(file, value, root):
            continue
        line = line_of(value)
        if line in seen:
            continue
        seen.add(line)
        findings.append(Finding("AUTH-001", TITLE, file.path, line, IMPACT, Severity.CRITICAL,
                                note=NOTE.format(value=text(value), root=root)))
    return findings


def in_database_filter(pair: Node) -> bool:
    """Is this  key: value  inside a Prisma  where: { }  or a Mongoose filter?"""
    for outer in ancestors(pair):
        if outer.type in FUNCTIONS:
            return False
        if outer.type == "pair" and text(field(outer, "key")) == "where":
            return True
        if outer.type == "call_expression":
            callee = field(outer, "function")
            name = text(field(callee, "property")) if callee is not None and callee.type == "member_expression" else ""
            arguments = field(outer, "arguments")
            first = arguments.named_children[0] if arguments is not None and arguments.named_children else None
            if name in MONGOOSE_FILTERS and first is not None and first.start_byte <= pair.start_byte < first.end_byte:
                return True
    return False


def checked_first(file: SourceFile, value: Node, root: str) -> bool:
    """Does the function check for a login before this line?

        if (!session) return ...        if (!session?.user) throw ...
        if (!req.user) { ... }          if (session == null) ...
    """
    function = next((a for a in ancestors(value) if a.type in FUNCTIONS), None)
    start = function.start_byte if function is not None else 0
    before = file.source[start:value.start_byte].decode("utf-8", "replace")
    name = re.escape(root.split(".")[0])
    guard = rf"if\s*\(\s*(?:!\s*{name}\b|{name}\b[\w?.]*\s*(?:==|===)\s*(?:null|undefined))"
    return re.search(guard, before) is not None


# ===========================================================================
# AUTH-002: anyone logged in can change anyone's data
# ===========================================================================
#
# THE PROBLEM
#     def destroy(self, request, comment_pk=None):
#         comment = Comment.objects.get(pk=comment_pk)
#         comment.delete()
#
#     The comment's ID comes from the web address, so ANY logged-in user can
#     change the number and delete someone else's comment. Nothing checks
#     that it belongs to the person asking. (Found in python-2-django-realworld.)
#
# WHAT COUNTS (only the simple case, all inside one function)
#     1. something is looked up by an ID that comes from the request,
#     2. then it's changed or deleted,
#     3. and the function never mentions the person asking: no request.user,
#        req.user, owner/author check or permission check.
#     Admin pages are skipped: admins are meant to change anything.
#     Checks that live in another file (Laravel policies, a permission class
#     on the view) can't be seen, so this is a card, never a change.

AUTH2_TITLE = "Anyone logged in can change anyone's data"
AUTH2_IMPACT = "People can only change or delete their own things, not everyone's."
AUTH2_NOTE = ("This looks up {thing} by the ID in the request and then changes or deletes it, but never checks "
              "it belongs to the person asking, so any logged-in user could change the ID and edit or delete "
              "someone else's. Check the owner first, for example: {example}. If a check like this happens "
              "somewhere else (a permission class or policy), you can ignore this.")
AUTH2_EXAMPLE = {
    "python": "if comment.author != request.user: return HttpResponseForbidden()",
    "js": "if (post.authorId !== req.user.id) return res.status(403).end()",
}

# Looking something up by an ID:  Comment.objects.get(pk=...)  Post.findById(req.params.id)
LOOKUP = re.compile(
    r"(?P<var>[A-Za-z_]\w*)\s*=\s*(?:await\s+)?[\w.]*?"
    r"(?:\.objects\.get|\.queryset\.get|\.query\.get(?:_or_404)?|get_object_or_404|\.get_or_404|\.first_or_404"
    r"|\.findById|\.findByPk|\.findUnique|\.findFirst|\.findOne)\s*\((?P<args>[^)]*)\)")
# Changing or deleting what was looked up:  comment.delete()   serializer_class(instance, ...)
# (A Django serializer only CHANGES the object when it's given new data=...;
#  without it, it's just showing the object.)
CHANGE = (r"\b{var}\s*\.\s*(?:delete|destroy|remove|deleteOne|save|update|updateOne)\s*\("
          r"|(?:Serializer\w*|serializer_class)\(\s*{var}\b[^)]*\bdata\s*=")
# Changing or deleting straight by an ID from the request (JavaScript):
#   Post.findByIdAndDelete(req.params.id)   prisma.post.delete({ where: { id: req.params.id } })
DIRECT_CHANGE = re.compile(
    r"\.(?:findByIdAndDelete|findByIdAndUpdate|findByIdAndRemove|findOneAndDelete|findOneAndUpdate|deleteOne|updateOne)"
    r"\(\s*(?:\{[^)]*)?req\.(?:params|body|query)"
    r"|\.(?:delete|update|destroy)\(\s*\{\s*where\s*:\s*\{[^}]*req\.(?:params|body|query)")
# Any sign that the person asking is taken into account.
ASKER = re.compile(
    r"(?i)request\.user|current_user|req\.user|res\.locals\.user|\bsession\b|\buser_?id\b|\bauthor|\bowner|created_by"
    r"|has_perm|permission|authoriz|can_(?:edit|delete|update|change|manage)|is_admin|is_staff|is_superuser"
    r"|\bpolicy\b|\bgate\b|ctx\.state\.user|locals\.user|getServerSession|auth\(\)")
PY_FUNCTIONS = ("function_definition",)


def missing_owner_checks(file: SourceFile) -> list[Finding]:
    family = file.lang.family
    if family not in ("js", "python") or "admin" in file.path.as_posix().lower():
        return []
    function_types = PY_FUNCTIONS if family == "python" else FUNCTIONS
    findings = []
    seen = set()
    for function in file.nodes_of(*function_types):
        body = text(function)
        if ASKER.search(body) or owner_checked_on_class(function):
            continue
        place = changes_by_request_id(body, function, family)
        if place is None:
            continue
        thing, offset = place
        line = function.start_point.row + 1 + body.count("\n", 0, offset)
        if line in seen:
            continue
        seen.add(line)
        findings.append(Finding("AUTH-002", AUTH2_TITLE, file.path, line, AUTH2_IMPACT, Severity.CRITICAL,
                                note=AUTH2_NOTE.format(thing=thing, example=AUTH2_EXAMPLE[family])))
    return findings


def changes_by_request_id(body: str, function: Node, family: str) -> tuple[str, int] | None:
    """Where this function changes something it looked up by a request ID, or None."""
    if family == "js":
        direct = DIRECT_CHANGE.search(body)
        if direct:
            return "a record", direct.start()
    from_request = request_inputs(function, family)
    for lookup in LOOKUP.finditer(body):
        args = lookup.group("args")
        if not any(re.search(rf"\b{re.escape(name)}\b", args) for name in from_request):
            continue  # not looked up by an ID the visitor sent
        var = re.escape(lookup.group("var"))
        change = re.search(CHANGE.format(var=var), body[lookup.end():])
        if change:
            return f"'{lookup.group('var')}'", lookup.start()
    return None


def request_inputs(function: Node, family: str) -> list[str]:
    """Names that hold what the visitor sent: req.params / request, or a view's own parameters (slug, pk...)."""
    if family == "js":
        return ["req.params", "req.body", "req.query", "params"]
    parameters = field(function, "parameters")
    names = [] if parameters is None else re.findall(r"([A-Za-z_]\w*)\s*(?::[^,=)]*)?(?:=[^,)]*)?(?:,|$)",
                                                     text(parameters).strip("()"))
    return [n for n in names if n not in ("self", "cls", "request", "args", "kwargs")] + ["request"]


def owner_checked_on_class(function: Node) -> bool:
    """Django REST: a permission class on the view that checks the owner (IsOwner, IsAuthorOrReadOnly...)."""
    for outer in ancestors(function):
        if outer.type == "class_definition":
            return re.search(r"(?i)owner|isauthor|has_object_permission", text(outer)) is not None
    return False
