"""
injection.py: ten common ways visitor input becomes an attack, in every language.

  CMD-001     Command injection. Visitor text glued into a computer command:
                  shell_exec("ping " . $_GET["ip"])
              Typing  1.1.1.1; rm -rf /  runs the second command too.
  EVAL-001    Visitor text run as code:   eval(req.body.amount)
  PATH-001    A file picked by the visitor:   res.sendFile(req.query.file)
              Asking for  ../../.env  downloads your secrets.
  DESER-001   Unsafe data loading:   pickle.loads(...)  Marshal.load(...)
              These formats can carry hidden code that runs when loaded.
              FIX (Python): yaml.load(x)  ->  yaml.safe_load(x)
  NOSQL-001   NoSQL injection (MongoDB):   find({ $where: "this.id == " + id })
              or a visitor's whole object used as a filter: { _id: req.body.id }
              (a visitor can send  {"$ne": null}  and match everything).
  REDIRECT-001  Open redirect:   res.redirect(req.query.url)
              Scammers send links to YOUR site that bounce people to theirs.
  SSRF-001    The server fetches a web address the visitor chose:
                  fetch(req.body.url)
              They can make it read your internal services or cloud keys.
  XXE-001     XML read with "external entities" switched on, which lets a
              visitor's XML file read files from your server.
  HASH-001    Passwords scrambled with MD5 or SHA-1, which can be cracked in
              seconds. Use bcrypt, argon2 or scrypt instead.
  CSRF-001    CSRF protection switched off, so other websites can submit
              forms as your logged-in visitors.

HOW IT WORKS (the same three steps for every rule)
    1. Find the danger point:  exec(...), eval(...), sendFile(...)...
    2. Find the function (or file) it's in, and work out which names hold
       visitor input there:  const ip = req.query.ip   ->  "ip" is visitor input.
       (Names built from those count too:  const cmd = "ping " + ip.)
    3. Report it only if visitor input reaches the danger point.
       exec("ls") is fine; exec("ping " + ip) isn't.
    HASH-001, XXE-001 and CSRF-001 don't need step 2: they're settings or
    choices that are risky wherever they are.

    Almost everything is a "What to do" card: whether a value is safe often
    depends on checks only a person can judge. The one automatic fix
    (yaml.safe_load) can't change what a normal app does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from decaloguex.languages import SourceFile, line_of
from decaloguex.models import Finding, Fix, Severity, TextEdit

# ===========================================================================
# STEP 2: WHAT COUNTS AS VISITOR INPUT
# ===========================================================================

VISITOR_INPUT = {
    "js": r"\breq\.(?:body|query|params|headers|cookies|files?)\b|\brequest\.(?:body|query|params)\b"
          r"|\b(?:req|request)\.(?:json|formData|text)\s*\(|\bnextUrl\.searchParams\b|\bsearchParams\.get\("
          r"|\b(?:req|request)\.(?:url|nextUrl)\b|\w\(\s*(?:await\s+)?(?:req|request)\s*[,)]"
          r"|\bctx\.(?:request|query|params)\b|\bevent\.(?:body|queryStringParameters|pathParameters)\b"
          r"|searchParams\.get\(|formData\.get\(|\blocation\.(?:search|hash)\b",
    "python": r"\brequest\.(?:GET|POST|args|form|json|data|values|files|query_params|body|cookies|headers|get_json)\b",
    "php": r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|\$request->|\brequest\(\)->|->input\(|->query\(",
    "ruby": r"\bparams\s*(?:\[|\.(?:require|permit|fetch|dig|to_unsafe_h|slice|except)\b)"
            r"|\brequest\.(?:params|body|query_parameters)\b|\bcookies\[",
    "java": r"getParameter\(|getHeader\(|getInputStream\(|getQueryString\(",
    "kotlin": r"getParameter\(|call\.(?:parameters|receive|request\.queryParameters)",
    "go": r"\br\.(?:URL\.Query|FormValue|PostFormValue|Form|PostForm|Body)\b|\bc\.(?:Query|Param|PostForm|FormValue|DefaultQuery|Bind\w*)\(|mux\.Vars\(",
    "csharp": r"\bRequest\.(?:Query|Form|Body|Cookies|Headers)\b",
}
# Function parameters that ARE visitor input:  @RequestParam String file   [FromQuery] string url
ANNOTATED_PARAMETER = re.compile(
    r"(?:@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|Query|Param|Body|Headers)\b(?:\([^)]*\))?"
    r"|\[From(?:Query|Body|Route|Form|Header)\])\s*(?:final\s+)?(?:[\w<>\[\],.?]+\s+)?(?P<name>[A-Za-z_]\w*)")
# Python web routes: their own parameters come from the web address.
PY_ROUTE = re.compile(r"@\w+\.(?:route|get|post|put|patch|delete|api_route)\(|@(?:api_view|action)\b")
NOT_NAMES = {"const", "let", "var", "final", "val", "String", "int", "long", "Integer", "string", "auto",
             "self", "this", "new", "return", "await", "public", "private", "static", "def", "if", "for"}
# Helpers that check or clean a value: its result isn't raw visitor input any more.
# (Not schema checks like zod's safeParse or joi's validate: they confirm the TYPE,
#  so a URL or file path that passes them is still exactly what the visitor typed.)
CLEANED = re.compile(r"(?i)\b(?!safe_?parse)\w*(?:safe|resolve|sanitize|clean|secure|whitelist|allowlist|basename)\w*\s*\(")
ASSIGNMENT = re.compile(r"^\s*(?P<lhs>[^=;()]+?)\s*(?::=|\+=|\.=|=)(?![=>~])(?P<rhs>.*)$")


def visitor_names(scope: str, family: str, parameters: str) -> set[str]:
    """Names in this function that hold visitor input (step 2)."""
    source = re.compile(VISITOR_INPUT.get(family, r"(?!x)x"))
    names = {m.group("name") for m in ANNOTATED_PARAMETER.finditer(parameters)}
    if family == "python" and parameters:
        names |= {n for n in re.findall(r"([A-Za-z_]\w*)\s*(?::[^,=)]*)?(?:=[^,)]*)?(?:,|$)", parameters)
                  if n not in ("self", "cls", "request", "args", "kwargs")}
    lines = scope.splitlines()
    for _ in range(2):  # twice, so names built from visitor names count too
        for line in lines:
            match = ASSIGNMENT.match(line)
            if match is None:
                continue
            rhs = match.group("rhs")
            if CLEANED.search(rhs):
                continue  # path = resolve_scan_path(x): the helper checks it
            unpacked_request = family == "js" and re.fullmatch(r"\s*(?:req|request|ctx\.request)\s*;?\s*", rhs)
            if unpacked_request or source.search(rhs) or any(re.search(rf"(?<![\w$]){re.escape(n)}\b", rhs) for n in names):
                for name in re.findall(r"\$?[A-Za-z_]\w*", match.group("lhs")):
                    if name not in NOT_NAMES and not name[0].isupper():
                        names.add(name)
    return names


def reaches(text_after: str, family: str, names: set[str]) -> bool:
    """Does visitor input appear in this (part of a) line?"""
    if re.search(VISITOR_INPUT.get(family, r"(?!x)x"), text_after):
        return True
    return any(re.search(rf"(?<![\w$.]){re.escape(n)}\b", text_after) for n in names)


# ===========================================================================
# STEP 1: THE DANGER POINTS, PER RULE AND LANGUAGE
# ===========================================================================

@dataclass(frozen=True)
class Danger:
    rule: str
    family: str
    regex: re.Pattern
    needs_input: bool = True   # False: risky wherever it is (settings, MD5 for passwords...)


def danger(rule: str, families: str, regex: str, needs_input: bool = True) -> list[Danger]:
    return [Danger(rule, f, re.compile(regex), needs_input) for f in families.split()]


DANGERS = [
    # --- CMD-001: command injection -------------------------------------------------
    *danger("CMD-001", "js", r"(?<![\w$.])(?:exec|execSync|spawn|spawnSync|execFile)\s*\("
                             r"|\b(?:child_process|childProcess|cp)\.(?:exec|execSync|spawn|spawnSync|execFile)\s*\("),
    *danger("CMD-001", "python", r"\bos\.(?:system|popen)\s*\(|\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True|\bcommands\.getoutput\("),
    *danger("CMD-001", "php", r"(?<![\w>:$])(?:shell_exec|exec|system|passthru|popen|proc_open|pcntl_exec)\s*\("
                              r"|(?:=|\becho\b|\bprint\b|\breturn\b)\s*`[^`]*\$"),
    *danger("CMD-001", "ruby", r"\b(?:system|exec|spawn)\s*\(|`[^`]*#\{|%x[\(\{\[]|\bIO\.popen\(|\bOpen3\.\w+\("),
    *danger("CMD-001", "java kotlin", r"Runtime\.getRuntime\(\)\.exec\(|\bProcessBuilder\s*\("),
    *danger("CMD-001", "go", r"\bexec\.Command(?:Context)?\("),
    *danger("CMD-001", "csharp", r"\bProcess\.Start\(|\bStartInfo\.(?:FileName|Arguments)\s*="),

    # --- EVAL-001: visitor text run as code ------------------------------------------
    *danger("EVAL-001", "js", r"(?<![.\w])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.run\w*\(|\bset(?:Timeout|Interval)\s*\(\s*[^,()]*(?:\+|`)"),
    *danger("EVAL-001", "python", r"(?<![.\w])(?:eval|exec)\s*\("),
    *danger("EVAL-001", "php", r"(?<![\w>])(?:eval|assert|create_function)\s*\("),
    *danger("EVAL-001", "ruby", r"(?<![.\w])(?:eval|instance_eval|class_eval|module_eval)\s*[\( ]|\.(?:send|public_send|constantize)\(\s*params"),

    # --- PATH-001: a file picked by the visitor --------------------------------------
    *danger("PATH-001", "js", r"\b(?:sendFile|download|readFile|readFileSync|createReadStream|unlink|unlinkSync|writeFile|writeFileSync|readdir|readdirSync)\s*\("),
    *danger("PATH-001", "python", r"(?<![.\w])open\s*\(|\bsend_file\s*\(|\bos\.(?:remove|unlink)\(|\bFileResponse\s*\("),
    *danger("PATH-001", "php", r"\b(?:include|require|include_once|require_once)\b\s*\(?|\b(?:file_get_contents|fopen|readfile|file|unlink|file_put_contents)\s*\("),
    *danger("PATH-001", "ruby", r"\bsend_file\s*\(?|\bFile\.(?:read|open|delete|binread)\(|\brender\s+file:"),
    *danger("PATH-001", "java kotlin", r"\bnew\s+(?:File|FileInputStream|FileReader)\s*\(|\bPaths\.get\(|\bPath\.of\(|\bFiles\.(?:read\w*|delete|newInputStream)\("),
    *danger("PATH-001", "go", r"\bos\.(?:Open|ReadFile|Remove)\(|\bioutil\.ReadFile\(|\bhttp\.ServeFile\("),
    *danger("PATH-001", "csharp", r"\bFile\.(?:ReadAll\w*|Open\w*|Delete)\(|\bPhysicalFile\("),

    # --- DESER-001: unsafe data loading -----------------------------------------------
    *danger("DESER-001", "python", r"\b(?:pickle|cPickle|dill|marshal)\.loads?\(|\byaml\.unsafe_load\(|\byaml\.load\((?![^)]*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe)Loader)", needs_input=False),
    *danger("DESER-001", "php", r"(?<![\w>])unserialize\s*\("),
    *danger("DESER-001", "ruby", r"\bMarshal\.load\(|\bYAML\.unsafe_load\(|\bOj\.load\("),
    *danger("DESER-001", "java kotlin", r"\bnew\s+ObjectInputStream\(|\bXMLDecoder\(|\bfromXML\("),
    *danger("DESER-001", "js", r"\bunserialize\s*\(|\bdeserialize\s*\("),
    *danger("DESER-001", "csharp", r"\bBinaryFormatter\b|TypeNameHandling\.(?:All|Auto|Objects)", needs_input=False),

    # --- NOSQL-001: MongoDB queries built from visitor input --------------------------
    *danger("NOSQL-001", "js", r"\$where\s*['\"]?\s*:\s*[^,}]*(?:\+|`|\$\{)", needs_input=False),
    *danger("NOSQL-001", "js", r"(?:\bdb\.\w+|\b[A-Z]\w*|\w*[Cc]ollection)\.(?:find|findOne|findOneAnd\w+|update|updateOne|updateMany|deleteOne|deleteMany|remove|countDocuments|count)"
                               r"\(\s*\{(?!\s*where\b)[^}]*:\s*req\.(?:body|query)\b"),
    *danger("NOSQL-001", "python", r"['\"]\$where['\"]\s*:\s*[^,}]*(?:\+|%|\.format|f['\"])", needs_input=False),

    # --- REDIRECT-001: open redirect ------------------------------------------------------
    *danger("REDIRECT-001", "js", r"\bres\.redirect\(|\bctx\.redirect\(|\bwindow\.location(?:\.href)?\s*=|\blocation\.(?:replace|assign)\("
                                  r"|\brouter\.(?:push|replace)\(|(?<![.\w])redirect\s*\(|NextResponse\.redirect\("),
    *danger("REDIRECT-001", "python", r"\b(?:redirect|HttpResponseRedirect|RedirectResponse)\s*\("),
    *danger("REDIRECT-001", "php", r"header\s*\(\s*['\"]Location:|->(?:to|away)\s*\(|redirect\s*\("),
    *danger("REDIRECT-001", "ruby", r"\bredirect_to\b"),
    *danger("REDIRECT-001", "java kotlin", r"\bsendRedirect\(|\"redirect:\"\s*\+"),
    *danger("REDIRECT-001", "go", r"\bhttp\.Redirect\(|\bc\.Redirect\("),
    *danger("REDIRECT-001", "csharp", r"\bRedirect\s*\("),

    # --- SSRF-001: the server fetches the visitor's web address ------------------------
    *danger("SSRF-001", "js", r"(?<![.\w])fetch\s*\(|\baxios(?:\.\w+)?\s*\(|(?<![.\w])got\s*\(|\bhttps?\.(?:get|request)\s*\(|\b(?:needle|superagent)(?:\.(?:get|post|put|request))?\s*\(|(?<![.\w])request(?:\.(?:get|post|put|patch|del|head))?\s*\(\s*(?!['\"])"),
    *danger("SSRF-001", "python", r"\brequests\.(?:get|post|put|head|request)\s*\(|\burlopen\s*\(|\bhttpx\.(?:get|post|request)\s*\("),
    *danger("SSRF-001", "php", r"\bcurl_init\s*\(|CURLOPT_URL|\bfile_get_contents\s*\(\s*\$_"),
    *danger("SSRF-001", "ruby", r"\bURI\.open\(|(?<![.\w])open\(\s*params|\bNet::HTTP\.get\w*\(|\bHTTParty\.\w+\(|\bFaraday\.\w+\("),
    *danger("SSRF-001", "java kotlin", r"\bnew\s+URL\s*\(|\bgetForObject\(|\bgetForEntity\(|\bexchange\("),
    *danger("SSRF-001", "go", r"\bhttp\.(?:Get|Post|Head)\(|\bhttp\.NewRequest\w*\("),
    *danger("SSRF-001", "csharp", r"\.(?:GetAsync|PostAsync|GetStringAsync|SendAsync)\("),

    # --- XXE-001: XML with external entities on ---------------------------------------------
    *danger("XXE-001", "js", r"\bnoent\s*:\s*true|XML_PARSE_NOENT", needs_input=False),
    *danger("XXE-001", "python", r"resolve_entities\s*=\s*True", needs_input=False),
    *danger("XXE-001", "php", r"LIBXML_NOENT", needs_input=False),
    *danger("XXE-001", "csharp", r"DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new\s+XmlUrlResolver", needs_input=False),
    *danger("XXE-001", "java kotlin", r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\.new\w*Instance\(", needs_input=False),

    # --- HASH-001: weak password scrambling --------------------------------------------------
    *danger("HASH-001", "js", r"createHash\(\s*['\"](?:md5|sha1)['\"]", needs_input=False),
    *danger("HASH-001", "python", r"\bhashlib\.(?:md5|sha1)\(|\bhashlib\.new\(\s*['\"](?:md5|sha1)", needs_input=False),
    *danger("HASH-001", "php", r"(?<![\w>])(?:md5|sha1)\s*\(", needs_input=False),
    *danger("HASH-001", "ruby", r"Digest::(?:MD5|SHA1)\b", needs_input=False),
    *danger("HASH-001", "java kotlin", r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"", needs_input=False),
    *danger("HASH-001", "go", r"\b(?:md5|sha1)\.(?:Sum|New)\(", needs_input=False),
    *danger("HASH-001", "csharp", r"\b(?:MD5|SHA1)\.(?:Create|HashData)\(", needs_input=False),

    # --- CSRF-001: CSRF protection switched off ----------------------------------------------
    *danger("CSRF-001", "python", r"@csrf_exempt\b|WTF_CSRF_ENABLED\s*=\s*False", needs_input=False),
    *danger("CSRF-001", "ruby", r"skip_before_action\s+:verify_authenticity_token|skip_forgery_protection", needs_input=False),
    *danger("CSRF-001", "java kotlin", r"\.csrf\(\)\s*\.disable\(\)|csrf\(\s*(?:AbstractHttpConfigurer::disable|\w+\s*->\s*\w+\.disable\(\))|csrf\s*\{\s*disable\(\)", needs_input=False),
    *danger("CSRF-001", "php", r"\$except\s*=\s*\[\s*['\"]\*['\"]", needs_input=False),
]

# REDIRECT-001: addresses built by the framework's own route helpers point
# inside your site, whatever values go into them:
#   redirect_to admin_user_path(params[:id])   url_for("view")   reverse("home")   route('login')
OWN_SITE_ADDRESS = re.compile(
    r"^\w[\w.]*\s*\(?\s*(?:[\w.:]+_(?:path|url)\b|url_for\(|reverse(?:_lazy)?\(|route\(|to_route\(|back\(|"
    r"['\"`]/(?!/)|new\s+URL\(\s*['\"`]/(?!/)|\w*(?:safe|valid|allowed)\w*)")

# ...and addresses made from a PATH on your own site (no web address of another site
# can get in):  @article.path   URI.parse(x).path   request.path   redirect_to(options.merge(...))
SITE_PATH = re.compile(r"\.path\b|_path\b|\brequest\.path\b|redirect_to\s*\(?\s*(?:\{|\w+\.merge\()")

# CSRF-001: switching it off is CORRECT for APIs that log in with tokens, and
# for webhooks that check a signature instead. Those are skipped:
CSRF_ON_PURPOSE = re.compile(r"(?i)\bif:|\bunless:|token|signature|signiture|webhook|bearer|jwt|stateless|api_key")
TOKEN_LOGIN_FILE = re.compile(
    r"DeviseTokenAuth|devise_token_auth|SessionCreationPolicy\.STATELESS|oauth2ResourceServer|JwtAuthentication"
    r"|BearerToken|authenticate_with_http_token|ActionController::API")


def csrf_off_on_purpose(file: SourceFile, line_text: str, source: str) -> bool:
    path = file.path.as_posix().lower()
    return bool(CSRF_ON_PURPOSE.search(line_text) or "/api/" in path or "webhook" in path
                or TOKEN_LOGIN_FILE.search(source))


# HASH-001 only counts when it's about passwords (MD5 is fine for, say, a file checksum).
PASSWORD_WORD = re.compile(r"(?i)passw|pwd|\bpass\b|\$pass\b")
# XXE-001 (Java): safe if the code switches external entities off somewhere in the file.
XXE_PROTECTED = re.compile(
    r"disallow-doctype-decl|external-general-entities|FEATURE_SECURE_PROCESSING|SUPPORT_DTD|IS_SUPPORTING_EXTERNAL_ENTITIES"
    r"|ACCESS_EXTERNAL_DTD|setExpandEntityReferences\(\s*false")


# ===========================================================================
# WHAT THE CARDS SAY
# ===========================================================================

TITLES = {
    "CMD-001": "Visitor text put into a computer command",
    "EVAL-001": "Visitor text run as code",
    "PATH-001": "Visitor picks which file is read",
    "DESER-001": "Data loaded in a way that can run hidden code",
    "NOSQL-001": "Database search built from visitor input",
    "REDIRECT-001": "Visitor picks where the site sends people",
    "SSRF-001": "Server fetches a web address the visitor chose",
    "XXE-001": "XML reader can be tricked into reading your files",
    "HASH-001": "Passwords scrambled with a weak method",
    "CSRF-001": "Protection against fake form submissions is off",
}
IMPACT = {
    "CMD-001": "Visitors can't run their own commands on your server.",
    "EVAL-001": "Visitors can't run their own code on your server.",
    "PATH-001": "Visitors can't download or delete files they shouldn't, like your .env.",
    "DESER-001": "Data sent to your app can't smuggle in code that runs.",
    "NOSQL-001": "Visitors can't twist your database searches to see everyone's data.",
    "REDIRECT-001": "Scammers can't use your site's address to send people to theirs.",
    "SSRF-001": "Visitors can't make your server read its private internal systems.",
    "XXE-001": "Uploaded XML can't read files from your server.",
    "HASH-001": "Stolen passwords can't be cracked in seconds.",
    "CSRF-001": "Other websites can't submit forms as your logged-in visitors.",
}
NOTES = {
    "CMD-001": "Don't build commands from visitor text. Pass values as separate arguments with no shell "
               "(for example execFile('ping', ['-c', '4', ip]) or subprocess.run(['ping', ip])), and check "
               "the value first (an IP address should only contain digits and dots).",
    "EVAL-001": "Never run visitor text as code. To read a number use Number(x) / int(x); to read data use "
                "JSON.parse(x) / json.loads(x).",
    "PATH-001": "Don't use a visitor's text as a file path. Keep a list of allowed files, or take only the "
                "file NAME (path.basename / os.path.basename) and check the result stays inside your folder.",
    "DESER-001": "Load visitor data as JSON instead. If you need this format, only load files you created "
                 "yourself, never data a visitor sent.",
    "NOSQL-001": "Never build $where from text, and don't pass a visitor's object straight into a query: "
                 "turn it into the type you expect first, e.g. String(req.body.id).",
    "REDIRECT-001": "Only redirect to addresses on your own site (check it starts with a single / and not //), "
                    "or pick from a fixed list.",
    "SSRF-001": "Only fetch addresses from a list you trust, and block internal ones (localhost, 127.0.0.1, "
                "169.254.169.254 and private network ranges).",
    "XXE-001": "Switch external entities off: in Java call "
               "factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true); "
               "elsewhere remove noent / LIBXML_NOENT / resolve_entities.",
    "HASH-001": "Use a password-hashing method made for it: bcrypt, argon2 or scrypt (for example "
                "password_hash() in PHP, has_secure_password in Rails, bcrypt in Node and Python).",
    "CSRF-001": "Keep CSRF protection on for pages that use login cookies. Switching it off is only fine for "
                "webhooks or APIs that log in with tokens.",
}
SEVERITY = {"REDIRECT-001": Severity.WARNING, "CSRF-001": Severity.WARNING}  # the rest are critical


# ===========================================================================
# THE RULE
# ===========================================================================

FUNCTION_TYPES = {
    "js": ("arrow_function", "function_expression", "function_declaration", "method_definition", "function"),
    "python": ("function_definition",),
    "php": ("function_definition", "method_declaration", "anonymous_function", "arrow_function"),
    "ruby": ("method", "singleton_method", "do_block"),
    "java": ("method_declaration", "constructor_declaration", "lambda_expression"),
    "kotlin": ("function_declaration", "lambda_literal"),
    "go": ("function_declaration", "method_declaration", "func_literal"),
    "csharp": ("method_declaration", "local_function_statement", "lambda_expression"),
}


def check(file: SourceFile, comments: list[tuple[int, int]], runs_on_server: bool) -> list[Finding]:
    """Check one code file. Returns findings; writes nothing."""
    family = file.lang.family
    if file.lang.embedded or family not in FUNCTION_TYPES:
        return []
    dangers = [d for d in DANGERS if d.family == family]
    if not dangers:
        return []
    source = file.source.decode("utf-8", "replace")
    functions = sorted(((n.start_byte, n.end_byte, n) for n in file.nodes_of(*FUNCTION_TYPES[family])),
                       key=lambda item: item[1] - item[0])  # smallest first
    scopes: dict[tuple[int, int], set[str]] = {}
    findings = []
    seen = set()
    where = Positions(source)
    for item in dangers:
        if item.rule == "SSRF-001" and family == "js" and not runs_on_server:
            continue  # fetch() in a web page runs in the visitor's own browser
        if item.rule == "XXE-001" and family in ("java", "kotlin") and XXE_PROTECTED.search(source):
            continue
        for match in item.regex.finditer(source):
            position = match.start()
            line_number, byte_position = where.line_and_byte(position)  # the code tree counts in bytes
            if any(s <= byte_position < e for s, e in comments):
                continue
            if (item.rule, line_number) in seen:
                continue
            line_end = source.find("\n", position)
            rest = source[position:line_end if line_end != -1 else len(source)]
            line_text = source[source.rfind("\n", 0, position) + 1:line_end if line_end != -1 else len(source)]
            if item.rule == "HASH-001" and not PASSWORD_WORD.search(line_text):
                continue
            if item.rule == "REDIRECT-001" and (OWN_SITE_ADDRESS.search(rest) or SITE_PATH.search(rest)):
                continue  # redirect_to user_path(...), url_for(...), reverse(...): an address on your own site
            if item.rule == "CSRF-001" and csrf_off_on_purpose(file, line_text, source):
                continue
            if item.needs_input:
                # Every function the line sits in, from the innermost outwards: a value
                # read in a component can be used in a smaller function inside it.
                enclosing = [(s, e, n) for s, e, n in functions if s <= byte_position < e] or [(0, len(file.source), None)]
                names: set[str] = set()
                for start, end, function in enclosing:
                    key = (start, end)
                    if key not in scopes:
                        scope_text = file.source[start:end].decode("utf-8", "replace")
                        scopes[key] = visitor_names(scope_text, family, parameters_of(function, file, family))
                    names |= scopes[key]
                if not reaches(rest, family, names):
                    continue
            seen.add((item.rule, line_number))
            fix = yaml_fix(file, match, byte_position) if item.rule == "DESER-001" and family == "python" else None
            findings.append(Finding(item.rule, TITLES[item.rule], file.path, line_number, IMPACT[item.rule],
                                    SEVERITY.get(item.rule, Severity.CRITICAL),
                                    fix=fix, note="" if fix else NOTES[item.rule]))
    return findings


def text_of(node) -> str:
    return node.text.decode("utf-8", "replace") if node is not None else ""


def parameters_of(function, file: SourceFile, family: str) -> str:
    """The function's parameter list, plus (Python) whether it's a web route."""
    if function is None:
        return ""
    head = file.source[function.start_byte:function.end_byte].decode("utf-8", "replace").split("{", 1)[0]
    head = head.split(":\n", 1)[0] if family == "python" else head
    if family == "python":
        decorated = function.parent is not None and function.parent.type == "decorated_definition"
        decorators = file.source[function.parent.start_byte:function.start_byte].decode("utf-8", "replace") if decorated else ""
        params = re.match(r"\s*(?:async\s+)?def\s+\w+\s*\((.*?)\)\s*(?:->[^:]*)?:", text_of(function), re.DOTALL)
        params_text = params.group(1) if params else ""
        # A web route's own parameters come from the web address; so do a Django view's
        # (its first parameter is the request).
        if PY_ROUTE.search(decorators) or re.match(r"\s*(?:self\s*,\s*)?request\b", params_text):
            return params_text
        return ""
    return head


class Positions:
    """Turns a character position into (line number, byte position), quickly.

    The text is searched as characters, but the code tree counts bytes (é is
    2 bytes). Working that out from the start of the file for every match was
    slow on big files, so the start of every line is worked out once, up front.
    """

    def __init__(self, text: str):
        self.text = text
        self.ascii = text.isascii()
        self.line_starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == "\n"]
        if not self.ascii:
            self.byte_starts = []
            total = 0
            previous = 0
            for start in self.line_starts:
                total += len(text[previous:start].encode("utf-8"))
                self.byte_starts.append(total)
                previous = start

    def line_and_byte(self, position: int) -> tuple[int, int]:
        import bisect
        line = bisect.bisect_right(self.line_starts, position)  # 1-based line number
        if self.ascii:
            return line, position
        start = self.line_starts[line - 1]
        return line, self.byte_starts[line - 1] + len(self.text[start:position].encode("utf-8"))


def yaml_fix(file: SourceFile, match: re.Match, start: int) -> Fix | None:
    """yaml.load(x)  ->  yaml.safe_load(x), only when no Loader is given.

    safe_load reads all normal YAML (text, numbers, lists...) and refuses only
    the special tags that can create objects and run code.
    """
    if not match.group(0).startswith("yaml.load("):
        return None
    source = file.source
    depth, end = 0, start
    while end < len(source):
        char = source[end:end + 1]
        if char == b"(":
            depth += 1
        elif char == b")":
            depth -= 1
            if depth == 0:
                break
        end += 1
    call = source[start:end + 1]
    if b"Loader" in call or b"\n" in call:
        return None  # a Loader was chosen on purpose (or the call is too long to be sure)
    edit = TextEdit(file.path, start, start + len(b"yaml.load"), b"yaml.safe_load")
    return Fix(edits=[edit], preview_before="yaml.load(...)", preview_after="yaml.safe_load(...)")
