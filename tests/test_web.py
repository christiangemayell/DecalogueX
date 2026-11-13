"""
Tests for the web-safety rules: debug mode, XSS, CORS, certificate checks
and mass assignment (rules/web.py).
"""

from pathlib import Path

import pytest

from decaloguex import cli, engine


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def rules(folder: Path, prefix: str) -> list[tuple[str, int, bool]]:
    """(file name, line, has an automatic fix?) for each finding of one rule."""
    return sorted((f.path.name, f.line, f.fix is not None)
                  for f in engine.scan(folder).findings if f.rule_id.startswith(prefix))


def fix(folder: Path) -> None:
    cli.run_scan(folder, assume_yes=True, no_color=True, no_animation=True)


# --- DEBUG-001 ---------------------------------------------------------------------

def test_django_debug_is_read_from_env(tmp_path):
    settings = write(tmp_path, "settings.py", 'ALLOWED_HOSTS = ["myapp.com"]\nDEBUG = True\n')
    fix(tmp_path)
    code = settings.read_text(encoding="utf-8")
    assert 'DEBUG = os.environ.get("DEBUG") == "1"' in code and code.startswith("import os\n")
    assert "DEBUG=1" in (tmp_path / ".env").read_text(encoding="utf-8")  # still on for you


def test_django_debug_without_allowed_hosts_is_a_card(tmp_path):
    # Switching debug off with an empty ALLOWED_HOSTS would turn every visitor away.
    write(tmp_path, "settings.py", "ALLOWED_HOSTS = []\nDEBUG = True\n")
    [finding] = [f for f in engine.scan(tmp_path).findings if f.rule_id == "DEBUG-001"]
    assert finding.fix is None and "ALLOWED_HOSTS" in finding.note


def test_flask_debug_is_read_from_env(tmp_path):
    app = write(tmp_path, "app.py", "app = Flask(__name__)\napp.run(host='0.0.0.0', debug=True)\n")
    fix(tmp_path)
    assert "app.run(host='0.0.0.0', debug=os.environ.get(\"FLASK_DEBUG\") == \"1\")" in app.read_text(encoding="utf-8")


def test_development_only_settings_are_left_alone(tmp_path):
    write(tmp_path, "config.py", "class DevConfig:\n    DEBUG = True\n")       # flask-realworld style
    write(tmp_path, "settings/local.py", "DEBUG = True\n")                    # a local-only settings file
    assert rules(tmp_path, "DEBUG") == []


def test_debug_mode_in_other_languages(tmp_path):
    write(tmp_path, "config/app.php", "<?php\nreturn ['debug' => true];\n")
    write(tmp_path, "main.go", "package main\n\nfunc main() { gin.SetMode(gin.DebugMode) }\n")
    write(tmp_path, "Program.cs", "var app = builder.Build();\napp.UseDeveloperExceptionPage();\n")
    write(tmp_path, "Good.cs", "if (app.Environment.IsDevelopment())\n{\n    app.UseDeveloperExceptionPage();\n}\n")
    assert rules(tmp_path, "DEBUG") == [("Program.cs", 2, False), ("app.php", 2, False), ("main.go", 3, False)]


# --- XSS-001 -----------------------------------------------------------------------

def test_raw_html_is_reported_in_each_framework(tmp_path):
    write(tmp_path, "src/Post.jsx", "export const Post = ({ body }) => <div dangerouslySetInnerHTML={{ __html: body }} />;\n")
    write(tmp_path, "src/Post.vue", '<template>\n  <div v-html="post.body"></div>\n</template>\n')
    write(tmp_path, "src/Post.svelte", "<div>{@html post.body}</div>\n")
    write(tmp_path, "views/post.blade.php", "<div>{!! $post->body !!}</div>\n")
    write(tmp_path, "Views/Post.cshtml", "<div>@Html.Raw(Model.Body)</div>\n")
    write(tmp_path, "templates/post.html", "<div>{{ post.body|safe }}</div>\n")
    write(tmp_path, "views/post.ejs", "<div><%- post.body %></div>\n")
    write(tmp_path, "src/page.js", "document.querySelector('#out').innerHTML = location.hash;\n")
    found = [name for name, _, _ in rules(tmp_path, "XSS")]
    assert sorted(found) == sorted(["Post.jsx", "Post.vue", "Post.svelte", "post.blade.php", "Post.cshtml",
                                    "post.html", "post.ejs", "page.js"])


def test_safe_html_is_not_reported(tmp_path):
    write(tmp_path, "src/a.jsx", "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(body) }} />;\n")
    write(tmp_path, "src/b.js", 'el.innerHTML = "";\nel.innerHTML = \'<b>Loading</b>\';\n// never use innerHTML = x\n')
    write(tmp_path, "src/c.vue", "<!-- eslint-disable-next-line vue/no-v-html -->\n<p>{{ text }}</p>\n")
    assert rules(tmp_path, "XSS") == []


def test_php_echo_of_visitor_input_is_escaped(tmp_path):
    page = write(tmp_path, "hello.php", "<?php\necho $_GET['name'];\necho 'Hi ' . $_POST['n'] . '!';\necho intval($_GET['age']);\n")
    fix(tmp_path)
    code = page.read_text(encoding="utf-8")
    assert "echo htmlspecialchars((string) $_GET['name'], ENT_QUOTES, 'UTF-8');" in code
    assert "echo 'Hi ' . htmlspecialchars((string) $_POST['n'], ENT_QUOTES, 'UTF-8') . '!';" in code
    assert "echo intval($_GET['age']);" in code  # already turned into a number: left alone


# --- CORS-001, TLS-001, MASS-001 ------------------------------------------------------

# Open CORS is only reported together with logins allowed through ("credentials").
@pytest.mark.parametrize("name, code", [
    ("server.js", 'const cors = require("cors");\napp.use(cors({ origin: true, credentials: true }));\n'),
    ("main.py", 'app.add_middleware(CORSMiddleware, allow_origins=["*"],\n    allow_credentials=True)\n'),
    ("Program.cs", "app.UseCors(x => x.SetIsOriginAllowed(_ => true).AllowCredentials());\n"),
    ("main.go", 'package main\n\nvar c = cors.Config{AllowAllOrigins: true, AllowCredentials: true}\n'),
    ("api.php", "<?php\nheader('Access-Control-Allow-Origin: *');\nheader('Access-Control-Allow-Credentials: true');\n"),
    ("Api.java", '@CrossOrigin(origins = "*", allowCredentials = "true")\nclass Api {}\n'),
    ("Server.kt", "fun Application.cors() { install(CORS) {\n    allowCredentials = true\n    anyHost()\n} }\n"),
])
def test_open_cors_with_logins_in_each_language(tmp_path, name, code):
    write(tmp_path, name, code)
    assert [rule[0] for rule in rules(tmp_path, "CORS")] == [name]


def test_open_cors_without_logins_is_fine(tmp_path):
    # Browsers refuse to send a visitor's login to a server that allows every website.
    write(tmp_path, "server.js", 'app.use(cors());\n')
    write(tmp_path, "auth.js", "app.use(require('express-session')({ secret: s }));\n")
    assert rules(tmp_path, "CORS") == []


def test_cors_for_a_named_site_is_fine(tmp_path):
    write(tmp_path, "server.js", 'app.use(cors({ origin: "https://myapp.com" }));\n')
    assert rules(tmp_path, "CORS") == []


@pytest.mark.parametrize("name, code", [
    ("fetch.py", 'requests.get(url, verify=False)\n'),
    ("fetch.js", 'const agent = new https.Agent({ rejectUnauthorized: false });\n'),
    ("fetch.go", 'package main\n\nvar t = &tls.Config{InsecureSkipVerify: true}\n'),
    ("fetch.php", "<?php\ncurl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);\n"),
])
def test_certificate_checks_switched_off(tmp_path, name, code):
    write(tmp_path, name, code)
    assert [rule[0] for rule in rules(tmp_path, "TLS")] == [name]


@pytest.mark.parametrize("name, code", [
    ("users.js", "const user = await User.create(req.body);\n"),
    ("UserController.php", "<?php\nUser::create($request->all());\n"),
    ("views.py", "user = User.objects.create(**request.data)\n"),
    ("users_controller.rb", "User.create(params.require(:user).permit!)\n"),
])
def test_whole_form_saved(tmp_path, name, code):
    write(tmp_path, name, code)
    assert [rule[0] for rule in rules(tmp_path, "MASS")] == [name]


def test_picking_fields_is_fine(tmp_path):
    write(tmp_path, "users.js", "const user = await User.create({ name: req.body.name, email: req.body.email });\n")
    assert rules(tmp_path, "MASS") == []


def test_web_rules_are_skipped_in_test_files(tmp_path):
    write(tmp_path, "tests/test_api.py", 'requests.get(url, verify=False)\n')
    write(tmp_path, "src/app.spec.js", "app.use(cors());\n")
    assert rules(tmp_path, "TLS") == [] and rules(tmp_path, "CORS") == []
