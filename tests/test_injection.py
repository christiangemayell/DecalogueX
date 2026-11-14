"""
The injection rules (rules/injection.py) and the XSS gaps found with the
broken-on-purpose apps.

Each rule gets a case it must catch (visitor input reaches the danger point)
and a look-alike it must leave alone (no visitor input, or a safe version).
"""

from pathlib import Path

import pytest

from decaloguex import cli, engine


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def rules(folder: Path, prefix: str) -> list[str]:
    return [f"{f.path.name}:{f.line}" for f in engine.scan(folder).findings if f.rule_id.startswith(prefix)]


# --- CMD-001: command injection -----------------------------------------------------------

@pytest.mark.parametrize("name, code", [
    ("ping.php", "<?php\n$target = $_REQUEST['ip'];\n$cmd = shell_exec('ping -c 4 ' . $target);\n"),
    ("app.js", "app.get('/ping', (req, res) => {\n  const host = req.query.host;\n  exec('ping ' + host, cb);\n});\n"),
    ("views.py", "import os\n\ndef ping(request):\n    host = request.GET['host']\n    os.system('ping ' + host)\n"),
    ("benefits.rb", "def backup\n  system(\"cp #{params[:file]} /tmp\")\nend\n"),
    ("Run.java", "class Run {\n  void go(@RequestParam String action) throws Exception {\n"
                 "    Process p = Runtime.getRuntime().exec(action);\n  }\n}\n"),
])
def test_commands_built_from_visitor_input(tmp_path, name, code):
    write(tmp_path, name, code)
    assert len(rules(tmp_path, "CMD")) == 1


def test_fixed_commands_and_regex_exec_are_fine(tmp_path):
    write(tmp_path, "build.js", "exec('npm run build', cb);\nconst m = /a(b)/.exec(text);\n")
    write(tmp_path, "tool.py", "import os\n\ndef clean():\n    os.system('rm -rf build')\n")
    assert rules(tmp_path, "CMD") == []


# --- EVAL-001 ---------------------------------------------------------------------------------

def test_eval_of_visitor_input(tmp_path):
    # NodeGoat: app/routes/contributions.js
    write(tmp_path, "contributions.js", "function handle(req, res) {\n  const preTax = eval(req.body.preTax);\n}\n")
    assert len(rules(tmp_path, "EVAL")) == 1


def test_eval_of_fixed_text_is_fine(tmp_path):
    write(tmp_path, "x.js", "const crypto = eval(\"require('crypto')\");\n")
    assert rules(tmp_path, "EVAL") == []


# --- PATH-001 ---------------------------------------------------------------------------------

def test_file_picked_by_the_visitor(tmp_path):
    write(tmp_path, "files.js", "app.get('/f', (req, res) => {\n  res.sendFile(req.query.name);\n});\n")
    write(tmp_path, "fi.php", "<?php\n$file = $_GET['page'];\ninclude($file);\n")
    assert len(rules(tmp_path, "PATH")) == 2


def test_fixed_file_paths_are_fine(tmp_path):
    write(tmp_path, "server.js", "const key = fs.readFileSync(path.resolve(__dirname, './cert/server.key'));\n")
    write(tmp_path, "app.php", "<?php\nrequire_once 'config.php';\n")
    assert rules(tmp_path, "PATH") == []


# --- DESER-001 ----------------------------------------------------------------------------------

def test_unsafe_loading_of_visitor_data(tmp_path):
    # RailsGoat: password_resets_controller.rb
    write(tmp_path, "resets.rb", "def reset\n  user = Marshal.load(Base64.decode64(params[:user]))\nend\n")
    write(tmp_path, "load.php", "<?php\n$obj = unserialize($_COOKIE['data']);\n")
    assert len(rules(tmp_path, "DESER")) == 2


def test_python_yaml_load_is_fixed_to_safe_load(tmp_path):
    app = write(tmp_path, "app.py", "import yaml\n\ndef read(text):\n    return yaml.load(text)\n")
    cli.run_scan(tmp_path, assume_yes=True, no_color=True, no_animation=True)
    assert "yaml.safe_load(text)" in app.read_text(encoding="utf-8")


def test_yaml_with_safe_loader_is_fine(tmp_path):
    write(tmp_path, "app.py", "import yaml\n\ndata = yaml.load(f, Loader=yaml.SafeLoader)\nother = yaml.safe_load(f)\n")
    assert rules(tmp_path, "DESER") == []


# --- NOSQL-001 -----------------------------------------------------------------------------------

def test_mongo_where_and_visitor_objects(tmp_path):
    # Juice Shop routes/trackOrder.ts and routes/updateProductReviews.ts
    write(tmp_path, "track.js", "function t(req, res) {\n  const id = req.params.id;\n"
                                "  db.orders.find({ $where: `this.orderId === '${id}'` });\n}\n")
    write(tmp_path, "reviews.js", "function u(req, res) {\n  db.reviews.update({ _id: req.body.id }, { $set: x });\n}\n")
    assert len(rules(tmp_path, "NOSQL")) == 2


def test_normal_mongo_queries_are_fine(tmp_path):
    write(tmp_path, "q.js", "db.users.find({ active: true });\ndb.users.findOne({ _id: String(userId) });\n")
    assert rules(tmp_path, "NOSQL") == []


# --- REDIRECT-001 ----------------------------------------------------------------------------------

def test_open_redirect(tmp_path):
    # NodeGoat: app/routes/index.js
    write(tmp_path, "index.js", "app.get('/learn', (req, res) => {\n  return res.redirect(req.query.url);\n});\n")
    assert len(rules(tmp_path, "REDIRECT")) == 1


def test_fixed_redirects_are_fine(tmp_path):
    write(tmp_path, "index.js", "app.get('/old', (req, res) => {\n  res.redirect('/new');\n});\n")
    assert rules(tmp_path, "REDIRECT") == []


# --- SSRF-001 --------------------------------------------------------------------------------------

def test_server_fetching_a_visitor_url(tmp_path):
    write(tmp_path, "app.py", "import requests\nfrom flask import Flask\napp = Flask(__name__)\n\n"
                              "@app.route('/fetch')\ndef go():\n    url = request.args.get('url')\n"
                              "    return requests.get(url).text\n")
    write(tmp_path, "upload.ts", "import express from 'express'\nexport async function up(req, res) {\n"
                                 "  const url = req.body.imageUrl\n  const response = await fetch(url)\n}\n")
    assert len(rules(tmp_path, "SSRF")) == 2


def test_browser_fetch_and_fixed_urls_are_fine(tmp_path):
    write(tmp_path, "page.js", "const q = location.search;\nfetch('/api/items' + q);\nwindow.document.title = 'x';\n")
    write(tmp_path, "client.py", "import requests\n\ndef ping():\n    return requests.get('https://api.example.com/health')\n")
    assert rules(tmp_path, "SSRF") == []


# --- XXE-001 ----------------------------------------------------------------------------------------

def test_xml_readers_with_external_entities(tmp_path):
    write(tmp_path, "Comments.java", "class C {\n  void p() {\n    var xif = XMLInputFactory.newInstance();\n  }\n}\n")
    write(tmp_path, "xml.js", "const doc = libxml.parseXml(data, { noblanks: true, noent: true });\n")
    assert len(rules(tmp_path, "XXE")) == 2


def test_protected_java_xml_reader_is_fine(tmp_path):
    write(tmp_path, "Safe.java", "class S {\n  void p() {\n    var f = DocumentBuilderFactory.newInstance();\n"
                                 "    f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n  }\n}\n")
    assert rules(tmp_path, "XXE") == []


# --- HASH-001 ----------------------------------------------------------------------------------------

def test_weak_password_hashing(tmp_path):
    # DVWA login.php and RailsGoat app/models/user.rb
    write(tmp_path, "login.php", "<?php\n$pass = md5( $pass );\n")
    write(tmp_path, "user.rb", "def hash_it\n  self.password = Digest::MD5.hexdigest(self.password)\nend\n")
    assert len(rules(tmp_path, "HASH")) == 2


def test_md5_for_other_things_is_fine(tmp_path):
    write(tmp_path, "cache.py", "import hashlib\n\nkey = hashlib.md5(url.encode()).hexdigest()\n")
    write(tmp_path, "avatar.php", "<?php\n$hash = md5(strtolower($email));\n")
    assert rules(tmp_path, "HASH") == []


# --- CSRF-001 ----------------------------------------------------------------------------------------

def test_csrf_protection_switched_off(tmp_path):
    write(tmp_path, "views.py", "from django.views.decorators.csrf import csrf_exempt\n\n"
                                "@csrf_exempt\ndef transfer(request):\n    pass\n")
    write(tmp_path, "Security.java", "class S {\n  void c(HttpSecurity http) throws Exception {\n"
                                     "    http.csrf().disable();\n  }\n}\n")
    assert len(rules(tmp_path, "CSRF")) == 2


# --- XSS gaps -----------------------------------------------------------------------------------------

def test_php_html_built_from_visitor_input(tmp_path):
    # DVWA vulnerabilities/xss_r/source/low.php
    write(tmp_path, "low.php", "<?php\n$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';\n")
    assert len(rules(tmp_path, "XSS")) == 1


def test_php_html_cleaned_first_is_fine(tmp_path):
    write(tmp_path, "high.php", "<?php\n$html .= '<pre>Hello ' . htmlspecialchars($_GET['name']) . '</pre>';\n")
    assert rules(tmp_path, "XSS") == []


def test_angular_cleaning_switched_off_and_template_escaping_off(tmp_path):
    write(tmp_path, "search.component.ts", "this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)\n")
    write(tmp_path, "server.js", "swig.setDefaults({\n  autoescape: false\n});\n")
    assert len(rules(tmp_path, "XSS")) == 2


# --- False alarms found on the 29 real projects (round 1 of the new rules) --------------------

def test_redirects_to_your_own_site_are_fine(tmp_path):
    # forem / chatwoot: Rails route helpers build addresses inside the site.
    write(tmp_path, "users_controller.rb", "def update\n  redirect_to admin_user_path(params[:id])\nend\n"
                                           "def other\n  redirect_to('/app') if params[:x]\nend\n")
    write(tmp_path, "views.py", "def go(request, filename):\n    return redirect(url_for('view_blog', filename=filename))\n")
    assert rules(tmp_path, "REDIRECT") == []


def test_redirect_to_a_visitor_address_in_rails_is_reported(tmp_path):
    write(tmp_path, "sessions_controller.rb", "def create\n  redirect_to params[:return_to]\nend\n")
    assert len(rules(tmp_path, "REDIRECT")) == 1


def test_csrf_off_for_token_apis_and_webhooks_is_fine(tmp_path):
    # forem / chatwoot / spring-realworld
    write(tmp_path, "app/controllers/follows_controller.rb",
          "class FollowsController < ApplicationController\n"
          "  skip_before_action :verify_authenticity_token, if: :token_authenticated?\nend\n")
    write(tmp_path, "app/controllers/incoming_webhooks/stripe_events_controller.rb",
          "class StripeEventsController < ApplicationController\n  skip_before_action :verify_authenticity_token\nend\n")
    write(tmp_path, "WebSecurityConfig.java", "class W {\n  void c(HttpSecurity http) throws Exception {\n"
                                              "    http.csrf().disable().sessionManagement()"
                                              ".sessionCreationPolicy(SessionCreationPolicy.STATELESS);\n  }\n}\n")
    assert rules(tmp_path, "CSRF") == []


def test_a_local_variable_called_params_is_not_visitor_input(tmp_path):
    # chatwoot app/services/tiktok/client.rb
    write(tmp_path, "client.rb", "def fetch\n  params = { fields: 'id' }\n"
                                 "  response = HTTParty.get(endpoint, query: params, headers: headers)\nend\n")
    assert rules(tmp_path, "SSRF") == []


def test_regex_exec_is_not_a_command(tmp_path):
    # forem app/javascript/listings/utils.js
    write(tmp_path, "utils.js", "function parse(req) {\n  const q = req.query.q;\n  while ((tokens = re.exec(q))) {}\n}\n")
    assert rules(tmp_path, "CMD") == []


def test_mysql_backticks_in_sql_are_not_commands(tmp_path):
    # DVWA login.php
    write(tmp_path, "login.php", "<?php\n$user = $_POST['username'];\n"
                                 "$query = \"SELECT * FROM `users` WHERE user='$user';\";\n")
    assert rules(tmp_path, "CMD") == []


def test_sequelize_where_is_not_mongodb(tmp_path):
    # Juice Shop routes/wallet.ts
    write(tmp_path, "wallet.js", "async function w(req, res) {\n"
                                 "  const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } });\n}\n")
    assert rules(tmp_path, "NOSQL") == []


def test_redirects_built_from_site_paths_are_fine(tmp_path):
    # forem: articles_controller.rb, discussion_locks_controller.rb
    write(tmp_path, "articles_controller.rb", "def a\n  redirect_to(Addressable::URI.parse(params[:destination]).path)\nend\n"
                                              "def b\n  redirect_to \"#{article.path}/manage\"\nend\n")
    assert rules(tmp_path, "REDIRECT") == []


# --- Gaps found with the broken apps (round 2) -------------------------------------------

def test_input_unpacked_from_the_request_counts(tmp_path):
    # Juice Shop routes/redirect.ts
    write(tmp_path, "redirect.js", "function go(req, res) {\n  const { query } = req;\n  const toUrl = query.to;\n"
                                   "  res.redirect(toUrl);\n}\n")
    assert len(rules(tmp_path, "REDIRECT")) == 1


def test_libxml_noent_constant_and_needle_ssrf(tmp_path):
    write(tmp_path, "xml.js", "const option = libxml2.ParseOption.XML_PARSE_NOENT | libxml2.ParseOption.XML_PARSE_DTDLOAD;\n")
    write(tmp_path, "research.js", "const needle = require('needle');\nconst express = require('express');\n"
                                   "function h(req, res) {\n  const url = req.query.url + req.query.symbol;\n"
                                   "  return needle.get(url, cb);\n}\n")
    assert len(rules(tmp_path, "XXE")) == 1 and len(rules(tmp_path, "SSRF")) == 1
