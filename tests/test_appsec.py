"""
The 7 rules added after the AI-written apps round:
SEC-005, Supabase key formats (SEC-001), JWT-001, UPLOAD-001, RAND-001, AI-001/002/003, RLS-001.

Each gets a case it must catch and a look-alike it must leave alone.
"""

import base64
import json
from pathlib import Path

from decaloguex import engine


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def rules(folder: Path, prefix: str) -> list[str]:
    return [f"{f.path.name}:{f.line}" for f in engine.scan(folder).findings if f.rule_id.startswith(prefix)]


def supabase_jwt(role: str) -> str:
    """A token shaped like Supabase's keys (made up here, signs nothing)."""
    def part(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    return part({"alg": "HS256", "typ": "JWT"}) + "." + part({"iss": "supabase", "role": role}) + ".Qm9ndXNTaWduYXR1cmVYeXpXdnU"


# --- SEC-005: secrets with public names ------------------------------------------------

def test_public_named_secrets_in_code_and_env_files(tmp_path):
    # oss-oopssec-store app/checkout/CheckoutClient.tsx and .env.local
    write(tmp_path, "CheckoutClient.tsx", 'const paymentSecret = process.env.NEXT_PUBLIC_PAYMENT_SECRET ?? "";\n')
    write(tmp_path, ".env.local", "NEXT_PUBLIC_PAYMENT_SECRET=abc\nVITE_OPENAI_API_KEY=\n")
    assert len(rules(tmp_path, "SEC-005")) == 3


def test_keys_meant_to_be_public_are_fine(tmp_path):
    write(tmp_path, "client.ts", "const url = import.meta.env.VITE_SUPABASE_URL;\n"
                                 "const key = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;\n"
                                 "const stripe = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;\n")
    write(tmp_path, ".env", "VITE_SUPABASE_ANON_KEY=x\nNEXT_PUBLIC_POSTHOG_KEY=y\n")
    assert rules(tmp_path, "SEC-005") == []


# --- Supabase key formats --------------------------------------------------------------

def test_supabase_service_role_key_is_found_but_not_the_anon_key(tmp_path):
    write(tmp_path, "admin.ts", f'const supabase = createClient(url, "{supabase_jwt("service_role")}");\n')
    write(tmp_path, "client.ts", f'const supabase = createClient(url, "{supabase_jwt("anon")}");\n')
    assert rules(tmp_path, "SEC-001") == ["admin.ts:1"]


# --- JWT-001 -----------------------------------------------------------------------------

def test_login_tokens_not_checked(tmp_path):
    # Zero-Health server.js: algorithms: ['HS256', 'none']
    write(tmp_path, "server.js", "const express = require('express');\n"
                                 "const decoded = jwt.verify(token, SECRET, { algorithms: ['HS256', 'none'] });\n")
    write(tmp_path, "auth.py", "import jwt\n\ndef user(token):\n"
                               "    return jwt.decode(token, options={'verify_signature': False})\n")
    assert len(rules(tmp_path, "JWT-001")) == 2


def test_checked_login_tokens_are_fine(tmp_path):
    write(tmp_path, "server.js", "const express = require('express');\n"
                                 "const decoded = jwt.verify(token, SECRET, { algorithms: ['HS256'] });\n")
    write(tmp_path, "Profile.tsx", "const claims = jwtDecode(token);\n")  # reading your own token in the browser
    assert rules(tmp_path, "JWT-001") == []


# --- UPLOAD-001 ----------------------------------------------------------------------------

def test_uploads_without_checks(tmp_path):
    write(tmp_path, "upload.js", "const upload = multer({ dest: 'uploads/' });\n")
    write(tmp_path, "upload.php", "<?php\nmove_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);\n")
    assert len(rules(tmp_path, "UPLOAD")) == 2


def test_checked_uploads_are_fine(tmp_path):
    write(tmp_path, "upload.js", "const upload = multer({ dest: 'uploads/', fileFilter: onlyImages, limits: { fileSize: 1e6 } });\n")
    write(tmp_path, "app.py", "from werkzeug.utils import secure_filename\n\ndef up():\n"
                              "    f = request.files['photo']\n    f.save(secure_filename(f.filename))\n")
    assert rules(tmp_path, "UPLOAD") == []


# --- RAND-001 ------------------------------------------------------------------------------

def test_guessable_codes(tmp_path):
    write(tmp_path, "reset.js", "const express = require('express');\n"
                                "const resetToken = Math.random().toString(36).slice(2);\n")
    write(tmp_path, "otp.py", "import random\n\notp_code = random.randint(100000, 999999)\n")
    assert len(rules(tmp_path, "RAND")) == 2


def test_random_numbers_for_harmless_things_are_fine(tmp_path):
    write(tmp_path, "ui.js", "const delay = Math.random() * 1000;\nconst color = colors[Math.floor(Math.random() * 5)];\n")
    assert rules(tmp_path, "RAND") == []


# --- AI-001, AI-002, AI-003 -----------------------------------------------------------------

def test_ai_key_in_the_browser(tmp_path):
    write(tmp_path, "chat.ts", "const client = new OpenAI({ apiKey: key, dangerouslyAllowBrowser: true });\n")
    assert len(rules(tmp_path, "AI-001")) == 1


def test_ai_output_put_into_the_page_or_a_query(tmp_path):
    write(tmp_path, "Answer.tsx", "async function show(el, prompt) {\n"
                                  "  const completion = await openai.chat.completions.create({ messages: prompt });\n"
                                  "  const answer = completion.choices[0].message.content;\n"
                                  "  el.innerHTML = answer;\n}\n")
    write(tmp_path, "report.py", "def run(question):\n"
                                 "    response = client.chat.completions.create(messages=question)\n"
                                 "    sql = response.choices[0].message.content\n"
                                 "    cursor.execute(sql)\n")
    assert len(rules(tmp_path, "AI-002")) == 2


def test_ai_output_shown_as_text_is_fine(tmp_path):
    write(tmp_path, "Answer.tsx", "async function show(el, prompt) {\n"
                                  "  const completion = await openai.chat.completions.create({ messages: prompt });\n"
                                  "  el.textContent = completion.choices[0].message.content;\n}\n")
    assert rules(tmp_path, "AI-002") == []


def test_ai_calls_without_any_rate_limit(tmp_path):
    write(tmp_path, "server.js", "const express = require('express');\n"
                                 "app.post('/chat', async (req, res) => {\n"
                                 "  res.json(await openai.chat.completions.create({ messages: req.body.messages }));\n});\n")
    assert len(rules(tmp_path, "AI-003")) == 1


def test_ai_calls_with_a_rate_limit_are_fine(tmp_path):
    write(tmp_path, "server.js", "const express = require('express');\n"
                                 "app.post('/chat', async (req, res) => {\n"
                                 "  res.json(await openai.chat.completions.create({ messages: req.body.messages }));\n});\n")
    write(tmp_path, "limits.js", "const rateLimit = require('express-rate-limit');\napp.use(rateLimit({ max: 20 }));\n")
    assert rules(tmp_path, "AI-003") == []


# --- RLS-001 ------------------------------------------------------------------------------

def test_supabase_tables_without_access_rules(tmp_path):
    write(tmp_path, "supabase/migrations/001_init.sql",
          "create table public.messages (id uuid primary key, body text);\n"
          "create table public.profiles (id uuid primary key);\n"
          "create table auth.audit (id int);\n")
    write(tmp_path, "supabase/migrations/002_rls.sql",
          "alter table public.profiles enable row level security;\n"
          'create policy "anyone edits" on public.profiles for update using (true);\n'
          'create policy "server" on public.profiles for all to service_role using (true);\n')
    found = sorted(rules(tmp_path, "RLS"))
    assert found == ["001_init.sql:1", "002_rls.sql:2"]  # messages has no RLS; one rule lets anyone edit


def test_sql_outside_supabase_is_not_checked(tmp_path):
    write(tmp_path, "db/schema.sql", "create table messages (id int);\n")
    assert rules(tmp_path, "RLS") == []


# --- False alarms found on the projects ---------------------------------------------------

def test_reading_the_header_then_verifying_is_fine(tmp_path):
    # forem app/services/delegated_access/verifier.rb
    write(tmp_path, "verifier.rb", "def verify(token)\n  _payload, header = JWT.decode(token, nil, false)\n"
                                   "  payload, = JWT.decode(token, nil, true, algorithms: ['RS256'], jwks: keys)\nend\n")
    assert rules(tmp_path, "JWT") == []


def test_ai_names_dont_leak_between_functions_in_files_with_emoji(tmp_path):
    # Zero-Health routes/chatbot.js (has emoji): only the query that uses AI output counts.
    write(tmp_path, "chatbot.js", "// 🤖 assistant\n"
                                  "async function history(userId) {\n"
                                  "  const historyQuery = `SELECT * FROM chat WHERE user_id = ${userId}`;\n"
                                  "  return pool.query(historyQuery);\n}\n"
                                  "async function ask(prompt) {\n"
                                  "  const completion = await openai.chat.completions.create({ messages: prompt });\n"
                                  "  const sql = completion.choices[0].message.content;\n"
                                  "  return pool.query(sql);\n}\n")
    assert rules(tmp_path, "AI-002") == ["chatbot.js:9"]


def test_random_ids_in_browser_code_are_fine(tmp_path):
    # r10review src/App.tsx: a local chat id made in the browser
    write(tmp_path, "App.tsx", "const sessionId = `local-session-${Date.now()}-${Math.random().toString(36)}`;\n"
                               "document.title = 'x';\n")
    assert rules(tmp_path, "RAND") == []


def test_anyone_can_add_rows_is_worth_a_look(tmp_path):
    write(tmp_path, "supabase/migrations/1.sql", "alter table public.q enable row level security;\n"
                                                 'create policy "Anyone can ask" on public.q for insert with check (true);\n')
    findings = [f for f in engine.scan(tmp_path).findings if f.rule_id == "RLS-001"]
    assert len(findings) == 1 and engine.is_worth_a_look(findings[0])


def test_an_express_server_that_sends_html_is_still_server_code(tmp_path):
    # Zero-Health server.js: web pages inside text strings mention document., but it's a server.
    write(tmp_path, "server.js", "const express = require('express');\nconst app = express();\n"
                                 "const page = `<script>document.title = 'x'</script>`;\n"
                                 "const recoveryCode = Math.random().toString(36).substring(2, 15);\n"
                                 "app.listen(3000);\n")
    assert rules(tmp_path, "RAND") == ["server.js:4"]


def test_analytics_and_chat_widget_tokens_are_public(tmp_path):
    # paynless .env.example
    write(tmp_path, ".env.example", "VITE_CHATWOOT_WEBSITE_TOKEN=\nVITE_MIXPANEL_PROJECT_TOKEN=\nVITE_SUPABASE_SERVICE_ROLE_KEY=\n")
    assert rules(tmp_path, "SEC-005") == [".env.example:3"]
