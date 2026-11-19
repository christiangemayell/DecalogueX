"""
Tests from the AI-written apps round (10 vibe-coded apps from GitHub, plus the
Zero-Health and oss-oopssec-store training apps).

Each test is a small copy of the real code. The project is named in the test.
"""

from pathlib import Path

from decaloguex import cli, engine


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def found(folder: Path, prefix: str) -> list:
    return [f for f in engine.scan(folder).findings if f.rule_id.startswith(prefix)]


# --- Things that must now be CAUGHT ----------------------------------------------------

def test_nextjs_app_router_input_reaches_ssrf_and_redirect(tmp_path):
    # oss-oopssec-store: visitor data in Next.js route handlers comes from request.json() / searchParams.
    write(tmp_path, "app/api/screenshot/route.ts",
          "import { NextResponse } from 'next/server'\n"
          "export async function POST(request: Request) {\n"
          "  const { screenshotUrl } = await request.json()\n"
          "  const response = await fetch(screenshotUrl)\n"
          "  return NextResponse.json({ ok: response.ok })\n}\n")
    write(tmp_path, "app/login/route.ts",
          "import { NextResponse } from 'next/server'\n"
          "export async function GET(request: Request) {\n"
          "  const target = new URL(request.url).searchParams.get('redirect')\n"
          "  return NextResponse.redirect(target)\n}\n")
    assert len(found(tmp_path, "SSRF")) == 1 and len(found(tmp_path, "REDIRECT")) == 1


def test_guessable_secret_under_a_strong_name(tmp_path):
    # Zero-Health server.js
    write(tmp_path, "server.js", "const JWT_SECRET = 'zero-health-super-secret-key';\n")
    assert [f.rule_id for f in found(tmp_path, "SEC")] == ["SEC-002"]


def test_labels_are_still_not_secrets(tmp_path):
    write(tmp_path, "form.js", "const labels = { password: 'Password', secret_key: 'SECRET_KEY' };\n")
    assert found(tmp_path, "SEC") == []


def test_prisma_saving_the_whole_request_body(tmp_path):
    write(tmp_path, "app/api/users/route.ts",
          "export async function POST(request: Request) {\n"
          "  const user = await prisma.user.create({ data: await request.json() })\n}\n")
    assert len(found(tmp_path, "MASS")) == 1


def test_user_written_html_is_a_sure_problem(tmp_path):
    # ama_bolt QuestionDetailPage.tsx: questions and answers typed by users, shown as raw HTML.
    write(tmp_path, "QuestionDetailPage.tsx",
          "export function Q({ question }) {\n"
          "  return <div dangerouslySetInnerHTML={{ __html: question.content }} />\n}\n")
    xss = found(tmp_path, "XSS")
    assert len(xss) == 1 and not engine.is_worth_a_look(xss[0])


# --- Things that must now be LEFT ALONE ------------------------------------------------

def test_tailwind_classes_are_not_secrets(tmp_path):
    # pokecollector CardItem.jsx
    write(tmp_path, "CardItem.jsx", "const colors = { 'Rare Secret': 'text-orange-400' };\n")
    assert found(tmp_path, "SEC") == []


def test_a_sentence_in_a_translation_file_is_not_a_secret(tmp_path):
    # pokecollector frontend/src/i18n/locales/ja.json
    write(tmp_path, "ja.json", '{\n    "telegramBotTokenDesc": "@BotFather からの Bot Token",\n}\n')
    assert found(tmp_path, "SEC") == []


def test_supabase_config_env_references_are_not_secrets(tmp_path):
    # paynless-framework supabase/config.toml
    write(tmp_path, "supabase/config.toml", 'openai_api_key = "env(OPENAI_API_KEY)"\nsecret = "env(GITHUB_SECRET)"\n')
    assert found(tmp_path, "SEC") == []


def test_more_test_file_names(tmp_path):
    # paynless _integration.test.utils.ts, flightlesssomething backend_test.sh, paynless update-seed.ts
    write(tmp_path, "_shared/_integration.test.utils.ts", 'const testUserPassword = "password123";\n')
    write(tmp_path, "backend_test.sh", 'SESSION_SECRET="test-secret-backend-must-be-at-least-32-chars"\n')
    write(tmp_path, "scripts/update-seed.ts", 'const adminPassword = "Seed!Pass9876";\n')
    assert found(tmp_path, "SEC") == []


def test_sql_built_from_fixed_text_variables(tmp_path):
    # pokecollector backend/database.py
    write(tmp_path, "database.py", "from sqlalchemy import text\n\ndef check(conn):\n"
                                   "    allowed_sql = \"('Normal', 'Holo', 'Reverse Holo')\"\n"
                                   "    return conn.execute(text(f\"SELECT id FROM cards WHERE variant NOT IN {allowed_sql}\"))\n")
    assert found(tmp_path, "SQL") == []


def test_paths_checked_by_a_helper_are_fine(tmp_path):
    # pokecollector backend/api/scan_jobs.py
    write(tmp_path, "scan_jobs.py", "from fastapi.responses import FileResponse\n\n"
                                    "@router.get('/scan/{job_id}')\ndef photo(job_id: str):\n"
                                    "    path = resolve_scan_path(job_id)\n"
                                    "    return FileResponse(path, media_type='image/jpeg')\n")
    assert found(tmp_path, "PATH") == []


def test_shadcn_chart_component_is_not_xss(tmp_path):
    # Every Lovable app ships shadcn/ui's chart.tsx, which builds CSS from the app's own theme.
    write(tmp_path, "src/components/ui/chart.tsx", "<style dangerouslySetInnerHTML={{ __html: css }} />;\n")
    assert found(tmp_path, "XSS") == []


# --- Found by the fix-mode test on these apps --------------------------------------------

def test_error_instanceof_choice_becomes_one_friendly_message(tmp_path):
    # squadup / r10review / oopssec: the most common AI error pattern.
    app = write(tmp_path, "index.ts",
                "export async function handler(req: Request) {\n  try {\n    return await run(req)\n"
                "  } catch (error) {\n    return new Response(\n"
                "      JSON.stringify({ error: error instanceof Error ? error.message : \"Unknown error\" }),\n"
                "      { status: 500 }\n    )\n  }\n}\n")
    cli.run_scan(tmp_path, assume_yes=True, no_color=True, no_animation=True)
    code = app.read_text(encoding="utf-8")
    assert 'JSON.stringify({ error: "Something went wrong. Please try again." })' in code
    assert "instanceof" not in code


def test_a_four_parameter_helper_is_not_an_error_handler(tmp_path):
    # paynless supabase/functions/_shared/cors-headers.ts: fixing this would have
    # replaced EVERY successful response with an error message.
    original = ("export const createSuccessResponse = (data, status = 200, request, additionalHeaders = {}) => {\n"
                "  return new Response(JSON.stringify(data), { status })\n};\n")
    write(tmp_path, "cors-headers.ts", original)
    assert found(tmp_path, "ERR") == []


# --- oss-oopssec-store: Next.js patterns ------------------------------------------------

def test_input_through_a_schema_check_is_still_visitor_input(tmp_path):
    # app/api/support/route.ts: zod's safeParse confirms the TYPE, not that a URL is safe.
    write(tmp_path, "app/api/support/route.ts",
          "import { NextRequest } from 'next/server'\n"
          "export async function POST(request: NextRequest) {\n"
          "  const parsed = await parseBody(request, supportSchema)\n"
          "  const { screenshotUrl } = parsed.data\n"
          "  const response = await fetch(screenshotUrl)\n}\n")
    assert len(found(tmp_path, "SSRF")) == 1


def test_value_read_in_a_component_and_used_in_an_inner_function(tmp_path):
    # app/login/LoginForm.tsx
    write(tmp_path, "LoginForm.tsx",
          "export function LoginForm() {\n  const redirect = searchParams.get('redirect')\n"
          "  const onSubmit = async () => {\n    if (redirect) {\n      window.location.href = redirect\n    }\n  }\n}\n")
    assert len(found(tmp_path, "REDIRECT")) == 1


def test_own_site_redirects_are_fine(tmp_path):
    # middleware.ts and ProductSearchClient.tsx
    write(tmp_path, "middleware.ts", "export function middleware(request) {\n"
                                     "  return NextResponse.redirect(new URL('/login', request.url))\n}\n")
    write(tmp_path, "Search.tsx", "function go(searchQuery) {\n"
                                  "  const q = searchParams.get('q')\n"
                                  "  router.push(`/products/search?q=${encodeURIComponent(q)}`)\n}\n")
    assert found(tmp_path, "REDIRECT") == []
