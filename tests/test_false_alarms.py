"""
Tests from the false-alarm review (round 2).

Each test here is a small copy of real code, from one of the test projects,
that DecalogueX flagged when it shouldn't have. The project each came from
is named in the test.
"""

from pathlib import Path

from decaloguex import engine


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def found(folder: Path, prefix: str) -> list:
    return [f for f in engine.scan(folder).findings if f.rule_id.startswith(prefix)]


# --- js-1-express-realworld -------------------------------------------------------

EXPRESS_ERROR_HANDLER = """
app.use((err, req, res, next) => {
  if (err && err.errorCode) {
    res.status(err.errorCode).json(err.message);
  } else if (err) {
    res.status(500).json(err.message);
  }
});
"""


def test_error_with_its_own_status_is_not_a_leak(tmp_path):
    # src/main.ts. err.errorCode is only set by the app's own HttpException
    # (422 "can't be blank", 404 "not found"), so that message is meant for
    # the visitor. The 500 branch below it really does leak and is still found.
    write(tmp_path, "main.js", EXPRESS_ERROR_HANDLER)
    findings = found(tmp_path, "ERR")
    assert [f.line for f in findings] == [6]


def test_status_with_a_fallback_is_still_reported(tmp_path):
    # With "|| 500", any unexpected error lands on 500 and its message leaks.
    write(tmp_path, "main.js", "app.use((err, req, res, next) => {\n"
                               "  res.status(err.status || 500).json(err.message);\n});\n")
    assert len(found(tmp_path, "ERR")) == 1


# --- CORS: only a risk with cookie logins -------------------------------------------

def test_cors_with_token_logins_is_not_reported(tmp_path):
    # js-1-express-realworld: app.use(cors()) with logins sent as "Authorization: Token ..."
    # headers. Another website can't attach that token, so it can't act as a visitor.
    write(tmp_path, "main.js", "const cors = require('cors');\napp.use(cors());\n"
                               "const token = req.headers.authorization;\n")
    assert found(tmp_path, "CORS") == []


def test_cors_star_with_cookie_logins_is_still_safe(tmp_path):
    # Corrected after the 29-project review: a plain * never carries logins, cookies or not.
    write(tmp_path, "main.js", "app.use(cors());\n")
    write(tmp_path, "auth.js", "const session = require('express-session');\napp.use(session({ secret: s }));\n")
    assert found(tmp_path, "CORS") == []


def test_cors_that_allows_credentials_is_always_reported(tmp_path):
    write(tmp_path, "main.js", "app.use(cors({\n  origin: true,\n  credentials: true,\n}));\n")
    assert len(found(tmp_path, "CORS")) == 1


# --- js-2-nextjs-commerce ------------------------------------------------------------

JSON_LD_PAGE = """export default function Page({ product }) {
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify(product),
        }}
      />
      <div dangerouslySetInnerHTML={{ __html: JSON.stringify(product) }} />
    </>
  );
}
"""


def test_json_in_a_script_tag_is_escaped(tmp_path):
    # app/product/[handle]/page.tsx: product info for Google, written with JSON.stringify.
    # A product name containing </script> would end the script early and run as code.
    from decaloguex import cli
    page = write(tmp_path, "page.tsx", JSON_LD_PAGE)
    cli.run_scan(tmp_path, assume_yes=True, no_color=True, no_animation=True)
    code = page.read_text(encoding="utf-8")
    assert r'__html: JSON.stringify(product).replace(/</g, "\\u003c"),' in code
    # In a <div> the escape would show on screen, so that one is only reported.
    assert "<div dangerouslySetInnerHTML={{ __html: JSON.stringify(product) }} />" in code


def test_already_escaped_json_is_left_alone(tmp_path):
    write(tmp_path, "page.tsx", r'<script dangerouslySetInnerHTML={{ __html: JSON.stringify(p).replace(/</g, "\\u003c") }} />;' + "\n")
    assert [f for f in found(tmp_path, "XSS") if f.fix] == []


# --- php-2-koel-music-app ------------------------------------------------------------

def test_html_cleaned_on_another_line_is_not_reported(tmp_path):
    # components/podcast/PodcastItem.vue: cleaned with DOMPurify where the variable is made.
    write(tmp_path, "PodcastItem.vue", """<template>
  <div class="description" v-html="description" />
</template>
<script setup lang="ts">
import DOMPurify from 'dompurify'
const description = computed(() => DOMPurify.sanitize(podcast.description))
</script>
""")
    assert found(tmp_path, "XSS") == []


def test_html_not_cleaned_is_still_reported(tmp_path):
    write(tmp_path, "AlbumInfo.vue", '<template>\n  <div v-html="info.wiki.full" />\n</template>\n')
    assert len(found(tmp_path, "XSS")) == 1


def test_clearing_an_element_is_not_reported(tmp_path):
    # components/screens/VisualizerScreen.vue
    write(tmp_path, "screen.js", "el.value && (el.value.innerHTML = '')\n")
    assert found(tmp_path, "XSS") == []


def test_public_search_key_is_not_a_secret(tmp_path):
    # docs/.vitepress/config.mts: an Algolia search-only key, public by design.
    write(tmp_path, "config.mts", "export default {\n  search: {\n    provider: 'algolia',\n"
                                  "    options: {\n      appId: '2EQKL1O1UU',\n"
                                  "      apiKey: 'e9d7b5be73f29af4030535a726ec7196',\n    },\n  },\n}\n")
    assert found(tmp_path, "SEC") == []


# --- php-3-monica-crm ----------------------------------------------------------------

def test_translated_text_is_not_xss(tmp_path):
    # resources/js/Components/Pagination.vue: the app's own translated wording.
    write(tmp_path, "Pagination.vue", "<template>\n  <span v-html=\"$t('Previous')\"></span>\n</template>\n")
    assert found(tmp_path, "XSS") == []


def test_certificate_check_off_only_locally_is_fine(tmp_path):
    # app/Actions/AttemptToAuthenticateSocialite.php
    write(tmp_path, "Auth.php", "<?php\nif (App::environment('local') && $provider instanceof AbstractProvider) {\n"
                                + r"    $provider->setHttpClient(new \GuzzleHttp\Client(['verify' => false]));" + "\n}\n")
    assert found(tmp_path, "TLS") == []


def test_certificate_check_off_everywhere_is_still_reported(tmp_path):
    write(tmp_path, "Http.php", "<?php\n" + r"$client = new \GuzzleHttp\Client(['verify' => false]);" + "\n")
    assert len(found(tmp_path, "TLS")) == 1


def test_dummy_account_setup_is_treated_like_a_test(tmp_path):
    # app/Console/Commands/Local/SetupDummyAccount.php: made-up local login.
    write(tmp_path, "app/Console/Commands/SetupDummyAccount.php",
          "<?php\n$user = ['email' => 'admin@admin.com', 'password' => 'admin123'];\n")
    assert found(tmp_path, "SEC") == []


# --- go-2-gitea ----------------------------------------------------------------------

def test_table_names_in_sql_are_not_injection(tmp_path):
    # models/db/engine.go and models/db/index.go: table names come from the app's own code.
    write(tmp_path, "engine.go", 'package db\n\nfunc DeleteAllRecords(tableName string) error {\n'
                                 '\t_, err := x.Exec("DELETE FROM " + tableName)\n\treturn err\n}\n\n'
                                 'func bump(groupID int64) {\n'
                                 '\tx.Exec(fmt.Sprintf("UPDATE %s SET max_index=max_index+1 WHERE group_id=?", tableName), groupID)\n}\n')
    write(tmp_path, "clean.js", "db.query('DELETE FROM ' + tableName)\n")
    assert found(tmp_path, "SQL") == []


def test_table_name_from_the_request_is_still_injection(tmp_path):
    write(tmp_path, "clean.js", "db.query('DELETE FROM ' + req.query.table)\n")
    assert len(found(tmp_path, "SQL")) == 1


def test_a_text_pattern_named_token_is_not_a_secret(tmp_path):
    # services/mailer/incoming/reply.go
    write(tmp_path, "reply.go", "package incoming\n\nconst (\n"
                                + r"	yearToken = `\b\d{4}\b`" + "\n"
                                + r"	timeToken = `\b\d{1,2}[:.]\d{2}\b`" + "\n)\n")
    assert found(tmp_path, "SEC") == []


def test_ci_test_database_password_is_like_a_test_file(tmp_path):
    # .github/workflows/pull-db-tests.yml: a throwaway MSSQL test container.
    write(tmp_path, ".github/workflows/db.yml", "services:\n  mssql:\n    env:\n      SA_PASSWORD: MwantsaSecurePassword1\n")
    assert found(tmp_path, "SEC") == []


def test_skipping_certificates_for_the_same_machine_is_fine(tmp_path):
    # modules/private/internal.go
    write(tmp_path, "internal.go", "package private\n\nfunc cfg() *tls.Config {\n"
                                   "\tif internalAPIConnectionIsLocal(protocol, localURL) {\n"
                                   "\t\treturn &tls.Config{InsecureSkipVerify: true, ServerName: domain}\n\t}\n"
                                   "\treturn &tls.Config{}\n}\n")
    assert found(tmp_path, "TLS") == []


def test_icons_escaping_templates_and_fixed_html_are_not_xss(tmp_path):
    # gitea web_src/js: bundled icons, html`` templates (they escape values), copies of page HTML.
    write(tmp_path, "icons.ts", "btn.innerHTML = svg('octicon-copy');\n"
                                "this.button.innerHTML = octiconKebabHorizontal;\n"
                                "warningDiv.innerHTML = html`<p>File path contains whitespace.</p>`;\n"
                                "zone.innerHTML = document.querySelector('#editor-template')!.innerHTML;\n")
    write(tmp_path, "Tree.vue", '<template>\n  <span v-html="item.FileIcon"/>\n'
                                '  <span v-html="collapsed ? store.folderIcon : store.folderOpenIcon"/>\n</template>\n')
    write(tmp_path, "lfs.go", 'package setting\n\nfunc f() {\n\tprevLine := template.HTML("")\n\t_ = prevLine\n}\n')
    assert found(tmp_path, "XSS") == []


def test_server_html_put_in_the_page_is_still_reported(tmp_path):
    write(tmp_path, "graph.ts", "elGraphBody.innerHTML = await resp.text();\n")
    write(tmp_path, "page.go", "package web\n\nfunc f(r *http.Request) template.HTML {\n"
                               "\treturn template.HTML(r.FormValue(\"bio\"))\n}\n")
    assert len(found(tmp_path, "XSS")) == 2


# --- go-3-pocketbase -----------------------------------------------------------------

def test_values_in_sql_name_quotes_are_names(tmp_path):
    # core/collection_record_table_sync.go: {{table}} and [[column]] are PocketBase's name quotes.
    write(tmp_path, "sync.go", 'package core\n\nfunc f() {\n'
                               '\tq := db.NewQuery(fmt.Sprintf("UPDATE {{%s}} SET [[%s]] = 1", table, field))\n\t_ = q\n}\n')
    assert found(tmp_path, "SQL") == []


def test_private_key_placeholders_are_not_keys(tmp_path):
    # ui/src/collections/oauth2/appleOptions.js
    write(tmp_path, "options.js",
          r'const o = { placeholder: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----" };' + "\n")
    assert found(tmp_path, "SEC") == []


def test_real_looking_private_key_is_reported(tmp_path):
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" * 2
    write(tmp_path, "key.js", "const k = `-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----`;\n")
    assert [f.rule_id for f in found(tmp_path, "SEC")] == ["SEC-003"]


# --- java-1-spring-realworld / java-3-jhipster-sample --------------------------------

def test_library_names_with_versions_are_not_secrets(tmp_path):
    # build.gradle: 'io.jsonwebtoken:jjwt-jackson:0.11.2' (a library, not a token)
    write(tmp_path, "build.gradle", "dependencies {\n    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.2',\n"
                                    "                'io.jsonwebtoken:jjwt-jackson:0.11.2'\n}\n")
    assert found(tmp_path, "SEC") == []


def test_sample_settings_files_are_examples(tmp_path):
    # src/main/resources/config/application-secret-samples.yml
    write(tmp_path, "config/application-secret-samples.yml", "jwt:\n  base64-secret: bXktc2VjcmV0LWtleS13aGljaA9876\n")
    assert found(tmp_path, "SEC") == []


# --- ruby-1-rails-realworld ----------------------------------------------------------

def test_rails_development_and_test_keys_are_fine(tmp_path):
    # config/secrets.yml: Rails commits made-up keys for development and test on purpose.
    write(tmp_path, "config/secrets.yml",
          "development:\n  secret_key_base: 1cedd34d1be5424c2646c82e267fcbb817dd118d47d52ea8835e7fd\n\n"
          "test:\n  secret_key_base: 7d4d2daa8c4b79efe9a9206d20b877a2cde9c90f46987c6ec24f811\n\n"
          "production:\n  secret_key_base: 9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a3928170\n")
    found_lines = [f.line for f in found(tmp_path, "SEC")]
    assert found_lines == [8]  # only the production one


# --- kotlin-1-ktor-samples / kotlin-3-kotlinconf -------------------------------------

def test_kotlin_browser_code_coroutines_are_not_reported(tmp_path):
    # chat/src/frontendMain/kotlin/main.kt: Kotlin/JS in the browser prints errors, nothing crashes.
    write(tmp_path, "chat/src/frontendMain/kotlin/main.kt", "fun main() {\n    GlobalScope.launch { connect() }\n}\n")
    assert found(tmp_path, "ASYNC") == []


def test_sample_project_folders_are_examples(tmp_path):
    # jwt-auth-tests/src/main/resources/application.conf
    write(tmp_path, "jwt-auth-tests/src/main/kotlin/App.kt", 'val password = "Hunter2!secretpw"\n')
    assert found(tmp_path, "SEC") == []


def test_firebase_app_config_keys_are_public(tmp_path):
    key = "AIza" + "SyBX-TusTRUYosrNbpIs8MZX7Y0k_sdxwFg"
    write(tmp_path, "app/google-services.json", '{\n  "api_key": [\n    { "current_key": "' + key + '" }\n  ]\n}\n')
    assert found(tmp_path, "SEC") == []


def test_ktor_settings_reference_and_guessable_backup(tmp_path):
    # backend/src/main/resources/application.yaml
    write(tmp_path, "application.yaml", 'database:\n  password: "$DB0_PASSWORD:"\nadmin:\n  secret: "$ADMIN_SECRET:test"\n')
    assert [f.rule_id for f in found(tmp_path, "SEC")] == ["SEC-004"]


# --- swift-3-vapor / svelte-1-realworld ----------------------------------------------

def test_swift_task_whose_value_is_read_is_fine(tmp_path):
    # Sources/Vapor/Utilities/FileETagHashCache.swift
    write(tmp_path, "Cache.swift", "func get() async throws -> String {\n"
                                   "    let task = Task { try await compute() }\n"
                                   "    return try await task.value\n}\n")
    assert found(tmp_path, "ASYNC") == []


def test_benchmarks_are_like_tests(tmp_path):
    write(tmp_path, "Benchmarks/EndToEnd.swift", "func run() {\n    Task { try await server.run() }\n}\n")
    assert found(tmp_path, "ASYNC") == []


def test_sveltekit_html_cleaned_in_the_page_loader(tmp_path):
    # src/routes/article/[slug]/+page.server.js cleans the body; +page.svelte shows it.
    write(tmp_path, "src/routes/article/+page.server.js",
          "import sanitizeHtml from 'sanitize-html';\nexport async function load() {\n"
          "  article.body = sanitizeHtml(marked(article.body));\n  return { article };\n}\n")
    write(tmp_path, "src/routes/article/+page.svelte", "<div>{@html data.article.body}</div>\n")
    assert found(tmp_path, "XSS") == []


def test_sveltekit_html_not_cleaned_is_reported(tmp_path):
    write(tmp_path, "src/routes/article/+page.server.js", "export async function load() {\n  return { article };\n}\n")
    write(tmp_path, "src/routes/article/+page.svelte", "<div>{@html data.article.body}</div>\n")
    assert len(found(tmp_path, "XSS")) == 1


# --- ruby-2-forem-devto --------------------------------------------------------------

def test_fixed_text_and_highlighted_code_marked_safe_in_ruby(tmp_path):
    # app/helpers/comments_helper.rb and agent_sessions_helper.rb
    write(tmp_path, "comments_helper.rb", 'def a\n  return "".html_safe if tree.blank?\nend\n'
                                          'def b\n  num: "__FOREM_NUM__".html_safe\nend\n'
                                          'def c\n  content_tag(:code, highlighted.html_safe)\nend\n')
    assert found(tmp_path, "XSS") == []


def test_fixed_html_text_and_translations_in_javascript(tmp_path):
    write(tmp_path, "votes.js", "this.element.innerHTML = '<p class=\"color-base-60 italic\">No votes yet.</p>';\n"
                                "this.target.innerHTML = null;\n"
                                "trigger.innerHTML = locale('core.comments_preview');\n")
    assert found(tmp_path, "XSS") == []


def test_lines_marked_as_checked_are_not_reported(tmp_path):
    write(tmp_path, "helper.rb", "def a\n  html.html_safe # rubocop:disable Rails/OutputSafety\nend\n")
    write(tmp_path, "page.js", "// decaloguex-ignore\nel.innerHTML = userBio;\n"
                               "other.innerHTML = comment; // nosemgrep\n")
    assert found(tmp_path, "XSS") == []


def test_unmarked_html_is_still_reported(tmp_path):
    write(tmp_path, "page.js", "el.innerHTML = userBio;\n")
    write(tmp_path, "helper.rb", "def a\n  params[:bio].html_safe\nend\n")
    assert len(found(tmp_path, "XSS")) == 2


def test_obviously_fake_keys_are_not_reported(tmp_path):
    # spec/services/.../sensitive_data_scrubber_spec.rb: AWS's own documentation key and an alphabet "token".
    write(tmp_path, "scrubber.js", "const aws = 'AKIAIOSFODNN7EXAMPLE';\n"
                                   "const gh = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890';\n")
    assert found(tmp_path, "SEC") == []


def test_rails_development_environment_file_is_like_a_test(tmp_path):
    # config/environments/development.rb
    write(tmp_path, "config/environments/development.rb",
          'config.secret_key_base = ENV.fetch("SECRET_KEY_BASE", "a60edc976c913b19fd9fc8118936fbe1df2b07f4")\n')
    assert found(tmp_path, "SEC") == []


def test_rails_blocks_model_new_params_by_itself(tmp_path):
    # app/controllers/feedback_messages_controller.rb: Rails raises unless fields are permitted.
    write(tmp_path, "feedback_controller.rb", "def create\n  @feedback_message = FeedbackMessage.new(params)\nend\n"
                                              "def check\n  return if params.to_unsafe_h[:article].is_a?(Hash)\nend\n")
    assert found(tmp_path, "MASS") == []


def test_rails_permit_bang_is_reported(tmp_path):
    # app/controllers/admin/pages_controller.rb
    write(tmp_path, "pages_controller.rb", "def update\n  @page.update(template_data.permit!.to_h)\nend\n")
    assert len(found(tmp_path, "MASS")) == 1


def test_ruby_where_values_and_quoted_sql_are_fine(tmp_path):
    # app/models/concerns/taggable.rb and app/controllers/api/v1/articles_controller.rb
    write(tmp_path, "taggable.rb", 'def tagged(tag)\n  where("cached_tag_list ~ ?", "[[:<:]]#{tag}[[:>:]]")\nend\n'
                                   'def near(quoted_vector, t)\n  where("embedding <=> #{quoted_vector} <= ?", t)\nend\n')
    assert found(tmp_path, "SQL") == []


def test_ruby_where_with_like_and_a_visitor_value_is_reported(tmp_path):
    write(tmp_path, "search.rb", "def search\n  User.where(\"name LIKE '%#{params[:q]}%'\")\nend\n")
    assert len(found(tmp_path, "SQL")) == 1


# --- ruby-3-chatwoot -----------------------------------------------------------------

def test_api_documentation_examples_are_not_secrets(tmp_path):
    # swagger/paths/application/inboxes/index.yml
    write(tmp_path, "swagger/paths/index.yml", "bot_token: 123456789:telegram-bot-token\nwebsite_token: 4cWzuf9i9jxN9tbnv8K9STKU\n")
    assert found(tmp_path, "SEC") == []


def test_generated_random_password_is_not_a_secret(tmp_path):
    # app/builders/agent_builder.rb
    write(tmp_path, "agent_builder.rb", 'def build\n  temp_password = "1!aA#{SecureRandom.alphanumeric(12)}"\nend\n')
    assert found(tmp_path, "SEC") == []


def test_seed_file_is_like_a_test(tmp_path):
    # db/seeds.rb
    write(tmp_path, "db/seeds.rb", "user = User.new(name: 'John', password: 'Password1!')\n")
    assert found(tmp_path, "SEC") == []


def test_ruby_condition_after_the_line_counts_as_development_only(tmp_path):
    # app/models/channel/line.rb
    write(tmp_path, "line.rb", "def c\n  config.http_options = { verify_mode: OpenSSL::SSL::VERIFY_NONE } if Rails.env.development?\nend\n")
    assert found(tmp_path, "TLS") == []


def test_ruby_4xx_status_name_is_a_deliberate_message(tmp_path):
    # app/controllers/api/v1/accounts/integrations/shopify_controller.rb
    write(tmp_path, "shopify_controller.rb", "def create\n  do_it\nrescue StandardError => e\n"
                                             "  render json: { error: e.message }, status: :unprocessable_entity\nend\n")
    assert found(tmp_path, "ERR") == []


def test_ruby_500_status_name_still_leaks(tmp_path):
    write(tmp_path, "health.rb", "def create\n  do_it\nrescue StandardError => e\n"
                                 "  render status: :internal_server_error, json: { error: e.message }\nend\n")
    assert len(found(tmp_path, "ERR")) == 1


def test_constants_numbers_and_migrations_in_sql_are_fine(tmp_path):
    write(tmp_path, "stale_job.rb", 'def go\n  Account.where("id % #{DISTRIBUTION_GROUPS} = ?", r)\n'
                                    '  having("count(*) >= #{limit.to_i}")\nend\n')
    write(tmp_path, "db/migrate/20261014_enable.rb", 'def up\n  Account.where("#{column} & #{bit} = 0")\nend\n')
    assert found(tmp_path, "SQL") == []


# --- Decisions after the 29-project review --------------------------------------------

def test_private_keys_in_test_files_are_not_reported(tmp_path):
    # gitea models/asymkey/ssh_key_test.go: tests make their own throwaway keys.
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" * 2
    write(tmp_path, "keys_test.go", "package asymkey\n\nconst k = `-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----`\n")
    assert found(tmp_path, "SEC") == []


def test_rails_to_json_in_a_script_is_safe_by_default(tmp_path):
    # chatwoot app/views/widgets/show.html.erb
    write(tmp_path, "app/views/widgets/show.html.erb",
          "<script>\n  window.portal = <%= @web_widget.inbox.portal.to_json.html_safe %>;\n"
          "  window.globalConfig = <%= raw @global_config.to_json %>\n</script>\n")
    assert found(tmp_path, "XSS") == []


def test_rails_to_json_is_reported_when_escaping_is_switched_off(tmp_path):
    write(tmp_path, "config/initializers/json.rb", "ActiveSupport.escape_html_entities_in_json = false\n")
    write(tmp_path, "app/views/widgets/show.html.erb",
          "<script>\n  window.portal = <%= @web_widget.inbox.portal.to_json.html_safe %>;\n</script>\n")
    assert len(found(tmp_path, "XSS")) == 1


def test_the_same_secret_in_several_files_is_one_card(tmp_path):
    # eShopOnWeb: one Docker database password in docker-compose.yml and 4 connection strings.
    write(tmp_path, "docker-compose.yml", "services:\n  db:\n    environment:\n      - SA_PASSWORD=someThingComplicated1234\n")
    write(tmp_path, "appsettings.Docker.json", '{\n  "DbPassword": "someThingComplicated1234"\n}\n')
    write(tmp_path, "web/appsettings.Docker.json", '{\n  "DbPassword": "someThingComplicated1234"\n}\n')
    cards = found(tmp_path, "SEC")
    assert len(cards) == 1
    places = ["docker-compose.yml", "appsettings.Docker.json", "web/appsettings.Docker.json"]
    listed = cards[0].note + " " + cards[0].path.relative_to(tmp_path).as_posix()
    assert "also in" in cards[0].note and all(place in listed for place in places)
