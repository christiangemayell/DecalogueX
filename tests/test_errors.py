"""
Tests for Safe Error Masking, the PII Shield (ERR-001).
"""

from pathlib import Path

from decaloguex import engine
from decaloguex.cli import run_scan

GENERIC = "Something went wrong. Please try again."


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.write_text(text, encoding="utf-8")
    return path


def err_findings(folder: Path):
    return [f for f in engine.scan(folder).findings if f.rule_id == "ERR-001"]


def fix(folder: Path) -> None:
    run_scan(folder, assume_yes=True, no_color=True)


# --- JavaScript ---------------------------------------------------------------

def test_catch_block_message_is_masked_and_logged(tmp_path):
    app = write(tmp_path, "app.js",
                "async function handler(req, res) {\n"
                "  try {\n"
                "    await work();\n"
                "  } catch (err) {\n"
                "    res.status(500).json({ error: err.message });\n"
                "  }\n"
                "}\n")
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert "    console.error(err);\n    res.status(500).json({ error: \"" + GENERIC + "\" });" in code
    assert "err.message" not in code


def test_whole_error_object_sent_as_json_becomes_an_object(tmp_path):
    app = write(tmp_path, "app.js",
                "try { a(); } catch (e) {\n"
                "  res.json(e);\n"
                "}\n")
    fix(tmp_path)
    assert 'res.json({ error: "' + GENERIC + '" });' in app.read_text(encoding="utf-8")


def test_express_error_middleware_arrow_gets_a_body(tmp_path):
    app = write(tmp_path, "app.js",
                "app.use((err, req, res, next) => res.status(500).send(`Error: ${err.stack}`));\n")
    fix(tmp_path)
    assert ('app.use((err, req, res, next) => { console.error(err); '
            'return res.status(500).send("' + GENERIC + '"); });') in app.read_text(encoding="utf-8")


def test_promise_catch_callback(tmp_path):
    app = write(tmp_path, "app.js",
                "save().catch((error) => {\n"
                "  res.status(500).send(String(error));\n"
                "});\n")
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert 'res.status(500).send("' + GENERIC + '");' in code
    assert "console.error(error);" in code


def test_nextjs_response(tmp_path):
    app = write(tmp_path, "route.ts",
                "try { await run(); } catch (err) {\n"
                "  return NextResponse.json({ message: err.message }, { status: 500 });\n"
                "}\n")
    fix(tmp_path)
    assert 'NextResponse.json({ message: "' + GENERIC + '" }, { status: 500 });' in app.read_text(encoding="utf-8")


def test_existing_logging_is_not_duplicated(tmp_path):
    app = write(tmp_path, "app.js",
                "try { a(); } catch (err) {\n"
                "  logger.error(err);\n"
                "  res.status(500).send(err.message);\n"
                "}\n")
    fix(tmp_path)
    assert "console.error" not in app.read_text(encoding="utf-8")


def test_client_errors_4xx_are_left_alone(tmp_path):
    write(tmp_path, "app.js",
          "try { validate(body); } catch (err) {\n"
          "  res.status(400).json({ error: err.message });\n"
          "}\n")
    assert err_findings(tmp_path) == []


# --- Python -------------------------------------------------------------------

def test_flask_broad_except_is_masked_and_logged(tmp_path):
    app = write(tmp_path, "app.py",
                '"""App."""\n'
                "from flask import jsonify\n"
                "\n"
                "def view():\n"
                "    try:\n"
                "        work()\n"
                "    except Exception as e:\n"
                '        return jsonify({"error": str(e)}), 500\n')
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert '        logging.exception("Unhandled error")\n        return jsonify({"error": "' + GENERIC + '"}), 500' in code
    assert code.startswith('"""App."""\nimport logging\n')


def test_fastapi_http_exception_detail(tmp_path):
    app = write(tmp_path, "api.py",
                "import logging\n"
                "async def get():\n"
                "    try:\n"
                "        await work()\n"
                "    except Exception as exc:\n"
                '        raise HTTPException(status_code=500, detail=f"Failed: {exc}")\n')
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert 'detail="' + GENERIC + '"' in code
    assert code.count("import logging") == 1  # already there, so not added twice


def test_traceback_in_route_return(tmp_path):
    app = write(tmp_path, "app.py",
                "import traceback\n"
                '@app.route("/x")\n'
                "def x():\n"
                "    try:\n"
                "        work()\n"
                "    except:\n"
                "        return traceback.format_exc(), 500\n")
    fix(tmp_path)
    assert 'return "' + GENERIC + '", 500' in app.read_text(encoding="utf-8")


def test_specific_exception_with_client_message_is_left_alone(tmp_path):
    write(tmp_path, "app.py",
          "def view():\n"
          "    try:\n"
          "        parse()\n"
          "    except ValueError as e:\n"
          '        return jsonify({"error": str(e)})\n')
    assert err_findings(tmp_path) == []


def test_python_4xx_is_left_alone(tmp_path):
    write(tmp_path, "app.py",
          "def view():\n"
          "    try:\n"
          "        parse()\n"
          "    except Exception as e:\n"
          '        return jsonify({"error": str(e)}), 422\n')
    assert err_findings(tmp_path) == []


def test_one_line_except_is_reported_not_rewritten(tmp_path):
    original = (
        "def view():\n"
        "    try: parse()\n"
        "    except Exception as e: return jsonify(error=str(e)), 500\n"
    )
    app = write(tmp_path, "app.py", original)
    [finding] = err_findings(tmp_path)
    assert finding.fix is None
    fix(tmp_path)
    assert app.read_text(encoding="utf-8") == original
