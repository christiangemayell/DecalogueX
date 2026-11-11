"""
Tests for Unhandled Async Error Boundaries (ASYNC-001 to ASYNC-004).
"""

from pathlib import Path

from decaloguex import engine
from decaloguex.cli import run_scan


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.write_text(text, encoding="utf-8")
    return path


def async_ids(folder: Path):
    return [f.rule_id for f in engine.scan(folder).findings if f.rule_id.startswith("ASYNC")]


def fix(folder: Path) -> None:
    run_scan(folder, assume_yes=True, no_color=True)


# --- ASYNC-001: Express async routes ------------------------------------------

EXPRESS_ROUTE = (
    'const express = require("express");\n'
    "const app = express();\n"
    'app.get("/users/:id", async (req, res) => {\n'
    "  const user = await db.find(req.params.id);\n"
    "  res.json(user);\n"
    "});\n"
)


def test_express_route_is_wrapped_in_try_catch(tmp_path):
    app = write(tmp_path, "server.js", EXPRESS_ROUTE)
    fix(tmp_path)
    assert app.read_text(encoding="utf-8") == (
        'const express = require("express");\n'
        "const app = express();\n"
        'app.get("/users/:id", async (req, res, next) => {\n'
        "  try {\n"
        "    const user = await db.find(req.params.id);\n"
        "    res.json(user);\n"
        "  } catch (err) {\n"
        "    next(err);\n"
        "  }\n"
        "});\n"
    )


def test_existing_next_parameter_is_reused(tmp_path):
    app = write(tmp_path, "server.js",
                'const express = require("express");\n'
                'router.post("/x", async function (req, res, done) {\n'
                "  await save(req.body);\n"
                "});\n")
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert "done(err);" in code and "next" not in code


def test_typescript_next_gets_a_type(tmp_path):
    app = write(tmp_path, "server.ts",
                'import express from "express";\n'
                'app.get("/", async (req: Request, res: Response) => {\n'
                "  res.json(await load());\n"
                "});\n")
    fix(tmp_path)
    assert "(req: Request, res: Response, next: (err?: unknown) => void)" in app.read_text(encoding="utf-8")


def test_multi_line_strings_are_not_reindented(tmp_path):
    app = write(tmp_path, "server.js",
                'const express = require("express");\n'
                'app.get("/", async (req, res) => {\n'
                "  const text = `line one\n"
                "line two`;\n"
                "  res.send(await render(text));\n"
                "});\n")
    fix(tmp_path)
    # "line two" must keep zero indentation, or the string's value would change.
    assert "\nline two`;" in app.read_text(encoding="utf-8")


def test_express_5_is_left_alone(tmp_path):
    # Express 5 already passes async errors to the error handler.
    write(tmp_path, "package.json", '{"dependencies": {"express": "^5.0.0"}}')
    write(tmp_path, "server.js", EXPRESS_ROUTE)
    assert async_ids(tmp_path) == []


def test_guarded_route_and_non_express_file_are_left_alone(tmp_path):
    write(tmp_path, "guarded.js",
          'const express = require("express");\n'
          'app.get("/", async (req, res, next) => {\n'
          "  try { res.json(await load()); } catch (e) { next(e); }\n"
          "});\n")
    write(tmp_path, "fastify.js",  # no Express import: Fastify handles async errors itself
          'app.get("/", async (req, reply) => {\n'
          "  return await load();\n"
          "});\n")
    assert async_ids(tmp_path) == []


# --- ASYNC-002: .then() without .catch() --------------------------------------

def test_then_chain_gets_a_catch(tmp_path):
    app = write(tmp_path, "app.js", "fetch(url).then((r) => r.json()).then(show);\n")
    fix(tmp_path)
    assert app.read_text(encoding="utf-8") == \
        "fetch(url).then((r) => r.json()).then(show).catch((err) => console.error(err));\n"


def test_handled_promises_are_left_alone(tmp_path):
    write(tmp_path, "app.js",
          "load().then(show).catch(report);\n"   # has .catch
          "load().then(show, report);\n"         # second argument handles errors
          "await load().then(show);\n"           # awaited: the caller handles errors
          "return_value = load().then(show);\n")  # stored: may be handled later
    assert async_ids(tmp_path) == []


# --- ASYNC-003: Python coroutine never awaited ---------------------------------

def test_missing_await_is_added(tmp_path):
    app = write(tmp_path, "app.py",
                "async def send(to):\n"
                "    ...\n"
                "\n"
                "async def signup(user):\n"
                "    send(user.email)\n")
    fix(tmp_path)
    assert "    await send(user.email)\n" in app.read_text(encoding="utf-8")


def test_method_called_on_self(tmp_path):
    app = write(tmp_path, "app.py",
                "class Bot:\n"
                "    async def reply(self):\n"
                "        ...\n"
                "    async def run(self):\n"
                "        self.reply()\n")
    fix(tmp_path)
    assert "        await self.reply()\n" in app.read_text(encoding="utf-8")


def test_top_level_call_uses_asyncio_run(tmp_path):
    app = write(tmp_path, "main.py",
                "async def main():\n"
                "    ...\n"
                "\n"
                "main()\n")
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert code.startswith("import asyncio\n")
    assert code.endswith("asyncio.run(main())\n")


def test_call_from_sync_function_is_reported_only(tmp_path):
    write(tmp_path, "app.py",
          "async def send():\n"
          "    ...\n"
          "def view():\n"
          "    send()\n")
    [finding] = [f for f in engine.scan(tmp_path).findings if f.rule_id == "ASYNC-003"]
    assert finding.fix is None


# --- ASYNC-004: fire-and-forget tasks ------------------------------------------

def test_create_task_is_kept_alive(tmp_path):
    app = write(tmp_path, "app.py",
                "import asyncio\n"
                "\n"
                "async def start():\n"
                "    asyncio.create_task(worker())\n"
                "    asyncio.create_task(other())\n")
    fix(tmp_path)
    code = app.read_text(encoding="utf-8")
    assert code.count("_background_tasks: set = set()") == 1  # defined once, after the imports
    assert ("    _task = asyncio.create_task(worker())\n"
            "    _background_tasks.add(_task)\n"
            "    _task.add_done_callback(_background_tasks.discard)\n") in code


def test_kept_tasks_and_task_groups_are_left_alone(tmp_path):
    write(tmp_path, "app.py",
          "import asyncio\n"
          "async def start():\n"
          "    task = asyncio.create_task(worker())\n"
          "    async with asyncio.TaskGroup() as tg:\n"
          "        tg.create_task(other())\n")
    assert async_ids(tmp_path) == []
