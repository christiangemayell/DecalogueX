#!/usr/bin/env node
/*
 * decaloguex.js: the launcher behind `npx decaloguex`.
 *
 * DecalogueX itself is written in Python. This small JavaScript file lets
 * JavaScript developers run it with the tools they already have (npm/npx).
 * It tries these, in order, and uses the first one that works:
 *
 *   1. A Python that already has DecalogueX installed
 *   2. uvx   (runs Python tools without installing them permanently)
 *   3. pipx  (the same idea, an older tool)
 *   4. Any Python: installs DecalogueX for this user once, then runs it
 *
 * If there's no Python at all, it explains how to get it.
 *
 * Everything you type after `npx decaloguex` is passed straight through,
 * so `npx decaloguex scan . --dry-run` works exactly like `decaloguex scan . --dry-run`.
 */

"use strict";

const { spawnSync } = require("child_process");
const posthog = require("./posthog");

const args = process.argv.slice(2); // what the user typed after "decaloguex"

// Python goes by different names on different systems. "py" is the Windows launcher.
const pythons = [process.env.DECALOGUEX_PYTHON, "python3", "python", "py"].filter(Boolean);

/** True if the command runs and succeeds (exit code 0). Prints nothing. */
function works(command, commandArgs) {
  const result = spawnSync(command, commandArgs, { stdio: "ignore" });
  return result.status === 0;
}

async function exitWithAnalytics(event, properties, exitCode) {
  if (posthog) {
    posthog.capture({ event, properties });
    await posthog.shutdown(3000).catch(() => {});
  }

  process.exit(exitCode);
}

/** Run a command, showing its output, then record its outcome before exiting. */
async function runAndExit(command, commandArgs, runner) {
  const result = spawnSync(command, commandArgs, { stdio: "inherit" });
  const exitCode = result.status === null ? 1 : result.status;

  await exitWithAnalytics(
    "decaloguex_run_completed",
    {
      runner,
      succeeded: exitCode === 0,
    },
    exitCode
  );
}

async function main() {
  // 1. A Python that already has DecalogueX installed.
  for (const python of pythons) {
    if (works(python, ["-c", "import decaloguex"])) {
      await runAndExit(python, ["-m", "decaloguex", ...args], "installed_python");
      return;
    }
  }

  // 2 and 3. Tools that run Python programs without a permanent install.
  if (works("uvx", ["--version"])) {
    await runAndExit("uvx", ["decaloguex", ...args], "uvx");
    return;
  }

  if (works("pipx", ["--version"])) {
    await runAndExit("pipx", ["run", "decaloguex", ...args], "pipx");
    return;
  }

  // 4. Any working Python: install DecalogueX for this user (once), then run it.
  for (const python of pythons) {
    if (works(python, ["--version"])) {
      console.error("Setting up DecalogueX (one time only)...");
      const install = spawnSync(python, ["-m", "pip", "install", "--user", "--quiet", "decaloguex"], {
        stdio: "inherit",
      });
      if (install.status === 0) {
        await runAndExit(python, ["-m", "decaloguex", ...args], "python_user_install");
        return;
      }
    }
  }

  console.error(
    [
      "",
      "DecalogueX needs Python 3.10 or newer, and I couldn't find it on this computer.",
      "",
      "  1. Install Python from https://www.python.org/downloads/",
      '     (on Windows, tick "Add python.exe to PATH" during the install)',
      "  2. Run this command again.",
      "",
    ].join("\n")
  );
  await exitWithAnalytics("decaloguex_launch_unavailable", { reason: "no_runnable_python" }, 1);
}

main();
