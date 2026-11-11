"""
cli.py: the `decaloguex` command.

Usage:
  decaloguex scan [path]                 scan, explain, then ask what to do
  decaloguex scan [path] --yes           fix everything without asking (for AI agents)
  decaloguex scan [path] --dry-run       only show problems; never change anything
  decaloguex scan [path] --no-animation  no moving bars or spinners
  decaloguex scan [path] --no-color      plain text, no colours

Exit codes (what scripts and AI agents check):
  0  nothing left to fix
  1  problems remain (skipped, dry run, or needing a manual step)
  2  bad arguments, or the path doesn't exist
  130  stopped with Ctrl+C (the usual code for that)
"""

from __future__ import annotations

import argparse  # reads the command-line options, like picocli in Java
import sys
from pathlib import Path

from decaloguex import __version__, engine, ui


def main(argv: list[str] | None = None) -> int:
    """Entry point. argv=None means "use the real command line".

    Taking argv as a parameter lets tests call main(["scan", "x"]), the
    same way you'd call main(String[] args) from a JUnit test.
    """
    parser = argparse.ArgumentParser(
        prog="decaloguex",
        description="Crash Doctor: finds and fixes the mistakes AI coding tools leave behind.",
    )
    parser.add_argument("--version", action="version", version=f"decaloguex {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan_cmd = commands.add_parser("scan", help="scan a file or folder")
    scan_cmd.add_argument("path", nargs="?", default=".", help="file or folder to scan (default: this folder)")
    scan_cmd.add_argument("-y", "--yes", action="store_true", help="fix everything without asking")
    scan_cmd.add_argument("--dry-run", action="store_true", help="only show problems; change nothing")
    scan_cmd.add_argument("--no-animation", action="store_true", help="no moving bars or spinners")
    scan_cmd.add_argument("--no-color", action="store_true", help="plain text, no colours")

    args = parser.parse_args(argv)
    # argparse turns "--dry-run" into the attribute name dry_run.
    return run_scan(Path(args.path), assume_yes=args.yes, dry_run=args.dry_run,
                    no_color=args.no_color, no_animation=args.no_animation)


def run_scan(
    target: Path,
    assume_yes: bool = False,
    dry_run: bool = False,
    no_color: bool = False,
    no_animation: bool = False,
    ask: ui.Ask = input,
) -> int:
    """Scan, explain, ask, fix. Returns the exit code.

    `ask` defaults to Python's built-in input() (like Scanner.nextLine()).
    Tests pass a fake function instead of typing at a keyboard. That's
    dependency injection, with a function standing in for an interface.
    """
    screen = ui.setup_screen(no_color, no_animation)
    try:
        return _run(screen, target, assume_yes, dry_run, ask)
    except KeyboardInterrupt:
        # Ctrl+C. Fixes are only written at the very end, so stopping
        # before that leaves every file exactly as it was.
        screen.settle("")
        screen.say(screen.dim("  Stopped. Nothing was changed."))
        return 130
    finally:
        screen.cursor(True)  # never leave the cursor hidden


def _run(screen: ui.Screen, target: Path, assume_yes: bool, dry_run: bool, ask: ui.Ask) -> int:
    if not target.exists():
        screen.say(screen.coral(f"  I can't find {target}. Check the spelling and try again."))
        return 2

    # 1 and 2: start-up, then scan with a live progress bar.
    ui.show_start(screen)
    progress = ui.ScanProgress(screen)
    result = engine.scan(target, on_progress=progress.update)
    progress.finish(result.files_checked, result.seconds)

    # 3: the report, one card per problem.
    ui.show_report(screen, result.findings, result.root)
    fixable, manual = ui.sort_findings(result.findings)
    if not result.findings:
        screen.say()
        return 0

    if dry_run:
        screen.say()
        screen.say(screen.dim("  Dry run: nothing was changed."))
        return 1
    if not fixable:
        ui.show_summary(screen, len(result.findings), [], [], 0, manual)
        return 1

    # 4: the choice.
    if assume_yes:
        chosen = fixable
    elif not sys.stdin.isatty() and ask is input:
        # Never wait for an answer when no person is at the keyboard (an AI
        # agent ran the command, say). Hanging forever would be worse.
        screen.say()
        screen.say(screen.dim("  No one is here to answer. Run again with --yes to fix everything."))
        return 1
    else:
        how = ui.ask_how(screen, ask, len(fixable))
        if how == "all":
            chosen = fixable
        elif how == "one":
            chosen = ui.ask_each(screen, ask, fixable, result.root)
        else:
            chosen = []

    if not chosen:
        screen.say()
        screen.say(screen.dim("  OK, nothing was changed."))
        screen.say()
        return 1

    # Safety: if secrets are moving into .env, the .gitignore fix MUST go in
    # too. Otherwise .env could be uploaded, which is worse than before.
    moves_secrets = any(append.path.name.startswith(".env") for f in chosen for append in f.fix.appends)
    protection = [f for f in fixable if f.rule_id.startswith("GIT") and f not in chosen]
    if moves_secrets and protection:
        chosen += protection
        screen.say()
        screen.say(screen.amber("  ⚠ ") + "I'm also adding .env to the \"never upload\" list, so the secrets "
                   "I move there stay private.")

    # 5: apply the chosen fixes, then the summary.
    ui.show_applying(screen, len(chosen))
    outcome = engine.apply_fixes(chosen)
    skipped = len(fixable) - len(chosen)
    ui.show_summary(screen, len(result.findings), outcome.applied, outcome.rejected, skipped, manual)

    problems_left = manual or outcome.rejected or skipped
    return 1 if problems_left else 0
