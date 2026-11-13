"""
cli.py: the `decaloguex` command.

Usage:
  decaloguex scan [path]                 scan, explain, then ask what to do
  decaloguex scan [path] --yes           fix everything without asking
  decaloguex scan [path] --dry-run       only show problems; never change anything
  decaloguex scan [path] --json          a report for AI tools (add --yes to also fix)
  decaloguex scan [path] --no-animation  no moving bars or spinners
  decaloguex scan [path] --no-color      plain text, no colours
  decaloguex undo [path]                 put back everything the last fix changed
  decaloguex telemetry [on|off|status]   control the anonymous usage stats

Exit codes (what scripts and AI agents check):
  0    nothing left to fix
  1    problems remain (skipped, dry run, or needing a manual step)
  2    bad arguments, or the path doesn't exist
  130  stopped with Ctrl+C (the usual code for that)
"""

from __future__ import annotations

import argparse  # reads the command-line options, like picocli in Java
import json
import sys
from pathlib import Path

from decaloguex import EARLY_ACCESS_NOTICE, __version__, blindspots, engine, project, telemetry, ui, undo
from decaloguex.explain import explain


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
    scan_cmd.add_argument("--json", action="store_true", help="print a JSON report for AI tools")
    scan_cmd.add_argument("--no-animation", action="store_true", help="no moving bars or spinners")
    scan_cmd.add_argument("--no-color", action="store_true", help="plain text, no colours")

    undo_cmd = commands.add_parser("undo", help="put back everything the last fix changed")
    undo_cmd.add_argument("path", nargs="?", default=".", help="the project folder (default: this folder)")
    undo_cmd.add_argument("-y", "--yes", action="store_true", help="don't ask, even if files changed since")
    undo_cmd.add_argument("--no-color", action="store_true", help="plain text, no colours")

    telemetry_cmd = commands.add_parser("telemetry", help="control the anonymous usage stats")
    telemetry_cmd.add_argument("setting", nargs="?", choices=["on", "off", "status"], default="status")

    args = parser.parse_args(argv)
    try:
        if args.command == "undo":
            return run_undo(Path(args.path), assume_yes=args.yes, no_color=args.no_color)
        if args.command == "telemetry":
            return run_telemetry(args.setting)
        if args.json:
            return run_json(Path(args.path), assume_yes=args.yes)
        # argparse turns "--dry-run" into the attribute name dry_run.
        return run_scan(Path(args.path), assume_yes=args.yes, dry_run=args.dry_run,
                        no_color=args.no_color, no_animation=args.no_animation)
    finally:
        telemetry.finish()  # let any usage stats finish sending (at most 1.5 seconds)


# ===========================================================================
# SCAN (the normal, human mode)
# ===========================================================================

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
    if not dry_run:
        blindspots.save(result.root, result.blind_spots)

    # 3: the report, one card per problem, then the blind spots.
    ui.show_report(screen, result.findings, result.root)
    ui.show_blind_spots(screen, result.blind_spots)
    fixable, manual = ui.sort_findings(result.findings)

    if not result.findings or dry_run or not fixable:
        if dry_run:
            screen.say()
            screen.say(screen.dim("  Dry run: nothing was changed."))
        elif fixable == [] and manual:
            ui.show_summary(screen, len(result.findings), [], [], 0, manual)
        if not result.findings:
            # Clean code: the big finish.
            ui.show_stamp(screen, result.files_checked, result.blind_spots.files_not_checked())
        else:
            screen.say()
        finish_scan(screen, result, "dry_run" if dry_run else "none")
        return 1 if result.findings else 0

    # 4: the choice.
    if assume_yes:
        chosen, choice = fixable, "yes"
    elif not sys.stdin.isatty() and ask is input:
        # Never wait for an answer when no person is at the keyboard (an AI
        # agent ran the command, say). Hanging forever would be worse.
        screen.say()
        screen.say(screen.dim("  No one is here to answer. Run again with --yes to fix everything."))
        finish_scan(screen, result, "none")
        return 1
    else:
        choice = ui.ask_how(screen, ask, len(fixable))
        if choice == "all":
            chosen = fixable
        elif choice == "one":
            chosen, reported_wrong = ui.ask_each(screen, ask, fixable, result.root)
            if reported_wrong:
                # Save the "this looks wrong" reports with the other blind spots.
                result.blind_spots.reported_wrong += reported_wrong
                blindspots.save(result.root, result.blind_spots)
        else:
            chosen = []

    if not chosen:
        screen.say()
        screen.say(screen.dim("  OK, nothing was changed."))
        screen.say()
        finish_scan(screen, result, choice)
        return 1

    chosen = add_required_protection(screen, chosen, fixable)

    # 5: apply the chosen fixes, then the summary.
    ui.show_applying(screen, len(chosen))
    outcome = engine.apply_fixes(chosen, result.root, result.fingerprints)
    skipped = len(fixable) - len(chosen)
    ui.show_summary(screen, len(result.findings), outcome.applied, outcome.rejected, skipped, manual)
    if len(outcome.applied) == len(result.findings):
        # Everything found was fixed: the big finish.
        ui.show_stamp(screen, result.files_checked, result.blind_spots.files_not_checked())
    finish_scan(screen, result, choice, chosen, outcome.applied, outcome.rejected)

    problems_left = manual or outcome.rejected or skipped
    return 1 if problems_left else 0


def add_required_protection(screen: ui.Screen, chosen: list, fixable: list) -> list:
    """If secrets are moving into .env, the .gitignore fix MUST go in too.

    Otherwise .env could be uploaded, which is worse than before.
    """
    moves_secrets = any(append.path.name.startswith(".env") for f in chosen for append in f.fix.appends)
    protection = [f for f in fixable if f.rule_id.startswith("GIT") and f not in chosen]
    if moves_secrets and protection:
        screen.say()
        screen.say(screen.amber("  ⚠ ") + "I'm also adding .env to the \"never upload\" list, so the secrets "
                   "I move there stay private.")
        return chosen + protection
    return chosen


def finish_scan(screen: ui.Screen, result, choice: str, chosen=(), applied=(), rejected=()) -> None:
    """The last steps of every scan: send the usage stats, show the one-time
    stats notice, and end with the early-access line."""
    telemetry.send("scan_completed", telemetry.scan_stats(result, choice, chosen, applied, rejected),
                   root=result.root)
    notice = telemetry.take_notice()
    if notice:
        ui.show_notice(screen, notice)
    ui.show_early_access(screen)


# ===========================================================================
# SCAN --json (for AI tools)
# ===========================================================================

def run_json(target: Path, assume_yes: bool = False) -> int:
    """Print one JSON report. No animations and no questions.

    Without --yes nothing is changed. With --yes every fix is applied, and
    the report says which ones worked.
    """
    if not target.exists():
        print(json.dumps({"error": f"path not found: {target}"}))
        return 2
    result = engine.scan(target)
    blindspots.save(result.root, result.blind_spots)

    fixable = [f for f in result.findings if f.fix]
    applied, rejected = [], []
    if assume_yes and fixable:
        outcome = engine.apply_fixes(fixable, result.root, result.fingerprints)
        applied, rejected = outcome.applied, outcome.rejected

    report = {
        "tool": "decaloguex",
        "version": __version__,
        "root": str(result.root),
        "files_checked": result.files_checked,
        "languages": dict(result.languages),
        "seconds": round(result.seconds, 3),
        "findings": [finding_json(f, result.root, applied, rejected) for f in result.findings],
        "blind_spots": result.blind_spots.to_dict(),
        "fixes_applied": len(applied),
        "undo": "decaloguex undo" if applied else None,
        # AI tools are asked (in SKILL.md) to pass this on to the user once.
        "notice": EARLY_ACCESS_NOTICE,
    }
    # ensure_ascii=True writes characters like "…" as …, so the report
    # is plain ASCII. Otherwise, on Windows, a report saved to a file came out
    # in the old cp1252 encoding, which other programs (and AI tools) can't read.
    print(json.dumps(report, indent=2, ensure_ascii=True))

    telemetry.send("scan_completed", telemetry.scan_stats(result, "yes" if assume_yes else "json",
                                                          fixable if assume_yes else (), applied, rejected),
                   root=result.root)
    notice = telemetry.take_notice()
    if notice:
        print(notice, file=sys.stderr)  # stderr, so it never breaks the JSON on stdout

    remaining = len(result.findings) - len(applied)
    return 1 if remaining else 0


def finding_json(finding, root: Path, applied: list, rejected: list) -> dict:
    """One finding as plain data, for AI tools to read."""
    info = explain(finding.rule_id)
    if any(f is finding for f in applied):
        status = "fixed"
    elif any(f is finding for f in rejected):
        status = "fix_failed_safety_check"
    elif finding.fix:
        status = "fixable"
    else:
        status = "manual"
    return {
        "rule": finding.rule_id,
        "severity": finding.severity.value,
        "title": finding.title,
        "file": engine.relative(root, finding.path),
        "line": finding.line,
        "explanation": info.problem,
        "status": status,
        "fix": {"before": finding.fix.preview_before, "after": finding.fix.preview_after} if finding.fix else None,
        "manual_step": finding.note or None,
    }


# ===========================================================================
# UNDO
# ===========================================================================

def run_undo(target: Path, assume_yes: bool = False, no_color: bool = False, ask: ui.Ask = input) -> int:
    """Put back every file the last round of fixes changed."""
    screen = ui.setup_screen(no_color, no_animation=False)
    root = project.find_root(target.resolve())
    plan = undo.latest(root)
    if plan is None:
        screen.say(screen.dim("  Nothing to undo: no fixes have been applied in this project yet."))
        return 1

    if plan.edited_since and not assume_yes:
        ui.show_undo_warning(screen, plan.edited_since)
        if not sys.stdin.isatty() and ask is input:
            screen.say(screen.dim("  No one is here to answer. Run again with --yes to undo anyway."))
            return 1
        if screen.ask(ask, screen.cyan("  Undo anyway? (y/n) ")) not in ("y", "yes"):
            screen.say(screen.dim("  OK, nothing was changed."))
            return 1

    restored = undo.restore(plan)
    ui.show_undo_done(screen, restored, plan.created)
    telemetry.send("undo_used", {"files_restored": len(restored)}, root=root)
    return 0


# ===========================================================================
# TELEMETRY SETTINGS
# ===========================================================================

def run_telemetry(setting: str) -> int:
    screen = ui.setup_screen()
    if setting in ("on", "off"):
        telemetry.set_enabled(setting == "on")
    ui.show_telemetry_status(screen, telemetry.is_enabled(), telemetry.will_send(),
                             log=telemetry.log_file(), in_ci=telemetry.running_in_ci())
    return 0
