"""
ui.py: everything you see on screen.

The goal is a screen that feels like a cockpit: things light up, bars fill,
counters tick up, and every problem is explained in plain words (those
words live in explain.py).

WHAT THE USER SEES, IN ORDER
    1. Start-up   the title types itself out, then the scanners power up
    2. Scanning   a progress bar fills as each file is checked
    3. Report     a counter ticks up to the number of problems, then one
                  "card" per problem says what's wrong and how it'll be fixed
    4. Choice     fix everything, choose one by one, or change nothing
    5. Fixing     a random fantasy scene plays (the scenes live in scenes.py)
    6. Summary    a safety bar fills up to show how much got fixed

HOW THE ANIMATIONS WORK
    A terminal can't move pictures, but it CAN go back to the start of the
    current line ("\\r") and draw over it. Redrawing one line many times a
    second, with a spinner or a growing bar, looks like movement.

    Colours and line-clearing use "ANSI escape codes": invisible character
    sequences that tell the terminal what to do. \\x1b[38;2;R;G;Bm sets a
    colour, \\x1b[2K clears the line and \\x1b[0m resets everything.

    Animations only run when a person is watching. When the output goes to
    a file, the tests or an AI agent, everything prints instantly and plainly.
"""

from __future__ import annotations

import os
import shutil
import sys
import textwrap  # wraps long sentences onto several lines
import time
from collections.abc import Callable
from pathlib import Path

from decaloguex import __version__, scenes
from decaloguex.explain import explain
from decaloguex.models import Finding, Severity

# The colours (red, green, blue), each from 0 to 255.
CYAN = (0x00, 0xF0, 0xFF)    # the cockpit: titles, scanning
MINT = (0x00, 0xE6, 0x76)    # good news: fixes
CORAL = (0xFF, 0x52, 0x52)   # serious problems
AMBER = (0xFF, 0xC1, 0x07)   # warnings, and things you need to do yourself

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"       # drawn one after another, these seem to spin
SCANNERS = ["code reader", "secret detector", "database guard", "error shield", "crash catcher"]

# How long each animation takes, in seconds. Lower them to make everything snappier.
TYPING_SECONDS_PER_LETTER = 0.012
BOOT_SECONDS = 0.8
SCAN_SECONDS = 0.7      # the minimum: a scan of 2 files would otherwise flash past
COUNT_UP_SECONDS = 0.5
CARD_PAUSE_SECONDS = 0.06
APPLY_SECONDS = 0.7
SAFETY_BAR_SECONDS = 0.7

Ask = Callable[[str], str]  # a function that shows a question and returns the answer


# ===========================================================================
# THE SCREEN
# ===========================================================================

class Screen:
    """Draws on the terminal: colours, animations and questions.

    `color` and `animate` switch the fancy parts on or off, so the same
    code also prints plain text for the tests and AI agents.
    """

    def __init__(self, color: bool, animate: bool):
        self.color = color
        self.animate = animate
        # Fit the terminal, but never wider than 80 columns (easier to read).
        self.width = min(shutil.get_terminal_size((80, 24)).columns, 80)

    # --- colours -------------------------------------------------------------

    def paint(self, text: str, rgb: tuple[int, int, int], bold: bool = False) -> str:
        if not self.color:
            return text
        red, green, blue = rgb
        weight = "\x1b[1m" if bold else ""
        return f"{weight}\x1b[38;2;{red};{green};{blue}m{text}\x1b[0m"

    def cyan(self, text: str, bold: bool = False) -> str:
        return self.paint(text, CYAN, bold)

    def mint(self, text: str, bold: bool = False) -> str:
        return self.paint(text, MINT, bold)

    def coral(self, text: str, bold: bool = False) -> str:
        return self.paint(text, CORAL, bold)

    def amber(self, text: str, bold: bool = False) -> str:
        return self.paint(text, AMBER, bold)

    def bold(self, text: str) -> str:
        return f"\x1b[1m{text}\x1b[0m" if self.color else text

    def dim(self, text: str) -> str:
        return f"\x1b[2m{text}\x1b[0m" if self.color else text

    # --- writing -------------------------------------------------------------

    def say(self, text: str = "") -> None:
        """Print a normal line."""
        print(text)

    def redraw(self, text: str) -> None:
        """Draw over the current line. This is what makes things move.

        \\r jumps back to the start of the line and \\x1b[2K wipes it, so the
        new text replaces the old. Without animation this does nothing,
        and only the final line (from `settle`) is printed.
        """
        if self.animate:
            sys.stdout.write("\r\x1b[2K" + text)
            sys.stdout.flush()  # show it NOW, don't wait for the end of the line

    def settle(self, text: str) -> None:
        """Replace the moving line with its final text and move on."""
        if self.animate:
            sys.stdout.write("\r\x1b[2K")
        print(text)

    def pause(self, seconds: float) -> None:
        if self.animate:
            time.sleep(seconds)

    def type_out(self, text: str, rgb: tuple[int, int, int]) -> None:
        """Print text one letter at a time, like someone typing it."""
        if not self.animate:
            self.say(self.paint(text, rgb, bold=True))
            return
        if self.color:
            sys.stdout.write(f"\x1b[1m\x1b[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m")
        for letter in text:
            sys.stdout.write(letter)
            sys.stdout.flush()
            time.sleep(TYPING_SECONDS_PER_LETTER)
        sys.stdout.write("\x1b[0m\n" if self.color else "\n")

    def cursor(self, visible: bool) -> None:
        """Hide the blinking cursor during animations, so it doesn't flicker."""
        if self.animate:
            sys.stdout.write("\x1b[?25h" if visible else "\x1b[?25l")
            sys.stdout.flush()

    def ask(self, ask: Ask, question: str) -> str:
        """Ask a question and return the answer, tidied up."""
        self.cursor(True)  # the person needs to see where they're typing
        return ask(question).strip().lower()

    # --- drawing helpers -----------------------------------------------------

    def bar(self, fraction: float, width: int, paint: Callable[[str], str]) -> str:
        """A progress bar like ██████░░░░, `fraction` full (0.0 to 1.0)."""
        filled = round(max(0.0, min(1.0, fraction)) * width)
        return paint("█" * filled) + self.dim("░" * (width - filled))

    def wrap(self, text: str, indent: int) -> list[str]:
        """Split a long sentence into lines that fit the screen."""
        return textwrap.wrap(text, width=max(30, self.width - indent))


def setup_screen(no_color: bool = False, no_animation: bool = False) -> Screen:
    """Prepare the terminal, and decide whether to use colours and animations."""
    # Windows terminals often start in an old character set that can't show
    # the bars, boxes and icons. Switching to UTF-8 fixes that.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass  # stdout was replaced (by pytest, for example); leave it alone

    # Fancy output only when a person is watching (isatty) and nobody opted out.
    # NO_COLOR is a convention many tools follow: https://no-color.org
    watching = sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
    color = watching and not no_color and "NO_COLOR" not in os.environ
    animate = watching and not no_animation
    if (color or animate) and os.name == "nt":  # "nt" means Windows
        _enable_windows_ansi()
    return Screen(color, animate)


def _enable_windows_ansi() -> None:
    """Turn on colour and line-redrawing in older Windows consoles.

    ctypes calls Windows' own functions directly (Java would need JNI).
    0x0004 is the setting called ENABLE_VIRTUAL_TERMINAL_PROCESSING.
    """
    try:
        import ctypes  # imported here because only Windows needs it

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # -11 means "the normal output"
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass  # worst case: no colours. Never a crash.


# ===========================================================================
# 1. START-UP
# ===========================================================================

def show_start(screen: Screen) -> None:
    """The title, then the scanners powering up one by one."""
    screen.cursor(False)
    screen.say()
    screen.type_out("  ◆ DECALOGUEX  ·  CRASH DOCTOR", CYAN)
    screen.say(screen.dim(f"    v{__version__}  ·  finds and fixes the mistakes AI coding tools leave behind"))
    screen.say()

    # One line that keeps changing: a spinner, and the scanner being started.
    frames_each = 4
    frame_seconds = BOOT_SECONDS / (len(SCANNERS) * frames_each)
    for number, name in enumerate(SCANNERS):
        for frame in range(frames_each):
            spin = SPINNER[(number * frames_each + frame) % len(SPINNER)]
            lights = screen.mint("●" * number) + screen.dim("○" * (len(SCANNERS) - number))
            screen.redraw(f"  {screen.cyan(spin)} Powering up the {name}…  {lights}")
            screen.pause(frame_seconds)
    screen.settle(f"  {screen.mint('✔')} All {len(SCANNERS)} scanners ready  {screen.mint('●' * len(SCANNERS))}")


# ===========================================================================
# 2. SCANNING
# ===========================================================================

class ScanProgress:
    """The progress bar that fills while files are checked.

    The engine calls update() after each file (see engine.scan's
    on_progress). A tiny pause per file makes sure even a 2-file scan
    shows the bar for a moment instead of flashing past.
    """

    def __init__(self, screen: Screen):
        self.screen = screen
        self.frame = 0

    def update(self, done: int, total: int, path: Path) -> None:
        screen = self.screen
        if not screen.animate:
            return
        self.frame += 1
        spin = screen.cyan(SPINNER[self.frame % len(SPINNER)])
        bar = screen.bar(done / total, 24, screen.cyan)
        name = path.name if len(path.name) <= 26 else path.name[:25] + "…"
        screen.redraw(f"  {spin} Scanning  {bar}  {done}/{total}  {screen.dim(name)}")
        screen.pause(SCAN_SECONDS / total)

    def finish(self, files_checked: int, seconds: float) -> None:
        plural = "" if files_checked == 1 else "s"
        self.screen.settle(f"  {self.screen.mint('✔')} Checked {files_checked} file{plural} "
                           f"in {seconds:.2f} seconds")


# ===========================================================================
# 3. THE REPORT
# ===========================================================================

def sort_findings(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (ones we can fix, ones that need a person),
    with the serious ones first in each list."""
    # sorted() keeps the original order for ties, so files stay grouped.
    by_severity = sorted(findings, key=lambda f: f.severity is not Severity.CRITICAL)
    fixable = [f for f in by_severity if f.fix]
    manual = [f for f in by_severity if not f.fix]
    return fixable, manual


def show_report(screen: Screen, findings: list[Finding], root: Path) -> None:
    """Count up the problems, show the dashboard, then one card per problem."""
    screen.say()
    if not findings:
        screen.say(screen.mint("  ✔ All clear! I didn't find anything to fix.", bold=True))
        screen.say(screen.dim("    Your code has none of the mistakes I look for."))
        return

    # The counter ticks up from 1 to the number of problems.
    total = len(findings)
    for count in range(1, total + 1):
        screen.redraw(screen.coral(f"  ▲ Found {count} problem{'' if count == 1 else 's'}", bold=True))
        screen.pause(COUNT_UP_SECONDS / total)
    screen.settle(screen.coral(f"  ▲ Found {total} problem{'' if total == 1 else 's'}", bold=True))

    # The dashboard: four numbers at a glance.
    fixable, manual = sort_findings(findings)
    serious = sum(1 for f in findings if f.severity is Severity.CRITICAL)  # sum of 1s = a count
    dashboard = []
    if serious:
        dashboard.append(screen.coral("●") + f" {serious} serious")
    if total - serious:
        dashboard.append(screen.amber("●") + f" {total - serious} warning{'' if total - serious == 1 else 's'}")
    if fixable:
        dashboard.append(screen.mint("●") + f" {len(fixable)} I can fix")
    if manual:
        dashboard.append(screen.amber("✋") + f" {len(manual)} need{'s' if len(manual) == 1 else ''} you")
    screen.say("    " + "   ".join(dashboard))

    if fixable:
        show_section(screen, "I CAN FIX THESE")
        for number, finding in enumerate(fixable, start=1):
            show_card(screen, finding, root, f"{number}/{len(fixable)}")
    if manual:
        show_section(screen, "THESE NEED YOU")
        for finding in manual:
            show_card(screen, finding, root, "✋")


def show_section(screen: Screen, title: str) -> None:
    screen.say()
    line = "─" * max(0, screen.width - len(title) - 6)
    screen.say(screen.cyan(f"  ── {title} {line}", bold=True))


def show_card(screen: Screen, finding: Finding, root: Path, label: str) -> None:
    """One problem, explained simply.

        ╭─ 1/11 ─ SERIOUS ──────────────────────────
        │  🔑  Secret key left in your code
        │  This is a key to one of your online accounts...
        │  ➜ I'll lock it away in a private file...
        │
        │  server.js · line 5 · SEC-001
        │  "sk_live_••••ey00"  →  process.env.STRIPE_SECRET_KEY
        ╰───────────────────────────────────────────
    """
    info = explain(finding.rule_id)
    serious = finding.severity is Severity.CRITICAL
    paint = screen.coral if serious else screen.amber
    border = paint("│")
    tag = "SERIOUS" if serious else "WARNING"

    top = f"╭─ {label} ─ {tag} "
    lines = [paint(top + "─" * max(0, screen.width - len(top) - 4))]
    lines.append(f"{border}  {info.icon}  {screen.bold(info.headline)}")
    for text in screen.wrap(info.problem, indent=8):
        lines.append(f"{border}  {text}")

    if finding.fix:
        fix_lines = screen.wrap(info.fix, indent=10)
        lines.append(f"{border}  {screen.mint('➜')} {screen.mint(fix_lines[0])}")
        lines += [f"{border}    {screen.mint(text)}" for text in fix_lines[1:]]
    else:
        lines.append(f"{border}  {screen.amber('✋ What to do:')}")
        lines += [f"{border}    {text}" for text in screen.wrap(finding.note, indent=10)]

    # The technical details, dimmed, for anyone who wants them.
    lines.append(border)
    lines.append(f"{border}  {screen.dim(where(finding, root) + ' · ' + finding.rule_id)}")
    if finding.fix:
        room = max(10, (screen.width - 16) // 2)  # half the line each for "before" and "after"
        before = cut(finding.fix.preview_before, room)
        after = cut(finding.fix.preview_after, room)
        lines.append(f"{border}  {screen.dim(before)}  →  {screen.mint(after)}")
    lines.append(paint("╰" + "─" * max(0, screen.width - 5)))

    screen.say()
    for line in lines:
        screen.say("  " + line)
    screen.pause(CARD_PAUSE_SECONDS)  # cards appear one after another, not all at once


def cut(text: str, limit: int) -> str:
    """Shorten text to `limit` characters, ending with … if it was cut."""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def where(finding: Finding, root: Path) -> str:
    """"server.js · line 5", or just the file name for whole-file problems."""
    try:
        name = finding.path.relative_to(root).as_posix()
    except ValueError:
        name = finding.path.name
    return f"{name} · line {finding.line}" if finding.line else name


# ===========================================================================
# 4. THE CHOICE
# ===========================================================================

def ask_how(screen: Screen, ask: Ask, count: int) -> str:
    """Fix everything, choose one by one, or change nothing?

    Returns "all", "one" or "none". Just pressing Enter means "none", so a
    slip of the finger never changes your code.
    """
    screen.say()
    screen.say(screen.bold("  What would you like to do?"))
    screen.say(f"    {screen.mint('[A]', bold=True)} Fix all {count}     "
               f"{screen.cyan('[O]', bold=True)} Choose one by one     "
               f"{screen.dim('[N]')} Change nothing")
    for _ in range(3):  # three tries, then play it safe
        answer = screen.ask(ask, screen.cyan("  ➜ "))
        if answer in ("a", "all", "y", "yes"):
            return "all"
        if answer in ("o", "one", "1"):
            return "one"
        if answer in ("n", "no", "", "q"):
            return "none"
        screen.say(screen.dim("    Type A, O or N, then press Enter."))
    return "none"


def ask_each(screen: Screen, ask: Ask, fixable: list[Finding], root: Path) -> list[Finding]:
    """Go through the fixes one at a time and return the ones the user wants."""
    screen.say()
    screen.say(screen.dim("    y = fix it    n = skip it    a = fix this one and all the rest    q = skip the rest"))
    chosen = []
    for number, finding in enumerate(fixable, start=1):
        info = explain(finding.rule_id)
        screen.say()
        screen.say(f"  {screen.cyan(f'{number}/{len(fixable)}')}  {info.icon}  {screen.bold(info.headline)}  "
                   f"{screen.dim('(' + where(finding, root) + ')')}")
        answer = ""
        while answer not in ("y", "n", "a", "q"):
            answer = screen.ask(ask, screen.cyan("      Fix it? (y/n/a/q) ")) or "n"
            answer = {"yes": "y", "no": "n", "all": "a", "quit": "q"}.get(answer, answer)
            if answer not in ("y", "n", "a", "q"):
                screen.say(screen.dim("      Type y, n, a or q."))

        if answer == "y":
            chosen.append(finding)
            screen.say(screen.mint("      ✔ Will fix"))
        elif answer == "n":
            screen.say(screen.dim("      – Skipped"))
        elif answer == "a":
            chosen += fixable[number - 1:]  # this one and everything after it
            screen.say(screen.mint(f"      ✔ Will fix this and the {len(fixable) - number} after it"))
            break
        else:  # "q"
            screen.say(screen.dim("      – Skipping the rest"))
            break
    return chosen


# ===========================================================================
# 5. APPLYING AND THE SUMMARY
# ===========================================================================

def show_applying(screen: Screen, count: int) -> None:
    """A fantasy scene plays while the fixes go in (or a simple bar, if the
    terminal is too narrow for the scene)."""
    screen.cursor(False)
    screen.say()
    if play_scene(screen, scenes.random_scene()):
        return
    steps = 20
    for step in range(steps + 1):
        spin = screen.mint(SPINNER[step % len(SPINNER)])
        screen.redraw(f"  {spin} Applying {count} fix{'' if count == 1 else 'es'}  "
                      f"{screen.bar(step / steps, 24, screen.mint)}")
        screen.pause(APPLY_SECONDS / steps)


def play_scene(screen: Screen, scene: scenes.Scene) -> bool:
    """Play a fantasy scene (see scenes.py). Returns False if it can't be shown.

    A scene is several lines tall, so redrawing one line isn't enough. After
    drawing a frame, \\x1b[<n>A moves the cursor UP n lines, back to the top
    of the picture, and the next frame is drawn over the old one.
    """
    if not screen.animate or screen.width < scenes.WIDTH + 4:
        return False
    height = scenes.HEIGHT + 1  # the picture plus the message line
    for number, frame in enumerate(scene.frames):
        if number > 0:
            sys.stdout.write(f"\x1b[{height}A")  # back up to the top of the picture
        lines = [paint_scene_line(screen, scene, line, frame.glowing) for line in frame.lines]
        lines.append(screen.mint(frame.message.center(scenes.WIDTH).rstrip(), bold=True))
        for line in lines:
            sys.stdout.write("\r\x1b[2K  " + line + "\n")
        sys.stdout.flush()
        time.sleep(frame.seconds)
    return True


def paint_scene_line(screen: Screen, scene: scenes.Scene, line: str, glowing: bool) -> str:
    """Colour each character of a scene line using the scene's palette."""
    colours = {"cyan": screen.cyan, "mint": screen.mint, "coral": screen.coral, "amber": screen.amber}
    painted = []
    for letter in line:
        if glowing and letter in scene.hero:
            painted.append(screen.mint(letter, bold=True))  # the hero shines green at the end
        elif letter in scene.palette:
            painted.append(colours[scene.palette[letter]](letter))
        else:
            painted.append(letter)
    return "".join(painted)


def show_summary(screen: Screen, total: int, applied: list[Finding], rejected: list[Finding],
                 skipped: int, manual: list[Finding]) -> None:
    """The final dashboard: what got fixed, and what's left to do."""
    fixed = len(applied)
    if applied or rejected:
        screen.settle(f"  {screen.mint('✔')} Applied {fixed} fix{'' if fixed == 1 else 'es'}")

    # The safety bar fills from empty up to the share of problems fixed.
    screen.say()
    share = fixed / total if total else 1.0
    steps = 24
    for step in range(steps + 1):
        screen.redraw(f"  SAFETY  {screen.bar(share * step / steps, 30, screen.mint)}  {fixed} of {total} fixed")
        screen.pause(SAFETY_BAR_SECONDS / steps)
    screen.settle(f"  {screen.bold('SAFETY')}  {screen.bar(share, 30, screen.mint)}  {fixed} of {total} fixed")

    counts = [screen.mint("✔") + f" {fixed} fixed"]
    if manual:
        counts.append(screen.amber("✋") + f" {len(manual)} need{'s' if len(manual) == 1 else ''} you")
    if skipped:
        counts.append(screen.dim("–") + f" {skipped} skipped")
    if rejected:
        counts.append(screen.coral("✖") + f" {len(rejected)} couldn't be applied")
    screen.say("    " + "   ".join(counts))

    for finding in rejected:
        screen.say(screen.coral(f"    ✖ {explain(finding.rule_id).headline}: the change would have broken the "
                                "file, so I left it alone. Run the scan again to retry."))
    if any(f.rule_id.startswith("SEC") for f in applied):
        screen.say()
        advice = ("One more thing: if any of those keys were ever put online, cancel them on the "
                  "company's website and make new ones.")
        for number, text in enumerate(screen.wrap(advice, indent=6)):
            screen.say(("  " + screen.amber("⚠ ") if number == 0 else "    ") + text)

    screen.say()
    if fixed == total:
        screen.say(screen.mint("  ✔ All done. Your code is in great shape!", bold=True))
    elif manual:
        screen.say(screen.bold("  Next step: ") + "do the jobs marked ✋ above, then scan again.")
    else:
        screen.say(screen.dim("  Run the scan again any time to fix the rest."))
    screen.say()
    screen.cursor(True)
