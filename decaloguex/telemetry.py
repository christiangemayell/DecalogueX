"""
telemetry.py: anonymous usage stats, so you can see how DecalogueX is used.

WHAT IS SENT (after each scan)
    * DecalogueX version, operating system, Python version
    * how many files of each language were checked
    * how many problems each rule found (e.g. "SQL-001: 2")
    * what the user chose (fix all / one by one / nothing), and which
      rules' fixes were accepted, skipped, or failed the safety check
    * blind spots: unsupported languages, which rules tripped (the error
      TYPE only), how many files were too big
    * roughly how long the scan took ("1-5s")
    * a random ID for this computer, so users can be counted without
      knowing who they are

WHAT IS NEVER SENT
    Code, file names, folder names, project names, secrets, error messages,
    or anything that could identify a person.

THE RULES IT FOLLOWS
    * A short notice is shown ONCE, the first time DecalogueX runs.
    * Nothing at all is sent until that notice has been shown, so the very
      first run only tells people about the stats; it doesn't send any.
    * Anyone can switch it off:  decaloguex telemetry off
    * It's also off when the DO_NOT_TRACK setting is on (a standard many
      developers use), or DECALOGUEX_TELEMETRY=off.
    * It never slows anything down: sending happens in the background, and
      if it fails (no internet, say) nothing happens.

WHERE THE DATA GOES
    PostHog (posthog.com), on its free plan. Put your project's API key in
    POSTHOG_API_KEY below. Until then, nothing is sent at all.
    In PostHog's project settings, turn on "Discard client IP data" so
    visitors' IP addresses aren't stored either.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import threading
import urllib.request  # Python's built-in way to send web requests (Java: HttpClient)
import uuid
from collections import Counter
from pathlib import Path

from decaloguex import __version__

# Paste your PostHog "Project API key" here (it starts with phc_). It's safe
# to publish: it can only SEND stats, never read them.
POSTHOG_API_KEY = ""
POSTHOG_URL = "https://us.i.posthog.com/i/v0/e/"  # use eu.i.posthog.com for an EU project

NOTICE = ("DecalogueX sends anonymous usage stats (never your code) to help improve it.\n"
          "Turn off any time: decaloguex telemetry off")

_pending: list[threading.Thread] = []  # stats still being sent in the background


# ===========================================================================
# SETTINGS (stored in your home folder, not in the project)
# ===========================================================================

def settings_file() -> Path:
    """~/.decaloguex/config.json, or wherever DECALOGUEX_HOME points (the tests use that)."""
    home = os.environ.get("DECALOGUEX_HOME")
    folder = Path(home) if home else Path.home() / ".decaloguex"
    return folder / "config.json"


def load() -> dict:
    try:
        return json.loads(settings_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save(settings: dict) -> None:
    try:
        path = settings_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    except OSError:
        pass  # can't save settings: not worth crashing over


def set_enabled(enabled: bool) -> None:
    settings = load()
    settings["telemetry"] = enabled
    settings["notice_shown"] = True  # they clearly know about it now
    save(settings)


def is_enabled() -> bool:
    """Should stats be sent? Every way of saying "no" wins."""
    if os.environ.get("DO_NOT_TRACK", "").lower() in ("1", "true", "yes"):
        return False
    if os.environ.get("DECALOGUEX_TELEMETRY", "").lower() in ("0", "off", "false", "no"):
        return False
    return load().get("telemetry", True) is not False


def api_key() -> str:
    return os.environ.get("DECALOGUEX_POSTHOG_KEY", POSTHOG_API_KEY)


def will_send() -> bool:
    return is_enabled() and bool(api_key())


def has_been_told() -> bool:
    """Has this user already seen the notice about usage stats?"""
    return bool(load().get("notice_shown"))


def take_notice() -> str | None:
    """The one-time notice, the first time it's needed. None every time after."""
    if not is_enabled():
        return None
    settings = load()
    if settings.get("notice_shown"):
        return None
    settings["notice_shown"] = True
    save(settings)
    return NOTICE


def install_id() -> str:
    """A random ID for this computer, made once. It says nothing about who you are."""
    settings = load()
    if "install_id" not in settings:
        settings["install_id"] = str(uuid.uuid4())  # e.g. "3f2c9a1e-..."
        save(settings)
    return settings["install_id"]


# ===========================================================================
# BUILDING THE STATS
# ===========================================================================

def scan_stats(result, choice: str, chosen=(), applied=(), rejected=()) -> dict:
    """The anonymous stats for one scan.

    `result` is the engine's ScanResult. `choice` is what the user picked:
    "all", "one", "none", "yes" (--yes), "dry_run" or "json".
    Only rule IDs, counts and language names go in. Never paths or code.
    """
    findings = result.findings
    fixable = [f for f in findings if f.fix]
    chosen_ids = {id(f) for f in chosen}  # id() gives each object's unique number
    declined = [f for f in fixable if id(f) not in chosen_ids] if choice in ("all", "one", "none", "yes") else []
    spots = result.blind_spots
    return {
        "files_total": result.files_checked,
        "files_by_language": dict(result.languages),
        "findings_by_rule": count_rules(findings),
        "choice": choice,
        "fixes_applied_by_rule": count_rules(applied),
        "fixes_declined_by_rule": count_rules(declined),
        "fixes_failed_safety_by_rule": count_rules(rejected),
        "manual_by_rule": dict(spots.manual),
        "blind_unsupported_languages": dict(spots.unsupported),
        "blind_tripped": dict(Counter(f"{t['rule']}:{t['error']}" for t in spots.tripped)),
        "blind_too_big": len(spots.too_big),
        "duration": duration_bucket(result.seconds),
    }


def count_rules(findings) -> dict:
    return dict(Counter(f.rule_id for f in findings))


def duration_bucket(seconds: float) -> str:
    """A rough range instead of the exact time: less detail, same insight."""
    for limit, label in ((1, "<1s"), (5, "1-5s"), (30, "5-30s"), (120, "30s-2m")):
        if seconds < limit:
            return label
    return ">2m"


# ===========================================================================
# SENDING
# ===========================================================================

def send(event: str, properties: dict) -> None:
    """Send stats in the background. Does nothing if telemetry is off or not set up."""
    if not will_send() or not has_been_told():
        return  # (people must be TOLD about the stats before any are sent)
    payload = {
        "api_key": api_key(),
        "event": event,
        "distinct_id": install_id(),
        "properties": {
            **properties,  # ** copies every key from `properties` into this dict
            "version": __version__,
            "os": platform.system(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            "ci": bool(os.environ.get("CI")),
            "$process_person_profile": False,  # tells PostHog: don't build a profile of anyone
            "$geoip_disable": True,            # ...and don't look up a location from the IP address
        },
    }
    thread = threading.Thread(target=_post, args=(payload,), daemon=True)
    thread.start()
    _pending.append(thread)


def _post(payload: dict) -> None:
    try:
        request = urllib.request.Request(
            POSTHOG_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": f"decaloguex/{__version__}"},
        )
        urllib.request.urlopen(request, timeout=3).close()
    except Exception:
        pass  # no internet, PostHog down, anything: the user should never notice


def finish(max_seconds: float = 1.5) -> None:
    """Give background sends a moment to finish before the program exits."""
    for thread in _pending:
        thread.join(timeout=max_seconds)
    _pending.clear()
