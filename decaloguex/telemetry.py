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
    * findings the user marked as wrong with the "w" key, as counts by
      rule and reason (e.g. "SQL-001:false_alarm: 1")
    * a random ID for this computer, so users can be counted without
      knowing who they are
    * a random ID for the PROJECT, stored in its .decaloguex folder, so
      "weekly active projects" can be counted: how many different
      projects were scanned each week (installs alone can't show that)

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
    * It's off on automated test servers ("CI", such as GitHub Actions):
      those runs aren't real people, and would inflate the numbers.
    * Everything sent is also written to a log file on the user's own
      computer (~/.decaloguex/telemetry.log), so anyone can check for
      themselves exactly what left their machine.
    * It never slows anything down: sending happens in the background, and
      if it fails (no internet, say) nothing happens.

WHERE THE DATA GOES
    PostHog (posthog.com), on its free plan, stored in the EU. The project's
    key is in POSTHOG_API_KEY below. "Discard client IP data" is turned on
    in PostHog's project settings, so IP addresses aren't stored either.
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
from datetime import datetime
from pathlib import Path

from decaloguex import __version__

# Paste your PostHog "Project API key" here (it starts with phc_). It's safe
# to publish: it can only SEND stats, never read them.
POSTHOG_API_KEY = "phc_pFK8eYDjaBNHhanQNBYdKVd7uqJLLmkYCPANYf8FNMGt"
POSTHOG_URL = "https://eu.i.posthog.com/i/v0/e/"  # the project is on PostHog's EU Cloud

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


# Settings that automated test servers ("CI") set. If any is present, no
# person is watching, so the run shouldn't count as real use.
CI_SETTINGS = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "TRAVIS", "BUILDKITE",
               "JENKINS_URL", "TF_BUILD", "BITBUCKET_BUILD_NUMBER", "TEAMCITY_VERSION")


def running_in_ci() -> bool:
    for name in CI_SETTINGS:
        value = os.environ.get(name, "")
        if value and value.lower() not in ("0", "false", "no"):
            return True
    return False


def is_enabled() -> bool:
    """Should stats be sent? Every way of saying "no" wins."""
    if os.environ.get("DO_NOT_TRACK", "").lower() in ("1", "true", "yes"):
        return False
    if os.environ.get("DECALOGUEX_TELEMETRY", "").lower() in ("0", "off", "false", "no"):
        return False
    if running_in_ci():
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


def log_file() -> Path:
    """The local copy of everything sent: ~/.decaloguex/telemetry.log"""
    return settings_file().parent / "telemetry.log"


def project_id(root: Path) -> str | None:
    """A random ID for this project, made the first time it's needed.

    It's kept in the project's own .decaloguex folder (which is never
    uploaded to Git). Being random, it says nothing about the project:
    not its name, its files, or who owns it. It only lets the stats tell
    "the same project scanned again" apart from "a new project".
    """
    from decaloguex.blindspots import private_folder  # imported here to avoid a circular import

    folder = private_folder(root)
    if folder is None:
        return None
    path = folder / "project-id"
    try:
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    except OSError:
        pass
    new_id = str(uuid.uuid4())
    try:
        path.write_text(new_id + "\n", encoding="utf-8")
    except OSError:
        return None
    return new_id


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
        "blind_generated": len(spots.generated),
        "test_files": spots.test_files,
        # "w" key reports, as rule:reason counts. Never the file or line.
        "reported_wrong": dict(Counter(f"{r['rule']}:{r['reason']}" for r in spots.reported_wrong)),
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

def send(event: str, properties: dict, root: Path | None = None) -> None:
    """Send stats in the background. Does nothing if telemetry is off or not set up.

    `root` is the project folder. When it's given, the project's random ID
    is included, so weekly active PROJECTS can be counted.
    """
    if not will_send() or not has_been_told():
        return  # (people must be TOLD about the stats before any are sent)
    extra = {}
    if root is not None:
        extra["project_id"] = project_id(root)
    payload = {
        "api_key": api_key(),
        "event": event,
        "distinct_id": install_id(),
        "properties": {
            **properties,  # ** copies every key from `properties` into this dict
            **extra,
            "version": __version__,
            "os": platform.system(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            "$process_person_profile": False,  # tells PostHog: don't build a profile of anyone
            "$geoip_disable": True,            # ...and don't look up a location from the IP address
        },
    }
    write_to_log(payload)
    thread = threading.Thread(target=_post, args=(payload,), daemon=True)
    thread.start()
    _pending.append(thread)


MAX_LOG_SIZE = 500_000  # bytes. A bigger log is started afresh (the old one is kept as .old).


def write_to_log(payload: dict) -> None:
    """Append exactly what's being sent to the local log, one line per send.

    The API key is left out: it's the same in every line, and it isn't
    information about the user anyway.
    """
    entry = {key: value for key, value in payload.items() if key != "api_key"}
    entry["sent_at"] = datetime.now().isoformat(timespec="seconds")
    try:
        path = log_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > MAX_LOG_SIZE:
            path.replace(path.with_name("telemetry.log.old"))  # keep one old copy, start a new one
        with path.open("a", encoding="utf-8") as log:  # "a" = append, like FileWriter(path, true)
            log.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # a log that can't be written is no reason to crash


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
