"""
explain.py: every problem DecalogueX finds, explained in plain words.

The rules speak "programmer" (SEC-001, ERR-001, ...). This file translates
each one into something anyone can understand, with no coding knowledge
needed. The screen shows these instead of the technical titles.

Each explanation has four parts:
  icon      a picture that shows the kind of problem at a glance
  headline  the problem in a few words
  problem   what's wrong and why it matters (one sentence)
  fix       what DecalogueX will do about it (one sentence)

To change what users read, edit the text here. Nothing else needs to change.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Explanation:
    icon: str
    headline: str
    problem: str
    fix: str


# Rule ID -> its plain-English explanation.
EXPLANATIONS = {
    # --- Secrets ---------------------------------------------------------------
    "SEC-001": Explanation(
        "🔑", "Secret key left in your code",
        "This is a key to one of your online accounts, and anyone who sees your code could use it, "
        "like leaving your house key in the front door.",
        "I'll lock it away in a private file that never leaves your computer.",
    ),
    "SEC-002": Explanation(
        "🔑", "Password written in your code",
        "A password is typed right into your code, where anyone reading it can see it.",
        "I'll lock it away in a private file that never leaves your computer.",
    ),
    "SEC-003": Explanation(
        "🔑", "Master key left in your code",
        "This is a private key, like a master password for your server, and it's sitting in plain sight.",
        "This one is too delicate for me to move, so I'll tell you how to do it.",
    ),

    # --- .gitignore ------------------------------------------------------------
    "GIT-001": Explanation(
        "🙈", "Secret files could be uploaded",
        "Some secret files aren't on the \"never upload\" list, so they could end up online by accident.",
        "I'll add them to the list.",
    ),
    "GIT-002": Explanation(
        "🙈", "A secret file was already saved",
        "A secret file has already been saved to your project's history, so it may already be online.",
        "I can't undo the past, so I'll tell you how to remove it and stay safe.",
    ),
    "GIT-003": Explanation(
        "🙈", "No \"never upload\" list",
        "Your project has no list of files to keep private, so secrets could be uploaded with everything else.",
        "I'll create the list, with your secret files already on it.",
    ),

    # --- SQL ------------------------------------------------------------------
    "SQL-001": Explanation(
        "💉", "Hackers could control your database",
        "Your app pastes whatever people type straight into a database command, "
        "so a sneaky person could type a command of their own and read or delete your data.",
        "I'll keep what people type separate from the command, so it's only ever treated as plain text.",
    ),
    "SQL-002": Explanation(
        "💉", "Hackers could control your database",
        "Your app builds a database command out of whatever people type, "
        "so a sneaky person could slip in a command of their own.",
        "I'll keep what people type separate from the command, so it's only ever treated as plain text.",
    ),

    # --- Errors ---------------------------------------------------------------
    "ERR-001": Explanation(
        "🤫", "Your app shows its secrets when it breaks",
        "When something goes wrong, visitors see the raw error, which can reveal private details "
        "about your app and the people using it.",
        "Visitors will see a friendly \"Something went wrong\" instead, and the real error is kept just for you.",
    ),

    # --- Async ----------------------------------------------------------------
    "ASYNC-001": Explanation(
        "💥", "One error could crash your whole website",
        "If something goes wrong on this page, nothing catches the error, so it can take the whole site "
        "down for everyone.",
        "I'll add a safety net that catches the error so the site keeps running.",
    ),
    "ASYNC-002": Explanation(
        "📡", "No backup plan if the internet fails",
        "This code asks for something over the internet but has no plan for when the answer doesn't come.",
        "I'll add a backup plan that notes the problem instead of failing silently.",
    ),
    "ASYNC-003": Explanation(
        "⏳", "A job that never actually runs",
        "This code starts a job but forgets to wait for it, so the job never happens.",
        "I'll add the missing \"wait for it\" instruction.",
    ),
    "ASYNC-004": Explanation(
        "⏳", "A background job could vanish",
        "This starts a job in the background, but nothing holds on to it, so it can be thrown away halfway through.",
        "I'll keep hold of the job until it's finished.",
    ),
    "ASYNC-005": Explanation(
        "💥", "One error could crash your whole app",
        "This job is set up so that if it fails, nothing can catch the error, and the whole app crashes.",
        "I'll change it so errors can be caught safely.",
    ),
    "ASYNC-006": Explanation(
        "💥", "A background job could crash everything",
        "If this background job crashes, it takes the whole program down with it, not just itself.",
        "I'll add a safety net so a crash in the job stays inside the job.",
    ),
    "ASYNC-007": Explanation(
        "⏳", "Background errors disappear without a trace",
        "If this background job fails, the error is quietly thrown away, so you'd never know something broke.",
        "I'll make sure any error gets printed so you can see it.",
    ),
    "ASYNC-008": Explanation(
        "💥", "A background job could crash your app",
        "This starts a job that runs on its own with no safety net, so one error inside it can crash the app.",
        "I'll tell you how to give it a safety net.",
    ),
    "ASYNC-009": Explanation(
        "⏳", "Background errors disappear without a trace",
        "If this background job fails, the error is quietly thrown away, so you'd never know something broke.",
        "I'll tell you how to catch and show the error.",
    ),
}

# Used if a new rule is added without an explanation here yet.
UNKNOWN = Explanation("⚠️", "A risky piece of code", "This code could cause a crash or a leak.",
                      "I'll make it safer.")


def explain(rule_id: str) -> Explanation:
    """The plain-English explanation for a rule (or a general one if it's missing)."""
    return EXPLANATIONS.get(rule_id, UNKNOWN)
