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
    "AUTH-001": Explanation(
        "🚧", "Logged-out visitors get past the owner check",
        "This checks that the data belongs to the person asking, but when nobody is logged in the check "
        "is quietly skipped, so anyone can reach everyone's data.",
        "I'll show you the one line to add so logged-out visitors are turned away first.",
    ),
    "AUTH-002": Explanation(
        "🚧", "Anyone logged in can change anyone's data",
        "This changes or deletes something picked by an ID in the web address, but never checks it belongs "
        "to the person asking, so anyone could change the number and edit someone else's.",
        "I'll show you the check to add so people can only change their own things.",
    ),
    "CMD-001": Explanation(
        "💣", "Visitors could run commands on your server",
        "Text a visitor typed is glued into a computer command, so they can add their own command, "
        "like one that deletes everything.",
        "I'll show you how to pass the value safely, without a command line in between.",
    ),
    "EVAL-001": Explanation(
        "💣", "Visitors could run their own code",
        "Text a visitor typed is run as code, so they can type code that does anything your app can do.",
        "I'll show you how to read the value as plain data instead.",
    ),
    "PATH-001": Explanation(
        "📂", "Visitors pick which file is opened",
        "A visitor can ask for any file, like ../../.env, and download your secrets or delete files.",
        "I'll show you how to only allow the files you mean to share.",
    ),
    "DESER-001": Explanation(
        "📦", "Loaded data could run hidden code",
        "This way of loading data can create objects and run code hidden inside it.",
        "I'll switch to the safe loader where I can, and tell you how otherwise.",
    ),
    "NOSQL-001": Explanation(
        "🗃️", "Database search can be twisted",
        "A visitor can change what this MongoDB search looks for, and see or change everyone's data.",
        "I'll show you how to turn the input into plain text first.",
    ),
    "REDIRECT-001": Explanation(
        "↪️", "Your site can be used to send people to scam sites",
        "A visitor picks where your site sends people, so scammers can share links that look like yours.",
        "I'll show you how to only allow your own pages.",
    ),
    "SSRF-001": Explanation(
        "🛰️", "Your server fetches any address a visitor gives",
        "A visitor can make your server open private addresses, like internal systems or cloud passwords.",
        "I'll show you how to only allow addresses you trust.",
    ),
    "XXE-001": Explanation(
        "📄", "XML files could read your server's files",
        "This XML reader follows links inside the file, so an uploaded XML file can read files on your server.",
        "I'll show you the one setting that switches that off.",
    ),
    "HASH-001": Explanation(
        "🔓", "Passwords are scrambled the weak way",
        "MD5 and SHA-1 can be reversed in seconds, so stolen passwords would be readable.",
        "I'll show you the password scrambler made for the job.",
    ),
    "CSRF-001": Explanation(
        "🎭", "Fake form protection is switched off",
        "Other websites can submit forms on your site as your logged-in visitors.",
        "I'll show you when it's safe to switch off, and how to turn it back on.",
    ),
    "SEC-004": Explanation(
        "🔑", "Backup secret anyone can guess",
        "If the real secret is ever missing, your app quietly uses a backup word that's written in your "
        "code, like a lock that opens with a password printed in the public instructions.",
        "I'll remove the backup, so the app stops instead of running unlocked, and put a fresh secret "
        "in your private .env file so it still works on your computer.",
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
    # --- Web safety ---------------------------------------------------------
    "DEBUG-001": Explanation(
        "🐞", "Debug mode is left on",
        "When something breaks, debug mode shows anyone a detailed page of your code and settings, "
        "sometimes even passwords.",
        "I'll make debug mode stay on for you on your computer, and switch off once the app is online.",
    ),
    "XSS-001": Explanation(
        "🪤", "Visitors could sneak scripts into your pages",
        "This puts raw HTML into a page, so if a visitor types code into it, that code can run in other "
        "visitors' browsers and steal their logins.",
        "I'll make sure what visitors type is shown as plain text, not run as code.",
    ),
    "CORS-001": Explanation(
        "🚪", "Any website can use your server",
        "Your server lets every website on the internet call it, so a bad site could use it on your "
        "visitors' behalf.",
        "I'll tell you how to allow only your own website.",
    ),
    "TLS-001": Explanation(
        "🔓", "A security check is switched off",
        "The check that proves you're talking to the real server is turned off, so someone on the same "
        "Wi-Fi could pretend to be it and read everything.",
        "I'll tell you how to switch the check back on safely.",
    ),
    "MASS-001": Explanation(
        "📝", "Visitors could give themselves extra powers",
        "Everything a visitor sends gets saved, so they could add a field like \"admin: yes\" that your "
        "form never had.",
        "I'll tell you how to save only the fields you choose.",
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
