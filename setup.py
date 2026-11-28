"""
setup.py: a safety check that runs while DecalogueX is being installed.

Everything about the package lives in pyproject.toml. This file only exists
because old installers (like the one built into macOS, with Python 3.9 and
setuptools 58) can't read pyproject.toml. Without this check they "succeed"
but install an empty package called UNKNOWN-0.0.0, and the person has no
idea it didn't work. With it, they get a clear message saying what to do.
"""

import sys

MAC_TIP = ("\n  Get the newest Python from https://www.python.org/downloads/ and install it."
           "\n  (On a Mac, also double-click 'Install Certificates.command' in the window"
           "\n  that opens afterwards.) Then close the terminal, open a new one, and try again.\n")

if sys.version_info < (3, 10):
    sys.exit(f"\n  DecalogueX needs Python 3.10 or newer, but this is Python "
             f"{sys.version_info.major}.{sys.version_info.minor}.{MAC_TIP}")

import setuptools  # noqa: E402  (imported after the check on purpose)

if int(setuptools.__version__.split(".")[0]) < 61:
    sys.exit(f"\n  Your Python's install tools are too old (setuptools {setuptools.__version__})."
             f"\n  Run this, then try again:\n\n      python3 -m pip install --upgrade pip setuptools\n")

setuptools.setup()
