"""
Lets you run the tool with:  python -m decaloguex scan <path>

JAVA COMPARISON: `python -m decaloguex` is like `java -jar decaloguex.jar`.
Python looks for a __main__.py file inside the package and runs it.
"""

from decaloguex.cli import main

# SystemExit is how a Python program sets its exit code, the same as
# System.exit(code) in Java. main() returns 0 for success, 1 if problems remain.
raise SystemExit(main())
