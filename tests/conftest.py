"""
conftest.py: setup that pytest applies to EVERY test automatically.

pytest looks for a file with exactly this name and loads it first. A
"fixture" marked autouse=True runs around every single test, like a JUnit
@BeforeEach that you never have to remember to call.
"""

import pytest


@pytest.fixture(autouse=True)
def private_settings(tmp_path, monkeypatch):
    """Keep tests away from real settings and the internet.

    monkeypatch changes things just for the duration of one test, then puts
    them back. Here it:
      * points DecalogueX's settings at a throwaway folder, so tests never
        touch the real ~/.decaloguex folder;
      * switches telemetry off, so tests never send anything.
    """
    monkeypatch.setenv("DECALOGUEX_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("DECALOGUEX_TELEMETRY", "off")
    monkeypatch.delenv("DECALOGUEX_POSTHOG_KEY", raising=False)
    # Automated test servers set settings like CI=true, which switch the
    # stats off. Clear them, so tests behave the same on any computer.
    from decaloguex.telemetry import CI_SETTINGS
    for name in CI_SETTINGS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def project_loads_env(monkeypatch):
    """Treat every test project as one that loads its .env file.

    DecalogueX only moves a secret into .env when it can see that the app
    will READ .env (see project.py). Most tests are about what a fix looks
    like, not about that check, so this setting says "assume .env is
    loaded". The tests of the check itself (in test_review.py) switch it
    back off with monkeypatch.delenv("DECALOGUEX_ENV_LOADED").
    """
    monkeypatch.setenv("DECALOGUEX_ENV_LOADED", "1")
