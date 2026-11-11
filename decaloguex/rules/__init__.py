"""
The rules package: one module per Phase 0 capability.

  secrets.py    Exposed Secret Scrubbing          SEC-001..003
  gitignore.py  .gitignore Hardener               GIT-001..003
  sql.py        SQL Query Parameterization        SQL-001..002
  errors.py     Safe Error Masking (PII Shield)   ERR-001
  async_.py     Unhandled Async Error Boundaries  ASYNC-001..004
  common.py     helpers shared by the rules above (not a rule itself)

Each rule exposes a check(...) function that returns a list of Findings and
never writes to disk. The CLI decides what actually gets applied.

A finding either carries a Fix (DecalogueX can repair it safely) or a note
(a "manual step" telling the user what to do). When a rule isn't SURE its
rewrite keeps the code working exactly as before, it chooses the note.
"""
