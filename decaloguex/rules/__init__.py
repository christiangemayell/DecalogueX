"""
The rules package: one module per kind of problem.

  JavaScript/TypeScript and Python (detailed rules):
    secrets.py          Exposed Secret Scrubbing          SEC-001..003
    sql.py              SQL Query Parameterization        SQL-001..002
    errors.py           Safe Error Masking (PII Shield)   ERR-001
    async_.py           Unhandled Async Error Boundaries  ASYNC-001..004

  Every other language (shared rules, one profile per language):
    other_languages.py  PHP, Java, C#, Go, Ruby, Kotlin, Swift
                        SEC, SQL, ERR and ASYNC-005..009

  Whole-project and settings files:
    gitignore.py        .gitignore Hardener               GIT-001..003
    config_files.py     secrets in .yml/.json/... files    SEC-001..003

  common.py             helpers shared by the rules above (not a rule itself)

Each rule exposes a check(...) function that returns a list of Findings and
never writes to disk. The engine decides what actually gets applied.

A finding either carries a Fix (DecalogueX can repair it safely) or a note
(a "What to do" card telling the user what to do). When a rule isn't SURE
its rewrite keeps the code working exactly as before, it chooses the note.
"""
