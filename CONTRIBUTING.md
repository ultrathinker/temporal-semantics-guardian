# Contributing

Thanks for looking. This plugin is small on purpose: a skill, a command and one dependency-free Python script.
Please keep it that way: no runtime packages, no network access, and a scanner that never edits or writes the
project it reads.

## Development setup

Python 3.9 or newer. There is nothing to install.

    python -m unittest discover -s tests -v

Use `python3` where that is the name of the interpreter. The scanner's expected results live in `tests/fixtures`:
code that must be flagged, and code that must stay quiet. Use synthetic code only.

## Pull requests

- One logical change per pull request, with a test that fails without it. For a new rule add both a "must flag" and a
  "must stay quiet" example.
- Keep `README.md`, `PRIVACY.md` and the skill text true: if behaviour changes, the words change in the same
  pull request.
- Keep the scanner on the standard library and keep it working on Python 3.9.
- Run `claude plugin validate .` if you have Claude Code installed.

## Reporting problems

Bugs and ideas: open an issue. Security problems: see `SECURITY.md` and do not open a public issue.
