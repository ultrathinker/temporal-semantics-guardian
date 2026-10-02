# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0]

First public release.

### Added
- The `/temporal-semantics-guardian:temporal-check` command and the `temporal-review` skill: a read-only review of
  date and time meaning, time zone boundaries and daylight-saving arithmetic in JavaScript, TypeScript and Python.
- A dependency-free Python scanner (`scripts/temporal_scan.py`, Python 3.9 or newer) with text and JSON output, a
  findings cap, an allowlist and a `--fail-on` switch for use in a local CI command.
- A regression corpus in `tests/fixtures` (code that must be flagged and code that must stay quiet) and a test suite
  that runs on Windows, Linux and macOS.
