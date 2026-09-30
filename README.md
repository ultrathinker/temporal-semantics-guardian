# Temporal Semantics Guardian

Temporal Semantics Guardian is a read-only Claude Code plugin for finding date and time bugs before they become
booking failures, shifted deadlines, incorrect invoices, or reports that change at midnight. It combines a small,
deterministic scanner with Claude's repository-level reasoning. The scanner highlights concrete syntax patterns;
Claude then maps each value to a temporal meaning and checks the boundaries where that meaning can be lost.

The plugin is aimed at backend and full-stack teams working in JavaScript, TypeScript, and Python. It is useful for
APIs, database models, queues, schedulers, billing code, dashboards, and user-facing forms that cross time zones.

## What it does

The /temporal-semantics-guardian:temporal-check command:

1. Establishes the requested review scope and looks for repository guidance.
2. Runs the bundled dependency-free scanner over source files.
3. Classifies important fields as instants, calendar dates, local wall-clock times, durations, or recurring schedules.
4. Traces conversions at API, database, queue, job, and UI boundaries.
5. Checks daylight-saving transitions and ambiguous or skipped local times when the code's behavior depends on them.
6. Reports evidence, impact, confidence, and a proposed diff without changing project files.

The review is intentionally quiet about code that already makes its zone and meaning explicit. A scanner finding is
a prompt for inspection, not proof of a defect. The final review should say when a pattern is safe because the
business meaning and the conversion zone are documented.

## Use it

Load the plugin for a local Claude Code session:

~~~text
claude --plugin-dir /path/to/temporal-semantics-guardian
~~~

Then run:

~~~text
/temporal-semantics-guardian:temporal-check
~~~

You can add a narrower scope in the command prompt, such as src/billing or services/reminders. The command is
read-only by instruction; normal Claude Code permissions still apply. It pre-approves only the bundled scanner
invocation and may inspect source and test files, but the scanner does not edit, format, install packages, call a
network service, or send data anywhere.

The deterministic scanner can also be run directly from the repository you want to scan:

~~~text
python /path/to/temporal-semantics-guardian/scripts/temporal_scan.py --root . --format text
python /path/to/temporal-semantics-guardian/scripts/temporal_scan.py --root . --format json
~~~

The scanner requires Python 3.9 or newer and uses only the standard library. Use python3 when that is the name of
the local interpreter. If Python is not available, the skill continues with a clearly labeled scanner-free review.
The scanner exits successfully by default so it can be used as an advisory check; --fail-on warning or --fail-on
error can make findings fail a local CI command. It shows at most 25 findings by default, puts the complete counts
in the summary, and reports truncation; use --max-findings 0 for no output cap or --list-files to include the full
scanned-file list in JSON.

## Scanner rules

The scanner reports stable rule IDs so teams can discuss and suppress a known, reviewed exception:

- JS001: date-only text passed to Date or Date.parse.
- JS002: ISO date-time text without an offset passed to Date or Date.parse.
- JS003: UTC ISO output sliced to make a calendar date.
- JS004: date/time locale formatting that may use the runtime timezone.
- JS005: fixed 24-hour millisecond arithmetic near date/time code.
- PY001: naive datetime.now() or datetime.today().
- PY002: datetime.utcnow(), which returns a naive UTC value.
- PY003: datetime.fromtimestamp() without a timezone argument.
- PY004: datetime.utcfromtimestamp(), which returns a naive UTC value.
- PY005: direct pytz timezone assignment through tzinfo=.
- PY006: changing timezone metadata through replace(tzinfo=...).
- PY007: adding or subtracting a one-day or 24-hour timedelta where calendar arithmetic may be intended.

Findings include a production or test context. Production findings are shown first within each severity; test
fixtures remain visible so they cannot hide coverage gaps.

The scanner is deliberately pattern-based. It does not attempt to understand every date library or prove the
business meaning of a field. Claude's review should confirm the finding against call sites, schemas, contracts, and
tests before calling it a bug.

## A small example

Input:

~~~typescript
const birthday = new Date("2026-03-08");
const local = new Date("2026-03-08 10:00");
const reportDay = createdAt.toISOString().split("T")[0];
~~~

The scanner reports JS001, JS002, and JS003 with file and line evidence. The review then adds the missing decision:
whether birthday is a calendar date, which IANA zone defines reportDay, and whether local is an input wall-clock time
or an instant that must carry an offset. It can recommend an unapplied diff plus tests around UTC midnight and the
relevant spring-forward and fall-back transitions; it does not change the file.

## Pair it with language linters

Where available, run language-aware checks such as Ruff's DTZ rules or flake8-datetimez alongside this plugin. Those
tools are better suited to precise Python linting; this scanner also covers JavaScript and TypeScript. The plugin's
distinct value is Claude's repository-level reasoning about field meaning, API and database boundaries, display zones,
and missing daylight-saving regression tests, not the regexes alone.

## Allowlist and semantic notes

Create .temporal-guardian.json at the repository root when a finding is intentionally accepted. Every ignore entry
must include a known rule, a path, and a non-empty reason. It may also include a line and a match substring for a
more durable exception:

~~~json
{
  "fields": [
    {
      "name": "birth_date",
      "kind": "calendar-date",
      "notes": "Never represents an instant."
    },
    {
      "name": "created_at",
      "kind": "instant",
      "zone": "UTC"
    }
  ],
  "ignore": [
    {
      "rule": "JS001",
      "path": "src/profile/birth-date.ts",
      "line": 18,
      "match": "new Date",
      "reason": "The value is a calendar date and is never converted to an instant."
    }
  ]
}
~~~

The scanner applies only the ignore entries and rejects unknown config or entry keys. The fields section is a
human-readable semantic inventory for Claude and reviewers, so it can document why a date is allowed without hiding
that decision in code. Ignored findings remain visible in scanner output as suppressed entries with their reasons.

## Limitations

The plugin does not replace domain decisions, database inspection, or integration tests. Static checks can miss
behavior hidden behind helpers, third-party date libraries, serialized data, and configuration. It does not parse
moment, dayjs, luxon, date-fns, SQL types, Java, or framework files such as Vue and Svelte. It can also flag
intentional local-time behavior. For high-impact flows, the review should recommend, as an unapplied patch,
regression tests for the relevant IANA zones, including a skipped spring-forward time and a repeated fall-back time,
and state whether the application chooses the earlier, later, or rejected interpretation. Useful 2026 transition
dates include America/New_York on March 8 and November 1, and Europe/Budapest on March 29 and October 25.

The scanner reads only these extensions: .cjs, .cts, .js, .jsx, .mjs, .mts, .py, .ts, and .tsx. It skips common
dependency and generated directories, including .git, node_modules, dist, build, out, vendor, coverage, .venv,
venv, env, site-packages, .next, .nuxt, .turbo, .cache, .eggs, .mypy_cache, .pytest_cache, .tox, __pycache__,
and __pypackages__. Files over 1 MB, individual lines over 2,000 characters, and unusually long or unclosed calls
are skipped with warnings or bounded as appropriate.
The scanner is line-oriented and can miss multiline abstractions, interpolated JavaScript template and Python
f-string expressions, receiver names that do not expose temporal tokens, uncalled datetime references beyond the
simple forms it knows, and third-party date libraries.

## Privacy

The scanner only reads source files and prints a report: it writes nothing and makes no network requests, and the
plugin itself sends nothing anywhere. Claude handles what it reads inside your own Claude Code session. Privacy:
`PRIVACY.md`. Security reports: `SECURITY.md`.

## License

MIT. See LICENSE.
