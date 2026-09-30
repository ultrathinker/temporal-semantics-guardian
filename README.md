# Temporal Semantics Guardian

Temporal Semantics Guardian is a read-only Claude Code plugin for finding date and time bugs before they become
booking failures, shifted deadlines, incorrect invoices, or reports that change at midnight. It combines a small,
deterministic scanner with Claude's repository-level reasoning. The scanner highlights concrete syntax patterns;
Claude then maps each value to a temporal meaning and checks the boundaries where that meaning can be lost.

The plugin is aimed at backend and full-stack teams working in JavaScript, TypeScript, and Python. It is useful for
APIs, database models, queues, schedulers, billing code, dashboards, and user-facing forms that cross time zones.

## What it does

The /temporal-semantics-guardian:temporal-review command:

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
/temporal-semantics-guardian:temporal-review
~~~

You can add a narrower scope in the command prompt, such as src/billing or services/reminders. The command is
read-only. It may inspect source and test files and run the bundled scanner, but it does not edit, format, install
packages, call a network service, or send repository data anywhere.

The deterministic scanner can also be run directly:

~~~text
python scripts/temporal_scan.py --root . --format text
python scripts/temporal_scan.py --root . --format json
~~~

Use python3 when that is the name of the local Python interpreter. The scanner uses only the Python standard
library. It exits successfully by default so it can be used as an advisory check; --fail-on warning or
--fail-on error can make findings fail a local CI command.

## Scanner rules

The scanner reports stable rule IDs so teams can discuss and suppress a known, reviewed exception:

- JS001: date-only text passed to Date or Date.parse.
- JS002: ISO date-time text without an offset passed to Date or Date.parse.
- JS003: UTC ISO output sliced to make a calendar date.
- JS004: locale formatting without an explicit timeZone option.
- JS005: fixed 24-hour millisecond arithmetic near date/time code.
- PY001: naive datetime.now().
- PY002: datetime.utcnow(), which returns a naive UTC value.
- PY003: datetime.fromtimestamp() without a timezone argument.
- PY004: datetime.utcfromtimestamp(), which returns a naive UTC value.
- PY005: direct pytz timezone assignment through tzinfo=.
- PY006: attaching a timezone through replace(tzinfo=...).
- PY007: adding or subtracting a one-day or 24-hour timedelta where calendar arithmetic may be intended.

The scanner is deliberately pattern-based. It does not attempt to understand every date library or prove the
business meaning of a field. Claude's review should confirm the finding against call sites, schemas, contracts, and
tests before calling it a bug.

## Allowlist and semantic notes

Create .temporal-guardian.json at the repository root when a finding is intentionally accepted. Match a rule and
path, optionally a line, and explain the business reason:

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
      "reason": "The value is a calendar date and is never converted to an instant."
    }
  ]
}
~~~

The scanner applies only the ignore entries. The fields section is a human-readable semantic inventory for
Claude and reviewers, so it can document why a date is allowed without hiding that decision in code. Ignored findings
remain visible in scanner output as suppressed entries with their reasons.

## Limitations

The plugin does not replace domain decisions, database inspection, or integration tests. Static checks can miss
behavior hidden behind helpers, third-party date libraries, serialized data, and configuration. They can also flag
intentional local-time behavior. For high-impact flows, the review should add regression tests for the relevant IANA
zones, including a skipped spring-forward time and a repeated fall-back time, and state whether the application
chooses the earlier, later, or rejected interpretation.

## License

MIT. See LICENSE.
