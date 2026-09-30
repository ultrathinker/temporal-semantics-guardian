---
name: temporal-review
description: Use when reviewing a repository for date and time bugs involving time zones, daylight saving time, calendar dates, instants, local times, durations, schedules, parsing, storage, formatting, or temporal API boundaries.
---

# Temporal semantics review

Perform a read-only, evidence-first review. Do not modify, format, generate, or delete project files. Do not call
network services. If the user asks for a fix, finish the review first and present an unapplied patch or a focused
implementation plan unless the user explicitly authorizes edits.

## Review workflow

1. Establish scope.

   Identify the requested paths, the application language, relevant package or framework guidance, and the
   user-visible behavior at risk. If no scope is given, review the smallest relevant set of source files and their
   tests rather than pretending that a repository-wide scan proves completeness.

2. Read repository semantics.

   Look for schema definitions, API contracts, serialization code, persistence mappings, job configuration, and
   existing timezone helpers. Inspect .temporal-guardian.json if present. Treat its fields entries as semantic
   evidence, not as permission to ignore a contradiction in code.

3. Run the deterministic scan.

   From the repository root, run:

   ~~~text
   python "${CLAUDE_PLUGIN_ROOT}/scripts/temporal_scan.py" --root . --format json
   ~~~

   If the environment exposes Python as python3, use that executable. Pass a narrower path when the user gave one.
   If no Python interpreter is available, say so and continue with a clearly labeled model-only review. The scanner is
   read-only and has no third-party dependencies.

4. Build a semantic inventory.

   For each important field or value, record:

   - meaning: instant, calendar date, local wall-clock time, duration/interval, or recurring schedule;
   - source and storage representation;
   - zone or offset at creation;
   - behavior at serialization and deserialization;
   - consumer expectations and display zone;
   - whether the value is allowed to be ambiguous, skipped, or missing.

   Do not infer an instant from a field named date, or a calendar date from a string shaped like an ISO timestamp.
   Use call sites and contracts.

5. Check boundaries and arithmetic.

   Give special attention to:

   - date-only text entering JavaScript Date or a timestamp column;
   - timestamp text without an offset;
   - naive Python datetimes crossing a process or API boundary;
   - local-midnight calculations and fixed 24-hour additions;
   - formatting that silently uses the machine's zone;
   - queue payloads, database drivers, and JSON serializers that add or remove offsets;
   - recurring schedules across daylight-saving transitions;
   - comparisons between calendar dates, local times, and instants.

   A finding is stronger when the review can name both sides of the boundary and show the conversion line.

6. Assess tests.

   Check whether tests exercise at least two relevant IANA zones and both daylight-saving transition shapes where
   applicable: a skipped local time during spring forward and a repeated local time during fall back. Also check
   date-only values near UTC midnight and an explicit-offset instant. Prefer assertions about meaning and chosen
   policy over assertions that merely match the host machine's local zone.

7. Report only actionable evidence.

   Start with a short risk summary. Then provide findings ordered by impact, each with:

   - severity and confidence;
   - file and line evidence;
   - the temporal meaning the code appears to use;
   - the boundary or arithmetic that can change that meaning;
   - a concrete recommendation;
   - a regression test idea.

   Separate confirmed defects, likely defects, and questions requiring domain confirmation. If a scanner finding is
   safe, say why and do not inflate it into a bug. End with a compact semantic inventory and test gaps.

## Safety and trust rules

- Never edit source code automatically.
- Never treat a pattern match as a defect without checking semantics.
- Keep findings quiet when an explicit IANA zone, offset, or calendar-date type makes the behavior intentional.
- Prefer a boundary-specific explanation over a generic warning about UTC.
- When suggesting code, show a minimal diff or pseudocode and name the policy decision it relies on.
- Preserve the repository's terminology and existing temporal helpers.
- Do not recommend storing a local wall-clock time as an instant unless the product has a documented zone policy.
- Do not recommend converting every value to UTC as a substitute for modeling calendar dates and recurring schedules.
