---
description: Review the current repository for date and time semantic bugs, timezone boundary mistakes, and daylight-saving regressions without changing files.
argument-hint: "[path or scope]"
allowed-tools: Read, Grep, Glob, Bash(python ${CLAUDE_PLUGIN_ROOT}/scripts/temporal_scan.py:*), Bash(python3 ${CLAUDE_PLUGIN_ROOT}/scripts/temporal_scan.py:*)
---

Run the temporal-review skill for the user's requested scope: $ARGUMENTS. Keep this command as a thin trigger; the
skill owns the review workflow.

Use the repository's own contracts and tests as evidence. From the repository root, start with the bundled scanner:

~~~text
python "${CLAUDE_PLUGIN_ROOT}/scripts/temporal_scan.py" --root . --format json --max-findings 25
~~~

If the user supplied a path or scope, pass it as a positional path after the options; otherwise scan the repository
root. Use python3 if that is the available interpreter. If Python is unavailable, continue with a scanner-free review
and say so. Then inspect relevant findings in context, classify the value's meaning, trace conversions across
boundaries, and report confirmed defects separately from questions. Include file and line evidence, impact,
confidence, a concrete recommendation, and a regression-test idea. Do not edit files, install packages, access the
network, or silently suppress findings; honor documented .temporal-guardian.json exceptions and explain their
reasons.
