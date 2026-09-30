---
description: Review the current repository for date and time semantic bugs, timezone boundary mistakes, and daylight-saving regressions without changing files.
---

Run the temporal-review skill for the user's requested scope: $ARGUMENTS

Use the repository's own contracts and tests as evidence. Start with the bundled read-only scanner:

~~~text
python "${CLAUDE_PLUGIN_ROOT}/scripts/temporal_scan.py" --root . --format json
~~~

Use python3 if that is the available interpreter. Then inspect each relevant finding in context, classify the
value's meaning, trace conversions across boundaries, and report confirmed defects separately from questions. Include
file and line evidence, impact, confidence, a concrete recommendation, and a regression-test idea. Do not edit files,
install packages, access the network, or silently suppress findings; honor documented .temporal-guardian.json
exceptions and explain their reasons.
