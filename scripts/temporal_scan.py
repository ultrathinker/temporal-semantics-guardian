#!/usr/bin/env python3
"""Run a deterministic, read-only scan for common temporal semantics hazards.

The scanner intentionally reports review prompts rather than claiming that a
pattern is always a defect. It has no third-party dependencies and never
writes to the repository.
"""

from __future__ import annotations

import argparse
import bisect
import fnmatch
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union


SCANNER_VERSION = "0.2.0"
DEFAULT_MAX_FILE_BYTES = 1_000_000
DEFAULT_MAX_FINDINGS = 25
MAX_LINE_CHARS = 2_000
SOURCE_EXTENSIONS = {
    ".cts",
    ".cjs",
    ".js",
    ".jsx",
    ".mjs",
    ".mts",
    ".py",
    ".ts",
    ".tsx",
}
EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".svn",
    ".tox",
    ".venv",
    ".next",
    ".nuxt",
    ".turbo",
    "__pycache__",
    "__pypackages__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "env",
    "site-packages",
    "vendor",
    "venv",
}
SEVERITY_RANK = {"info": 1, "warning": 2, "error": 3}


RULES: Dict[str, Dict[str, str]] = {
    "JS001": {
        "severity": "warning",
        "confidence": "high",
        "message": "An ISO date-only literal enters JavaScript's Date parser.",
        "rationale": (
            "JavaScript normalizes date-only ISO strings as UTC midnight; "
            "displaying or comparing them in a local zone can move the calendar date."
        ),
        "suggestion": (
            "Keep calendar dates as date-only values, or parse them with an explicit "
            "business zone and a deliberate type."
        ),
    },
    "JS002": {
        "severity": "warning",
        "confidence": "high",
        "message": "An ISO date-time literal has no offset before entering JavaScript's Date parser.",
        "rationale": (
            "Without an offset, the instant depends on the runtime's local timezone "
            "and can differ between machines."
        ),
        "suggestion": (
            "Require an offset for an instant, or parse as a local wall-clock value "
            "with an explicit IANA zone."
        ),
    },
    "JS003": {
        "severity": "warning",
        "confidence": "high",
        "message": "UTC ISO output is sliced to produce a calendar date.",
        "rationale": (
            "The slice uses UTC rather than the user's or business timezone, so values "
            "near midnight can land on the wrong calendar date."
        ),
        "suggestion": (
            "Convert to the intended zone before extracting a calendar date, or keep "
            "the value typed as a date."
        ),
    },
    "JS004": {
        "severity": "info",
        "confidence": "medium",
        "message": "Date/time formatting may use the runtime timezone.",
        "rationale": (
            "The result follows the machine or process timezone, which can differ "
            "between development, CI, and users."
        ),
        "suggestion": (
            "For business output, pass an explicit IANA timeZone; leave it implicit "
            "only when local-device display is intentional."
        ),
    },
    "JS005": {
        "severity": "warning",
        "confidence": "medium",
        "message": "Date/time code uses a fixed 24-hour millisecond interval.",
        "rationale": (
            "A fixed millisecond interval and a civil-day recurrence are different "
            "policies around daylight-saving transitions."
        ),
        "suggestion": (
            "Choose elapsed-time arithmetic or calendar arithmetic explicitly and "
            "use a zone-aware API; do not infer intent from the numeric constant."
        ),
    },
    "PY001": {
        "severity": "warning",
        "confidence": "high",
        "message": "datetime.now() creates a naive datetime.",
        "rationale": (
            "A naive value does not carry the zone needed to interpret it consistently "
            "when it crosses a process, storage, or API boundary."
        ),
        "suggestion": (
            "Use an aware datetime with the intended zone, commonly "
            "datetime.now(timezone.utc) for an instant."
        ),
    },
    "PY002": {
        "severity": "warning",
        "confidence": "high",
        "message": "datetime.utcnow() creates a naive UTC datetime.",
        "rationale": (
            "The value looks like UTC but has no offset, so later code can treat it "
            "as local time or mix it with aware values."
        ),
        "suggestion": (
            "Use datetime.now(timezone.utc) and keep the value aware."
        ),
    },
    "PY003": {
        "severity": "warning",
        "confidence": "medium",
        "message": "datetime.fromtimestamp() has no timezone argument.",
        "rationale": (
            "The result defaults to the host's local timezone and can change with "
            "deployment configuration."
        ),
        "suggestion": (
            "Pass the intended zone explicitly, or use an aware UTC instant when "
            "the input is an epoch timestamp."
        ),
    },
    "PY004": {
        "severity": "warning",
        "confidence": "high",
        "message": "datetime.utcfromtimestamp() creates a naive UTC datetime.",
        "rationale": (
            "The UTC meaning is not carried in the result's tzinfo, which makes "
            "later comparisons and serialization unsafe."
        ),
        "suggestion": (
            "Use datetime.fromtimestamp(value, tz=timezone.utc) for an aware instant."
        ),
    },
    "PY005": {
        "severity": "warning",
        "confidence": "high",
        "message": "pytz timezone is assigned directly through tzinfo.",
        "rationale": (
            "Direct pytz assignment bypasses pytz's localization rules and can use "
            "the wrong historical offset or mishandle DST transitions."
        ),
        "suggestion": (
            "Use zone.localize for a naive wall time, normalize after arithmetic, "
            "or migrate to zoneinfo."
        ),
    },
    "PY006": {
        "severity": "info",
        "confidence": "medium",
        "message": "A timezone is attached with replace(tzinfo=...).",
        "rationale": (
            "replace changes the label without resolving whether the wall time is "
            "valid or ambiguous in that zone."
        ),
        "suggestion": (
            "Use a zone-aware construction or an explicit policy for skipped and "
            "repeated local times; keep replace only for a proven relabeling."
        ),
    },
    "PY007": {
        "severity": "info",
        "confidence": "medium",
        "message": "Code adds or subtracts a one-day or 24-hour timedelta.",
        "rationale": (
            "The business intent may be elapsed time or a calendar recurrence. "
            "Python zoneinfo-aware datetimes preserve local wall time across DST, "
            "while UTC, naive values, and pytz have different semantics."
        ),
        "suggestion": (
            "Confirm the value's timezone and whether the requirement is elapsed "
            "time or the next local calendar day before changing the arithmetic."
        ),
    },
}


JS_DATE_ONLY = re.compile(
    r"""\b(?:new\s+Date|Date\.parse)\s*\(\s*(?P<quote>["'\x60])(?P<value>\d{4}-\d{2}-\d{2})(?P=quote)"""
)
JS_LOCAL_DATETIME = re.compile(
    r"""\b(?:new\s+Date|Date\.parse)\s*\(\s*(?P<quote>["'\x60])(?P<value>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)(?P=quote)"""
)
JS_ISO_DATE_SLICE = re.compile(
    r"""\.toISOString\s*\(\s*\)\s*\.\s*(?:slice|substring|substr)\s*\(\s*0\s*,\s*10\s*\)"""
)
JS_ISO_DATE_SPLIT = re.compile(
    r"""\.toISOString\s*\(\s*\)\s*\.\s*split\s*\(\s*(?P<quote>["'])T(?P=quote)\s*\)\s*\[\s*0\s*\]""",
    re.DOTALL,
)
JS_LOCALE_CALL = re.compile(
    r"""(?P<receiver>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)?\.(?P<method>toLocaleString|toLocaleDateString|toLocaleTimeString)\s*\("""
)
JS_INTL_FORMAT = re.compile(
    r"""\bIntl\.DateTimeFormat\s*\("""
)
JS_FIXED_DAY_PRODUCT = re.compile(
    r"""(?<![\w.])\d[\d_]*(?:\s*\*\s*\d[\d_]*){2,}(?![\w.])"""
)
JS_FIXED_DAY_LITERAL = re.compile(
    r"""(?<![\w.])86_?400_?000(?![\w.])"""
)
JS_TEMPORAL_CONTEXT = re.compile(
    r"""\b(?:date|time|timestamp|epoch|millis|milliseconds|ms|day|days|daymilliseconds?|duration|timeout|deadline|expiry|expires|ttl)\b""",
    re.IGNORECASE,
)
JS_DATE_OPTION = re.compile(
    r"""\b(?:dateStyle|timeStyle|weekday|era|year|month|day|hour|minute|second|fractionalSecondDigits|hour12|hourCycle)\s*:""",
    re.IGNORECASE,
)
JS_TIMEZONE_OPTION = re.compile(
    r"""(?:"timeZone"|'timeZone'|\btimeZone)\s*:""",
    re.IGNORECASE,
)
JS_DATE_LIKE_RECEIVER = re.compile(
    r"""(?:date|time|created|updated|due|expiry|expires|scheduled|timestamp|instant|start|end|deadline)""",
    re.IGNORECASE,
)

PY_DATETIME_METHOD = re.compile(
    r"""\b(?P<receiver>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\.(?P<method>now|utcnow|fromtimestamp|utcfromtimestamp)\s*\("""
)
PY_DATETIME_IMPORT = re.compile(
    r"""\bfrom\s+datetime\s+import\s+datetime(?:\s+as\s+(?P<alias>[A-Za-z_]\w*))?\b"""
)
PY_DATETIME_MODULE_IMPORT = re.compile(
    r"""\bimport\s+datetime(?:\s+as\s+(?P<alias>[A-Za-z_]\w*))?\b"""
)
PY_PYTZ_ASSIGNMENT = re.compile(
    r"""\btzinfo\s*=\s*pytz\.timezone\s*\("""
)
PY_REPLACE_CALL = re.compile(
    r"""\.replace\s*\("""
)
PY_FIXED_DAY = re.compile(
    r"""(?:\+|\-)\s*timedelta\s*\(\s*(?:days\s*=\s*1(?![\d.])|hours\s*=\s*24(?![\d.])|seconds\s*=\s*86400(?![\d.]))"""
)


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    confidence: str
    language: str
    path: str
    context: str
    line: int
    message: str
    evidence: str
    rationale: str
    suggestion: str


@dataclass(frozen=True)
class IgnoreRule:
    rule: str
    path: str
    line: Optional[int]
    reason: str
    match: Optional[str]


def _context_for_path(path: str) -> str:
    normalized = path.replace("\\", "/").lower()
    parts = normalized.split("/")
    filename = parts[-1] if parts else normalized
    if any(part in {"test", "tests", "__test__", "__tests__"} for part in parts):
        return "test"
    if filename.startswith("test_") or re.search(
        r"(?:^|[._-])(?:test|spec)(?:[._-]|$)", filename
    ):
        return "test"
    return "production"


def _language_for_path(path: str) -> Optional[str]:
    suffix = Path(path).suffix.lower()
    if suffix in {".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"}:
        return "javascript"
    if suffix == ".py":
        return "python"
    return None


def _snippet(line: str) -> str:
    value = " ".join(line.strip().split())
    if len(value) > 240:
        return value[:237] + "..."
    return value


def _make_finding(rule: str, language: str, path: str, line_number: int, line: str) -> Finding:
    metadata = RULES[rule]
    return Finding(
        rule=rule,
        severity=metadata["severity"],
        confidence=metadata["confidence"],
        language=language,
        path=path,
        context=_context_for_path(path),
        line=line_number,
        message=metadata["message"],
        evidence=_snippet(line),
        rationale=metadata["rationale"],
        suggestion=metadata["suggestion"],
    )


def _deduplicate(findings: Iterable[Finding]) -> List[Finding]:
    result: List[Finding] = []
    seen = set()
    for finding in findings:
        key = (finding.rule, finding.path, finding.line)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result


def _mask_source(text: str, language: str) -> str:
    """Replace comments and string contents while preserving positions and newlines."""

    characters = list(text)
    length = len(text)
    index = 0

    def blank(start: int, end: int) -> None:
        for position in range(start, min(end, length)):
            if characters[position] != "\n":
                characters[position] = " "

    quote_characters = {"'", '"', chr(96)}
    while index < length:
        if language == "python" and text[index] == "#":
            end = text.find("\n", index)
            blank(index, length if end < 0 else end)
            index = length if end < 0 else end
            continue
        if language == "javascript" and text.startswith("//", index):
            end = text.find("\n", index)
            blank(index, length if end < 0 else end)
            index = length if end < 0 else end
            continue
        if language == "javascript" and text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = length if end < 0 else end + 2
            blank(index, end)
            index = end
            continue
        if text[index] not in quote_characters:
            index += 1
            continue

        quote = text[index]
        triple = language == "python" and text.startswith(quote * 3, index)
        delimiter_length = 3 if triple else 1
        end_delimiter = quote * delimiter_length
        start = index
        index += delimiter_length
        while index < length:
            if text[index] == "\\" and not triple:
                index += 2
                continue
            if text.startswith(end_delimiter, index):
                index += delimiter_length
                break
            index += 1
        blank(start, index)
    return "".join(characters)


def _mask_long_lines(text: str) -> str:
    characters = list(text)
    offset = 0
    for line in text.splitlines(keepends=True):
        content_length = len(line.rstrip("\r\n"))
        if content_length > MAX_LINE_CHARS:
            for position in range(offset, offset + content_length):
                characters[position] = " "
        offset += len(line)
    return "".join(characters)


def _line_starts(text: str) -> List[int]:
    return [0] + [match.end() for match in re.finditer("\n", text)]


def _line_number(position: int, starts: Sequence[int]) -> int:
    return bisect.bisect_right(starts, position)


def _line_text(lines: Sequence[str], line_number: int) -> str:
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1]
    return ""


def _is_code_position(masked: str, position: int) -> bool:
    return 0 <= position < len(masked) and masked[position] != " "


def _balanced_call(
    masked: str, opening_position: int
) -> Optional[Tuple[int, str]]:
    depth = 0
    for position in range(opening_position, len(masked)):
        character = masked[position]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return position, masked[opening_position + 1 : position]
    return None


def _call_arguments(
    source: str, masked: str, opening_position: int
) -> Optional[Tuple[str, str]]:
    balanced = _balanced_call(masked, opening_position)
    if balanced is None:
        return None
    closing_position, masked_arguments = balanced
    return source[opening_position + 1 : closing_position], masked_arguments


def _has_second_positional_argument(masked_arguments: str) -> bool:
    depth = 0
    last_comma = -1
    for position, character in enumerate(masked_arguments):
        if character in "([{":
            depth += 1
        elif character in ")]}":
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            last_comma = position
    if last_comma < 0:
        return False
    return bool(masked_arguments[last_comma + 1 :].strip())


def _python_datetime_receivers(masked: str) -> set:
    receivers = {"datetime", "datetime.datetime"}
    for match in PY_DATETIME_IMPORT.finditer(masked):
        receivers.add(match.group("alias") or "datetime")
    for match in PY_DATETIME_MODULE_IMPORT.finditer(masked):
        alias = match.group("alias") or "datetime"
        receivers.add(alias + ".datetime")
    return receivers


def _js_locale_has_timezone(raw_arguments: str, masked_arguments: str) -> bool:
    return bool(
        JS_TIMEZONE_OPTION.search(masked_arguments)
        or JS_TIMEZONE_OPTION.search(raw_arguments)
    )


def _js_locale_is_temporal(
    match: re.Match,
    method: str,
    masked: str,
    masked_arguments: str,
) -> bool:
    if method in {"toLocaleDateString", "toLocaleTimeString"}:
        return True
    receiver = match.group("receiver") or ""
    if JS_DATE_LIKE_RECEIVER.search(receiver):
        return True
    if JS_DATE_OPTION.search(masked_arguments):
        return True
    prefix = masked[max(0, match.start() - 80) : match.start()]
    return bool(re.search(r"\b(?:new\s+)?Date\s*\([^)]*\)\s*$", prefix))


def _js_product_is_day(expression: str) -> bool:
    product = 1
    terms = re.findall(r"\d[\d_]*", expression)
    for term in terms:
        product *= int(term.replace("_", ""))
        if product > 86_400_000:
            return False
    return product == 86_400_000


def _js_temporal_context(line: str) -> bool:
    normalized = re.sub(r"([a-z])([A-Z])", r"\1 \2", line)
    return bool(JS_TEMPORAL_CONTEXT.search(normalized))


def _python_duration_is_explicitly_safe(line: str) -> bool:
    if re.search(r"\bdate\.today\s*\(\s*\)", line):
        return True
    return bool(
        re.search(
            r"\b(?:datetime|dt)\.now\s*\([^)]*(?:timezone\.utc|ZoneInfo\s*\()",
            line,
        )
    )


def scan_text(text: str, path: str) -> List[Finding]:
    """Scan one source string and return stable, line-oriented findings."""

    language = _language_for_path(path)
    if language is None:
        return []

    scan_text_source = _mask_long_lines(text)
    masked = _mask_long_lines(_mask_source(text, language))
    lines = text.splitlines()
    starts = _line_starts(text)
    findings: List[Finding] = []
    if language == "javascript":
        for matcher, rule in ((JS_DATE_ONLY, "JS001"), (JS_LOCAL_DATETIME, "JS002")):
            for match in matcher.finditer(scan_text_source):
                if _is_code_position(masked, match.start()):
                    line_number = _line_number(match.start(), starts)
                    findings.append(
                        _make_finding(
                            rule, language, path, line_number, _line_text(lines, line_number)
                        )
                    )

        for matcher in (JS_ISO_DATE_SLICE, JS_ISO_DATE_SPLIT):
            source_to_search = (
                masked if matcher is JS_ISO_DATE_SLICE else scan_text_source
            )
            for match in matcher.finditer(source_to_search):
                if not _is_code_position(masked, match.start()):
                    continue
                line_number = _line_number(match.start(), starts)
                findings.append(
                    _make_finding(
                        "JS003", language, path, line_number, _line_text(lines, line_number)
                    )
                )

        for match in JS_LOCALE_CALL.finditer(masked):
            call = _call_arguments(text, masked, match.end() - 1)
            if call is None:
                continue
            raw_arguments, masked_arguments = call
            if _js_locale_has_timezone(raw_arguments, masked_arguments):
                continue
            if not _js_locale_is_temporal(
                match, match.group("method"), masked, masked_arguments
            ):
                continue
            line_number = _line_number(match.start(), starts)
            findings.append(
                _make_finding(
                    "JS004", language, path, line_number, _line_text(lines, line_number)
                )
            )

        for match in JS_INTL_FORMAT.finditer(masked):
            call = _call_arguments(text, masked, match.end() - 1)
            if call is None:
                continue
            raw_arguments, masked_arguments = call
            if _js_locale_has_timezone(raw_arguments, masked_arguments):
                continue
            line_number = _line_number(match.start(), starts)
            findings.append(
                _make_finding(
                    "JS004", language, path, line_number, _line_text(lines, line_number)
                )
            )

        masked_lines = masked.splitlines()
        for matcher in (JS_FIXED_DAY_PRODUCT, JS_FIXED_DAY_LITERAL):
            for match in matcher.finditer(masked):
                if masked.count("\n", match.start(), match.end()):
                    continue
                line_number = _line_number(match.start(), starts)
                line = _line_text(masked_lines, line_number)
                if not _js_temporal_context(line):
                    continue
                if matcher is JS_FIXED_DAY_PRODUCT and not _js_product_is_day(
                    match.group(0)
                ):
                    continue
                findings.append(
                    _make_finding(
                        "JS005",
                        language,
                        path,
                        line_number,
                        _line_text(lines, line_number),
                    )
                )

    if language == "python":
        receivers = _python_datetime_receivers(masked)
        masked_lines = masked.splitlines()
        for match in PY_DATETIME_METHOD.finditer(masked):
            if match.group("receiver") not in receivers:
                continue
            call = _call_arguments(text, masked, match.end() - 1)
            if call is None:
                continue
            _, masked_arguments = call
            method = match.group("method")
            line_number = _line_number(match.start(), starts)
            line = _line_text(lines, line_number)
            if method == "now" and not masked_arguments.strip():
                findings.append(_make_finding("PY001", language, path, line_number, line))
            elif method == "utcnow":
                findings.append(_make_finding("PY002", language, path, line_number, line))
            elif method == "fromtimestamp":
                has_keyword_timezone = bool(re.search(r"\btz\s*=", masked_arguments))
                has_positional_timezone = _has_second_positional_argument(masked_arguments)
                if not has_keyword_timezone and not has_positional_timezone:
                    findings.append(_make_finding("PY003", language, path, line_number, line))
            elif method == "utcfromtimestamp":
                findings.append(_make_finding("PY004", language, path, line_number, line))

        for match in PY_PYTZ_ASSIGNMENT.finditer(masked):
            line_number = _line_number(match.start(), starts)
            findings.append(
                _make_finding(
                    "PY005", language, path, line_number, _line_text(lines, line_number)
                )
            )

        for match in PY_REPLACE_CALL.finditer(masked):
            call = _call_arguments(text, masked, match.end() - 1)
            if call is None:
                continue
            _, masked_arguments = call
            if not re.search(r"\btzinfo\s*=", masked_arguments):
                continue
            line_number = _line_number(match.start(), starts)
            findings.append(
                _make_finding(
                    "PY006", language, path, line_number, _line_text(lines, line_number)
                )
            )

        for match in PY_FIXED_DAY.finditer(masked):
            line_number = _line_number(match.start(), starts)
            line = _line_text(masked_lines, line_number)
            if _python_duration_is_explicitly_safe(line):
                continue
            findings.append(
                _make_finding(
                    "PY007", language, path, line_number, _line_text(lines, line_number)
                )
            )

    return sorted(
        _deduplicate(findings),
        key=lambda finding: (finding.line, finding.rule, finding.path),
    )


def parse_ignore_rules(config: Optional[Dict[str, Any]]) -> List[IgnoreRule]:
    """Parse only the scanner's ignore section and leave semantic notes untouched."""

    if not config:
        return []
    unknown_config_keys = set(config) - {"fields", "ignore"}
    if unknown_config_keys:
        raise ValueError(
            "Unknown config field(s): {}.".format(
                ", ".join(sorted(unknown_config_keys))
            )
        )
    raw_rules = config.get("ignore", [])
    if not isinstance(raw_rules, list):
        raise ValueError("The ignore field in .temporal-guardian.json must be an array.")

    allowed_rule_keys = {"rule", "path", "line", "reason", "match"}
    parsed: List[IgnoreRule] = []
    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise ValueError("Ignore entry {} must be an object.".format(index + 1))
        unknown_rule_keys = set(raw_rule) - allowed_rule_keys
        if unknown_rule_keys:
            raise ValueError(
                "Ignore entry {} has unknown field(s): {}.".format(
                    index + 1, ", ".join(sorted(unknown_rule_keys))
                )
            )
        missing_keys = {"rule", "path", "reason"} - set(raw_rule)
        if missing_keys:
            raise ValueError(
                "Ignore entry {} needs: {}.".format(
                    index + 1, ", ".join(sorted(missing_keys))
                )
            )

        if not isinstance(raw_rule["rule"], str):
            raise ValueError("Ignore entry {} has an invalid rule.".format(index + 1))
        if not isinstance(raw_rule["path"], str) or not raw_rule["path"].strip():
            raise ValueError("Ignore entry {} has an invalid path.".format(index + 1))
        if not isinstance(raw_rule["reason"], str):
            raise ValueError("Ignore entry {} has an invalid reason.".format(index + 1))

        rule = raw_rule["rule"].upper()
        if rule != "*" and rule not in RULES:
            raise ValueError("Ignore entry {} has an unknown rule.".format(index + 1))
        path = raw_rule["path"].replace("\\", "/")
        while path.startswith("./"):
            path = path[2:]
        if not path:
            raise ValueError("Ignore entry {} has an invalid path.".format(index + 1))
        raw_line = raw_rule.get("line")
        line: Optional[int]
        if raw_line is None:
            line = None
        elif isinstance(raw_line, bool) or not isinstance(raw_line, int) or raw_line < 1:
            raise ValueError("Ignore entry {} has an invalid line.".format(index + 1))
        else:
            line = raw_line

        reason = raw_rule["reason"].strip()
        if not reason:
            raise ValueError("Ignore entry {} needs a non-empty reason.".format(index + 1))
        match = raw_rule.get("match")
        if match is not None and (not isinstance(match, str) or not match):
            raise ValueError("Ignore entry {} has an invalid match.".format(index + 1))
        parsed.append(
            IgnoreRule(rule=rule, path=path, line=line, reason=reason, match=match)
        )
    return parsed


def _matches_ignore(finding: Finding, rule: IgnoreRule) -> bool:
    if rule.rule not in {"*", finding.rule}:
        return False
    if not fnmatch.fnmatchcase(finding.path, rule.path):
        return False
    if rule.line is not None and rule.line != finding.line:
        return False
    return rule.match is None or rule.match in finding.evidence


def filter_ignored(
    findings: Iterable[Finding], ignore_rules: Sequence[IgnoreRule]
) -> Tuple[List[Finding], List[Dict[str, Any]]]:
    active: List[Finding] = []
    ignored: List[Dict[str, Any]] = []
    for finding in findings:
        matching_rule = next((rule for rule in ignore_rules if _matches_ignore(finding, rule)), None)
        if matching_rule is None:
            active.append(finding)
        else:
            ignored.append(
                {
                    "rule": finding.rule,
                    "path": finding.path,
                    "line": finding.line,
                    "reason": matching_rule.reason,
                }
            )
    return active, ignored


def _inside(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def iter_source_files(
    root: Path,
    targets: Sequence[str],
    excluded_directories: Optional[List[str]] = None,
) -> Iterable[Path]:
    """Yield source files below root in a stable order, without following links."""

    requested = list(targets) if targets else ["."]
    yielded = set()
    for target in requested:
        target_path = Path(target)
        candidate = target_path if target_path.is_absolute() else root / target_path
        candidate = candidate.resolve()
        if not _inside(root, candidate):
            raise ValueError("Requested path is outside the scan root: {}".format(target))
        if not candidate.exists():
            raise FileNotFoundError("Requested path does not exist: {}".format(target))

        if candidate.is_file():
            candidates = [candidate]
        elif candidate.is_dir():
            candidates = []
            for current, directory_names, file_names in os.walk(
                str(candidate), topdown=True, followlinks=False
            ):
                current_path = Path(current)
                kept_directories = []
                for name in sorted(directory_names):
                    directory = current_path / name
                    if name in EXCLUDED_DIRS:
                        if excluded_directories is not None:
                            excluded_directories.append(
                                directory.relative_to(root).as_posix()
                            )
                        continue
                    if not directory.is_symlink():
                        kept_directories.append(name)
                directory_names[:] = kept_directories
                candidates.extend(
                    current_path / name
                    for name in sorted(file_names)
                    if not (current_path / name).is_symlink()
                )
        else:
            continue

        for path in candidates:
            if path in yielded or path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            yielded.add(path)
            yield path


def load_config(root: Path, config_path: Optional[str]) -> Tuple[List[IgnoreRule], Optional[str]]:
    default_path = root / ".temporal-guardian.json"
    if config_path is None:
        candidate = default_path
        if not candidate.is_file():
            return [], None
    else:
        raw_path = Path(config_path)
        candidate = raw_path if raw_path.is_absolute() else root / raw_path
        candidate = candidate.resolve()
        if not _inside(root, candidate):
            raise ValueError("Config path is outside the scan root: {}".format(config_path))
        if not candidate.is_file():
            raise FileNotFoundError("Config file does not exist: {}".format(config_path))

    data_text = candidate.read_text(encoding="utf-8-sig")
    if data_text.startswith("\ufeff"):
        data_text = data_text[1:]
    data = json.loads(data_text)
    if not isinstance(data, dict):
        raise ValueError("The temporal guardian config must contain a JSON object.")
    relative = candidate.relative_to(root).as_posix()
    return parse_ignore_rules(data), relative


def scan(
    root: Union[str, Path],
    targets: Sequence[str],
    ignore_rules: Sequence[IgnoreRule] = (),
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    list_files: bool = False,
) -> Dict[str, Any]:
    """Scan source files below root and return a JSON-serializable result."""

    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError("Scan root is not a directory: {}".format(root))
    if max_file_bytes < 1:
        raise ValueError("max_file_bytes must be positive.")
    if max_findings < 0:
        raise ValueError("max_findings must be zero or positive.")

    findings: List[Finding] = []
    scanned_files: List[str] = []
    skipped: List[Dict[str, str]] = []
    excluded_directories: List[str] = []
    long_lines: List[Dict[str, Any]] = []

    for path in iter_source_files(root_path, targets, excluded_directories):
        relative_path = path.relative_to(root_path).as_posix()
        try:
            size = path.stat().st_size
        except OSError as exc:
            skipped.append({"path": relative_path, "reason": str(exc)})
            continue
        if size > max_file_bytes:
            skipped.append(
                {
                    "path": relative_path,
                    "reason": "file exceeds max-file-bytes ({})".format(max_file_bytes),
                }
            )
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            skipped.append({"path": relative_path, "reason": str(exc)})
            continue

        scanned_files.append(relative_path)
        long_line_count = sum(
            1 for line in text.splitlines() if len(line) > MAX_LINE_CHARS
        )
        if long_line_count:
            long_lines.append({"path": relative_path, "count": long_line_count})
        findings.extend(scan_text(text, relative_path))

    active, ignored = filter_ignored(findings, ignore_rules)
    active.sort(
        key=lambda finding: (
            -SEVERITY_RANK[finding.severity],
            0 if finding.context == "production" else 1,
            finding.path,
            finding.line,
            finding.rule,
        )
    )
    total_findings = len(active)
    displayed_findings = (
        active if max_findings == 0 else active[:max_findings]
    )
    findings_by_severity = {
        severity: sum(1 for finding in active if finding.severity == severity)
        for severity in ("error", "warning", "info")
    }
    findings_by_rule = {
        rule: sum(1 for finding in active if finding.rule == rule)
        for rule in sorted(RULES)
        if any(finding.rule == rule for finding in active)
    }
    warnings: List[str] = []
    if not scanned_files:
        warnings.append(
            "No supported source files found; this is not a clean scan. "
            "Supported extensions: {}.".format(
                ", ".join(sorted(SOURCE_EXTENSIONS))
            )
        )
    if max_findings and total_findings > max_findings:
        warnings.append(
            "Findings are truncated at {}; summary counts all {} findings. "
            "Use --max-findings 0 or narrow the path.".format(
                max_findings, total_findings
            )
        )
    if skipped:
        warnings.append(
            "{} file(s) could not be analyzed; inspect the skipped list.".format(
                len(skipped)
            )
        )
    if excluded_directories:
        warnings.append(
            "Excluded directories were not scanned: {}.".format(
                ", ".join(sorted(set(excluded_directories)))
            )
        )
    if long_lines:
        warnings.append(
            "{} file(s) contain line(s) longer than {}; those lines were not analyzed.".format(
                len(long_lines), MAX_LINE_CHARS
            )
        )

    result: Dict[str, Any] = {
        "scanner_version": SCANNER_VERSION,
        "root": root_path.as_posix(),
        "summary": {
            "files_scanned": len(scanned_files),
            "files_skipped": len(skipped),
            "excluded_directories": len(set(excluded_directories)),
            "total_findings": total_findings,
            "displayed_findings": len(displayed_findings),
            "findings_by_severity": findings_by_severity,
            "findings_by_rule": findings_by_rule,
        },
        "warnings": warnings,
        "findings": [asdict(finding) for finding in displayed_findings],
        "ignored": ignored,
        "skipped": skipped,
        "excluded_directories": sorted(set(excluded_directories)),
        "long_lines_skipped": long_lines,
    }
    if list_files:
        result["scanned_files"] = scanned_files
    return result


def render_text(result: Dict[str, Any]) -> str:
    summary = result.get("summary", {})
    files_scanned = summary.get("files_scanned", result.get("files_scanned", 0))
    total_findings = summary.get("total_findings", len(result.get("findings", [])))
    displayed_findings = summary.get(
        "displayed_findings", len(result.get("findings", []))
    )
    lines = [
        "Temporal Semantics Guardian scan",
        "Root: {}".format(result["root"]),
        "Files scanned: {}".format(files_scanned),
        "Findings shown: {} of {}".format(displayed_findings, total_findings),
    ]
    if result["skipped"]:
        lines.append("Skipped: {}".format(len(result["skipped"])))

    if result.get("warnings"):
        lines.extend(["", "Warnings:"])
        for warning in result["warnings"]:
            lines.append("  {}".format(warning))

    for finding in result["findings"]:
        lines.extend(
            [
                "",
                "[{severity}] {rule} {path}:{line} ({context}, {confidence} confidence)".format(
                    **finding
                ),
                "  {}".format(finding["message"]),
                "  Evidence: {}".format(finding["evidence"] or "<blank line>"),
                "  Why: {}".format(finding["rationale"]),
                "  Suggestion: {}".format(finding["suggestion"]),
            ]
        )

    if result["ignored"]:
        lines.extend(["", "Suppressed by .temporal-guardian.json:"])
        for ignored in result["ignored"]:
            lines.append(
                "  {rule} {path}:{line} - {reason}".format(**ignored)
            )

    if result["skipped"]:
        lines.extend(["", "Skipped files:"])
        for skipped in result["skipped"]:
            lines.append("  {path} - {reason}".format(**skipped))

    if not result["findings"] and not files_scanned:
        lines.extend(
            ["", "No supported source files were found; the scan is inconclusive."]
        )
    elif not result["findings"]:
        lines.extend(["", "No temporal findings matched the configured rules."])
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only scan for common date and time semantics hazards."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Files or directories below --root to scan; defaults to the whole root.",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root used for relative paths and config discovery.",
    )
    parser.add_argument(
        "--config",
        help="Optional config path below --root; otherwise auto-discovers .temporal-guardian.json.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help="Skip files larger than this size.",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=DEFAULT_MAX_FINDINGS,
        help="Maximum findings to print; use 0 for no limit.",
    )
    parser.add_argument(
        "--list-files",
        action="store_true",
        help="Include every scanned file in JSON output.",
    )
    parser.add_argument(
        "--fail-on",
        choices=("never", "warning", "error"),
        default="never",
        help="Exit with status 1 when a finding reaches this severity.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    stream = getattr(sys, "stdout", None)
    if hasattr(stream, "reconfigure"):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_file_bytes < 1:
        parser.error("--max-file-bytes must be positive.")
    if args.max_findings < 0:
        parser.error("--max-findings must be zero or positive.")

    try:
        root = Path(args.root).resolve()
        ignore_rules, config = load_config(root, args.config)
        result = scan(
            root=root,
            targets=args.paths,
            ignore_rules=ignore_rules,
            max_file_bytes=args.max_file_bytes,
            max_findings=args.max_findings,
            list_files=args.list_files,
        )
        result["config"] = config
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=False))
    else:
        print(render_text(result))

    threshold = {"never": 99, "warning": 2, "error": 3}[args.fail_on]
    if any(
        count
        for severity, count in result["summary"]["findings_by_severity"].items()
        if SEVERITY_RANK[severity] >= threshold
    ):
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(3)
    except Exception as exc:
        print("error: unexpected scanner failure: {}".format(exc), file=sys.stderr)
        raise SystemExit(3)
