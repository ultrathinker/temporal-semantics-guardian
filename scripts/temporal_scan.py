#!/usr/bin/env python3
"""Run a deterministic, read-only scan for common temporal semantics hazards.

The scanner intentionally reports review prompts rather than claiming that a
pattern is always a defect. It has no third-party dependencies and never
writes to the repository.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union


SCANNER_VERSION = "0.1.0"
DEFAULT_MAX_FILE_BYTES = 1_000_000
SOURCE_EXTENSIONS = {
    ".cjs",
    ".js",
    ".jsx",
    ".mjs",
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
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "vendor",
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
        "message": "Date/time formatting does not specify a timeZone option.",
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
            "A civil day can be 23 or 25 elapsed hours across daylight-saving "
            "transitions."
        ),
        "suggestion": (
            "Choose elapsed-time arithmetic or calendar arithmetic explicitly and "
            "use a zone-aware API."
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
        "message": "datetime.fromtimestamp() has no timezone argument on this line.",
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
        "severity": "warning",
        "confidence": "medium",
        "message": "Code adds or subtracts a one-day or 24-hour timedelta.",
        "rationale": (
            "A fixed duration is not always the same as moving to the same local "
            "time on the next calendar day."
        ),
        "suggestion": (
            "Decide whether the operation means elapsed time or calendar recurrence, "
            "then use an API that preserves that meaning."
        ),
    },
}


JS_DATE_ONLY = re.compile(
    r"""\b(?:new\s+Date|Date\.parse)\s*\(\s*(?P<quote>["'])(?P<value>\d{4}-\d{2}-\d{2})(?P=quote)"""
)
JS_LOCAL_DATETIME = re.compile(
    r"""\b(?:new\s+Date|Date\.parse)\s*\(\s*(?P<quote>["'])(?P<value>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)(?P=quote)"""
)
JS_ISO_DATE_SLICE = re.compile(
    r"""\.toISOString\(\)\s*\.\s*(?:slice|substring|substr)\s*\(\s*0\s*,\s*10\s*\)"""
)
JS_LOCALE_CALL = re.compile(
    r"""\.(?:toLocaleString|toLocaleDateString|toLocaleTimeString)\s*\((?P<args>[^)]*)\)"""
)
JS_INTL_FORMAT = re.compile(
    r"""\bIntl\.DateTimeFormat\s*\((?P<args>[^)]*)\)"""
)
JS_FIXED_DAY = re.compile(
    r"""(?<![\w])(?:24\s*\*\s*60\s*\*\s*60\s*\*\s*1000|86_?400_?000)(?![\w])"""
)

PY_NAIVE_NOW = re.compile(
    r"""\b(?:datetime\.)?datetime\.now\s*\(\s*\)|\bdatetime\.now\s*\(\s*\)"""
)
PY_UTC_NOW = re.compile(
    r"""\b(?:datetime\.)?datetime\.utcnow\s*\(\s*\)|\bdatetime\.utcnow\s*\(\s*\)"""
)
PY_FROM_TIMESTAMP = re.compile(
    r"""\b(?:datetime\.)?datetime\.fromtimestamp\s*\(|\bdatetime\.fromtimestamp\s*\("""
)
PY_UTC_FROM_TIMESTAMP = re.compile(
    r"""\b(?:datetime\.)?datetime\.utcfromtimestamp\s*\(|\bdatetime\.utcfromtimestamp\s*\("""
)
PY_PYTZ_ASSIGNMENT = re.compile(
    r"""\btzinfo\s*=\s*pytz\.timezone\s*\("""
)
PY_REPLACE_TZINFO = re.compile(
    r"""\.replace\s*\([^)\n]*\btzinfo\s*="""
)
PY_FIXED_DAY = re.compile(
    r"""(?:\+|\-)\s*timedelta\s*\(\s*(?:days\s*=\s*1\b|hours\s*=\s*24\b)"""
)


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    confidence: str
    language: str
    path: str
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


def _language_for_path(path: str) -> Optional[str]:
    suffix = Path(path).suffix.lower()
    if suffix in {".cjs", ".js", ".jsx", ".mjs", ".ts", ".tsx"}:
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


def _single_line_call_args(line: str, opening_end: int) -> Optional[str]:
    closing = line.rfind(")")
    if closing < opening_end:
        return None
    return line[opening_end:closing]


def scan_text(text: str, path: str) -> List[Finding]:
    """Scan one source string and return stable, line-oriented findings."""

    language = _language_for_path(path)
    if language is None:
        return []

    findings: List[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if language == "javascript":
            if JS_DATE_ONLY.search(line):
                findings.append(_make_finding("JS001", language, path, line_number, line))
            if JS_LOCAL_DATETIME.search(line):
                findings.append(_make_finding("JS002", language, path, line_number, line))
            if JS_ISO_DATE_SLICE.search(line):
                findings.append(_make_finding("JS003", language, path, line_number, line))

            for matcher in (JS_LOCALE_CALL, JS_INTL_FORMAT):
                for match in matcher.finditer(line):
                    args = match.group("args")
                    if "timezone" not in args.lower():
                        findings.append(_make_finding("JS004", language, path, line_number, line))

            if JS_FIXED_DAY.search(line):
                findings.append(_make_finding("JS005", language, path, line_number, line))

        if language == "python":
            if PY_NAIVE_NOW.search(line):
                findings.append(_make_finding("PY001", language, path, line_number, line))
            if PY_UTC_NOW.search(line):
                findings.append(_make_finding("PY002", language, path, line_number, line))
            if PY_UTC_FROM_TIMESTAMP.search(line):
                findings.append(_make_finding("PY004", language, path, line_number, line))

            for match in PY_FROM_TIMESTAMP.finditer(line):
                args = _single_line_call_args(line, match.end())
                if args is not None and not re.search(r"\btz\s*=", args):
                    findings.append(_make_finding("PY003", language, path, line_number, line))

            if PY_PYTZ_ASSIGNMENT.search(line):
                findings.append(_make_finding("PY005", language, path, line_number, line))
            if PY_REPLACE_TZINFO.search(line):
                findings.append(_make_finding("PY006", language, path, line_number, line))
            if PY_FIXED_DAY.search(line):
                findings.append(_make_finding("PY007", language, path, line_number, line))

    return _deduplicate(findings)


def parse_ignore_rules(config: Optional[Dict[str, Any]]) -> List[IgnoreRule]:
    """Parse only the scanner's ignore section and leave semantic notes untouched."""

    if not config:
        return []
    raw_rules = config.get("ignore", [])
    if not isinstance(raw_rules, list):
        raise ValueError("The ignore field in .temporal-guardian.json must be an array.")

    parsed: List[IgnoreRule] = []
    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise ValueError("Ignore entry {} must be an object.".format(index + 1))

        rule = str(raw_rule.get("rule", "*")).upper()
        path = str(raw_rule.get("path", "**")).replace("\\", "/")
        raw_line = raw_rule.get("line")
        line: Optional[int]
        if raw_line is None:
            line = None
        elif isinstance(raw_line, bool) or not isinstance(raw_line, int) or raw_line < 1:
            raise ValueError("Ignore entry {} has an invalid line.".format(index + 1))
        else:
            line = raw_line

        reason = str(raw_rule.get("reason", "Intentionally accepted by repository policy.")).strip()
        if not reason:
            raise ValueError("Ignore entry {} needs a non-empty reason.".format(index + 1))
        parsed.append(IgnoreRule(rule=rule, path=path, line=line, reason=reason))
    return parsed


def _matches_ignore(finding: Finding, rule: IgnoreRule) -> bool:
    if rule.rule not in {"*", finding.rule}:
        return False
    if not fnmatch.fnmatchcase(finding.path, rule.path):
        return False
    return rule.line is None or rule.line == finding.line


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


def iter_source_files(root: Path, targets: Sequence[str]) -> Iterable[Path]:
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
                directory_names[:] = sorted(
                    name
                    for name in directory_names
                    if name not in EXCLUDED_DIRS
                    and not (current_path / name).is_symlink()
                )
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

    data = json.loads(candidate.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("The temporal guardian config must contain a JSON object.")
    relative = candidate.relative_to(root).as_posix()
    return parse_ignore_rules(data), relative


def scan(
    root: Union[str, Path],
    targets: Sequence[str],
    ignore_rules: Sequence[IgnoreRule] = (),
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> Dict[str, Any]:
    """Scan source files below root and return a JSON-serializable result."""

    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError("Scan root is not a directory: {}".format(root))
    if max_file_bytes < 1:
        raise ValueError("max_file_bytes must be positive.")

    findings: List[Finding] = []
    scanned_files: List[str] = []
    skipped: List[Dict[str, str]] = []

    for path in iter_source_files(root_path, targets):
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
        findings.extend(scan_text(text, relative_path))

    active, ignored = filter_ignored(_deduplicate(findings), ignore_rules)
    return {
        "scanner_version": SCANNER_VERSION,
        "root": root_path.as_posix(),
        "files_scanned": len(scanned_files),
        "scanned_files": scanned_files,
        "skipped": skipped,
        "findings": [asdict(finding) for finding in active],
        "ignored": ignored,
    }


def render_text(result: Dict[str, Any]) -> str:
    lines = [
        "Temporal Semantics Guardian scan",
        "Root: {}".format(result["root"]),
        "Files scanned: {}".format(result["files_scanned"]),
        "Findings: {}".format(len(result["findings"])),
    ]
    if result["skipped"]:
        lines.append("Skipped: {}".format(len(result["skipped"])))

    for finding in result["findings"]:
        lines.extend(
            [
                "",
                "[{severity}] {rule} {path}:{line} ({confidence} confidence)".format(
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

    if not result["findings"]:
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
        "--fail-on",
        choices=("never", "warning", "error"),
        default="never",
        help="Exit with status 1 when a finding reaches this severity.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_file_bytes < 1:
        parser.error("--max-file-bytes must be positive.")

    try:
        root = Path(args.root).resolve()
        ignore_rules, config = load_config(root, args.config)
        result = scan(
            root=root,
            targets=args.paths,
            ignore_rules=ignore_rules,
            max_file_bytes=args.max_file_bytes,
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
        SEVERITY_RANK[finding["severity"]] >= threshold
        for finding in result["findings"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
