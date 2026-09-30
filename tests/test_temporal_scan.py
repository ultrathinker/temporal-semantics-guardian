import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIR))

import temporal_scan


class TemporalScanTests(unittest.TestCase):
    def test_javascript_rules_and_explicit_safe_values(self):
        source = "\n".join(
            [
                'const birth = new Date("2026-03-08");',
                'const local = new Date("2026-03-08T02:30:00");',
                "const reportDate = created.toISOString().slice(0, 10);",
                "const label = created.toLocaleString();",
                "const next = Date.now() + 24 * 60 * 60 * 1000;",
                'const instant = new Date("2026-03-08T02:30:00Z");',
                'const zoned = new Intl.DateTimeFormat("en-US", { timeZone: "Europe/Budapest" });',
                'const amount = total.toLocaleString("en-US", { style: "currency", currency: "USD" });',
                "const nestedZone = created.toLocaleDateString(getLocale(lang), { timeZone: zone });",
                'const commonDay = 1000 * 60 * 60 * 24;',
                'const splitDay = created.toISOString().split("T")[0];',
                'const templateDate = new Date(`2026-04-01`);',
                "const comment = \"// new Date('2026-03-08')\";",
            ]
        )

        findings = temporal_scan.scan_text(source, "src/dates.ts")
        rules = {finding.rule for finding in findings}

        self.assertEqual(rules, {"JS001", "JS002", "JS003", "JS004", "JS005"})
        self.assertFalse(
            any(
                finding.line in {6, 7, 8, 9, 14}
                and finding.rule in {"JS001", "JS002", "JS004"}
                for finding in findings
            )
        )
        self.assertEqual(
            {finding.line for finding in findings if finding.rule == "JS001"},
            {1, 12},
        )
        self.assertEqual(
            {finding.line for finding in findings if finding.rule == "JS003"},
            {3, 11},
        )
        self.assertEqual(
            {finding.line for finding in findings if finding.rule == "JS005"},
            {5, 10},
        )

    def test_python_rules_and_aware_timestamp(self):
        source = "\n".join(
            [
                "naive = datetime.now()",
                "utc_naive = datetime.utcnow()",
                "local = datetime.fromtimestamp(epoch)",
                "aware = datetime.fromtimestamp(epoch, tz=timezone.utc)",
                "positional = datetime.fromtimestamp(epoch, timezone.utc)",
                "legacy = datetime.utcfromtimestamp(epoch)",
                'bad_zone = datetime(2024, 1, 1, tzinfo=pytz.timezone("Europe/Budapest"))',
                "relabeled = value.replace(tzinfo=timezone.utc)",
                "next_run = value + timedelta(days=1)",
                "safe_date = date.today() + timedelta(days=1)",
                "safe_utc = datetime.now(timezone.utc) + timedelta(days=1)",
                'safe_zone = datetime.now(tz=ZoneInfo("America/New_York")) + timedelta(days=1)',
                "fractional = value + timedelta(days=1.5)",
                "# datetime.utcnow()",
                'doc = """datetime.utcnow()"""',
            ]
        )

        findings = temporal_scan.scan_text(source, "src/time.py")
        rules = {finding.rule for finding in findings}

        self.assertEqual(
            rules,
            {"PY001", "PY002", "PY003", "PY004", "PY005", "PY006", "PY007"},
        )
        self.assertFalse(
            any(
                finding.line in {4, 5, 10, 11, 12, 13, 14, 15}
                and finding.rule in {"PY003", "PY007", "PY002"}
                for finding in findings
            )
        )
        self.assertEqual(
            {finding.line for finding in findings if finding.rule == "PY003"},
            {3},
        )
        self.assertEqual(
            {finding.line for finding in findings if finding.rule == "PY007"},
            {9},
        )

    def test_ignore_rules_preserve_audit_reason(self):
        source = 'value = new Date("2026-03-08")\nother = new Date("2026-04-01")'
        findings = temporal_scan.scan_text(source, "src/profile.ts")
        rules = temporal_scan.parse_ignore_rules(
            {
                "ignore": [
                    {
                        "rule": "JS001",
                        "path": "src/profile.ts",
                        "line": 1,
                        "match": "new Date",
                        "reason": "Birth date is a calendar date.",
                    }
                ]
            }
        )

        active, ignored = temporal_scan.filter_ignored(findings, rules)

        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].line, 2)
        self.assertEqual(ignored[0]["reason"], "Birth date is a calendar date.")

    def test_directory_corpus_flags_real_cases_and_stays_quiet_on_safe_cases(self):
        result = temporal_scan.scan(
            PROJECT_ROOT,
            ["tests/fixtures"],
            max_findings=0,
            list_files=True,
        )
        findings = result["findings"]
        actual = [(finding["path"], finding["line"], finding["rule"]) for finding in findings]
        expected = [
            ("tests/fixtures/temporal_mask_recovery.tsx", 2, "JS001"),
            ("tests/fixtures/temporal_mask_recovery.tsx", 3, "JS003"),
            ("tests/fixtures/temporal_mask_recovery.tsx", 6, "JS005"),
            ("tests/fixtures/temporal_mask_recovery.tsx", 7, "JS005"),
            ("tests/fixtures/temporal_mask_recovery.tsx", 8, "JS005"),
            ("tests/fixtures/temporal_mask_recovery.tsx", 9, "JS005"),
            ("tests/fixtures/temporal_mask_recovery.tsx", 10, "JS005"),
            ("tests/fixtures/temporal_mask_recovery.tsx", 11, "JS005"),
            ("tests/fixtures/temporal_must_flag.py", 4, "PY001"),
            ("tests/fixtures/temporal_must_flag.py", 5, "PY002"),
            ("tests/fixtures/temporal_must_flag.py", 6, "PY003"),
            ("tests/fixtures/temporal_must_flag.py", 8, "PY001"),
            ("tests/fixtures/temporal_must_flag.py", 9, "PY002"),
            ("tests/fixtures/temporal_must_flag.ts", 1, "JS001"),
            ("tests/fixtures/temporal_must_flag.ts", 2, "JS002"),
            ("tests/fixtures/temporal_must_flag.ts", 4, "JS003"),
            ("tests/fixtures/temporal_must_flag.ts", 6, "JS005"),
            ("tests/fixtures/temporal_must_flag.py", 7, "PY007"),
            ("tests/fixtures/temporal_must_flag.ts", 7, "JS004"),
        ]

        self.assertEqual(result["summary"]["files_scanned"], 4)
        self.assertEqual(actual, expected)
        self.assertTrue(all(finding["context"] == "test" for finding in findings))
        self.assertNotIn(
            "tests/fixtures/temporal_must_stay_quiet.ts",
            {finding["path"] for finding in findings},
        )

    def test_json_is_findings_first_and_truncation_is_explicit(self):
        output = io.StringIO()
        with patch.object(sys, "stdout", output):
            code = temporal_scan.main(
                [
                    "--root",
                    str(PROJECT_ROOT),
                    "--format",
                    "json",
                    "--max-findings",
                    "2",
                    "tests/fixtures",
                ]
            )

        payload = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(payload["summary"]["displayed_findings"], 2)
        self.assertGreater(payload["summary"]["total_findings"], 2)
        self.assertTrue(any("truncated" in warning for warning in payload["warnings"]))
        self.assertNotIn("scanned_files", payload)
        self.assertLess(list(payload).index("findings"), list(payload).index("warnings"))
        self.assertLess(list(payload).index("findings"), list(payload).index("skipped"))

    def test_excluded_directories_are_aggregated_and_paths_are_opt_in(self):
        def fake_iter(root, targets, excluded):
            excluded.extend(
                [
                    "packages/one/node_modules",
                    "packages/two/node_modules",
                    "packages/one/dist",
                    ".git",
                ]
            )
            yield PROJECT_ROOT / "scripts" / "temporal_scan.py"

        with patch.object(temporal_scan, "iter_source_files", fake_iter):
            result = temporal_scan.scan(PROJECT_ROOT, ["."], max_findings=0)
            listed = temporal_scan.scan(
                PROJECT_ROOT, ["."], max_findings=0, list_files=True
            )

        self.assertEqual(
            result["excluded_directories"],
            {".git": 1, "dist": 1, "node_modules": 2},
        )
        self.assertNotIn("excluded_directory_paths", result)
        self.assertEqual(
            listed["excluded_directory_paths"],
            [".git", "packages/one/dist", "packages/one/node_modules", "packages/two/node_modules"],
        )
        self.assertIn("node_modules x2", result["warnings"][0])
        self.assertNotIn("packages/one", result["warnings"][0])
        self.assertNotIn(".git", result["warnings"][0])

    def test_locale_heuristics_require_temporal_evidence(self):
        source = "\n".join(
            [
                "const amount = order.amountDue.toLocaleString(\"en-US\", { style: \"currency\" });",
                "const count = attendees.length.toLocaleString();",
                "const display = created.toLocaleString();",
                "const shorthand = created.toLocaleDateString(\"en-US\", timeZone && { timeZone });",
                "const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;",
            ]
        )
        findings = temporal_scan.scan_text(source, "src/display.ts")

        self.assertEqual(
            [(finding.line, finding.rule) for finding in findings],
            [(3, "JS004")],
        )

    def test_fail_on_threshold_uses_full_summary(self):
        warning_output = io.StringIO()
        with patch.object(sys, "stdout", warning_output):
            warning_code = temporal_scan.main(
                [
                    "--root",
                    str(PROJECT_ROOT),
                    "--format",
                    "json",
                    "--fail-on",
                    "warning",
                    "tests/fixtures",
                ]
            )

        error_output = io.StringIO()
        with patch.object(sys, "stdout", error_output):
            error_code = temporal_scan.main(
                [
                    "--root",
                    str(PROJECT_ROOT),
                    "--format",
                    "json",
                    "--fail-on",
                    "error",
                    "tests/fixtures",
                ]
            )

        self.assertEqual(warning_code, 1)
        self.assertEqual(error_code, 0)

    def test_no_source_files_are_reported_as_inconclusive(self):
        result = temporal_scan.scan(PROJECT_ROOT, ["README.md"])

        self.assertEqual(result["summary"]["files_scanned"], 0)
        self.assertTrue(any("No supported source files" in warning for warning in result["warnings"]))
        self.assertIn("inconclusive", temporal_scan.render_text(result))

    def test_scope_safety_exclusions_and_file_cap(self):
        with self.assertRaises(ValueError):
            temporal_scan.scan(PROJECT_ROOT, [".."])

        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as scratch_root:
            scratch = Path(scratch_root)
            (scratch / ".git").mkdir()
            (scratch / "sample.py").write_text(
                "value = datetime.utcnow()\n", encoding="utf-8"
            )
            root_result = temporal_scan.scan(scratch, ["."])
            self.assertEqual(root_result["excluded_directories"], {".git": 1})
            self.assertFalse(
                any("Excluded directories" in warning for warning in root_result["warnings"])
            )

        capped = temporal_scan.scan(
            PROJECT_ROOT,
            ["scripts/temporal_scan.py"],
            max_file_bytes=1,
        )
        self.assertEqual(capped["summary"]["files_scanned"], 0)
        self.assertEqual(len(capped["skipped"]), 1)
        self.assertTrue(capped["warnings"])

    def test_pathological_lines_are_skipped_with_a_warning(self):
        long_source = "x" * (temporal_scan.MAX_LINE_CHARS + 1) + " datetime.now()"
        with patch.object(Path, "read_text", return_value=long_source):
            result = temporal_scan.scan(
                PROJECT_ROOT,
                ["scripts/temporal_scan.py"],
                max_findings=0,
            )

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["long_lines_skipped"][0]["count"], 1)
        self.assertTrue(any("2000" in warning for warning in result["warnings"]))

    def test_masker_preserves_code_after_quotes_and_masks_literals(self):
        source = "\n".join(
            [
                "const escaped = (value) => value.replace(/'/g, \"&#39;\");",
                'const birthday = new Date("2026-03-08");',
                "export const reminder = () => <p>Don't forget</p>;",
                'const text = "// new Date(\\\"2026-03-08\\\")";',
                "const template = `${new Date(\"2026-04-01\")}`;",
            ]
        )
        findings = temporal_scan.scan_text(source, "src/reminder.tsx")

        self.assertEqual(
            [(finding.line, finding.rule) for finding in findings],
            [(2, "JS001")],
        )

        python_source = "value = '# datetime.utcnow()'\n# datetime.utcnow()\nvalue = datetime.utcnow()"
        python_findings = temporal_scan.scan_text(python_source, "src/value.py")
        self.assertEqual(
            [(finding.line, finding.rule) for finding in python_findings],
            [(3, "PY002")],
        )

    def test_call_and_line_bounds_keep_evidence_stable(self):
        unclosed = (
            "created.toLocaleDateString("
            + ("x" * temporal_scan.MAX_CALL_SCAN_CHARS)
            + ")"
        )
        self.assertIsNone(temporal_scan._balanced_call(unclosed, unclosed.index("(")))

        for separator in ("\f", "\u2028", "\u0085", "\r"):
            source = "prefix = 1" + separator + "value = datetime.now()"
            findings = temporal_scan.scan_text(source, "src/value.py")
            self.assertEqual(len(findings), 1)
            self.assertIn("datetime.now()", findings[0].evidence)

    def test_python_today_references_and_timezone_removal_are_described(self):
        source = "\n".join(
            [
                "today = datetime.today()",
                "factory = datetime.utcnow",
                "stripped = value.replace(tzinfo=None)",
            ]
        )
        findings = temporal_scan.scan_text(source, "src/time.py")

        self.assertEqual(
            [(finding.line, finding.rule) for finding in findings],
            [(1, "PY001"), (2, "PY002"), (3, "PY006")],
        )
        self.assertIn("rewrites timezone metadata", findings[-1].message)

    def test_entrypoint_and_cli_input_errors_have_distinct_statuses(self):
        with patch.object(temporal_scan, "main", side_effect=RuntimeError("boom")):
            with patch.object(sys, "stderr", io.StringIO()) as stderr:
                self.assertEqual(temporal_scan._entrypoint(), 3)
                self.assertIn("unexpected scanner failure", stderr.getvalue())

        output = io.StringIO()
        with patch.object(sys, "stdout", output), patch.object(sys, "stderr", io.StringIO()):
            code = temporal_scan.main(["--root", str(PROJECT_ROOT / "missing")])
        self.assertEqual(code, 2)

    def test_real_subprocess_handles_cp1252_pipe(self):
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as scratch_root:
            scratch = Path(scratch_root)
            (scratch / "sample.py").write_text(
                "value = datetime.utcnow()  # caf\u00e9\n", encoding="utf-8"
            )
            environment = os.environ.copy()
            environment["PYTHONIOENCODING"] = "cp1252"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / "temporal_scan.py"),
                    "--root",
                    str(scratch),
                    "--format",
                    "text",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                check=False,
            )

        output = completed.stdout.decode("utf-8")
        self.assertEqual(completed.returncode, 0)
        self.assertIn("caf\u00e9", output)
        self.assertNotIn("Traceback", completed.stderr.decode("utf-8", errors="replace"))

    def test_config_schema_bom_path_and_match(self):
        with self.assertRaises(ValueError):
            temporal_scan.parse_ignore_rules({"ignore": [{}]})
        with self.assertRaises(ValueError):
            temporal_scan.parse_ignore_rules(
                {
                    "ignore": [
                        {
                            "rule": "JS001",
                            "path": "src/a.ts",
                            "reason": "x",
                            "unexpected": True,
                        }
                    ]
                }
            )

        rules = temporal_scan.parse_ignore_rules(
            {
                "ignore": [
                    {
                        "rule": "JS001",
                        "path": "./src/a.ts",
                        "match": "new Date",
                        "reason": "Calendar date by contract.",
                    }
                ]
            }
        )
        findings = temporal_scan.scan_text(
            'value = new Date("2026-03-08")', "src/a.ts"
        )
        active, ignored = temporal_scan.filter_ignored(findings, rules)
        self.assertEqual(active, [])
        self.assertEqual(ignored[0]["reason"], "Calendar date by contract.")

        with patch.object(Path, "is_file", return_value=True), patch.object(
            Path, "read_text", return_value='\ufeff{"ignore": []}'
        ):
            parsed, path = temporal_scan.load_config(
                PROJECT_ROOT, "tests/fixtures/config.json"
            )
        self.assertEqual(parsed, [])
        self.assertEqual(path, "tests/fixtures/config.json")

        with patch.object(Path, "is_file", return_value=True), patch.object(
            Path,
            "read_text",
            side_effect=UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid"),
        ):
            with self.assertRaisesRegex(ValueError, "Config file"):
                temporal_scan.load_config(PROJECT_ROOT, "tests/fixtures/config.json")

    def test_cli_text_handles_cp1252_stdout_and_returns_finding_status(self):
        result = {
            "root": ".",
            "summary": {
                "files_scanned": 1,
                "files_skipped": 0,
                "excluded_directories": 0,
                "total_findings": 1,
                "displayed_findings": 1,
                "findings_by_severity": {"error": 0, "warning": 1, "info": 0},
                "findings_by_rule": {"PY001": 1},
            },
            "warnings": [],
            "findings": [
                {
                    "rule": "PY001",
                    "severity": "warning",
                    "confidence": "high",
                    "language": "python",
                    "path": "u.py",
                    "context": "production",
                    "line": 1,
                    "message": "datetime.now() creates a naive datetime.",
                    "evidence": "x = datetime.now()  # caf\u00e9 \U0001f552",
                    "rationale": "reason",
                    "suggestion": "suggest",
                }
            ],
            "ignored": [],
            "skipped": [],
        }
        raw = io.BytesIO()
        cp1252_stdout = io.TextIOWrapper(raw, encoding="cp1252")
        with patch.object(temporal_scan, "scan", return_value=result), patch.object(
            temporal_scan, "load_config", return_value=([], None)
        ), patch.object(sys, "stdout", cp1252_stdout):
            code = temporal_scan.main(["--root", ".", "--format", "text"])
            cp1252_stdout.flush()

        self.assertEqual(code, 0)
        self.assertIn("caf\u00e9 \U0001f552".encode("utf-8"), raw.getvalue())

    def test_render_text_is_useful_when_no_findings_match(self):
        result = {
            "root": ".",
            "files_scanned": 3,
            "findings": [],
            "ignored": [],
            "skipped": [],
        }

        output = temporal_scan.render_text(result)

        self.assertIn("Files scanned: 3", output)
        self.assertIn("No temporal findings matched", output)


if __name__ == "__main__":
    unittest.main()
