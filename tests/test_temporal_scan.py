import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
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
            ]
        )

        findings = temporal_scan.scan_text(source, "src/dates.ts")
        rules = {finding.rule for finding in findings}

        self.assertEqual(rules, {"JS001", "JS002", "JS003", "JS004", "JS005"})
        self.assertFalse(
            any(
                finding.line in {6, 7} and finding.rule in {"JS001", "JS002", "JS004"}
                for finding in findings
            )
        )

    def test_python_rules_and_aware_timestamp(self):
        source = "\n".join(
            [
                "naive = datetime.now()",
                "utc_naive = datetime.utcnow()",
                "local = datetime.fromtimestamp(epoch)",
                "aware = datetime.fromtimestamp(epoch, tz=timezone.utc)",
                "legacy = datetime.utcfromtimestamp(epoch)",
                'bad_zone = datetime(2024, 1, 1, tzinfo=pytz.timezone("Europe/Budapest"))',
                "relabeled = value.replace(tzinfo=timezone.utc)",
                "next_run = value + timedelta(days=1)",
            ]
        )

        findings = temporal_scan.scan_text(source, "src/time.py")
        rules = {finding.rule for finding in findings}

        self.assertEqual(
            rules,
            {"PY001", "PY002", "PY003", "PY004", "PY005", "PY006", "PY007"},
        )
        self.assertFalse(
            any(finding.line == 4 and finding.rule == "PY003" for finding in findings)
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
                        "reason": "Birth date is a calendar date.",
                    }
                ]
            }
        )

        active, ignored = temporal_scan.filter_ignored(findings, rules)

        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].line, 2)
        self.assertEqual(ignored[0]["reason"], "Birth date is a calendar date.")

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
