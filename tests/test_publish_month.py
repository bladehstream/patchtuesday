"""Publisher ordering and existing inference gates, using temporary data only."""

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "publish_month.py"
SPEC = importlib.util.spec_from_file_location("publish_month", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def assessed_record(cve="CVE-TEST-1"):
    return {
        "cve": cve,
        "inference": {"review_status": "reviewed", "framework_assessment": {"test": True}},
    }


class PublishMonthTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.manifest = self.data / "months.json"

    def set_manifest(self, months):
        entries = [{"month": month, "file": f"{month}.jsonl"} for month in months]
        self.manifest.write_text(json.dumps(entries) + "\n", encoding="utf-8")

    def publish(self, month, records, label=None):
        source = self.root / "input.jsonl"
        source.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
        argv = [str(MODULE_PATH), str(source), "--month", month]
        if label is not None:
            argv += ["--label", label]
        with patch.object(MODULE, "DATA", self.data), patch.object(MODULE, "MANIFEST", self.manifest), \
                patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
            MODULE.main()
        return json.loads(self.manifest.read_text(encoding="utf-8"))

    def test_every_calendar_month_and_year_order(self):
        months = [f"2026-{name}" for name in reversed(MODULE.MONTHS)]
        months += ["2027-Jan", "2025-Dec", "2026-Nov-demo"]
        entries = sorted(({"month": month} for month in months), key=MODULE.release_sort_key, reverse=True)
        self.assertEqual([entry["month"] for entry in entries], [
            "2027-Jan", "2026-Dec", "2026-Nov", "2026-Nov-demo", "2026-Oct", "2026-Sep",
            "2026-Aug", "2026-Jul", "2026-Jun", "2026-May", "2026-Apr", "2026-Mar",
            "2026-Feb", "2026-Jan", "2025-Dec",
        ])

    def test_november_publication_becomes_first_real_release(self):
        self.set_manifest(["2026-Sep-demo", "2026-Sep", "2026-Oct", "2026-Nov-demo"])
        rows = [assessed_record()]
        entries = self.publish("2026-Nov", rows, label="November 2026")
        self.assertEqual([entry["month"] for entry in entries], [
            "2026-Nov", "2026-Nov-demo", "2026-Oct", "2026-Sep", "2026-Sep-demo",
        ])
        preferred = next(entry for entry in entries if not entry["month"].endswith("-demo"))
        self.assertEqual(preferred["month"], "2026-Nov")
        self.assertEqual(preferred["label"], "November 2026")
        self.assertEqual(preferred["record_count"], 1)
        copied = [json.loads(line) for line in (self.data / preferred["file"]).read_text(encoding="utf-8").splitlines()]
        self.assertEqual(copied, rows)

    def test_new_year_comes_before_previous_december(self):
        self.set_manifest(["2026-Dec", "2026-Sep"])
        entries = self.publish("2027-Jan", [assessed_record()])
        self.assertEqual([entry["month"] for entry in entries], ["2027-Jan", "2026-Dec", "2026-Sep"])

    def test_republication_replaces_only_its_manifest_entry(self):
        self.set_manifest(["2026-Nov", "2026-Sep"])
        old_september = self.manifest.read_text(encoding="utf-8")
        september_entry = json.loads(old_september)[1]
        records = [assessed_record(), assessed_record("CVE-TEST-2")]
        entries = self.publish("2026-Nov", records)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[1], september_entry)
        self.assertEqual(entries[0]["record_count"], 2)

    def test_existing_rejection_gates_leave_manifest_and_dataset_untouched(self):
        self.set_manifest(["2026-Sep"])
        before = self.manifest.read_bytes()
        invalid = [
            ([], "JSONL file is empty"),
            ([assessed_record(), assessed_record()], "Duplicate CVEs"),
            ([{"cve": "CVE-TEST-1"}], "Refusing partial inference"),
            ([{"cve": "CVE-TEST-1", "inference": {"review_status": "reviewed"}}], "Refusing partial inference"),
            ([{"cve": "CVE-TEST-1", "inference": {"review_status": "pending", "framework_assessment": {"test": True}}}], "Refusing partial inference"),
        ]
        for records, message in invalid:
            with self.subTest(message=message, records=records):
                with self.assertRaisesRegex(SystemExit, message):
                    self.publish("2026-Nov", records)
                self.assertEqual(self.manifest.read_bytes(), before)
                self.assertFalse((self.data / "2026-Nov.jsonl").exists())

    def test_demo_keeps_its_existing_inference_exemption(self):
        self.set_manifest(["2026-Nov", "2026-Sep"])
        entries = self.publish("2026-Nov-demo", [{"cve": "CVE-TEST-DEMO"}])
        self.assertEqual([entry["month"] for entry in entries], ["2026-Nov", "2026-Nov-demo", "2026-Sep"])


if __name__ == "__main__":
    unittest.main()
