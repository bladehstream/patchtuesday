"""Offline monthly orchestration checks. No provider, remote Git or live HTTP calls."""
from __future__ import annotations

import ast
from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import shutil
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "tests")]
import claude_stream
import fetch_cve_enrichment
import monthly_sources as sources
import run_cli_inference as adapter
import run_month as monthly
from test_monthly_assessor import fixture, stream


def public_documents(count=2):
    record, _, _ = fixture()
    vulns, cnas = [], {}
    for index in range(count):
        cve = f"CVE-2026-{999900+index}"
        vulns.append({"CVE": cve, "Title": {"Value": record["title"]},
                      "Notes": [{"Title": "Description", "Type": 1, "Value": record["title"]}],
                      "Threats": [{"Type": 3, "Description": {"Value": "Important"}, "ProductID": ["100"]},
                                  {"Type": 1, "Description": {"Value": "Exploitation More Likely"}},
                                  {"Type": 0, "Description": {"Value": "Elevation of Privilege"}}],
                      "CVSSScoreSets": [{"BaseScore": 7.8, "Vector": record["cvss"]["vector"], "ProductID": ["100"]}],
                      "ProductStatuses": [{"Type": 3, "ProductID": ["100"]}]})
        cnas[cve] = {"cveMetadata": {"cveId": cve, "state": "PUBLISHED", "assignerShortName": "Microsoft"},
                     "containers": {"cna": {"providerMetadata": {"shortName": "Microsoft", "orgId": "private-metadata"},
                        "descriptions": [{"lang": "en", "value": record["title"]}],
                        "affected": [{"vendor": "Microsoft", "product": "Windows", "versions": [{"version": "1.2.3.4", "status": "affected"}]}]}}}
    return {"ProductTree": {"FullProductName": [{"ProductID": "100", "Value": "Windows Server 2022"}]}, "Vulnerability": vulns}, cnas


class OfflineRun(monthly.MonthlyRun):
    """Replace network, model process and external Git only; production validators run."""
    def __init__(self, args, work, documents):
        super().__init__(args)
        self.work, self.documents = work, documents
        self.cli, self.model_calls, self.git_calls = "fake-claude", 0, []
        self.snapshot_count, self.bad_answers, self.moved = 0, False, False
        self.revise = False

    def preflight(self):
        pass

    def script(self, name, *arguments, **kwargs):
        values = dict(zip(map(str, arguments[::2]), arguments[1::2]))
        if name == "fetch_sources.py":
            raw = Path(values["--output-dir"]); raw.mkdir(parents=True)
            self.snapshot_count += 1
            document = copy.deepcopy(self.documents[0])
            if self.revise and self.snapshot_count >= 2:
                document["Vulnerability"][0]["Threats"][2]["Description"]["Value"] = "Changed structured impact"
            (raw / f"{self.args.month}.json").write_bytes(sources.canonical(document))
            (raw / "known_exploited_vulnerabilities.json").write_text('{"vulnerabilities":[]}')
            (raw / "epss_scores-current.csv").write_text("cve,epss,percentile\n")
            (raw / f"{self.args.month}-fetch-metadata.json").write_text(json.dumps({"fetched_at": str(self.snapshot_count), "sources": {}}))
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if name == "fetch_cve_enrichment.py":
            cache = Path(values["--cache-dir"]); cache.mkdir(parents=True)
            rows = []
            for cve, doc in self.documents[1].items():
                raw = sources.canonical(doc); (cache / f"{cve}.json").write_bytes(raw)
                rows.append({"cve": cve, "status": "found", "sha256": sources.sha(raw),
                             "url": fetch_cve_enrichment.record_url(cve), **fetch_cve_enrichment.extract(doc)})
            sources.write_rows(Path(values["--output"]), rows)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if name == "run_cli_inference.py":
            self.model_calls += 1
            rows = sources.read_rows(Path(values["--records"]))
            answers = []
            for row in rows:
                answer = fixture()[1]; answer["cve"] = row["cve"]; answers.append(answer)
            if self.bad_answers:
                answers = []  # Exact cardinality must reject it, never repair it.
            raw = stream({"assessments": answers})
            def invoke(command, prompt, timeout, label, *, raw_path, stderr_path, **kwargs):
                assert "Synthetic good/bad" in prompt
                assert "public_msrc_evidence" in prompt
                assert "public_cve_evidence" in prompt
                raw_path.write_bytes(raw); stderr_path.write_text("")
                return 0, raw, "", None
            with patch.object(sys, "argv", [name, *map(str, arguments)]), patch.object(adapter, "invoke", side_effect=invoke):
                with redirect_stdout(io.StringIO()):
                    adapter.main()
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return super().script(name, *arguments, **kwargs)

    def git(self, *args, cwd=ROOT, **kwargs):
        self.git_calls.append(args)
        if args[:2] == ("worktree", "add"):
            directory = Path(args[3]); directory.mkdir(parents=True)
            (directory / "scripts").mkdir(); (directory / "data").mkdir()
            for name in ("index.html", "app.js", "styles.css", "engine.js", "risk-model.js", "_headers", "package.json"):
                shutil.copyfile(ROOT / name, directory / name)
            if (ROOT / "advisory-view.js").is_file():
                shutil.copyfile(ROOT / "advisory-view.js", directory / "advisory-view.js")
            for name in ("publish_month.py", "build-pages.mjs", "validate-coverage.mjs"):
                shutil.copyfile(ROOT / "scripts" / name, directory / "scripts" / name)
            for source in (ROOT / "data").glob("*.json"):
                shutil.copyfile(source, directory / "data" / source.name)
            (directory / "data/months.json").write_text("[]")
        if args[0] == "status": return " M data/months.json\n?? data/2026-Dec.jsonl"
        if args[:2] == ("diff", "--cached"): return "data/months.json\ndata/2026-Dec.jsonl"
        if args[0] == "rev-parse": return "candidate" if args[1] == "HEAD" else "base"
        return ""

    def remote_head(self):
        return "moved" if self.moved else "base"

    def command(self, argv, **kwargs):
        label = kwargs.get("label")
        if label in {"release-tests", "browser-benchmark"}:
            return SimpleNamespace(returncode=0, stdout="offline gate double", stderr="")
        if label == "release-build":
            return super().command([shutil.which("node"), "scripts/build-pages.mjs"], **kwargs)
        return super().command(argv, **kwargs)

    def verify_live(self, expected, expected_sha):
        asset = Path(self.receipt["publication"]) / "dist/data" / expected["file"]
        manifest = [{"month": self.args.month, "file": expected["file"]}]
        def get(url, **kwargs):
            address = url.full_url if hasattr(url, "full_url") else url
            return io.BytesIO(sources.canonical(manifest) if "months.json" in address else asset.read_bytes())
        with patch.object(monthly.urllib.request, "urlopen", side_effect=get):
            super().verify_live(expected, expected_sha)


class MonthlyRunTests(unittest.TestCase):
    def setUp(self):
        # Exact-source proofs require a repo-contained ignored cache.
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "work", prefix="monthly-test-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def make(self, count=2, no_publish=False):
        return OfflineRun(monthly.arguments(["2026-Dec"] + (["--no-publish"] if no_publish else []) +
                                           ["--concurrency", "1"]), self.work, public_documents(count))

    def test_complete_offline_run_and_resume_without_reassessing(self):
        run = self.make(); run.run()
        self.assertEqual(run.receipt["status"], "published-verified")
        self.assertEqual(run.model_calls, 1)
        self.assertEqual(run.snapshot_count, 2)
        rows = sources.read_rows(Path(run.receipt["candidate"]))
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(len(row["mitigation_candidates"]) == 17 for row in rows))
        self.assertTrue(all(row["threat"]["epss"] is None for row in rows))
        self.assertTrue(all(row["inference"]["assessment_status"] == "model-assessed" for row in rows))
        run.run()
        self.assertEqual(run.model_calls, 1, "unchanged cached raw receipts must avoid new calls")
        self.assertTrue(any(call[0] == "push" for call in run.git_calls))

    def test_changed_structured_impact_reassesses_only_one_cve(self):
        run = self.make(); run.revise = True; run.run()
        self.assertEqual(run.snapshot_count, 3)
        self.assertEqual([len(attempt["cves"]) for attempt in run.receipt["attempts"]], [2, 1])

    def test_missing_cve_failed_retry_stops_before_git(self):
        run = self.make(); run.bad_answers = True
        with self.assertRaisesRegex(RuntimeError, "isolation failed"):
            run.run()
        self.assertEqual(run.model_calls, 3)
        self.assertFalse(run.git_calls)
        self.assertEqual(len(list((self.work / "assessments").glob("*/model/stream-000.ndjson"))), 3)

    def test_tampered_cached_stream_is_rejected_without_new_calls(self):
        run = self.make(); snapshot = run.snapshot(); run.assess_snapshot(snapshot)
        raw = next((self.work / "assessments").glob("*/model/stream-000.ndjson"))
        raw.write_bytes(raw.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "captured call"):
            run.assess_snapshot(snapshot)
        self.assertEqual(run.model_calls, 1)

    def test_cached_request_cannot_mislabel_its_source_fingerprint(self):
        run = self.make(); snapshot = run.snapshot(); run.assess_snapshot(snapshot)
        request = next((self.work / "assessments").glob("*/request.json"))
        value = json.loads(request.read_text())
        value["fingerprints"][next(iter(value["fingerprints"]))] = "0" * 64
        request.write_bytes(sources.canonical(value))
        with self.assertRaisesRegex(ValueError, "Archived source fingerprints"):
            run.assess_snapshot(snapshot)
        self.assertEqual(run.model_calls, 1)

    def test_old_adapter_cannot_skip_raw_receipt_validation(self):
        run = self.make(); snapshot = run.snapshot(); run.assess_snapshot(snapshot)
        manifest = next((self.work / "assessments").glob("*/model/manifest.json"))
        value = json.loads(manifest.read_text()); value["adapter_version"] = "old"
        manifest.write_bytes(sources.canonical(value))
        with self.assertRaisesRegex(ValueError, "current production adapter"):
            run.assess_snapshot(snapshot)
        self.assertEqual(run.model_calls, 1)

    def test_complete_cpe_applicability_and_msrc_date_flags_are_kept(self):
        raw = {"containers": {"cna": {"cpeApplicability": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}]}]}]}}}
        self.assertEqual(sources.assessment_facts(raw, "cna")["containers"]["cna"]["cpeApplicability"], raw["containers"]["cna"]["cpeApplicability"])
        flags = {"DiscoveryDateSpecified": False, "ReleaseDateSpecified": True}
        self.assertEqual(sources.assessment_facts(flags, "msrc"), flags)

    def test_private_identifier_halts_before_assessment(self):
        run = self.make()
        run.documents[0]["Vulnerability"][0]["Notes"][0]["Value"] = "Customer host payroll.agency.internal"
        with self.assertRaisesRegex(ValueError, "Unproved public syntax"):
            run.run()
        self.assertEqual(run.model_calls, 0)
        self.assertFalse(run.git_calls)

    def test_upstream_movement_prevents_commit_and_push(self):
        run = self.make(); run.moved = True
        with self.assertRaisesRegex(RuntimeError, "moved during validation"):
            run.run()
        self.assertFalse(any(call[0] in {"commit", "push"} for call in run.git_calls))

    def test_no_publish_runs_gates_without_commit_or_push(self):
        run = self.make(no_publish=True); run.run()
        self.assertEqual(run.receipt["status"], "validated-not-published")
        self.assertFalse(any(call[0] in {"commit", "push"} for call in run.git_calls))

    def test_fingerprint_tracks_raw_score_sets_and_shared_products_not_fetch_time(self):
        packet = {"cve": "CVE-2026-999999", "public_msrc_evidence": {"CVSSScoreSets": [{"BaseScore": 7.8}],
                   "resolved_products": [{"name": "Windows"}]}, "dataset_provenance": {"fetched_at": "old"}}
        before = sources.material_fingerprint(packet)
        packet["dataset_provenance"]["fetched_at"] = "new"
        self.assertEqual(before, sources.material_fingerprint(packet))
        packet["public_msrc_evidence"]["CVSSScoreSets"].append({"BaseScore": 9.8})
        self.assertNotEqual(before, sources.material_fingerprint(packet))
        before = sources.material_fingerprint(packet)
        packet["public_msrc_evidence"]["resolved_products"][0]["name"] = "Windows Server"
        self.assertNotEqual(before, sources.material_fingerprint(packet))

    def test_parser_is_mechanically_equivalent_to_frozen_research(self):
        research_path = ROOT / "scripts/evaluate_historical.py"
        if not research_path.exists():
            self.skipTest("Research implementation intentionally absent from public checkout")
        # Read only implementation code, never protected holdout answers.
        research = ast.parse(research_path.read_text(encoding="utf-8"))
        production = ast.parse((ROOT / "scripts/claude_stream.py").read_text(encoding="utf-8"))
        names = {"_no_duplicates", "strict_loads", "items", "analyze_stream"}
        select = lambda tree: {node.name: ast.dump(node, include_attributes=False) for node in tree.body
                               if isinstance(node, ast.FunctionDef) and node.name in names}
        self.assertEqual(select(research), select(production))
        original = {}; exec(compile(ast.Module(body=[node for node in research.body if isinstance(node, ast.FunctionDef)
                             and node.name in names], type_ignores=[]), "frozen-parser", "exec"),
                             dict(vars(claude_stream)), original)
        for raw in (stream({"assessments": [fixture()[1]]}), b'{"a":1,"a":2}\n', b'\xff', b'{}\n'):
            self.assertEqual(original["analyze_stream"](raw, 0, False, True, monthly.MODEL),
                             claude_stream.analyze_stream(raw, 0, False, True, monthly.MODEL))

    def test_plan_never_calls_provider_fetch_or_git(self):
        with patch.object(monthly.MonthlyRun, "run", side_effect=AssertionError("not a plan")):
            self.assertEqual(monthly.main(["2026-Dec", "--plan"]), 0)

    def test_real_git_wrapper_preserves_porcelain_status_prefix(self):
        run = self.make()
        with patch.object(run, "command", return_value=SimpleNamespace(stdout=" M data/months.json\r\n")):
            output = monthly.MonthlyRun.git(run, "status", "--porcelain")
        self.assertEqual(output, " M data/months.json")
        self.assertEqual(output[3:], "data/months.json")

    def test_browser_failure_prevents_paid_probe(self):
        run = self.make(no_publish=True)
        def command(argv, **kwargs):
            if kwargs.get("label") == "claude-auth":
                return SimpleNamespace(returncode=0, stdout='{"loggedIn":true}')
            if kwargs.get("label") == "node":
                return SimpleNamespace(stdout="v24.0.0")
            if kwargs.get("label") == "browser-preflight":
                raise RuntimeError("browser unavailable")
            raise AssertionError(argv)
        with patch.object(run, "command", side_effect=command), patch.object(run, "probe") as probe, \
             patch.object(monthly.shutil, "which", return_value="installed"):
            with self.assertRaisesRegex(RuntimeError, "browser unavailable"):
                monthly.MonthlyRun.preflight(run)
            probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
