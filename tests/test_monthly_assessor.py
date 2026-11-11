"""Offline production-adapter checks. No provider or network calls."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_cli_inference as runner
import collect_cli_inference as collector
import customer_data_guard as privacy
import public_source_guard as public
from jsonschema import Draft202012Validator, ValidationError

MODEL = "claude-haiku-5-5"


def fixture():
    record = {"cve": "CVE-2026-999999", "title": "Local elevation of privilege", "severity": {"normalized_band": "high"},
              "customer_action_required": True, "tags": ["elevation-of-privilege"],
              "cvss": {"base_score": 7.8, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
              "attack": {"vector": "local", "privileges_required": "low", "user_interaction": "none"},
              "threat": {"exploitation_assessment": "more-likely", "kev": False, "exploitation_detected": False}}
    controls = {item["id"] for item in json.loads((ROOT / "data/mitigation-catalog.json").read_text())}
    overlay = {"cve": record["cve"], "cvss_basis": {"base_score": 7.8, "vector": record["cvss"]["vector"],
               "attack_vector": "local", "privileges_required": "low", "user_interaction": "none"},
               "attack_path": {"direction": "local", "evidence": "Local elevation of privilege"},
               "tags": ["elevation-of-privilege"], "mitigation_candidates": [{"id": control,
               "relevance": "unknown", "confidence": "low", "effect": {"likelihood_steps": 0,
               "consequence_steps": 0, "path_block": False}, "evidence": "No matching prevention capability is established."} for control in sorted(controls)],
               "framework_assessment": {"risk_model_version": "2026.09.1", "baseline_model": "elevated-high-severity",
               "baseline_likelihood": "Elevated", "baseline_action": "Out-of-cycle", "confidence": "medium",
               "factors": {key: "Source-grounded fixture reasoning." for key in runner.validation.REQUIRED_FACTORS},
               "risk_communication": {"summary": "Local elevation.", "why_this_action": "More Likely and Important.",
               "control_limitations": "No specific control established.", "reassessment_triggers": ["New exploitation evidence"]},
               "tag_evidence": [{"tag": "elevation-of-privilege", "evidence": "Local elevation of privilege"}],
               "review_requirement": {"required": False, "reasons": []}}}
    return record, overlay, controls


def stream(payload, model=MODEL):
    events = [{"type": "system", "subtype": "init", "session_id": "fixture", "tools": ["StructuredOutput"], "mcp_servers": []},
              {"type": "assistant", "message": {"id": "fixture-message", "model": model, "content": [{"type": "tool_use", "id": "format-1", "name": "StructuredOutput", "input": payload}]}},
              {"type": "result", "subtype": "success", "is_error": False, "terminal_reason": "completed", "session_id": "fixture", "structured_output": payload,
               "modelUsage": {model: {"canonicalModel": model, "provider": "fixture"}}, "result": ""}]
    return ("\n".join(json.dumps(item) for item in events) + "\n").encode()


class MonthlyTests(unittest.TestCase):
    def test_full_scaffold(self):
        text, pins = runner.scaffold(ROOT / "prompts/monthly-assessor.md", ROOT / "data/tag-taxonomy.json",
                                     ROOT / "data/mitigation-catalog.json", ROOT / "models/baseline-risk-models.md")
        for marker in ["Synthetic good/bad", "=== MODELS ===", "=== TAXONOMY ===", "=== CATALOGUE ===",
                       "PRODUCTION RESPONSE SKELETON", "already disabled", "bare driver/component"]:
            self.assertIn(marker, text)
        self.assertEqual(set(pins), {"method", "models", "taxonomy", "catalogue"})
        self.assertNotIn("Credit only when every relevant path", text)

    def test_command_is_toolless_persistent_and_no_system_file(self):
        cmd = runner.build_command("claude", MODEL, Path("unused"), Path("empty.json"), {"type": "object"})
        for flag in ["--safe-mode", "--session-id", "--strict-mcp-config", "--tools", "--effort", "--include-partial-messages"]:
            self.assertIn(flag, cmd)
        self.assertEqual(cmd[cmd.index("--tools") + 1], "")
        self.assertNotIn("--system-prompt-file", cmd)
        self.assertNotIn("--no-session-persistence", cmd)

    def test_schema_and_tag_evidence_match(self):
        source, answer, controls = fixture(); tags = {"elevation-of-privilege"}
        schema = runner.build_schema([source["cve"]], tags, controls)
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate({"assessments": [answer]})
        runner.validate_monthly_overlay(answer, source, tags, controls)
        broken = copy.deepcopy(answer); broken["tags"] = [{"tag": "elevation-of-privilege", "evidence": "source"}]
        with self.assertRaises(ValidationError): Draft202012Validator(schema).validate({"assessments": [broken]})
        broken = copy.deepcopy(answer); broken["framework_assessment"]["tag_evidence"] = []
        with self.assertRaisesRegex(ValueError, "each judgment tag"): runner.validate_monthly_overlay(broken, source, tags, controls)

    def test_schema_requires_exact_assigned_batch_cardinality(self):
        source, answer, controls = fixture()
        other = copy.deepcopy(answer); other["cve"] = "CVE-2026-999998"
        schema = runner.build_schema([source["cve"], other["cve"]], set(answer["tags"]), controls)
        validator = Draft202012Validator(schema)
        validator.validate({"assessments": [answer, other]})
        for wrong in ([answer], [answer, other, answer]):
            with self.assertRaises(ValidationError): validator.validate({"assessments": wrong})

    def test_schema_rejects_eighteenth_control_row(self):
        source, answer, controls = fixture()
        self.assertEqual(len(controls), 17)
        validator = Draft202012Validator(runner.build_schema([source["cve"]], set(answer["tags"]), controls))
        validator.validate({"assessments": [answer]})
        duplicate = next(c for c in answer["mitigation_candidates"] if c["id"] == "edr_exploit_prevention")
        answer["mitigation_candidates"].append(copy.deepcopy(duplicate))
        with self.assertRaises(ValidationError) as rejected:
            validator.validate({"assessments": [answer]})
        self.assertEqual(rejected.exception.validator, "maxItems")

    def test_unknown_is_visible_without_credit(self):
        source, answer, controls = fixture(); answer["attack_path"]["direction"] = "unknown"
        with self.assertRaisesRegex(ValueError, "explicit review flag"):
            runner.validate_monthly_overlay(answer, source, set(answer["tags"]), controls)
        answer["framework_assessment"]["review_requirement"] = {"required": True, "reasons": ["The source does not establish entry."]}
        runner.validate_monthly_overlay(answer, source, set(answer["tags"]), controls)
        next(c for c in answer["mitigation_candidates"] if c["id"] == "service_disabled_vendor_guidance").update(
            relevance="relevant", effect={"likelihood_steps": 1, "consequence_steps": 0, "path_block": False})
        with self.assertRaisesRegex(ValueError, "unknown direction permits no"):
            runner.validate_monthly_overlay(answer, source, set(answer["tags"]), controls)

    def test_missing_control_and_fabricated_cvss_rejected(self):
        source, answer, controls = fixture(); answer["mitigation_candidates"].pop()
        with self.assertRaisesRegex(ValueError, "every catalogue control"):
            runner.validate_monthly_overlay(answer, source, set(answer["tags"]), controls)
        source, answer, controls = fixture(); answer["cvss_basis"]["base_score"] = 0
        with self.assertRaisesRegex(ValueError, "cvss_basis"):
            runner.validate_monthly_overlay(answer, source, set(answer["tags"]), controls)

    def test_transport_rejects_other_model_and_preserves_result(self):
        payload = {"assessments": []}; raw = stream(payload)
        self.assertFalse(runner.analyze_transport(raw, 0, True, MODEL)["errors"])
        self.assertEqual(runner.terminal_envelope(raw)["structured_output"], payload)
        self.assertTrue(runner.analyze_transport(stream(payload, "claude-sonnet-5-5"), 0, True, MODEL)["errors"])
        self.assertTrue(runner.analyze_transport(stream(payload, "claude-sonnet-5-5"), 0, True, "haiku")["errors"])
        self.assertTrue(runner.analyze_transport(raw, 1, True, MODEL)["errors"])

    def test_temporary_cwd_cleanup_failure_keeps_completed_stream(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); cwd = work / "owned"; cwd.mkdir()
            raw = stream({"assessments": []})
            def fake(command, *, input, encoding, stdout, stderr, cwd, timeout):
                stdout.write(raw)
                return SimpleNamespace(returncode=0)
            with patch.object(runner.tempfile, "mkdtemp", return_value=str(cwd)), \
                 patch.object(runner.subprocess, "run", side_effect=fake), \
                 patch.object(Path, "rmdir", side_effect=PermissionError("fixture cleanup denied")):
                code, captured, stderr, error = runner.invoke(["fixture"], "Public advisory text", 10, "fixture",
                                                              raw_path=work / "raw.ndjson", stderr_path=work / "stderr.txt")
            self.assertEqual(code, 0)
            self.assertEqual(captured, raw)
            self.assertFalse(runner.analyze_transport(captured, code, True, MODEL)["errors"])
            self.assertIn("fixture cleanup denied", error)

    def test_known_cna_route_does_not_bypass_normalized_vector_gate(self):
        source, answer, controls = fixture()
        source["attack"]["vector"] = "unknown"
        answer["cvss_basis"]["attack_vector"] = "unknown"
        answer["attack_path"] = {"direction": "inbound", "evidence": "The assigning CNA describes a network service request."}
        candidate = next(c for c in answer["mitigation_candidates"] if c["id"] == "remove_external_exposure")
        candidate.update(relevance="relevant", effect={"likelihood_steps": 1, "consequence_steps": 0, "path_block": False})
        with self.assertRaisesRegex(ValueError, "cannot reduce likelihood for attack vector unknown"):
            runner.validate_monthly_overlay(answer, source, set(answer["tags"]), controls)
        candidate["effect"]["likelihood_steps"] = 0
        answer["framework_assessment"]["review_requirement"] = {"required": True, "reasons": ["The normalized vector is unknown; policy does not quantify this network control." ]}
        runner.validate_monthly_overlay(answer, source, set(answer["tags"]), controls)
        self.assertEqual(answer["attack_path"]["direction"], "inbound")

    def test_mocked_run_to_collector_has_exact_raw_bindings(self):
        source, answer, controls = fixture()
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); records = work / "source.jsonl"; run = work / "run"
            records.write_text(json.dumps(source) + "\n", encoding="utf-8")
            raw = stream({"assessments": [answer]})
            def fake(command, *, input, encoding, stdout, stderr, cwd, timeout):
                self.assertNotEqual(Path(cwd), ROOT)
                self.assertIn("CANONICAL PRODUCTION JSON SCHEMA", input)
                stdout.write(raw); stdout.flush()
                return SimpleNamespace(returncode=0)
            argv = ["run_cli_inference.py", "--records", str(records), "--run-dir", str(run), "--arm", "scaffolded", "--cli", "fixture"]
            with patch.object(sys, "argv", argv), patch.object(runner.subprocess, "run", side_effect=fake): runner.main()
            manifest = json.loads((run / "manifest.json").read_text())
            self.assertIsNotNone(manifest["finished_at"])
            self.assertTrue(manifest["calls"][0]["conformant"])
            self.assertEqual((run / "stream-000.ndjson").read_bytes(), raw)
            got = collector.collect_batch(run, manifest, manifest["calls"][0], "fixture", {source["cve"]: source}, set(), set(answer["tags"]), controls)
            self.assertEqual(got[0]["framework_assessment"], answer["framework_assessment"])
            self.assertEqual(got[0]["inference"]["model"], MODEL)
            self.assertEqual(got[0]["inference"]["independent_review_status"], "not-claimed")
            with (run / "stream-000.ndjson").open("ab") as handle: handle.write(b"\n")
            with self.assertRaisesRegex(ValueError, "captured call"):
                collector.collect_batch(run, manifest, manifest["calls"][0], "fixture", {source["cve"]: source}, set(), set(answer["tags"]), controls)


class PublicGuardTests(unittest.TestCase):
    def build(self, work):
        raw = work / "raw"; raw.mkdir()
        source = {"containers": {"cna": {"affected": [{"versions": [{"version": "1.2.3.4"}]}]}}}
        source_path = raw / "source.json"; source_path.write_text(json.dumps(source), encoding="utf-8")
        record = {"cve": "CVE-2026-999999", "version": "1.2.3.4"}
        finding = privacy.scan_value(record)[0]
        findings = {"findings": [{"cve": record["cve"], **finding.__dict__}]}
        inventory = work / "findings.json"; inventory.write_text(json.dumps(findings), encoding="utf-8")
        proof = {"finding_source": inventory.name, "finding_source_sha256": public.digest(inventory.read_bytes()), "proof": [{
            "finding_index": 0, "cve": record["cve"], "field": finding.field, "category": finding.category, "source_match": True,
            "source_path": str(source_path), "source_sha256": public.digest(source_path.read_bytes()),
            "source_pointer": "/containers/cna/affected/0/versions/0/version", "source_value_sha256": public.digest(b"1.2.3.4")}]}
        path = work / "proof.json"; path.write_text(json.dumps(proof), encoding="utf-8")
        return public.PublicSourceGuard(path, public.digest(path.read_bytes())), record, source_path

    def test_proven_version_only_in_exact_field_and_prompt(self):
        with tempfile.TemporaryDirectory() as temp:
            guard, record, _ = self.build(Path(temp)); domains = privacy.ALLOWED_DOMAINS
            guard.assert_record(record)
            prefix = "Complete public framework"; prompt = public.render_prompt(prefix, [record])
            self.assertEqual(guard.assert_prompt(prompt, prefix, [record]), public.digest(prompt.encode()))
            with self.assertRaises(ValueError): guard.assert_prompt(prompt + " extra", prefix, [record])
            for changed in [dict(record, customer_ip="10.20.30.40"), dict(record, customer_host="payroll.agency.internal"), dict(record, version="10.20.30.40")]:
                with self.assertRaises(privacy.CustomerDataError): guard.assert_record(changed)
            self.assertEqual(domains, privacy.ALLOWED_DOMAINS)

    def test_cache_drift_and_wrong_proof_hash_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); guard, record, source = self.build(work); guard.assert_record(record)
            source.write_text(source.read_text() + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source hash changed"): guard.assert_record(record)
            with self.assertRaisesRegex(ValueError, "approved hash"): public.PublicSourceGuard(work / "proof.json", "0" * 64)

    def test_msrc_fixed_build_requires_exact_typed_source_pointer(self):
        value = "10.0.123.45"
        record = {"cve": "CVE-2026-999999", "build": value}
        finding = privacy.scan_value(record)[0]
        pointer = "/Vulnerability/0/Remediations/0/FixedBuild"
        self.assertTrue(public._public_syntax(value, finding, pointer))
        for other in ("/FixedBuild", "/Vulnerability/0/FixedBuild",
                      "/Vulnerability/0/Remediations/0/Description",
                      "/Vulnerability/0/Remediations/0/FixedBuildSuffix",
                      "/Other/0/Remediations/0/FixedBuild",
                      "/Vulnerability/0/Remediations/0/FixedBuild/extra"):
            self.assertFalse(public._public_syntax(value, finding, other), other)
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); raw = work / "raw"; raw.mkdir()
            source = raw / "msrc.json"
            source.write_text(json.dumps({"Vulnerability": [{"Remediations": [{"FixedBuild": value, "Description": value}]}]}), encoding="utf-8")
            inventory = work / "findings.json"
            inventory.write_text(json.dumps({"findings": [{"cve": record["cve"], **finding.__dict__}]}), encoding="utf-8")
            entry = {"finding_index": 0, "cve": record["cve"], "field": finding.field,
                     "category": finding.category, "source_match": True, "source_path": str(source),
                     "source_sha256": public.digest(source.read_bytes()), "source_pointer": pointer,
                     "source_value_sha256": public.digest(value.encode())}
            proof = {"finding_source": inventory.name, "finding_source_sha256": public.digest(inventory.read_bytes()), "proof": [entry]}
            path = work / "proof.json"; path.write_text(json.dumps(proof), encoding="utf-8")
            guard = public.PublicSourceGuard(path, public.digest(path.read_bytes())); guard.assert_record(record)
            with self.assertRaises(privacy.CustomerDataError): guard.assert_record(dict(record, build="10.0.123.46"))
            entry["source_pointer"] = "/Vulnerability/0/Remediations/0/Description"
            path.write_text(json.dumps(proof), encoding="utf-8")
            with self.assertRaises(privacy.CustomerDataError):
                public.PublicSourceGuard(path, public.digest(path.read_bytes())).assert_record(record)

    def test_exact_public_reference_syntax_is_not_a_domain_or_email_allowlist(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp); raw = work / "raw"; raw.mkdir()
            source = {"URL": "https://downloads.vendor.dev/Subscription/d3c8b69d-6bf7-42be-a529-3fe9c2e70c90/Connector",
                      "description": "Reference https://lore.kernel.org/netdev/PublishedMessage123@mail.gmail.com/"}
            record = {"cve": "CVE-2026-999999", "reference": source["URL"], "description": source["description"]}
            source_path = raw / "public.json"; source_path.write_text(json.dumps(source), encoding="utf-8")
            hits = privacy.scan_value(record); self.assertTrue(hits)
            inventory = work / "findings.json"
            inventory.write_text(json.dumps({"findings": [{"cve": record["cve"], **x.__dict__} for x in hits]}), encoding="utf-8")
            entries = []
            for i, hit in enumerate(hits):
                value = record[hit.field]; pointer = "/URL" if hit.field == "reference" else "/description"
                entries.append({"finding_index": i, "cve": record["cve"], "field": hit.field, "category": hit.category,
                                "source_match": True, "source_path": str(source_path), "source_sha256": public.digest(source_path.read_bytes()),
                                "source_pointer": pointer, "source_value_sha256": public.digest(value.encode())})
            proof = {"finding_source": inventory.name, "finding_source_sha256": public.digest(inventory.read_bytes()), "proof": entries}
            path = work / "proof.json"; path.write_text(json.dumps(proof), encoding="utf-8")
            guard = public.PublicSourceGuard(path, public.digest(path.read_bytes())); guard.assert_record(record)
            for changed in [dict(record, reference=record["reference"] + "?customer=payroll.agency.internal"),
                            dict(record, email="PublishedMessage123@mail.gmail.com"),
                            dict(record, private_url="https://downloads.vendor.dev/customer/10.20.30.40")]:
                with self.assertRaises(privacy.CustomerDataError): guard.assert_record(changed)


if __name__ == "__main__": unittest.main()
