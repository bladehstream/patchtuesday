#!/usr/bin/env python3
"""Fetch, assess, validate and publish one MSRC month using the existing pipeline.

All intermediate evidence stays in ignored work/monthly/<month>. Repeating the
same command revalidates captured receipts and reuses unchanged assessments.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import uuid

import collect_cli_inference as collector
import customer_data_guard as privacy
import monthly_sources as sources
import run_cli_inference as assessor

ROOT = Path(__file__).resolve().parents[1]
SITE = "https://patchtuesday-6k8.pages.dev"
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
MODEL = "claude-haiku-5-5"
RETRY_GUIDANCE = ("\n\nThis is a fresh assessment after a rejected attempt. The unchanged source and complete scaffold are authoritative. "
                  "Do not copy or repair fields from the rejected response. Address this literal validator feedback:\n")
POLICY_FILES = ["prompts/monthly-assessor.md", "models/baseline-risk-models.md",
                "data/tag-taxonomy.json", "data/mitigation-catalog.json", "data/severity-scales.json"]
CODE_FILES = ["run_month.py", "monthly_sources.py", "claude_stream.py", "run_cli_inference.py",
              "collect_cli_inference.py", "merge_inference.py", "customer_data_guard.py",
              "public_source_guard.py", "enrich_cvrf.py", "apply_cve_enrichment.py",
              "normalize_severity.py", "severity.py", "tag_validators.py", "score_tags.py", "review_month.py",
              "fetch_sources.py", "fetch_cve_enrichment.py", "span_verify.py"]


def now():
    return datetime.now(timezone.utc).isoformat()


def emit(message):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", flush=True)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_bytes(sources.canonical(value) + b"\n")
    temporary.replace(path)


def fingerprint():
    paths = [ROOT / name for name in POLICY_FILES] + [ROOT / "scripts" / name for name in CODE_FILES]
    return sources.sha(sources.canonical({str(path.relative_to(ROOT)): sources.sha(path.read_bytes()) for path in paths}))


@contextmanager
def exclusive_run(path):
    """OS-owned lock releases on crashes; a stale JSON status never blocks resume."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        handle.seek(0)
        if path.stat().st_size == 0:
            handle.write(b"0"); handle.flush(); handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise RuntimeError("Another process owns this month's run; do not start concurrent publishers") from error
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class MonthlyRun:
    def __init__(self, args):
        self.args = args
        self.work = ROOT / "work" / "monthly" / args.month
        self.method = fingerprint()
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.cli = shutil.which("claude")
        self.receipt = {"month": args.month, "model": MODEL, "effort": "medium", "method_sha256": self.method,
                        "started_at": now(), "status": "preflight", "snapshots": [], "accepted": {}, "attempts": []}

    def save(self, **changes):
        with self.lock:
            self.receipt.update(changes)
            write_json(self.work / "run-receipt.json", self.receipt)

    def command(self, argv, *, cwd=ROOT, label=None, timeout=1200, check=True, input_text=None):
        log = self.work / "logs" / f"{label or Path(str(argv[0])).stem}-{uuid.uuid4().hex[:10]}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never")
        result = subprocess.run([str(value) for value in argv], cwd=cwd, input=input_text,
                                text=True, encoding="utf-8", errors="replace", capture_output=True,
                                timeout=timeout, env=env)
        log.write_text(result.stdout + result.stderr, encoding="utf-8")
        if check and result.returncode:
            raise RuntimeError(f"{label or argv[0]} failed ({result.returncode}); see {log}")
        return result

    def script(self, name, *arguments, **kwargs):
        return self.command([sys.executable, ROOT / "scripts" / name, *arguments], label=Path(name).stem, **kwargs)

    def git(self, *args, cwd=ROOT, **kwargs):
        return self.command(["git", *args], cwd=cwd, label="git", **kwargs).stdout.rstrip("\r\n")

    def preflight(self):
        from jsonschema import Draft202012Validator  # noqa: F401
        if sys.version_info < (3, 11):
            raise RuntimeError("Python 3.11+ is required")
        for executable in ("node", "npm", "git"):
            if not shutil.which(executable):
                raise RuntimeError(f"Install {executable} and add it to PATH")
        if not self.cli:
            raise RuntimeError("Install Claude Code and sign in once with claude auth login")
        status = self.command([self.cli, "auth", "status", "--json"], label="claude-auth", check=False)
        try:
            logged_in = json.loads(status.stdout).get("loggedIn") is True
        except ValueError:
            logged_in = False
        if status.returncode or not logged_in:
            raise RuntimeError("Claude is not signed in. Run claude auth login, then repeat the command")
        node = self.command(["node", "--version"], label="node").stdout.strip()
        if int(node.lstrip("v").split(".")[0]) < 22:
            raise RuntimeError("Node 22+ is required for the existing browser-backed checks")
        if not self.args.no_publish:
            remote = self.git("remote", "get-url", "origin")
            if not re.fullmatch(r"https://github\.com/[^/\s]+/[^/\s]+(?:\.git)?", remote):
                raise RuntimeError("origin must be the intended HTTPS GitHub repository, with no embedded credentials")
            self.git("ls-remote", "--exit-code", "origin", "refs/heads/main")
            # Read-only credential check. Never log its output (it contains a token).
            auth = subprocess.run(["git", "credential", "fill"], input=f"url={remote}\n\n", capture_output=True,
                                  text=True, cwd=ROOT, timeout=30,
                                  env=dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never"))
            if auth.returncode or "password=" not in auth.stdout:
                raise RuntimeError("Git has no non-interactive credential for origin. Sign in once locally, then retry")
            for key in ("user.name", "user.email"):
                if not self.git("config", "--get", key):
                    raise RuntimeError(f"Configure git {key} before publishing")
        for path in (ROOT / "tests/ui_performance.test.mjs", ROOT / "tests/support/cdp-browser.mjs"):
            if not path.is_file():
                raise RuntimeError(f"Missing production browser gate: {path}")
        if os.name == "nt" and not os.environ.get("PATCH_TUESDAY_BROWSER"):
            for base in (os.environ.get("PROGRAMFILES(X86)"), os.environ.get("PROGRAMFILES"), os.environ.get("LOCALAPPDATA")):
                if not base:
                    continue
                for relative in ("Microsoft/Edge/Application/msedge.exe", "Google/Chrome/Application/chrome.exe"):
                    browser = Path(base) / relative
                    if browser.is_file():
                        os.environ["PATCH_TUESDAY_BROWSER"] = str(browser)
                        break
                if os.environ.get("PATCH_TUESDAY_BROWSER"):
                    break
        browser_probe = ("import {launchPage} from './tests/support/cdp-browser.mjs'; "
                         "const page = await launchPage('about:blank'); await page.close();")
        self.command(["node", "--input-type=module", "-e", browser_probe], label="browser-preflight", timeout=60)
        emit("Prerequisites checked; validating tool-free Haiku access before the monthly budget")
        self.probe()

    def probe(self):
        directory = self.work / "probes" / uuid.uuid4().hex
        directory.mkdir(parents=True)
        mcp = assessor.write_sandbox_mcp_config(directory)
        schema = {"type": "object", "properties": {"ready": {"type": "boolean", "const": True}},
                  "required": ["ready"], "additionalProperties": False}
        prompt = 'Return {"ready":true} using the supplied output schema. Do not use tools.'
        command = assessor.build_command(self.cli, MODEL, directory / "unused", mcp.resolve(), schema, effort="medium")
        code, raw, _, _ = assessor.invoke(command, prompt, 120, "monthly preflight", raw_path=directory / "stream.ndjson",
                                          stderr_path=directory / "stderr.txt")
        result = assessor.analyze_transport(raw, code, True, MODEL)
        write_json(directory / "receipt.json", result)
        if result["errors"] or result["response"] != {"ready": True}:
            raise RuntimeError(f"Haiku preflight failed; see {directory}. No monthly assessments were started")

    def collect(self, directory, current):
        """Recheck raw streams, source and policy hashes even when using a cache."""
        request = json.loads((directory / "request.json").read_text())
        if request["method_sha256"] != self.method or request["model"] != MODEL or request["effort"] != "medium":
            return []
        manifest_path = directory / "model" / "manifest.json"
        if not manifest_path.is_file():
            return []  # Interrupted invocation remains preserved, never called valid.
        manifest = json.loads(manifest_path.read_text())
        run_dir = manifest_path.parent
        required = {"adapter_version": assessor.ADAPTER_VERSION, "arm": "scaffolded", "schema_enforced": True,
                    "model_configured": MODEL, "effort_configured": "medium"}
        if any(manifest.get(key) != value for key, value in required.items()):
            raise ValueError("Cached invocation does not match the current production adapter/model/effort contract")
        if Path(manifest["source_records"]).resolve() != (directory / "input.jsonl").resolve():
            raise ValueError("Cached invocation source is not its owned immutable input")
        collector.verify_run_source(run_dir, manifest, Path(manifest["source_records"]))
        proof = manifest.get("public_source_guard") or {}
        public_guard = assessor.PublicSourceGuard(Path(proof["proof"]), proof["proof_sha256"])
        original_rows = sources.read_rows(Path(manifest["source_records"]))
        original = {row["cve"]: row for row in original_rows}
        if {cve: sources.material_fingerprint(row) for cve, row in original.items()} != request["fingerprints"]:
            raise ValueError("Archived source fingerprints differ from the cached request")
        for row in original.values():
            public_guard.assert_record(row)
        tags = collector.validation.allowed_tags(ROOT / "data/tag-taxonomy.json")
        controls = collector.validation.allowed_mitigations(ROOT / "data/mitigation-catalog.json")
        taxonomy = json.loads((ROOT / "data/tag-taxonomy.json").read_text())
        judgement_tags = {tag for namespace in ("workload", "delivery", "impact") for tag in taxonomy["namespaces"][namespace]}
        feedback = request.get("feedback", "")
        privacy.assert_clean("cached validator feedback", feedback, "retry guidance")
        if len(feedback) > 8000:
            raise ValueError("Cached retry guidance exceeds the permitted literal feedback bound")
        method = directory / "retry-method.md" if feedback else ROOT / "prompts/monthly-assessor.md"
        if feedback and method.read_text(encoding="utf-8") != (ROOT / "prompts/monthly-assessor.md").read_text(encoding="utf-8") + RETRY_GUIDANCE + feedback:
            raise ValueError("Cached retry method differs from the complete method plus saved literal feedback")
        system, pins = assessor.scaffold(method, ROOT / "data/tag-taxonomy.json", ROOT / "data/mitigation-catalog.json",
                                         ROOT / "models/baseline-risk-models.md")
        if manifest.get("scaffold_hashes") != pins or (run_dir / "system-prompt.txt").read_text(encoding="utf-8") != system:
            raise ValueError("Cached invocation did not receive the exact current full scaffold")
        accepted, seen = [], set()
        for call in manifest["calls"]:
            if not call.get("conformant"):
                continue
            if set(call["cves"]) != set(original) or len(call["cves"]) != len(original):
                raise ValueError("Cached batch assignment differs from its original input")
            schema = assessor.build_schema(call["cves"], judgement_tags, controls)
            if json.loads((run_dir / f"schema-{call['batch']:03d}.json").read_text()) != schema:
                raise ValueError("Cached schema differs from the current exact-cardinality production schema")
            prefix = system + "\n\n=== CANONICAL PRODUCTION JSON SCHEMA ===\n" + json.dumps(schema)
            prompt = (run_dir / f"prompt-{call['batch']:03d}.txt").read_text(encoding="utf-8")
            if public_guard.assert_prompt(prompt, prefix, original_rows) != call.get("prompt_sha256"):
                raise ValueError("Cached invocation prompt differs from the complete scaffold and exact public evidence")
            authored = collector.collect_batch(run_dir, manifest, call, str(directory.relative_to(self.work)), original, seen, tags, controls)
            for row in authored:
                cve = row["cve"]
                if current.get(cve) == request["fingerprints"].get(cve):
                    # Also validate against this newly fetched source, not merely
                    # the archived packet against which the provider was called.
                    collector.validate_overlay(row, self.current_packets[cve], tags, controls)
                    assessor.validate_monthly_overlay(row, self.current_packets[cve], tags, controls)
                    accepted.append(row)
        return accepted

    def attempt(self, rows, snapshot, feedback=""):
        if self.stop.is_set():
            raise RuntimeError("Monthly run stopped after an authentication/quota failure")
        directory = self.work / "assessments" / uuid.uuid4().hex
        directory.mkdir(parents=True)
        source_path = directory / "input.jsonl"
        sources.write_rows(source_path, rows)
        write_json(directory / "request.json", {"method_sha256": self.method, "model": MODEL, "effort": "medium",
                   "feedback": feedback,
                   "fingerprints": {row["cve"]: snapshot["fingerprints"][row["cve"]] for row in rows}})
        contract = ROOT / "prompts/monthly-assessor.md"
        if feedback:
            privacy.assert_clean("validator feedback", feedback, "retry guidance")
            contract = directory / "retry-method.md"
            contract.write_text((ROOT / "prompts/monthly-assessor.md").read_text(encoding="utf-8") +
                                RETRY_GUIDANCE + feedback,
                                encoding="utf-8")
        result = self.script("run_cli_inference.py", "--records", source_path, "--run-dir", directory / "model",
                             "--arm", "scaffolded", "--model", MODEL, "--effort", "medium", "--batch-size", len(rows),
                             "--cli", self.cli, "--contract", contract, "--public-source-proof", snapshot["proof"],
                             "--public-source-proof-sha256", snapshot["proof_sha256"], check=False)
        manifest_path = directory / "model/manifest.json"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
        failures = [call.get("conformance_failure", "") for call in manifest.get("calls", []) if not call.get("conformant")]
        failure = "; ".join(failures) or (f"Adapter exited {result.returncode}; see the saved invocation logs" if result.returncode else "Incomplete captured invocation")
        provider_errors = []
        for path in (directory / "model").glob("stderr-*.txt"):
            provider_errors.append(path.read_text(encoding="utf-8", errors="replace")[:3000])
        for path in (directory / "model").glob("stream-*.ndjson"):
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if isinstance(event, dict) and (event.get("type") == "error" or event.get("is_error") is True):
                    provider_errors.append(json.dumps(event))
        failure += "\n" + "\n".join(provider_errors)
        # Validation messages include the entire schema (including the control
        # strong_authentication). Only provider error events/stderr establish an
        # auth/quota failure; do not mistake a schema rejection for one.
        if re.search(r"(?i)oauth|not logged|authentication|unauthorized|rate.limit|quota|usage.limit|credit.balance", "\n".join(provider_errors)):
            self.stop.set()
            raise RuntimeError(f"Authentication/quota failure; no automatic login or further retry. Inspect {directory}")
        accepted = self.collect(directory, snapshot["fingerprints"]) if manifest.get("finished_at") else []
        with self.lock:
            self.receipt["attempts"].append({"directory": str(directory), "cves": [row["cve"] for row in rows],
                                               "accepted": len(accepted), "failure": None if accepted else failure})
        self.save()
        return accepted, failure

    def assess_batch(self, rows, snapshot):
        feedback = ""
        for _ in range(2):
            accepted, feedback = self.attempt(rows, snapshot, feedback)
            if len(accepted) == len(rows):
                return accepted
            feedback = feedback.split("\n\nFailed validating", 1)[0][:8000]
        if len(rows) == 1:
            raise RuntimeError(f"Assessment still invalid after bounded retries: {rows[0]['cve']}: {feedback}")
        isolated = []
        for row in rows:
            accepted, failure = self.attempt([row], snapshot, feedback)
            if len(accepted) != 1:
                raise RuntimeError(f"Single-case isolation failed for {row['cve']}: {failure}")
            isolated.extend(accepted)
        return isolated

    def assess_snapshot(self, snapshot):
        self.current_packets = {row["cve"]: row for row in sources.read_rows(Path(snapshot["packets"]))}
        fingerprints = snapshot["fingerprints"]
        accepted = {}
        for directory in sorted((self.work / "assessments").glob("*")):
            for row in self.collect(directory, fingerprints):
                accepted[row["cve"]] = row
        pending = [row for cve, row in sorted(self.current_packets.items()) if cve not in accepted]
        emit(f"{len(fingerprints)} CVEs; {len(accepted)} validated unchanged cached assessments; {len(pending)} need inference")
        batches = [pending[index:index+self.args.batch_size] for index in range(0, len(pending), self.args.batch_size)]
        with ThreadPoolExecutor(max_workers=self.args.concurrency) as pool:
            futures = [pool.submit(self.assess_batch, batch, snapshot) for batch in batches]
            try:
                for future in as_completed(futures):
                    for row in future.result():
                        accepted[row["cve"]] = row
                    emit(f"Validated {len(accepted)}/{len(fingerprints)} CVEs")
            except BaseException:
                self.stop.set()
                for future in futures:
                    future.cancel()
                raise
        if set(accepted) != set(fingerprints):
            raise RuntimeError("Refusing incomplete or extra-CVE release")
        self.save(accepted={cve: fingerprints[cve] for cve in accepted})
        return [accepted[cve] for cve in sorted(accepted)]

    def snapshot(self):
        directory = self.work / "snapshots" / uuid.uuid4().hex
        directory.mkdir(parents=True)
        emit("Fetching fresh MSRC, KEV, EPSS and full CVE Program evidence")
        result = sources.prepare(directory, self.args.month, self.script)
        self.receipt["snapshots"].append(result)
        self.save(status="assessing")
        return result

    def run(self):
        self.work.mkdir(parents=True, exist_ok=True)
        self.preflight()
        snapshot = self.snapshot()
        for revision in range(3):
            overlays = self.assess_snapshot(snapshot)
            fresh = self.snapshot()
            if fresh["fingerprints"] == snapshot["fingerprints"]:
                snapshot = fresh
                break
            changed = set(fresh["fingerprints"]) ^ set(snapshot["fingerprints"])
            changed.update(cve for cve in set(fresh["fingerprints"]) & set(snapshot["fingerprints"])
                           if fresh["fingerprints"][cve] != snapshot["fingerprints"][cve])
            emit(f"Source revision changed {len(changed)} CVEs; only affected inputs will be reassessed")
            snapshot = fresh
        else:
            raise RuntimeError("Sources changed in all three revision passes; live site unchanged. Repeat the command to resume")
        output = self.work / "candidates" / uuid.uuid4().hex
        output.mkdir(parents=True)
        overlay_path, candidate = output / "inference.jsonl", output / f"{self.args.month}.jsonl"
        sources.write_rows(overlay_path, overlays)
        self.script("merge_inference.py", "--baseline", snapshot["lean"], "--inference", overlay_path,
                    "--output", candidate, "--require-complete")
        annotated = output / f"{self.args.month}-reviewed.jsonl"
        self.script("review_month.py", "--records", candidate, "--output", output / "tier1-review.json", "--annotate", annotated)
        candidate = annotated
        self.save(status="validated", candidate=str(candidate), candidate_sha256=sources.sha(candidate.read_bytes()))
        self.publish(candidate)

    def remote_head(self):
        return self.git("ls-remote", "--exit-code", "origin", "refs/heads/main").split()[0]

    def publish(self, candidate):
        emit("Preparing an isolated publication from freshly fetched origin/main")
        self.git("fetch", "origin", "main")
        base = self.git("rev-parse", "refs/remotes/origin/main")
        publication = self.work / "publication" / uuid.uuid4().hex
        publication.parent.mkdir(parents=True, exist_ok=True)
        self.git("worktree", "add", "--detach", publication, base)
        # All subsequent mutations are in this owned worktree; no checkout/reset
        # of the operator's branch, and no import of development commit history.
        self.command([sys.executable, publication / "scripts/publish_month.py", candidate, "--month", self.args.month],
                     cwd=publication, label="publish-month")
        self.command([shutil.which("npm"), "test"], cwd=publication, label="release-tests")
        self.command([shutil.which("npm"), "run", "build"], cwd=publication, label="release-build")
        # Run the current production browser check against the candidate tree
        # even when the base commit's npm script predates that check.
        env_root = os.environ.get("PATCH_TUESDAY_TEST_ROOT")
        try:
            os.environ["PATCH_TUESDAY_TEST_ROOT"] = str(publication)
            self.command(["node", ROOT / "tests/ui_performance.test.mjs"], cwd=publication, label="browser-benchmark")
        finally:
            if env_root is None:
                os.environ.pop("PATCH_TUESDAY_TEST_ROOT", None)
            else:
                os.environ["PATCH_TUESDAY_TEST_ROOT"] = env_root
        oversized = [str(path.relative_to(publication / "dist")) for path in (publication / "dist").rglob("*")
                     if path.is_file() and path.stat().st_size >= 25 * 1024 * 1024]
        if oversized:
            raise RuntimeError(f"Cloudflare asset limit exceeded: {oversized}")
        manifest = json.loads((publication / "dist/data/months.json").read_text())
        first = next(item for item in manifest if not item["month"].endswith("-demo"))
        if first["month"] != self.args.month:
            raise RuntimeError("Requested release would not become the default month; refusing publication")
        built = publication / "dist/data" / first["file"]
        if Path(first["file"]).name != first["file"] or not built.is_file():
            raise RuntimeError("Invalid built asset path")
        expected = {f"data/{self.args.month}.jsonl", "data/months.json"}
        changed = set(self.git("status", "--porcelain", cwd=publication).splitlines())
        changed_paths = {line[3:] for line in changed}
        if changed_paths - expected:
            raise RuntimeError(f"Publication whitelist mismatch: {sorted(changed_paths)}")
        self.save(status="ready-to-publish", publication=str(publication), base_commit=base,
                  built_asset=first["file"], built_asset_sha256=sources.sha(built.read_bytes()))
        if not changed_paths:
            if not self.args.no_publish:
                self.verify_live(first, sources.sha(built.read_bytes()))
            self.save(status="already-current" if not self.args.no_publish else "validated-not-published", finished_at=now())
            emit("Release content is already current; no commit or push needed")
            return
        if self.args.no_publish:
            self.save(status="validated-not-published", finished_at=now())
            emit(f"All release gates passed. --no-publish retained candidate in {publication}")
            return
        if self.remote_head() != base:
            raise RuntimeError("origin/main moved during validation; nothing pushed. Repeat the command to rebuild on the new main")
        self.git("add", "--", *sorted(expected), cwd=publication)
        staged = set(self.git("diff", "--cached", "--name-only", cwd=publication).splitlines())
        if not staged or staged - expected:
            raise RuntimeError("Staged publication contains an unexpected path")
        self.git("commit", "-m", f"Publish assessed {self.args.month} MSRC release", cwd=publication)
        commit = self.git("rev-parse", "HEAD", cwd=publication)
        if self.git("rev-parse", "HEAD^", cwd=publication) != base or self.remote_head() != base:
            raise RuntimeError("Publication parent or remote changed; nothing pushed")
        self.git("push", "origin", "HEAD:refs/heads/main", cwd=publication)
        self.save(status="deployment-pending", published_commit=commit)
        self.verify_live(first, sources.sha(built.read_bytes()))
        self.save(status="published-verified", finished_at=now())
        emit(f"Published and verified {self.args.month}: {SITE}")

    def verify_live(self, expected, expected_sha):
        emit("Waiting for Cloudflare's Git deployment and checking exact built bytes")
        deadline = time.monotonic() + 900
        failure = "deployment not visible"
        while time.monotonic() < deadline:
            try:
                request = urllib.request.Request(f"{SITE}/data/months.json?release={uuid.uuid4().hex}", headers={"Cache-Control": "no-cache"})
                with urllib.request.urlopen(request, timeout=30) as response:
                    manifest = json.load(response)
                first = next(item for item in manifest if not item["month"].endswith("-demo"))
                if first["month"] == self.args.month and first["file"] == expected["file"]:
                    with urllib.request.urlopen(f"{SITE}/data/{expected['file']}", timeout=60) as response:
                        if sources.sha(response.read()) == expected_sha:
                            return
                failure = "live default month or asset bytes differ"
            except Exception as error:
                failure = str(error)
            time.sleep(15)
        raise RuntimeError(f"Git push succeeded but Cloudflare deployment was not verified: {failure}. See saved commit/asset receipt")


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("month", nargs="?", default=f"{datetime.now().year}-{MONTHS[datetime.now().month-1]}")
    parser.add_argument("--plan", action="store_true", help="Show the bounded workflow without fetching, spending or publishing")
    parser.add_argument("--no-publish", action="store_true", help="Run all assessments and release gates; do not commit or push")
    parser.add_argument("--batch-size", type=int, default=10)
    parser.add_argument("--concurrency", type=int, default=6)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"20\d\d-(?:" + "|".join(MONTHS) + ")", args.month):
        parser.error("month must be YYYY-Mmm, for example 2026-Dec")
    if not 1 <= args.batch_size <= 50 or not 1 <= args.concurrency <= 12:
        parser.error("batch-size must be 1–50 and concurrency 1–12")
    return args


def main(argv=None):
    args = arguments(argv)
    if args.plan:
        print(json.dumps({"month": args.month, "model": MODEL, "effort": "medium", "batch_size": args.batch_size,
                          "concurrency": args.concurrency, "publishes": not args.no_publish,
                          "workflow": ["auth/prerequisite preflight", "fresh public sources", "full-scaffold assessment",
                                       "raw receipt/schema/source/control validation", "bounded live-source reconciliation",
                                       "complete merge", "isolated origin/main tests/build/browser gates", "whitelisted fast-forward push",
                                       "verify Cloudflare default month and built asset SHA256"],
                          "work": str(ROOT / "work/monthly" / args.month)}, indent=2))
        return 0
    run = MonthlyRun(args)
    acquired = False
    try:
        with exclusive_run(run.work / "run.lock"):
            acquired = True
            run.run()
        return 0
    except (Exception, KeyboardInterrupt) as error:
        if acquired:
            run.save(status="failed", error=str(error), finished_at=now())
        print(f"Monthly run stopped: {error}\nReceipt: {run.work / 'run-receipt.json'}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
