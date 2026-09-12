#!/usr/bin/env python3
"""Self-test for customer_data_guard.py. Plain python, no test framework.

    python3 scripts/customer_data_guard_self_test.py

A gate that cannot fail is not a gate. Every detector class here gets a fixture
it must reject AND a realistic advisory fixture it must pass, and the two are
built to differ in the thing under test rather than in incidental shape - a
negative fixture that merely omits the whole construct proves nothing, so each
one keeps the surrounding prose and changes only what makes the span
identifying. "10.14.22.7" against "6.6.150.1-1 on Azure Linux 3.0" is the model:
both are dotted quads in product prose; one is an address and one is a version.

The negatives are real strings from data/2026-Sep.jsonl wherever the corpus
supplies one, so the exemptions are tested against text the pipeline actually
carries rather than against text invented to suit them.

Three layers are exercised:

  1. detectors      - reject/accept pairs per category
  2. the refusal    - CustomerDataError names the record, field path and span,
                      and returns no redacted value
  3. the wiring     - prepare_full_inference.py and run_cli_inference.py both
                      stop on a planted record, and both pass on a clean one
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import customer_data_guard as guard  # noqa: E402

PUBLISHED = ROOT / "data" / "2026-Sep.jsonl"
PREPARE = ROOT / "scripts" / "prepare_full_inference.py"
RUNNER = ROOT / "scripts" / "run_cli_inference.py"

failures: list[str] = []
checks = 0


def rejects(category: str, name: str, text: str) -> None:
    """The guard must flag `text`, and must flag it as `category`."""
    global checks
    checks += 1
    findings = guard.scan_text(text)
    if not findings:
        failures.append(f"{category}/{name}: gate did not fire on {text!r}")
        return
    if category not in {finding.category for finding in findings}:
        failures.append(
            f"{category}/{name}: fired as {sorted({f.category for f in findings})}, "
            f"expected {category}, on {text!r}")
        return
    match = next(finding for finding in findings if finding.category == category)
    if match.span not in text:
        failures.append(f"{category}/{name}: reported span {match.span!r} is not in the input")


def passes(category: str, name: str, text: str) -> None:
    """Realistic advisory text the guard must leave alone."""
    global checks
    checks += 1
    findings = guard.scan_text(text)
    if findings:
        failures.append(
            f"{category}/{name}: false positive on advisory text {text!r}\n"
            + "\n".join(f"      {finding.describe()}" for finding in findings))


def case(name: str, ok: bool, detail: str = "") -> None:
    global checks
    checks += 1
    if not ok:
        failures.append(f"{name}: {detail}")


# ---------------------------------------------------------------------------
# 1. Detectors: one rejected fixture and one accepted fixture per class.
#    Each pair shares its surrounding prose; only the span under test differs.
# ---------------------------------------------------------------------------
def detector_cases() -> None:
    # IPv4. Both sides are a dotted quad sitting next to a product name.
    rejects("ipv4_address", "rfc1918",
            "Patch the DHCP relay at 10.14.22.7 before the change window.")
    rejects("ipv4_address", "public-literal",
            "The service was reachable from 203.0.113.45 during the incident.")
    rejects("ipv4_address", "loopback-bound-listener",
            "Agent listens on 127.0.0.1 and forwards to 172.20.8.30.")
    passes("ipv4_address", "four-part-package-version",
           "azl3 kernel 6.6.150.1-1 on Azure Linux 3.0")          # real, 98 records
    passes("ipv4_address", "four-part-version-range",
           "zlib 1.3.1.2 through 1.3.2 Heap Buffer Overflow via gz_vacate")  # real
    passes("ipv4_address", "erlang-build",
           "azl3 erlang 26.2.5.21-4 on Azure Linux 3.0")          # real, 14 records

    # IPv6 versus the timestamps and CVSS vectors the pipeline is full of.
    rejects("ipv6_address", "link-local",
            "Management interface fe80::1c2b:5aff:fe11:2233 on the OOB segment.")
    rejects("ipv6_address", "global-unicast",
            "Published AAAA record 2001:0db8:85a3:0000:0000:8a2e:0370:7334 for the edge.")
    passes("ipv6_address", "iso-timestamp",
           "Refreshed MSRC feed retrieved at 2026-09-10T04:18:17Z before the run.")
    passes("ipv6_address", "cvss-vector",
           "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C")

    # MAC addresses versus hex-ish vendor strings.
    rejects("mac_address", "colon-form",
            "The affected NIC 00:1A:2B:3C:4D:5E requires the firmware update.")
    rejects("mac_address", "cisco-form",
            "The affected NIC 001a.2b3c.4d5e requires the firmware update.")
    passes("mac_address", "kb-and-scores",
           "The affected build KB5124008 requires the update; EPSS 0.00631, percentile 0.48188.")

    # Email. A published vendor role address is not a person.
    rejects("email_address", "named-person-at-customer",
            "Raise the change with bob.smith@health.nsw.gov.au before Tuesday.")
    rejects("email_address", "person-at-vendor",
            "Raise the change with bob.smith@microsoft.com before Tuesday.")
    passes("email_address", "vendor-role-address",
           "Raise the change with secure@microsoft.com before Tuesday.")

    # GUIDs. The corpus carries 406 of them inside Microsoft download URLs.
    rejects("tenant_identifier", "entra-tenant",
            "Tenant ID: 3f2504e0-4f89-11d3-9a0c-0305e82c3301 is affected by the Entra change.")
    rejects("tenant_identifier", "tenant-guid-inside-a-vendor-url",
            "See https://portal.azure.com/#home/tenantId=3f2504e0-4f89-11d3-9a0c-0305e82c3301")
    rejects("guid", "bare-guid-in-prose",
            "The object 550e8400-e29b-41d4-a716-446655440000 was still registered.")
    passes("guid", "download-familyid",
           "https://www.microsoft.com/download/details.aspx?familyid=e668fe5f-ea1e-41fb-97f7-1bc12e91150b")

    # SIDs.
    rejects("security_identifier", "domain-admin-sid",
            "Membership of S-1-5-21-1004336348-1177238915-682003330-512 grants the path.")
    passes("security_identifier", "product-version-run",
           "Affected builds are 10.0.26100.1742 and 10.0.22631.4169 on x64 systems.")

    # Hostnames: URL host, bare FQDN, and a labelled bare host.
    rejects("hostname", "customer-url",
            "Remediation tracked at https://itsm.agency.gov.au/change/CHG0041882")
    rejects("hostname", "customer-fqdn-in-prose",
            "Patch SYD-DC-01.corp.agency.gov.au during the Saturday window.")
    rejects("hostname", "split-horizon-suffix",
            "Patch sydfs01.internal during the Saturday window.")
    rejects("hostname", "labelled-bare-host",
            "hostname: SYD-APP-07 is the only unpatched node.")
    passes("hostname", "vendor-update-urls",
           "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5124008 and "
           "https://support.microsoft.com/help/5124008")
    passes("hostname", "dotted-product-name",
           "ASP.NET Core Denial of Service Vulnerability")        # real title shape
    passes("hostname", "source-file-paths",
           "Fixed in libfreeipmi/sel/ipmi-sel-string-fujitsu-irmc-common.c and "
           "ipmi-oem/ipmi-oem-dell.c")                            # real note text
    passes("hostname", "driver-and-arch-names",
           "Windows Spaceport.sys, Windows Win32K, ARM64 and x64 builds are affected.")
    passes("hostname", "labelled-product-version",
           "Affected: Microsoft Exchange Server: 2019 Cumulative Update 14")

    # UNC and absolute filesystem paths versus registry and system paths.
    rejects("unc_path", "file-server-share",
            r"Copy the export from \\SYDFS01\Payroll\assets.csv before patching.")
    rejects("filesystem_path", "user-profile-path",
            r"The inventory is at C:\Users\bsmith\Desktop\agency-assets.xlsx.")
    rejects("filesystem_path", "posix-home-path",
            "The inventory is at /home/bsmith/exports/agency-assets.json.")
    passes("filesystem_path", "registry-mitigation",
           r"Set HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion"
           r"\Policies\System\LocalAccountTokenFilterPolicy to 0.")
    passes("filesystem_path", "short-registry-hive-form",
           r"Set HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters to 1.")
    passes("filesystem_path", "windows-system-path",
           r"The update replaces C:\Windows\System32\ntdll.dll on affected systems.")
    passes("filesystem_path", "generic-posix-system-path",
           "The daemon reads /etc/ipmi/config and writes to /var/log/messages.")

    # Asset inventories: repetition on one line is what separates them from prose.
    rejects("asset_inventory", "csv-header-row",
            "Hostname,IP Address,OS Version,Last Seen,Asset Tag")
    rejects("asset_inventory", "run-of-asset-names",
            "Still unpatched: SYD-DC-01, SYD-APP-07, MEL-FS-02.")
    passes("asset_inventory", "single-inventory-term-in-a-product-name",
           "Windows IP Address Management (IPAM) Service Elevation of Privilege "
           "Vulnerability")                                        # real title
    passes("asset_inventory", "single-hyphenated-uppercase-token",
           "A CD-ROM drive is required to apply the offline media update.")  # real
    passes("asset_inventory", "run-of-public-identifiers",
           "Supersedes CVE-2026-50031, CVE-2026-84323 and CVE-2026-84325; see KB5124008.")

    # A whole realistic advisory record, assembled from real September text.
    passes("advisory", "full-description-note",
           "Improper link resolution before file access ('link following') in Windows "
           "Update Stack allows an authorized attacker to elevate privileges locally. "
           "An attacker who successfully exploited this vulnerability could gain SYSTEM "
           "privileges. See https://support.microsoft.com/help/5122871 for KB5122871.")


# ---------------------------------------------------------------------------
# 2. The refusal itself: named record, named field path, verbatim span, and no
#    redacted value handed back.
# ---------------------------------------------------------------------------
def refusal_cases() -> None:
    packet = {
        "cve": "CVE-2026-81963",
        "title": "Windows Update Stack Elevation of Privilege Vulnerability",
        "notes": [
            {"title": "Description", "text": "Improper link resolution before file access."},
            {"title": "Scope", "text": "Confirmed on 10.14.22.7 in the agency DMZ."},
        ],
    }
    try:
        guard.assert_clean(packet["cve"], packet, "inference packet")
    except guard.CustomerDataError as error:
        message = str(error)
        case("refusal/names-the-record", "CVE-2026-81963" in message, message)
        case("refusal/names-the-field", "notes[1].text" in message, message)
        case("refusal/quotes-the-span", "10.14.22.7" in message, message)
        case("refusal/says-it-did-not-send",
             "REFUSING TO SEND" in message and "nothing was sent" in message, message)
        case("refusal/carries-findings", len(error.findings) == 1 and
             error.findings[0].category == "ipv4_address", message)
    else:
        case("refusal/fires-at-all", False, "assert_clean returned on a dirty packet")

    # assert_clean has no return value to mistake for a cleaned packet, and the
    # input is left untouched.
    clean = {"cve": "CVE-2026-81963", "title": "Windows Update Stack Elevation of Privilege"}
    before = json.dumps(clean, sort_keys=True)
    case("refusal/returns-nothing", guard.assert_clean(clean["cve"], clean, "packet") is None)
    case("refusal/does-not-mutate", json.dumps(clean, sort_keys=True) == before)

    # Keys are scanned, not just values: a field named after a customer host is
    # itself the disclosure.
    findings = guard.scan_value({"assets.agency.gov.au": "see attached"})
    case("refusal/scans-keys", any(finding.category == "hostname" for finding in findings),
         str([finding.describe() for finding in findings]))

    # The allowlist must not be widenable to a public suffix by accident: adding
    # one organisation must not admit another under the same suffix.
    case("allowlist/subdomain-match", guard.domain_allowed("docs.microsoft.com"))
    case("allowlist/suffix-is-not-a-domain", not guard.domain_allowed("agency.gov.au"))
    case("allowlist/no-substring-match", not guard.domain_allowed("notmicrosoft.com"))
    case("allowlist/holds-no-public-suffix",
         not any(domain in guard.ALLOWED_DOMAINS
                 for domain in ("gov.au", "com.au", "org.au", "edu.au", "co.uk", "gov.uk")))


# ---------------------------------------------------------------------------
# 3. The wiring: both entry points must stop, and both must run clean otherwise.
# ---------------------------------------------------------------------------
def _baseline_records(count: int) -> list[dict]:
    rows = []
    with PUBLISHED.open(encoding="utf-8") as handle:
        for line in handle:
            rows.append(json.loads(line))
            if len(rows) >= count:
                break
    if len(rows) < count:
        raise SystemExit(f"Need {count} records in {PUBLISHED}")
    return rows


def _plant(record: dict) -> dict:
    """Put a customer address where a consultant would actually put one: in the
    free text of a vendor note, not in a field invented for the test."""
    dirty = json.loads(json.dumps(record))
    notes = dirty.setdefault("vendor_guidance", {}).setdefault("notes", [])
    notes.append({"title": "Scope", "type": 2,
                  "value": "<p>Confirmed exploitable on SYDDC01.corp.agency.gov.au "
                           "(10.14.22.7) during the assessment.</p>"})
    return dirty


def _write(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n",
                    encoding="utf-8")


def wiring_cases() -> None:
    rows = _baseline_records(9)
    with tempfile.TemporaryDirectory() as raw:
        work = Path(raw)
        clean_path, dirty_path = work / "clean.jsonl", work / "dirty.jsonl"
        _write(clean_path, rows)
        _write(dirty_path, rows[:-1] + [_plant(rows[-1])])
        planted = rows[-1]["cve"]

        def run(command: list[str]) -> subprocess.CompletedProcess:
            return subprocess.run(command, capture_output=True, text=True, cwd=ROOT)

        # prepare_full_inference.py
        result = run([sys.executable, str(PREPARE), "--month", "2026-Sep",
                      "--source", str(clean_path), "--output-dir", str(work / "prep-clean")])
        case("wiring/prepare-accepts-real-records", result.returncode == 0,
             result.stdout + result.stderr)

        result = run([sys.executable, str(PREPARE), "--month", "2026-Sep",
                      "--source", str(dirty_path), "--output-dir", str(work / "prep-dirty")])
        combined = result.stdout + result.stderr
        case("wiring/prepare-refuses-planted-record", result.returncode != 0, combined)
        case("wiring/prepare-names-the-record", planted in combined, combined)
        case("wiring/prepare-names-the-span",
             "10.14.22.7" in combined and "agency.gov.au" in combined, combined)
        # Refuse means refuse: no shard file for the dirty month reaches disk.
        case("wiring/prepare-wrote-no-shard",
             not list((work / "prep-dirty").rglob("input-*.jsonl")),
             str(list((work / "prep-dirty").rglob("*"))))

        # run_cli_inference.py. A deliberately non-existent CLI proves the
        # guard fires before any subprocess is launched: with the dirty file the
        # run must stop on the guard, not on "command not found".
        missing_cli = str(work / "no-such-model-cli")
        result = run([sys.executable, str(RUNNER), "--records", str(dirty_path),
                      "--run-dir", str(work / "run-dirty"), "--arm", "scaffolded",
                      "--cli", missing_cli])
        combined = result.stdout + result.stderr
        case("wiring/runner-refuses-planted-record", result.returncode != 0, combined)
        case("wiring/runner-stops-on-the-guard-not-the-cli",
             "REFUSING TO SEND" in combined and "FileNotFoundError" not in combined,
             combined)
        case("wiring/runner-names-the-record", planted in combined, combined)
        case("wiring/runner-wrote-no-prompt",
             not list((work / "run-dirty").rglob("prompt-*.txt")),
             str(list((work / "run-dirty").rglob("*"))))

        # The same invocation on clean records must get past the guard and fail
        # later, at the missing CLI - otherwise "refuses" would be indistinguishable
        # from "refuses everything".
        result = run([sys.executable, str(RUNNER), "--records", str(clean_path),
                      "--run-dir", str(work / "run-clean"), "--arm", "scaffolded",
                      "--cli", missing_cli])
        combined = result.stdout + result.stderr
        case("wiring/runner-passes-real-records",
             "REFUSING TO SEND" not in combined, combined)
        case("wiring/runner-reached-the-cli-on-clean-records",
             "FileNotFoundError" in combined or "No such file" in combined, combined)


# ---------------------------------------------------------------------------
# 4. Measured false-positive rate on the real dataset. Reported as a number, and
#    asserted, so a loosened detector cannot pass unnoticed and a tightened one
#    cannot start flagging published vendor text without failing here.
# ---------------------------------------------------------------------------
def corpus_case() -> int:
    rows = [json.loads(line) for line in PUBLISHED.read_text(encoding="utf-8").splitlines() if line.strip()]
    hits = []
    for record in rows:
        hits += [(record.get("cve"), finding) for finding in guard.scan_value(record)]
    case("corpus/zero-false-positives-on-published-advisory-data", not hits,
         "\n".join(f"      {cve} {finding.describe()}" for cve, finding in hits[:20]))
    print(f"false positives over {len(rows)} records in {PUBLISHED.name}: {len(hits)}")
    return len(hits)


def main() -> None:
    detector_cases()
    refusal_cases()
    wiring_cases()
    corpus_case()
    for failure in failures:
        print(f"FAIL {failure}")
    print(f"{checks - len(failures)}/{checks} customer-data guard checks behaved as specified")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
