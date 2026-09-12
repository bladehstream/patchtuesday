#!/usr/bin/env python3
"""Self-test for tag_validators.py (Tier 1). Plain python, no test framework.

    python3 scripts/tag_validators_self_test.py

Every Tier 1 check gets a fixture it must reject and a fixture it must accept. A
check that has only ever been seen to pass is not evidence that it works: the
recall check in particular is one regex table away from silently flagging nothing.

Cases are drawn from real failures observed in the 2026-09 dev runs, not invented.
Previously carried as tests/test_tag_validators.py in pytest style, which nothing
in this repository ever ran.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import tag_validators as tv  # noqa: E402

NS = tv.load_namespaces(ROOT / "data" / "tag-taxonomy.json")
WORKLOAD = NS["workload"]
JUDGE = NS["workload"] | NS["delivery"] | NS["impact"]


def record(title, ui="required", vector="network", products=()):
    return {"cve": "CVE-TEST", "title": title,
            "products": [{"product_id": "1", "name": n} for n in products],
            "attack": {"vector": vector, "privileges_required": "none", "user_interaction": ui}}


def overlay(*pairs):
    return {"tags": [{"tag": t, "evidence": e} for t, e in pairs]}


# --- workload recall: the eight real misses from cycle 4 ---

RECALL_MISSES = [
    ("Windows Remote Desktop Remote Code Execution Vulnerability", "remote-desktop"),
    ("Windows Services for NFS ONCRPC XDR Driver Remote Code Execution", "nfs"),
    ("Windows Kerberos Denial of Service Vulnerability", "identity"),
    ("Windows Shell Remote Code Execution Vulnerability", "windows-shell"),
    ("Windows SMB Server Network Transport Driver Elevation of Privilege", "file-services"),
    ("Windows DNS Server Remote Code Execution Vulnerability", "dns"),
]


def recall_flags_a_named_role_that_was_not_tagged():
    for title, expected in RECALL_MISSES:
        findings = tv.check_workload_recall(record(title), overlay())
        assert any(f["tag"] == expected and f["code"] == "workload-recall-miss" for f in findings), \
            f"expected a {expected} recall miss for {title!r}"


def recall_is_silent_when_the_role_was_tagged():
    r = record("Windows DNS Server Remote Code Execution Vulnerability")
    assert tv.check_workload_recall(r, overlay(("dns", "Windows DNS Server"))) == []


def recall_is_silent_when_no_role_is_named():
    """Chromium passthroughs name no role. Abstaining is correct, not a miss."""
    r = record("Chromium: CVE-2026-84350 Use after free in TabStrip")
    assert tv.check_workload_recall(r, overlay()) == []


# --- workload precision ---

def precision_flags_a_tag_with_no_corroboration():
    r = record("Microsoft Exchange Server Elevation of Privilege Vulnerability")
    findings = tv.check_workload_precision(r, overlay(("identity", "Exchange implies directory")), WORKLOAD)
    assert [f["code"] for f in findings] == ["workload-uncorroborated"]


def precision_accepts_a_corroborated_tag():
    r = record("Windows DHCP Server Denial of Service Vulnerability")
    assert tv.check_workload_precision(r, overlay(("dhcp", "Windows DHCP Server")), WORKLOAD) == []


# --- delivery vs CVSS: the real CVE-2026-69380 contradiction ---

def delivery_flags_user_content_against_ui_none():
    r = record("Microsoft Exchange Server Elevation of Privilege Vulnerability", ui="none")
    findings = tv.check_delivery_consistency(r, overlay(("user-content", "crafted message"), ("email", "mail flow")))
    assert len(findings) == 2
    assert {f["tag"] for f in findings} == {"user-content", "email"}


def delivery_flags_local_access_against_network_vector():
    r = record("Something", ui="required", vector="network")
    findings = tv.check_delivery_consistency(r, overlay(("local-access", "requires local logon")))
    assert findings and findings[0]["code"] == "delivery-contradicts-cvss"


def delivery_accepts_a_consistent_tag():
    r = record("Excel Remote Code Execution", ui="required", vector="local")
    assert tv.check_delivery_consistency(r, overlay(("user-content", "user opens a crafted file"))) == []


# --- evidence presence and grounding ---

def missing_evidence_is_flagged():
    r = record("Windows DNS Server Remote Code Execution Vulnerability")
    findings = tv.check_evidence_present(r, overlay(("dns", "  ")), JUDGE)
    assert findings and findings[0]["code"] == "evidence-missing"


def evidence_citing_its_own_reasoning_is_flagged():
    """The signature of a fabricated citation: no lexical contact with the source."""
    r = record("Windows DNS Server Remote Code Execution Vulnerability")
    findings = tv.check_evidence_grounded(r, overlay(("dns", "generally accepted industry practice")), JUDGE)
    assert findings and findings[0]["code"] == "evidence-ungrounded"


def evidence_quoted_from_the_record_passes():
    r = record("Windows DNS Server Remote Code Execution Vulnerability")
    assert tv.check_evidence_grounded(r, overlay(("dns", "Windows DNS Server")), JUDGE) == []


def pre_change_bare_string_tags_are_tolerated():
    """Older runs stored tags as plain strings; the validators must not crash."""
    assert tv.asserted({"tags": ["dns", "remote-code-execution"]}) == {"dns": "", "remote-code-execution": ""}



# --- WORKLOAD_TERMS: one fixture per term ---------------------------------
#
# The term table is the whole of Tier 1's workload judgement, and it is the part
# most likely to be extended in a hurry. Every term therefore owns a pair of
# fixtures: a record it must match, and a genuinely different record it must not.
# `every_workload_term_has_a_fixture` makes that mandatory - add a term without a
# pair here and this file fails. A term list nobody can fail is not a gate.
#
# Negatives are near-misses where a near-miss exists (Chromoting for remote-desktop,
# ext4 for file-services, PowerShell for windows-shell, Cosmos DB for identity):
# those are the real 2026-09 records the table has to keep out.

FAR = "Windows Common Log File System Driver Elevation of Privilege Vulnerability"

NEGATIVE = {
    "file-services": "ext4: don't enable DAX on new encrypted files",
    "windows-shell": "Windows PowerShell Elevation of Privilege Vulnerability",
    "remote-desktop": "Chromium: CVE-2026-84334 Incorrect authorization in Chromoting",
    "identity": "Azure Cosmos DB Spoofing Vulnerability",
    "web-server": "Microsoft Excel Remote Code Execution Vulnerability",
    "graphics": "Microsoft DirectMusic Remote Code Execution Vulnerability",
}

# (tag, term, a record the term must match)
TERM_FIXTURES = [
    ("dns", "dns", "Windows DNS Server Remote Code Execution Vulnerability"),
    ("dns", "domain name system", "Windows Domain Name System Denial of Service Vulnerability"),
    ("dns", "name resolution", "Windows Name Resolution Spoofing Vulnerability"),

    ("dhcp", "dhcp", "Windows DHCP Server Denial of Service Vulnerability"),
    ("dhcp", "dynamic host configuration", "Windows Dynamic Host Configuration Protocol Elevation of Privilege"),

    ("hyper-v", "hyper-v", "Windows Hyper-V Remote Code Execution Vulnerability"),
    ("hyper-v", "virtual machine bus", "Windows Virtual Machine Bus Elevation of Privilege Vulnerability"),
    ("hyper-v", "vmbus", "Windows VMBus Denial of Service Vulnerability"),

    # Client-side spellings: the definition puts both ends of the connection in scope.
    ("remote-desktop", "remote desktop", "Remote Desktop Client Remote Code Execution Vulnerability"),
    ("remote-desktop", "terminal services", "Windows Terminal Services Elevation of Privilege Vulnerability"),
    ("remote-desktop", "rdp", "Windows RDP Listener Denial of Service Vulnerability"),
    ("remote-desktop", "mstsc", "Windows mstsc Client Information Disclosure Vulnerability"),

    # The HTTP server side, whoever ships it - not just IIS.
    ("web-server", "iis", "Microsoft IIS Server Elevation of Privilege Vulnerability"),
    ("web-server", "internet information services", "Internet Information Services Remote Code Execution"),
    ("web-server", "httpd", "inets, httpd: HTTP Request Smuggling via Transfer-Encoding and Content-Length"),
    ("web-server", "nginx", "NGINX ngx_http_js_module vulnerability"),
    ("web-server", "apache", "Apache Traffic Server request smuggling"),
    ("web-server", "inets", "inets: memory exhaustion during chunked body read"),
    ("web-server", "http server", "Embedded HTTP Server Denial of Service Vulnerability"),
    ("web-server", "web server", "Azure Linux web server configuration bypass"),
    ("web-server", "http.sys", "Windows HTTP.sys Remote Code Execution Vulnerability"),
    ("web-server", "tomcat", "Tomcat session fixation"),

    # Everything whose own job is identity - must track the taxonomy definition.
    ("identity", "active directory", "Windows Active Directory Domain Services Denial of Service Vulnerability"),
    ("identity", "domain controller", "Windows Domain Controller Elevation of Privilege Vulnerability"),
    ("identity", "kerberos", "Windows Kerberos Denial of Service Vulnerability"),
    ("identity", "netlogon", "Windows Netlogon Spoofing Vulnerability"),
    ("identity", "entra", "Microsoft Entra ID Elevation of Privilege Vulnerability"),
    ("identity", "key distribution center", "Windows Key Distribution Center Denial of Service Vulnerability"),
    ("identity", "kdc", "Windows KDC Proxy Remote Code Execution Vulnerability"),
    ("identity", "ad cs", "AD CS Tampering Vulnerability"),
    ("identity", "ad fs", "AD FS Denial of Service Vulnerability"),
    ("identity", "adfs", "Windows ADFS Spoofing Vulnerability"),
    ("identity", "certificate services", "Certificate Services Elevation of Privilege Vulnerability"),
    ("identity", "federation services", "Federation Services Information Disclosure Vulnerability"),
    ("identity", "domain services", "Windows Domain Services Remote Code Execution Vulnerability"),
    ("identity", "azure ad", "Azure AD Connect Elevation of Privilege Vulnerability"),
    ("identity", "b2c", "Microsoft B2C Identity Experience Framework Spoofing Vulnerability"),
    ("identity", "microsoft account", "Microsoft Account Elevation of Privilege Vulnerability"),
    ("identity", "msal", "MSAL for Node.js Spoofing Vulnerability"),
    ("identity", "authentication library", "Microsoft Authentication Library for Java Spoofing Vulnerability"),
    ("identity", "ntlm", "Windows NTLM Elevation of Privilege Vulnerability"),
    ("identity", "ldap", "Windows LDAP Remote Code Execution Vulnerability"),

    ("nfs", "services for nfs", "Windows Services for NFS Driver Remote Code Execution Vulnerability"),
    ("nfs", "network file system", "Windows Network File System Denial of Service Vulnerability"),
    ("nfs", "oncrpc", "ONCRPC XDR Driver Information Disclosure Vulnerability"),

    ("netlogon", "netlogon", "Windows Netlogon Spoofing Vulnerability"),

    ("print", "print spooler", "Windows Print Spooler Components Elevation of Privilege Vulnerability"),
    ("print", "print provider", "Windows HTTP Print Provider Remote Code Execution Vulnerability"),
    ("print", "print driver", "Windows Print Driver Elevation of Privilege Vulnerability"),
    ("print", "printer", "Windows Printer Metadata Troubleshooter Elevation of Privilege Vulnerability"),
    ("print", "printing", "Windows Internet Printing Protocol Denial of Service Vulnerability"),

    ("file-services", "smb", "Windows SMB Server Elevation of Privilege Vulnerability"),
    ("file-services", "server message block", "Windows Server Message Block Information Disclosure Vulnerability"),
    ("file-services", "cifs", "Linux CIFS client out-of-bounds read"),
    ("file-services", "samba", "Samba winbind memory disclosure"),
    ("file-services", "file share", "Windows File Share Redirector Elevation of Privilege Vulnerability"),
    ("file-services", "file server", "Windows File Server Resource Manager Denial of Service Vulnerability"),
    ("file-services", "file sharing", "Windows File Sharing Service Information Disclosure Vulnerability"),
    ("file-services", "dfs namespace", "Windows DFS Namespace Elevation of Privilege Vulnerability"),

    ("database", "sql server", "Microsoft SQL Server Remote Code Execution Vulnerability"),
    ("database", "sqlite", "Information disclosure in the zipfile extension in SQLite v3.51.1"),
    ("database", "database", "Azure Cosmos DB database account spoofing"),
    ("database", "mysql", "MySQL Server privilege escalation"),
    ("database", "postgres", "PostgreSQL client library buffer overflow"),
    ("database", "mariadb", "MariaDB server denial of service"),

    ("message-queuing", "message queuing", "Windows Message Queuing Remote Code Execution Vulnerability"),
    ("message-queuing", "msmq", "Windows MSMQ Denial of Service Vulnerability"),

    ("failover-cluster", "failover cluster", "Windows Failover Cluster Elevation of Privilege Vulnerability"),

    ("sstp", "sstp", "Windows SSTP Remote Code Execution Vulnerability"),
    ("sstp", "secure socket tunneling", "Windows Secure Socket Tunneling Protocol Remote Code Execution"),

    ("rras", "routing and remote access", "Windows Routing and Remote Access Service Denial of Service"),
    ("rras", "rras", "Windows RRAS Denial of Service Vulnerability"),

    ("windows-shell", "windows shell", "Windows Shell Elevation of Privilege Vulnerability"),
    ("windows-shell", "explorer.exe", "Windows explorer.exe Security Feature Bypass Vulnerability"),
    ("windows-shell", "shell32", "Windows shell32 Remote Code Execution Vulnerability"),

    ("graphics", "graphics component", "Windows Graphics Component Remote Code Execution Vulnerability"),
    ("graphics", "graphic", "Graphic Fonts Remote Code Execution Vulnerability"),
    ("graphics", "gdi", "Windows GDI+ Information Disclosure Vulnerability"),
    ("graphics", "directwrite", "DirectWrite Remote Code Execution Vulnerability"),
    ("graphics", "direct2d", "Direct2D Elevation of Privilege Vulnerability"),
    ("graphics", "font", "Windows Font Driver Host Remote Code Execution Vulnerability"),
    ("graphics", "gpu", "Chromium: CVE-2026-84351 Buffer overflow in GPU"),
    ("graphics", "win32k", "Windows Win32k Elevation of Privilege Vulnerability"),
    ("graphics", "display driver", "Windows Display Driver Elevation of Privilege Vulnerability"),

    ("imaging", "image extension", "HEIF Image Extensions Remote Code Execution Vulnerability"),
    ("imaging", "imaging component", "Windows Imaging Component Information Disclosure Vulnerability"),
    ("imaging", "image codec", "Windows Image Codec Remote Code Execution Vulnerability"),
    ("imaging", "heif", "HEIF decoder out-of-bounds read"),

    ("update-stack", "windows update stack", "Windows Update Stack Elevation of Privilege Vulnerability"),
    ("update-stack", "update stack", "Servicing update stack elevation of privilege"),
    ("update-stack", "servicing stack", "Windows Servicing Stack Elevation of Privilege Vulnerability"),

    ("alpc", "alpc", "Windows ALPC Elevation of Privilege Vulnerability"),
    ("alpc", "advanced local procedure call", "Windows Advanced Local Procedure Call Elevation of Privilege"),

    ("internet-connection-sharing", "internet connection sharing",
     "Windows Internet Connection Sharing (ICS) Tampering Vulnerability"),
    ("internet-connection-sharing", "ics", "Windows ICS Service Denial of Service Vulnerability"),
]


def negative_for(tag):
    return NEGATIVE.get(tag, FAR)


def every_workload_term_has_a_fixture():
    """No term may enter the table without a pair of fixtures."""
    covered = {(tag, term) for tag, term, _ in TERM_FIXTURES}
    declared = {(tag, term) for tag, terms in tv.WORKLOAD_TERMS.items() for term in terms}
    missing = declared - covered
    assert not missing, f"terms with no fixture: {sorted(missing)}"
    stale = covered - declared
    assert not stale, f"fixtures for terms no longer in the table: {sorted(stale)}"


def the_terms_table_matches_the_taxonomy():
    """A term entry for a tag the taxonomy does not have produces findings nobody
    can act on - `remote-desktop-gateway` sat here as a phantom tag for four cycles."""
    assert set(tv.WORKLOAD_TERMS) == WORKLOAD, (
        f"only in table: {sorted(set(tv.WORKLOAD_TERMS) - WORKLOAD)}; "
        f"only in taxonomy: {sorted(WORKLOAD - set(tv.WORKLOAD_TERMS))}")


def each_negative_fixture_genuinely_differs():
    """A negative that happens to contain the term proves nothing."""
    for tag, term, positive in TERM_FIXTURES:
        negative = negative_for(tag)
        assert negative != positive, f"{tag}/{term}: negative is the positive"
        for other in tv.WORKLOAD_TERMS[tag]:
            assert not tv.mentions(negative.lower(), other), \
                f"{tag}/{term}: negative {negative!r} contains {other!r}"


def every_term_corroborates_its_own_fixture():
    """Precision must ACCEPT the tag on a record that names the role."""
    for tag, term, positive in TERM_FIXTURES:
        findings = tv.check_workload_precision(record(positive), overlay((tag, positive)), WORKLOAD)
        assert findings == [], f"{tag}/{term}: {positive!r} was called uncorroborated"


def every_term_rejects_a_genuinely_different_record():
    """Precision must FLAG the same tag on a record that names nothing of the kind."""
    for tag, term, _ in TERM_FIXTURES:
        negative = negative_for(tag)
        findings = tv.check_workload_precision(record(negative), overlay((tag, "asserted anyway")), WORKLOAD)
        assert [f["code"] for f in findings] == ["workload-uncorroborated"], \
            f"{tag}/{term}: {negative!r} should not corroborate {tag}"


def every_term_raises_a_recall_miss_when_untagged():
    for tag, term, positive in TERM_FIXTURES:
        findings = tv.check_workload_recall(record(positive), overlay())
        assert any(f["tag"] == tag for f in findings), f"{tag}/{term}: no recall miss for {positive!r}"


def no_term_raises_a_recall_miss_on_its_negative():
    for tag, term, _ in TERM_FIXTURES:
        negative = negative_for(tag)
        findings = tv.check_workload_recall(record(negative), overlay())
        assert not any(f["tag"] == tag for f in findings), \
            f"{tag}/{term}: spurious recall miss on {negative!r}"


# --- matching itself ------------------------------------------------------

def matching_requires_a_word_boundary():
    """The real defect. Widening `identity` from 'entra id' to 'entra' made the
    precision check - which used a bare substring test - read "centrally managed
    policies" as corroboration, excusing an identity tag on a device-management
    advisory. Both workload checks now use one boundary-aware matcher."""
    assert tv.mentions("preventing its centrally managed policies", "entra") is False
    assert tv.mentions("microsoft entra id elevation of privilege", "entra") is True
    r = record("Windows Modern Device Management (MDM) Security Feature Bypass Vulnerability",
               products=("preventing its centrally managed policies from being enforced",))
    findings = tv.check_workload_precision(r, overlay(("identity", "MDM enrolment is identity")), WORKLOAD)
    assert [f["code"] for f in findings] == ["workload-uncorroborated"], findings


def powershell_does_not_corroborate_the_windows_shell_tag():
    r = record("Windows PowerShell Elevation of Privilege Vulnerability")
    findings = tv.check_workload_precision(r, overlay(("windows-shell", "PowerShell is a shell")), WORKLOAD)
    assert [f["code"] for f in findings] == ["workload-uncorroborated"]


# --- the 2026-09 records the rewritten definitions turn on -----------------

DEFINITION_CASES_CORROBORATED = [
    ("remote-desktop", "Remote Desktop Client Remote Code Execution Vulnerability"),
    ("remote-desktop", "Windows Remote Desktop Client Denial of Service Vulnerability"),
    ("identity", "Windows Key Distribution Center Denial of Service Vulnerability"),
    ("identity", "Active Directory Certificate Services (AD CS) Tampering Vulnerability"),
    ("identity", "Microsoft Azure Active Directory B2C Elevation of Privilege Vulnerability"),
    ("identity", "Microsoft Account Elevation of Privilege Vulnerability"),
    ("identity", "Microsoft Authentication Library (MSAL) for Node.js Spoofing Vulnerability"),
    ("web-server", "inets, httpd: HTTP Request Smuggling via Whitespace-Before-Colon Header Dropping"),
    ("web-server", "NGINX ngx_http_js_module vulnerability"),
    ("print", "Windows HTTP Print Provider Remote Code Execution Vulnerability"),
    ("graphics", "Graphic Fonts Remote Code Execution Vulnerability"),
    ("database", "An information disclosure issue in the zipfile extension in SQLite v3.51.1 and earlier"),
]

DEFINITION_CASES_STILL_UNCORROBORATED = [
    # The taxonomy boundary clauses say these are out, so Tier 1 must keep flagging them.
    ("identity", "Azure Cosmos DB Spoofing Vulnerability"),
    ("identity", "Copilot Studio Elevation of Privilege Vulnerability"),
    ("identity", "Azure AI Language Elevation of Privilege Vulnerability"),
    ("identity", "Skype for Business Remote Code Execution Vulnerability"),
    ("identity", "Chromium: CVE-2026-84329 Confused deputy in CredentialProvider"),
    ("remote-desktop", "Chromium: CVE-2026-84334 Incorrect authorization in Chromoting"),
    ("file-services", "ext4: don't enable DAX on new encrypted files"),
    ("file-services", "ocfs2: fix missing metadata reservation for large xattrs"),
    ("windows-shell", "Visual Studio Code Information Disclosure Vulnerability"),
]


def records_the_new_definitions_admit_are_corroborated():
    for tag, title in DEFINITION_CASES_CORROBORATED:
        findings = tv.check_workload_precision(record(title), overlay((tag, title)), WORKLOAD)
        assert findings == [], f"{tag} on {title!r} should now corroborate: {findings}"


def records_the_new_definitions_exclude_are_still_flagged():
    for tag, title in DEFINITION_CASES_STILL_UNCORROBORATED:
        findings = tv.check_workload_precision(record(title), overlay((tag, title)), WORKLOAD)
        assert [f["code"] for f in findings] == ["workload-uncorroborated"], \
            f"{tag} on {title!r} must stay flagged: {findings}"


# --- the taxonomy definitions themselves ----------------------------------

def every_workload_definition_is_a_criterion_not_a_list():
    """Cycle 7's failure mode: a definition written as a closed enumeration is read
    by the scorer as a membership whitelist. A workload definition must therefore
    carry an explicit boundary clause - the shape that worked for user-content."""
    import json
    definitions = json.loads((ROOT / "data" / "tag-taxonomy.json").read_text(encoding="utf-8"))["definitions"]
    defined = [t for t in WORKLOAD if t in definitions]
    assert defined, "no workload tag carries a definition"
    for tag in defined:
        text = definitions[tag]
        assert "does NOT" in text, f"{tag} definition has no boundary clause"
        assert "examples, not the whole list" in text or "are examples" in text, \
            f"{tag} definition does not mark its enumeration as illustrative"


CASES = [
    ("every workload term has a fixture", every_workload_term_has_a_fixture),
    ("the terms table matches the taxonomy", the_terms_table_matches_the_taxonomy),
    ("each negative fixture genuinely differs", each_negative_fixture_genuinely_differs),
    ("every term corroborates its own fixture", every_term_corroborates_its_own_fixture),
    ("every term rejects a genuinely different record", every_term_rejects_a_genuinely_different_record),
    ("every term raises a recall miss when untagged", every_term_raises_a_recall_miss_when_untagged),
    ("no term raises a recall miss on its negative", no_term_raises_a_recall_miss_on_its_negative),
    ("matching requires a word boundary", matching_requires_a_word_boundary),
    ("PowerShell does not corroborate windows-shell", powershell_does_not_corroborate_the_windows_shell_tag),
    ("records the new definitions admit are corroborated", records_the_new_definitions_admit_are_corroborated),
    ("records the new definitions exclude are still flagged", records_the_new_definitions_exclude_are_still_flagged),
    ("every workload definition is a criterion not a list", every_workload_definition_is_a_criterion_not_a_list),
    ("recall flags a named role that was not tagged", recall_flags_a_named_role_that_was_not_tagged),
    ("recall is silent when the role was tagged", recall_is_silent_when_the_role_was_tagged),
    ("recall is silent when no role is named", recall_is_silent_when_no_role_is_named),
    ("precision flags an uncorroborated tag", precision_flags_a_tag_with_no_corroboration),
    ("precision accepts a corroborated tag", precision_accepts_a_corroborated_tag),
    ("delivery flags user-content against UI:N", delivery_flags_user_content_against_ui_none),
    ("delivery flags local-access against AV:N", delivery_flags_local_access_against_network_vector),
    ("delivery accepts a consistent tag", delivery_accepts_a_consistent_tag),
    ("missing evidence is flagged", missing_evidence_is_flagged),
    ("ungrounded evidence is flagged", evidence_citing_its_own_reasoning_is_flagged),
    ("evidence quoted from the record passes", evidence_quoted_from_the_record_passes),
    ("bare string tags from older runs are tolerated", pre_change_bare_string_tags_are_tolerated),
]


def main() -> None:
    failures = []
    for label, case in CASES:
        try:
            case()
        except AssertionError as error:
            failures.append(f"{label}: {error}")
        except Exception as error:  # noqa: BLE001 - a crash is a failure, not an error to hide
            failures.append(f"{label}: {type(error).__name__}: {error}")
    for failure in failures:
        print(f"FAIL {failure}")
    print(f"{len(CASES) - len(failures)}/{len(CASES)} Tier 1 tag validator checks behaved as specified")
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
