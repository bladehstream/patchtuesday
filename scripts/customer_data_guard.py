#!/usr/bin/env python3
"""Refuse to send customer-identifying data to an inference provider.

CLAUDE.md and CLAUDE_ASSESSOR_HANDOFF.md both state the rule:

    No customer data in inference. No hostnames, IPs, tenant identifiers,
    inventories or topology. Public advisory material only.

Nothing enforced it. This module does. The user consults for Australian federal
and state government clients, so a customer identifier reaching a third-party
model API is the highest-consequence failure this tool can have - higher than a
wrong severity, because it cannot be corrected after the fact.

Three design decisions, each of which could reasonably have gone the other way:

1.  The check runs in the packet-construction path, before the prompt leaves the
    process. scripts/prepare_full_inference.py guards every packet it writes and
    scripts/run_claude_inference.py guards every record, every prompt and the
    system prompt immediately before subprocess.run. A detector that inspects a
    transcript afterwards tells you the data has already left.

2.  It fails loud and refuses to send, naming the record, the field path and the
    matched span. It never redacts and continues. A silent redaction hides that
    customer data reached the tool at all, and that - not the individual span -
    is what the consultant has to know, because it means an upstream process is
    feeding customer material into a public-advisory pipeline.

3.  Every exemption is derived from observed advisory text, not from guesswork.
    The exemption set below was tuned by running the detectors over all 1,185
    records in data/2026-Sep.jsonl and over the note text of the packets built
    from them. Measured false positives on that corpus: zero. Re-measure with

        python3 scripts/customer_data_guard.py --scan data/2026-Sep.jsonl

    after any change to a detector, and again on each new month before a run.

What is deliberately NOT detected, and why, is documented in NOT_DETECTED at the
bottom of this file. Read it before assuming a category is covered.
"""

from __future__ import annotations

import argparse
import html
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Vendor / public-advisory allowlists
#
# Every entry is a registrable domain that legitimately appears in public
# advisory material. Matching is exact-or-subdomain: "docs.microsoft.com" is
# allowed by "microsoft.com", and "agency.gov.au" is allowed by nothing.
#
# Deliberately absent: any public suffix ("com.au", "gov.au", "co.uk"). Adding
# one would allowlist every customer in that namespace at a stroke, which is the
# exact failure this guard exists to prevent. Add single organisations only.
# ---------------------------------------------------------------------------
ALLOWED_DOMAINS = frozenset({
    # observed in data/2026-Sep.jsonl
    "microsoft.com", "windows.net", "visualstudio.com", "google.com",
    "github.com", "nuget.org", "golang.org", "npmjs.com", "mvnrepository.com",
    "aka.ms",  # Microsoft's own short-link host; one remediation URL uses it
    "googleblog.com",  # chromereleases.googleblog.com, cited by Chromium notes
    # public feed hosts recorded in dataset_provenance by fetch_sources.py
    "githubusercontent.com", "empiricalsecurity.com",
    # public vulnerability sources the pipeline already fetches or cites
    "nist.gov", "cisa.gov", "cve.org", "mitre.org", "first.org",
    # upstream projects that appear in third-party advisory prose
    "nodejs.org", "python.org", "chromium.org", "mozilla.org", "apache.org",
    "kernel.org", "gnu.org", "openssl.org", "debian.org", "ubuntu.com",
    "redhat.com", "oracle.com", "adobe.com", "apple.com", "ibm.com",
    "vmware.com", "broadcom.com", "citrix.com", "atlassian.com", "gitlab.com",
    "curl.se", "openwall.com", "packagist.org", "pypi.org", "rubygems.org",
    "crates.io", "maven.org", "sonatype.com", "w3.org", "ietf.org", "iana.org",
    # RFC 2606 documentation placeholders
    "example.com", "example.org", "example.net", "localhost",
})

# Role addresses at an allowlisted vendor are published contact points, not
# customer identities. Anything else with an "@" in it is a person.
ROLE_LOCAL_PARTS = frozenset({
    "security", "secure", "psirt", "cert", "abuse", "support", "info",
    "contact", "disclosure", "vulnerability", "vulnerabilities", "sirt",
})

# Only these TLDs turn a dotted token into a hostname candidate. The list is a
# denylist in disguise: what it leaves out is the point. Source-file extensions
# that a dotted-name regex would otherwise swallow - .c .h .sys .dll .so .py .js
# .exe .msi .ps1 - are absent, which is why "ipmi-oem-fujitsu.c" and
# "Spaceport.sys" in the September corpus produce no hits.
HOSTNAME_TLDS = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name",
    "io", "ai", "co", "me", "tv", "cloud", "dev", "app", "online", "site",
    "xyz", "systems", "services", "solutions", "tech", "digital",
    "au", "nz", "uk", "us", "ca", "sg", "jp", "de", "fr", "nl", "se", "no",
    "fi", "dk", "ie", "it", "es", "ch", "at", "be", "pl", "cz", "in", "id",
    "my", "ph", "th", "cn", "kr", "hk", "tw", "br", "mx", "za", "il", "ae",
    # split-horizon / internal namespaces: the highest-value catch in the set
    "local", "lan", "internal", "intranet", "corp", "home", "private", "ad",
})

# Product names that are shaped like an FQDN. "ASP.NET" produced 12 of the 13
# false positives in the first measured pass over data/2026-Sep.jsonl - it is a
# dotted token whose last label is a real TLD. The entries below are exact
# lowercase tokens, not domains, so allowing "asp.net" does not allow
# "payroll.asp.net". Extend this list only from a measured false positive; the
# non-corpus entries are same-family .NET names carried for the next month.
PRODUCT_TOKEN_EXEMPTIONS = frozenset({
    "asp.net",                                    # measured, data/2026-Sep.jsonl
    "vb.net", "ado.net", "system.net", "microsoft.net", "asp.net.core",
})

# Windows roots that carry no customer identity. "C:\Users\..." is absent on
# purpose - a user profile path names a person.
SYSTEM_WINDOWS_ROOTS = ("windows", "winnt", "program files", "program files (x86)",
                        "programdata", "inetpub")

# Registry hives. Advisories routinely quote registry paths as mitigations; they
# are backslash-separated but never drive-rooted or UNC, so the path detectors
# below cannot reach them. The prefix check is belt-and-braces, and is covered by
# a self-test fixture so the exemption cannot silently rot.
REGISTRY_PREFIXES = ("hkey_local_machine", "hkey_current_user", "hkey_classes_root",
                     "hkey_users", "hkey_current_config", "hklm", "hkcu", "hkcr",
                     "hku", "hkcc")

# Identifier prefixes shaped like an asset name but published by a vendor.
PUBLIC_IDENTIFIER_PREFIXES = ("CVE", "CWE", "CAPEC", "GHSA", "RHSA", "RHBA", "USN",
                              "DSA", "DLA", "ELSA", "ALAS", "MFSA", "ADV", "MS",
                              "KB", "CAN", "OVE", "ZDI", "VU", "TALOS", "SUSE",
                              "OPENSSL", "NVD", "EPSS", "CVSS", "RFC", "SHA",
                              "AES", "RSA", "TLS", "HTTP", "SMB", "LDAP", "NTLM",
                              "ARM64", "X64", "X86", "CD", "DVD", "USB", "PCI",
                              "ISO", "IEC", "FIPS", "UEFI", "ACPI", "NVME")

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
RE_URL = re.compile(
    r"""\b(?:https?|ftp|ftps)://(?:[^\s/?#@"'<>]+@)?([A-Za-z0-9._-]+)(?::\d{1,5})?(?:[^\s"'<>)\]]*)""",
    re.IGNORECASE,
)

RE_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])")

RE_IPV6 = re.compile(
    r"(?<![\w:.])("
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"          # full 8-group form
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?"
    r"|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}"     # leading ::
    r")(?:%[A-Za-z0-9_.-]{1,16})?(?![\w:.])"
)

RE_MAC = re.compile(
    r"(?<![\w:.-])(?:(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
    r"|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})(?![\w:.-])"
)

RE_GUID = re.compile(
    r"(?<![\w-])\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?(?![\w-])"
)

RE_TENANT_CUE = re.compile(
    r"(?i)\b(?:tenant|directory|subscription|aad|entra|azure ad|object)"
    r"[ _-]?(?:id|ids|identifier|guid)\b[\s:=\"']*$"
)

RE_SID = re.compile(r"(?<![\w-])S-1-\d{1,10}(?:-\d{1,10}){1,15}(?![\w-])")

RE_EMAIL = re.compile(
    r"(?<![\w.+-])([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?![\w-])"
)

RE_UNC = re.compile(r"\\\\(?:\?\\UNC\\)?[A-Za-z0-9._$-]{1,63}\\[^\s\"'<>|]{1,120}")

RE_WINPATH = re.compile(r"(?<![\w\\:])([A-Za-z]):\\(?!\\)([^\s\"'<>|]{0,200})")

RE_POSIXPATH = re.compile(
    r"(?<![\w~.])(?:~|/(?:home|Users|root|mnt|media|srv|export|Volumes|net))"
    r"/[A-Za-z0-9._+-][^\s\"'<>|]{0,180}"
)

# A hostname asserted by a label, e.g. "Hostname: SYD-DC-01" or "server=fs02".
RE_HOST_LABEL = re.compile(
    r"(?i)\b(?:host ?name|computer ?name|machine ?name|node ?name|device ?name"
    r"|dns ?name|netbios ?name|fqdn|host|server|computer|machine|node|endpoint|asset)"
    r"\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9._-]{2,62})"
)
RE_HOST_LABEL_NEGATIVE = re.compile(
    r"(?i)^(?:yes|no|none|n/?a|unknown|true|false|required|not ?required)$"
)

# An enterprise asset name: uppercase, hyphenated, carries a number.
RE_ASSET_TOKEN = re.compile(r"(?<![\w-])([A-Z]{2,}[A-Z0-9]*(?:-[A-Z0-9]+)+)(?![\w-])")

INVENTORY_TERMS = (
    "host name", "hostname", "ip address", "ipaddress", "ip_address",
    "mac address", "asset tag", "asset id", "serial number", "serial no",
    "os version", "last seen", "last logon", "last boot", "patch level",
    "tenant id", "subscription id", "resource group", "domain controller",
    "computer name", "device name", "business unit", "site code",
    "installed version", "agent version", "ou path", "distinguished name",
)

# Version context around a dotted quad. Both directions, because the corpus has
# both shapes: "azl3 kernel 6.6.150.1-1" and "zlib 1.3.1.2 through 1.3.2".
RE_VERSION_BEFORE = re.compile(
    r"(?i)(?:\bversions?|\bver\.?|\bv|\bbuild|\brelease[ds]?|\brev\.?|\bupdates?"
    r"|\bpatch(?:es|ed)?|\bthrough|\bprior to|\bbefore|\bearlier than|\bup to"
    r"|\bsince|\bkernel|\bfirmware|\bpackage|\blibrary)\s*[:=]?\s*$"
)
RE_VERSION_AFTER = re.compile(
    r"(?i)^(?:[-_+~][0-9A-Za-z]"
    r"|\s*(?:through|to|and earlier|and later|or earlier|or later|and below"
    r"|and above|and prior|inclusive)\b)"
)

CONTEXT_WINDOW = 40


@dataclass(frozen=True)
class Finding:
    """One matched span. `span` is reproduced verbatim so the operator can grep
    their own source for it; the guard never rewrites or masks it."""

    category: str
    field: str
    span: str
    start: int
    end: int
    detail: str

    def describe(self) -> str:
        return (f"{self.category} at {self.field or '<text>'}[{self.start}:{self.end}]: "
                f"{self.span!r} - {self.detail}")


class CustomerDataError(RuntimeError):
    """Raised instead of sending. Carries the findings so a caller can report
    them; callers must not catch this to continue."""

    def __init__(self, record: str, where: str, findings: list[Finding]):
        self.record = record
        self.where = where
        self.findings = findings
        lines = [
            f"REFUSING TO SEND: customer-identifying data in {where} for {record}.",
            "CLAUDE.md: no customer data in inference - public advisory material only.",
            f"{len(findings)} finding(s); nothing was redacted and nothing was sent:",
        ]
        lines += [f"  - {finding.describe()}" for finding in findings]
        lines.append("Remove the data at source. Do not re-run until the source record is clean.")
        super().__init__("\n".join(lines))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def domain_allowed(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in ALLOWED_DOMAINS)


def _allowed_url_spans(text: str) -> list[tuple[int, int]]:
    """Spans of URLs whose host is an allowlisted vendor.

    Microsoft download links carry a GUID in `familyid=`; 406 of them appear in
    the September corpus. Exempting the whole URL span is narrower and more
    honest than exempting the GUID shape, because a tenant GUID in prose is
    still caught.
    """
    spans = []
    for match in RE_URL.finditer(text):
        if domain_allowed(match.group(1)):
            spans.append((match.start(), match.end()))
    return spans


def _inside(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(low <= start and end <= high for low, high in spans)


def _is_public_identifier(token: str) -> bool:
    head = token.split("-", 1)[0].upper()
    return head in PUBLIC_IDENTIFIER_PREFIXES


def _looks_like_version(text: str, start: int, end: int) -> bool:
    before = text[max(0, start - CONTEXT_WINDOW):start]
    after = text[end:end + CONTEXT_WINDOW]
    return bool(RE_VERSION_BEFORE.search(before) or RE_VERSION_AFTER.match(after))


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------
def _scan_ipv4(text: str, out: list, field: str) -> None:
    for match in RE_IPV4.finditer(text):
        literal = match.group(1)
        try:
            address = ipaddress.IPv4Address(literal)
        except ValueError:
            continue  # an octet over 255 is a version string, not an address
        reserved = address.is_private or address.is_loopback or address.is_link_local
        # A dotted quad is genuinely ambiguous with a four-part version number:
        # the corpus contains "6.6.150.1-1", "26.2.5.21-4" and "1.3.1.2". The
        # version exemption resolves the ambiguity - but never for RFC1918,
        # loopback or link-local space, where the ambiguity does not exist in
        # practice and the cost of a miss is a customer network address.
        if not reserved and _looks_like_version(text, match.start(1), match.end(1)):
            continue
        out.append(Finding(
            "ipv4_address", field, literal, match.start(1), match.end(1),
            "RFC1918/reserved address" if reserved else "public IPv4 address",
        ))


def _scan_ipv6(text: str, out: list, field: str) -> None:
    for match in RE_IPV6.finditer(text):
        literal = match.group(0)
        if literal.count(":") < 2:
            continue
        probe = literal.split("%")[0]
        try:
            ipaddress.IPv6Address(probe)
        except ValueError:
            continue
        out.append(Finding("ipv6_address", field, literal, match.start(), match.end(),
                           "IPv6 address literal"))


def _scan_guid(text: str, out: list, field: str, allowed_spans: list) -> None:
    for match in RE_GUID.finditer(text):
        before = text[max(0, match.start() - CONTEXT_WINDOW):match.start()]
        if RE_TENANT_CUE.search(before):
            # A tenant/subscription/directory GUID is customer identity even
            # when it is sitting inside a vendor portal URL, so this check runs
            # before the URL exemption rather than after it.
            out.append(Finding("tenant_identifier", field, match.group(0),
                               match.start(), match.end(),
                               "GUID labelled as a tenant/subscription/directory identifier"))
            continue
        if _inside(allowed_spans, match.start(), match.end()):
            continue
        out.append(Finding("guid", field, match.group(0), match.start(), match.end(),
                           "GUID outside a vendor advisory URL (Entra tenant, subscription or object id)"))


def _scan_email(text: str, out: list, field: str) -> None:
    for match in RE_EMAIL.finditer(text):
        local, domain = match.group(1), match.group(2)
        if domain_allowed(domain) and local.lower() in ROLE_LOCAL_PARTS:
            continue  # e.g. secure@microsoft.com, a published vendor contact
        out.append(Finding("email_address", field, match.group(0),
                           match.start(), match.end(), "email address"))


def _scan_hostnames(text: str, out: list, field: str, allowed_spans: list) -> None:
    for match in RE_URL.finditer(text):
        host = match.group(1)
        if domain_allowed(host):
            continue
        out.append(Finding("hostname", field, host, match.start(1), match.end(1),
                           "URL host is not an allowlisted vendor domain"))

    for match in re.finditer(
        r"(?<![\w.@:/-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24}))(?![\w-])",
        text,
    ):
        fqdn, tld = match.group(1), match.group(2).lower()
        if tld not in HOSTNAME_TLDS:
            continue  # source filenames, "Spaceport.sys", "ipmi-oem-fujitsu.c"
        if fqdn.lower() in PRODUCT_TOKEN_EXEMPTIONS:
            continue  # "ASP.NET" is a product, not a host in the .net zone
        if domain_allowed(fqdn):
            continue
        if _inside(allowed_spans, match.start(1), match.end(1)):
            continue
        out.append(Finding("hostname", field, fqdn, match.start(1), match.end(1),
                           f"FQDN with non-allowlisted registrable domain (.{tld})"))

    for match in RE_HOST_LABEL.finditer(text):
        value = match.group(1)
        if RE_HOST_LABEL_NEGATIVE.match(value):
            continue
        if not re.search(r"[A-Za-z]", value) or not re.search(r"[\d-]", value):
            # "Server: 2019" is a product version; a host name carries a letter
            # AND a digit or hyphen. This is what keeps the label detector off
            # vendor prose such as "Customer Action Required: Yes".
            continue
        if _is_public_identifier(value):
            continue
        out.append(Finding("hostname", field, value, match.start(1), match.end(1),
                           f"value labelled as a host by {match.group(0).split(':')[0].split('=')[0].strip()!r}"))


def _scan_paths(text: str, out: list, field: str) -> None:
    for match in RE_UNC.finditer(text):
        out.append(Finding("unc_path", field, match.group(0), match.start(), match.end(),
                           "UNC path names a file server and share"))
    for match in RE_WINPATH.finditer(text):
        remainder = match.group(2).lstrip("\\").lower()
        if any(remainder.startswith(root) for root in SYSTEM_WINDOWS_ROOTS):
            continue  # C:\Windows\System32\... identifies an OS, not a customer
        out.append(Finding("filesystem_path", field, match.group(0), match.start(), match.end(),
                           "absolute local filesystem path outside the system roots"))
    for match in RE_POSIXPATH.finditer(text):
        out.append(Finding("filesystem_path", field, match.group(0), match.start(), match.end(),
                           "absolute home/mount path"))


def _scan_sid_mac(text: str, out: list, field: str) -> None:
    for match in RE_SID.finditer(text):
        out.append(Finding("security_identifier", field, match.group(0),
                           match.start(), match.end(), "Windows SID"))
    for match in RE_MAC.finditer(text):
        out.append(Finding("mac_address", field, match.group(0),
                           match.start(), match.end(), "MAC address"))


def _scan_inventory(text: str, out: list, field: str) -> None:
    """Free text shaped like an asset inventory rather than advisory prose.

    Two independent signals, both requiring repetition on a single line, because
    any one of them alone fires on vendor text: the September corpus contains
    "Windows IP Address Management (IPAM) Service" (one inventory term) and
    "CD-ROM" (one asset-shaped token).
    """
    for offset, line in _lines(text):
        lowered = line.lower()
        terms = {term for term in INVENTORY_TERMS if term in lowered}
        if len(terms) >= 2:
            out.append(Finding("asset_inventory", field, line.strip()[:160], offset,
                               offset + len(line),
                               f"line carries {len(terms)} inventory column names: "
                               f"{', '.join(sorted(terms))}"))
            continue
        tokens = {
            match.group(1) for match in RE_ASSET_TOKEN.finditer(line)
            if re.search(r"\d", match.group(1)) and not _is_public_identifier(match.group(1))
        }
        if len(tokens) >= 3:
            out.append(Finding("asset_inventory", field, line.strip()[:160], offset,
                               offset + len(line),
                               f"line lists {len(tokens)} asset-shaped names: "
                               f"{', '.join(sorted(tokens))}"))


def _lines(text: str):
    offset = 0
    for line in text.splitlines(keepends=True):
        yield offset, line
        offset += len(line)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def scan_text(text: str, field: str = "") -> list[Finding]:
    """Every detector, over one string. Order is stable for reproducible output."""
    if not text:
        return []
    findings: list[Finding] = []
    allowed_spans = _allowed_url_spans(text)
    _scan_ipv4(text, findings, field)
    _scan_ipv6(text, findings, field)
    _scan_email(text, findings, field)
    _scan_guid(text, findings, field, allowed_spans)
    _scan_hostnames(text, findings, field, allowed_spans)
    _scan_paths(text, findings, field)
    _scan_sid_mac(text, findings, field)
    _scan_inventory(text, findings, field)
    return sorted(findings, key=lambda item: (item.start, item.category))


def scan_value(value, field: str = "") -> list[Finding]:
    """Recurse a packet. Keys are scanned as well as values, because a field
    named `customer_hostname` is itself the disclosure."""
    findings: list[Finding] = []
    if isinstance(value, str):
        findings += scan_text(value, field)
    elif isinstance(value, dict):
        for key, item in value.items():
            path = f"{field}.{key}" if field else str(key)
            if isinstance(key, str):
                findings += scan_text(key, f"{path}<key>")
            findings += scan_value(item, path)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            findings += scan_value(item, f"{field}[{index}]")
    return findings


def assert_clean(record: str, value, where: str) -> None:
    """The gate. Raises CustomerDataError; never returns a redacted value."""
    findings = scan_value(value) if not isinstance(value, str) else scan_text(value)
    if findings:
        raise CustomerDataError(record, where, findings)


def allow_domains(domains) -> None:
    """Extend the vendor allowlist for one process.

    Exposed so an operator can clear a genuine new-vendor false positive with an
    explicit, auditable CLI argument rather than by editing a detector. There is
    no switch that disables the guard, and none should be added.
    """
    global ALLOWED_DOMAINS
    extra = {domain.strip().lower().lstrip(".") for domain in domains if domain.strip()}
    ALLOWED_DOMAINS = frozenset(ALLOWED_DOMAINS | extra)


def add_allow_domain_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--guard-allow-domain", action="append", default=[], metavar="DOMAIN",
        help="Treat DOMAIN and its subdomains as a public vendor domain for this run. "
             "Repeatable. Never add a public suffix such as gov.au.",
    )


# ---------------------------------------------------------------------------
# Measurement CLI: report the false-positive rate against real advisory text
# ---------------------------------------------------------------------------
def _packet_strings(record: dict):
    """The text a packet actually carries, matching prepare_full_inference.py:
    note HTML is stripped and unescaped there, so it is stripped here too."""
    yield "title", record.get("title", "")
    for index, product in enumerate(record.get("products") or []):
        yield f"products[{index}].name", product.get("name", "")
    guidance = record.get("vendor_guidance") or {}
    for index, note in enumerate(guidance.get("notes") or []):
        yield f"notes[{index}].title", note.get("title") or ""
        yield f"notes[{index}].text", html.unescape(re.sub("<[^>]+>", " ", note.get("value", "") or ""))
    for index, remediation in enumerate(guidance.get("remediations") or []):
        for key in ("url", "description", "subtype"):
            yield f"remediations[{index}].{key}", str(remediation.get(key) or "")
    for index, tag in enumerate(record.get("tags") or []):
        yield f"tags[{index}]", str(tag)
    cvss = record.get("cvss") or {}
    yield "cvss.vector", str(cvss.get("vector") or "")


def _report(label: str, hits: list, show: int) -> None:
    by_category: dict = {}
    for _, finding in hits:
        by_category[finding.category] = by_category.get(finding.category, 0) + 1
    print(f"{label}: {len(hits)} finding(s) "
          f"{json.dumps(by_category, sort_keys=True) if by_category else ''}")
    for cve, finding in hits[:show]:
        print(f"    {cve}  {finding.describe()}")
    if len(hits) > show:
        print(f"    ... and {len(hits) - show} more")


def _scan_dataset(path: Path, show: int) -> int:
    """Two scopes, because two different things get sent.

    prepare_full_inference.py ships a projection of each record; the packet
    scope measures exactly those fields. run_claude_inference.py ships whole
    records from its --records file, so the record scope measures everything,
    including dataset_provenance URLs that never reach a packet.
    """
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    packet_hits, record_hits = [], []
    fields = 0
    for record in records:
        cve = record.get("cve")
        for field, text in _packet_strings(record):
            fields += 1
            packet_hits += [(cve, finding) for finding in scan_text(text, field)]
        record_hits += [(cve, finding) for finding in scan_value(record)]
    print(f"records scanned      : {len(records)}")
    print(f"packet fields scanned: {fields}")
    _report("packet scope         ", packet_hits, show)
    _report("whole-record scope   ", record_hits, show)
    total = len(packet_hits) + len(record_hits)
    print("\nPublished vendor data is public by definition, so every finding here is")
    print(f"a false positive. Measured false positives on {path.name}: {total}")
    return 0 if not total else 1


NOT_DETECTED = """\
Deliberately not detected, and why:

  Bare single-label hostnames in prose ("patching SRVAPP01 first"). A detector
  for uppercase alphanumeric tokens cannot be separated from product and
  component names - the September corpus alone contains ARM64, IPAM, NTFS,
  Win32K, Spaceport.sys, CD-ROM. Bare names are reached indirectly instead: by
  the labelled-host detector when a cue word is present, by the UNC detector
  when they appear as a share, and by the asset-inventory detector when three or
  more appear on one line. A single unlabelled bare hostname will pass.

  Generic POSIX system paths (/etc, /usr, /var, /opt). Upstream advisory prose
  quotes them constantly and they name no customer. Only user- and mount-rooted
  paths (~, /home, /Users, /root, /mnt, /media, /srv, /export, /Volumes, /net)
  are treated as identifying.

  Windows system-root paths (C:\\Windows, C:\\Program Files, C:\\ProgramData,
  C:\\inetpub). Same reasoning. C:\\Users\\... is NOT exempt: a profile path
  names a person.

  Registry paths. Advisories quote them as mitigations. They are never
  drive-rooted or UNC, so no path detector reaches them; the hive prefix list is
  a second, explicit guard against a future detector that would.

  Organisation names in prose ("Contoso Pty Ltd"). Indistinguishable from vendor
  and researcher credits without a customer list, and holding a customer list in
  this repository would create the exposure it is meant to prevent.

  Free-form topology description ("the DMZ sits behind the perimeter firewall").
  Carries no identifier and cannot be matched without semantics. The structured
  carriers of topology - addresses, hostnames, inventories - are detected.
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scan", type=Path, metavar="JSONL",
                        help="Measure findings over an enriched/published month. "
                             "Published vendor data is public by definition, so every "
                             "finding it reports is a false positive.")
    parser.add_argument("--text", help="Scan one string and print findings.")
    parser.add_argument("--show", type=int, default=25, help="Findings to print (default 25)")
    parser.add_argument("--explain", action="store_true", help="Print what is deliberately not detected.")
    add_allow_domain_argument(parser)
    args = parser.parse_args()
    allow_domains(args.guard_allow_domain)

    if args.explain:
        print(NOT_DETECTED)
    if args.text is not None:
        findings = scan_text(args.text)
        for finding in findings:
            print(finding.describe())
        print(f"{len(findings)} finding(s)")
        raise SystemExit(1 if findings else 0)
    if args.scan:
        raise SystemExit(_scan_dataset(args.scan, args.show))
    if not args.explain:
        parser.error("pass --scan, --text or --explain")


if __name__ == "__main__":
    main()
