"""Deterministic checks on judgement tags. Tier 1 of the tag review.

IMPORTANT BOUNDARY. These checks match terms in advisory prose. That is the same
mechanism deliberately removed from the risk path in "Take regex pattern matching
out of the risk path" - and the distinction is the point:

    assigning a tag from prose  -> a pattern match becomes a risk decision. Banned.
    flagging a tag for review   -> a pattern match raises a question for a human
                                   or a scorer. Nothing here reaches a rating.

Nothing in this module writes a tag, changes an effect, or selects a baseline. It
returns findings. Keep it that way.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# Terms that, appearing in the supplied record, indicate a workload. Used ONLY to
# ask "should this have been tagged?" - never to answer it.
#
# TWO RULES ABOUT THIS TABLE, both learned the expensive way.
#
# 1. Name the ROLE, not one vendor's product. The table was written against a
#    Microsoft-only corpus, so `web-server` was ("iis", "internet information
#    services") and `graphics` was ("graphics component", "gdi"). Once Azure Linux,
#    Erlang and nginx records entered the month, those entries could not match
#    anything: 10 of the 14 precision false positives were `web-server` flagging
#    Apache/Erlang httpd and nginx records that plainly ARE web servers. A term
#    list that only knows one vendor's spelling of a role reports the rest of the
#    world as uncorroborated.
#
# 2. Keep it in step with data/tag-taxonomy.json. check_workload_precision asks
#    whether a record corroborates a tag; the taxonomy says what the tag means. When
#    the `identity` definition was rewritten to cover the components whose job is
#    identity - AD CS, the Key Distribution Center, AD FS, Azure AD B2C, Microsoft
#    Account, MSAL - this table still knew five spellings and reported the rest as
#    invented. A validator that disagrees with the definition it validates against
#    is noise on both sides.
#
# Terms are matched case-insensitively at a left word boundary, by BOTH checks. The
# precision check used a bare substring test, so widening `identity` from "entra id"
# to "entra" made it match "centrally managed policies" and quietly excuse an
# `identity` tag on a device-management advisory. Prefer a term that is unambiguous
# at a word boundary ("kdc", "httpd") over a bare word that swallows unrelated
# compounds ("shell" would match "PowerShell").
WORKLOAD_TERMS: dict[str, tuple[str, ...]] = {
    "dns": ("dns", "domain name system", "name resolution"),
    "dhcp": ("dhcp", "dynamic host configuration"),
    "hyper-v": ("hyper-v", "virtual machine bus", "vmbus"),
    # Client-side components are in scope per the taxonomy definition, so the client
    # spellings belong here too - "remote desktop" already covers "Remote Desktop
    # Client", but a record that says only "RDP" or "mstsc" must corroborate as well.
    "remote-desktop": ("remote desktop", "terminal services", "rdp", "mstsc"),
    # The HTTP server side, whoever ships it.
    "web-server": ("iis", "internet information services", "httpd", "nginx", "apache",
                   "inets", "http server", "web server", "http.sys", "tomcat"),
    # The components whose own job is identity. Must track the taxonomy definition.
    "identity": ("active directory", "domain controller", "kerberos", "netlogon", "entra",
                 "key distribution center", "kdc", "ad cs", "ad fs", "adfs",
                 "certificate services", "federation services", "domain services",
                 "azure ad", "b2c", "microsoft account", "msal", "authentication library",
                 "ntlm", "ldap"),
    "nfs": ("services for nfs", "network file system", "oncrpc"),
    "netlogon": ("netlogon",),
    "print": ("print spooler", "print provider", "print driver", "printer", "printing"),
    # Network file sharing, not a local filesystem - see the taxonomy boundary clause.
    "file-services": ("smb", "server message block", "cifs", "samba", "file share",
                      "file server", "file sharing", "dfs namespace"),
    "database": ("sql server", "sqlite", "database", "mysql", "postgres", "mariadb"),
    "message-queuing": ("message queuing", "msmq"),
    "failover-cluster": ("failover cluster",),
    "sstp": ("sstp", "secure socket tunneling"),
    "rras": ("routing and remote access", "rras"),
    "windows-shell": ("windows shell", "explorer.exe", "shell32"),
    # The rendering stack, not only Microsoft's name for it.
    "graphics": ("graphics component", "graphic", "gdi", "directwrite", "direct2d",
                 "font", "gpu", "win32k", "display driver"),
    "imaging": ("image extension", "imaging component", "image codec", "heif"),
    "update-stack": ("windows update stack", "update stack", "servicing stack"),
    "alpc": ("alpc", "advanced local procedure call"),
    "internet-connection-sharing": ("internet connection sharing", "ics"),
}

# Delivery tags that presuppose something about the CVSS vector. A tag that
# contradicts the vendor's own vector is wrong regardless of how it is argued.
DELIVERY_REQUIRES_USER_INTERACTION = {"user-content", "email", "web"}
DELIVERY_REQUIRES_NON_NETWORK = {"local-access"}


def load_namespaces(taxonomy: Path) -> dict[str, set[str]]:
    data = json.loads(taxonomy.read_text(encoding="utf-8"))["namespaces"]
    return {name: set(tags) for name, tags in data.items()}


def source_text(record: dict) -> str:
    parts = [record.get("title", "")]
    parts += [product.get("name", "") for product in record.get("products") or []]
    for note in record.get("notes") or []:
        parts.append(note.get("value", "") if isinstance(note, dict) else str(note))
    guidance = record.get("vendor_guidance")
    if isinstance(guidance, str):
        parts.append(guidance)
    elif isinstance(guidance, dict):
        parts += [str(v) for v in guidance.values()]
    return " ".join(parts).lower()


def mentions(text: str, term: str) -> bool:
    """Does `term` appear in `text` at a word boundary?

    One matcher for both workload checks. They previously disagreed - recall
    required a boundary, precision accepted any substring - so a term could excuse
    a tag in one check that it would not raise in the other.
    """
    return re.search(r"\b" + re.escape(term), text) is not None


def asserted(overlay: dict) -> dict[str, str]:
    """Return {tag: evidence}. Tolerates the pre-2026-09-11 bare-string shape."""
    out: dict[str, str] = {}
    for item in overlay.get("tags") or []:
        if isinstance(item, dict):
            out[item.get("tag", "")] = item.get("evidence", "") or ""
        else:
            out[str(item)] = ""
    return out


def check_workload_recall(record: dict, overlay: dict) -> list[dict]:
    """The record names a role but no tag claims it."""
    text = source_text(record)
    have = set(asserted(overlay))
    findings = []
    for tag, terms in WORKLOAD_TERMS.items():
        if tag in have:
            continue
        for term in terms:
            if mentions(text, term):
                findings.append({
                    "code": "workload-recall-miss", "tag": tag, "matched_term": term,
                    "message": f"the record names {term!r} but no {tag} tag was asserted",
                })
                break
    return findings


def check_workload_precision(record: dict, overlay: dict, workload_tags: set[str]) -> list[dict]:
    """A workload tag with no corroborating term anywhere in the supplied record.

    Not automatically wrong - a role can be implied rather than named - so this is
    a candidate for adjudication, not a failure.
    """
    text = source_text(record)
    findings = []
    for tag, evidence in asserted(overlay).items():
        if tag not in workload_tags:
            continue
        terms = WORKLOAD_TERMS.get(tag, (tag,))
        if not any(mentions(text, term) for term in terms):
            findings.append({
                "code": "workload-uncorroborated", "tag": tag, "evidence": evidence,
                "message": f"{tag} asserted but no corroborating term appears in the supplied record",
            })
    return findings


def check_delivery_consistency(record: dict, overlay: dict) -> list[dict]:
    """A delivery tag that contradicts the vendor's own CVSS vector."""
    attack = record.get("attack") or {}
    ui, vector = attack.get("user_interaction"), attack.get("vector")
    findings = []
    for tag, evidence in asserted(overlay).items():
        if tag in DELIVERY_REQUIRES_USER_INTERACTION and ui == "none":
            findings.append({
                "code": "delivery-contradicts-cvss", "tag": tag, "evidence": evidence,
                "message": f"{tag} presupposes user interaction but the vendor vector says UI:N",
            })
        if tag in DELIVERY_REQUIRES_NON_NETWORK and vector == "network":
            findings.append({
                "code": "delivery-contradicts-cvss", "tag": tag, "evidence": evidence,
                "message": f"{tag} presupposes non-network access but the vendor vector says AV:N",
            })
    return findings


def check_evidence_present(record: dict, overlay: dict, judgement_tags: set[str]) -> list[dict]:
    """Rule 5: a judgement tag must carry a citation, and it must not be empty."""
    findings = []
    for tag, evidence in asserted(overlay).items():
        if tag not in judgement_tags:
            continue
        if not evidence.strip():
            findings.append({
                "code": "evidence-missing", "tag": tag,
                "message": f"{tag} asserted with no evidence fragment",
            })
    return findings


def check_evidence_grounded(record: dict, overlay: dict, judgement_tags: set[str],
                            min_overlap: int = 2) -> list[dict]:
    """Does the citation share any substantive wording with the supplied record?

    Deliberately weak: it only catches citations with no lexical contact at all,
    which is the signature of a model citing its own reasoning instead of the
    source. Anything subtler is the scorer's job.
    """
    text = source_text(record)
    stop = {"the", "a", "an", "is", "are", "and", "or", "of", "to", "in", "for",
            "with", "that", "this", "by", "on", "as", "it", "be", "can", "from"}
    findings = []
    for tag, evidence in asserted(overlay).items():
        if tag not in judgement_tags or not evidence.strip():
            continue
        words = {w for w in re.findall(r"[a-z0-9][a-z0-9\-]{2,}", evidence.lower()) if w not in stop}
        if not words:
            continue
        if len(words & set(re.findall(r"[a-z0-9][a-z0-9\-]{2,}", text))) < min_overlap:
            findings.append({
                "code": "evidence-ungrounded", "tag": tag, "evidence": evidence,
                "message": f"{tag} evidence shares almost no wording with the supplied record",
            })
    return findings


def review_record(record: dict, overlay: dict, namespaces: dict[str, set[str]]) -> list[dict]:
    workload = namespaces["workload"]
    judgement = namespaces["workload"] | namespaces["delivery"] | namespaces["impact"]
    findings = []
    findings += check_workload_recall(record, overlay)
    findings += check_workload_precision(record, overlay, workload)
    findings += check_delivery_consistency(record, overlay)
    findings += check_evidence_present(record, overlay, judgement)
    findings += check_evidence_grounded(record, overlay, judgement)
    for finding in findings:
        finding["cve"] = record.get("cve")
    return findings
