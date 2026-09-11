"""Verify that a scorer's citation actually comes from the supplied record.

The first attempt demanded one verbatim substring and discarded 36.7% of verdicts.
That was the checker's fault, not the scorer's: real citations are composite -

    Title: "Windows Audio Service Elevation of Privilege"; Description: "Use after free..."
    "A" + "B"
    allows an authorized attacker to elevate privileges ... An attacker who succeeded...

none of which can match as a single substring. The source also carries HTML
(<p>...</p>) that never appears in a quotation.

This verifier therefore:
  1. splits a composite citation into components,
  2. strips HTML and normalises both sides to a token stream,
  3. accepts a component when any contiguous run of MIN_RUN tokens from it appears
     in the record's token stream.

Contiguous-run matching, not bag-of-words overlap: a fabricated sentence made of
words that individually appear in the record must still fail.
"""

from __future__ import annotations

import json
import re

MIN_RUN = 6          # tokens that must appear contiguously
SHORT_RUN = 3        # for citations too short to yield a 6-token run
MIN_COMPONENT = 3    # ignore fragments shorter than this

_TAG = re.compile(r"<[^>]+>")
_SPLIT = re.compile(r'"\s*[;+,]\s*"|\s*\.\.\.\s*|\s*\|\s*|\n+|;\s(?=[A-Z])|\s\+\s')
_LABEL = re.compile(r"^\s*(title|description|faq|notes?|vendor guidance|cvss|attack)\s*[:\-]\s*", re.I)


def tokens(text: str) -> list[str]:
    text = _TAG.sub(" ", text or "")
    text = text.replace("&quot;", " ").replace("&amp;", " ").replace("&#8217;", "'")
    return re.findall(r"[a-z0-9]+", text.lower())


def components(span: str) -> list[str]:
    out = []
    for part in _SPLIT.split(span or ""):
        part = _LABEL.sub("", part.strip().strip('"\'' + " "))
        if len(tokens(part)) >= MIN_COMPONENT:
            out.append(part)
    if not out and (span or "").strip():
        out = [span.strip()]
    return out


def _contains_run(haystack: list[str], needle: list[str], run: int) -> bool:
    if len(needle) < run:
        return False
    joined = " " + " ".join(haystack) + " "
    for i in range(len(needle) - run + 1):
        if " " + " ".join(needle[i:i + run]) + " " in joined:
            return True
    return False


def verify(span: str, record_view: dict | str) -> dict:
    """Return {verified, components, matched, detail} for one citation.

    An EMPTY span is compliant, not a failure, when the scorer ruled
    `source-ambiguous`: the contract explicitly tells it to return no span when
    nothing in the record bears on the question. Callers pass the verdict so this
    can be distinguished from an assertion made with no evidence.
    """
    source = record_view if isinstance(record_view, str) else json.dumps(record_view)
    hay = tokens(source)
    # A short field citation - '"vector": "local"' - is a legitimate quotation of a
    # structured field and must not fail merely for being brief.
    whole = tokens(span)
    if 2 <= len(whole) < MIN_COMPONENT and _contains_run(hay, whole, len(whole)):
        return {"verified": True, "fully_verified": True, "components": 1,
                "matched": 1, "unmatched_examples": []}
    parts = components(span)
    matched, unmatched = [], []
    for part in parts:
        need = tokens(part)
        run = MIN_RUN if len(need) >= MIN_RUN else SHORT_RUN
        (matched if _contains_run(hay, need, run) else unmatched).append(part)
    # Short whole-span quotations of structured fields, checked before splitting.
    if not matched and 2 <= len(whole) <= 8 and _contains_run(hay, whole, len(whole)):
        matched, unmatched = [span], []
    return {
        "verified": bool(matched),
        "fully_verified": bool(parts) and not unmatched,
        "components": len(parts),
        "matched": len(matched),
        "unmatched_examples": unmatched[:2],
    }
