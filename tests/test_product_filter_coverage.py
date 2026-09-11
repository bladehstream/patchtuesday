"""Every published record should be reachable by a specific product filter.

An administrator's core question is "does this affect anything I run". A record
tagged only `microsoft` cannot be reached by any product selector, so it is
invisible to that question no matter how good its risk assessment is.

Measured 2026-09-11: 64 of 1185 records (5.4%) were generic-only, including all 23
Microsoft Edge advisories and every Exchange Server record.
"""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("enrich_cvrf", ROOT / "scripts" / "enrich_cvrf.py")
ENRICH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENRICH)

PUBLISHED = ROOT / "data" / "2026-Sep.jsonl"


def products(*names):
    return [{"product_id": str(i), "name": n} for i, n in enumerate(names)]


@pytest.mark.parametrize("name,expected", [
    ("Microsoft Edge (Chromium-based)", "edge"),
    ("Microsoft Exchange Server 2019 Cumulative Update 15", "exchange"),
    ("Microsoft Exchange Server Subscription Edition RTM", "exchange"),
    ("Visual Studio Code", "vscode"),
    ("Microsoft Visual Studio 2026 version 18.9", "visual-studio"),
    ("Microsoft Teams for Android", "teams"),
    (".NET 10.0 installed on Linux", "dotnet"),
    ("Microsoft Dynamics 365 (on-premises) version 9.1", "dynamics-365"),
    ("Power Automate for Desktop", "power-platform"),
    ("Microsoft Entra ID", "entra-id"),
    ("Microsoft Fabric", "fabric"),
    ("Windows Server 2022", "server-2022"),
    ("Windows 11 Version 24H2 for x64-based Systems", "windows-11"),
])
def test_product_name_yields_its_filter_tag(name, expected):
    assert expected in ENRICH.derive_product_tags(products(name))


def test_vscode_does_not_claim_the_visual_studio_ide_tag():
    """"Visual Studio Code" contains "visual studio" as a substring."""
    tags = ENRICH.derive_product_tags(products("Visual Studio Code"))
    assert "vscode" in tags
    assert "visual-studio" not in tags


def test_both_tags_when_both_products_are_present():
    tags = ENRICH.derive_product_tags(products("Visual Studio Code", "Microsoft Visual Studio 2026 version 18.9"))
    assert {"vscode", "visual-studio"} <= set(tags)


@pytest.mark.skipif(not PUBLISHED.exists(), reason="published dataset not present")
def test_published_records_are_reachable_by_a_specific_filter():
    with PUBLISHED.open(encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    generic = [r["cve"] for r in records if not (set(r.get("product_tags") or []) - {"microsoft"})]
    reachable = (len(records) - len(generic)) / len(records)
    assert reachable >= 0.99, (
        f"only {reachable:.1%} of records are reachable by a specific product filter; "
        f"generic-only: {generic[:15]}"
    )
