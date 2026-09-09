import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "enrich_cvrf.py"
SPEC = importlib.util.spec_from_file_location("enrich_cvrf", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_build_records_maps_product_and_vector():
    document = {
        "ProductTree": {"Branch": [{"FullProductName": {"ProductID": "p1", "Value": "Windows Server 2016"}}]},
        "Vulnerability": [{
            "CVE": "CVE-TEST-1",
            "Title": {"Value": "Windows DNS Server test vulnerability"},
            "ProductStatuses": [{"Status": "Known Affected", "ProductID": ["p1"]}],
            "Threats": [
                {"Type": "3", "Description": {"Value": "Critical"}},
                {"Type": "1", "Description": {"Value": "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Unlikely"}},
            ],
            "CVSSScoreSets": [{"BaseScore": 9.8, "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        }],
    }
    records = MODULE.build_records(document, "2026-Sep", {})
    assert len(records) == 1
    assert records[0]["products"][0]["name"] == "Windows Server 2016"
    assert {"server", "server-2016", "dns"}.issubset(set(records[0]["tags"]))
    assert records[0]["attack"]["vector"] == "network"
    assert records[0]["severity"] == "Critical"
    assert records[0]["products"][0]["product_id"] == "p1"
    assert records[0]["threat"]["exploitation_assessment"] == "unlikely"
    assert records[0]["cvss"]["base_score"] == 9.8


if __name__ == "__main__":
    test_build_records_maps_product_and_vector()
    print("CVRF enrichment tests passed")
