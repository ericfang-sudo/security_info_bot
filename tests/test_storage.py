import json

import pytest

from src.fetchers.storage import (
    list_saved_files,
    load_analysis,
    load_items,
    save_analysis,
    save_items,
)
from src.models import AnalysisResult, IntelItem


def _make_items() -> list[IntelItem]:
    return [
        IntelItem(
            intel_id="CVE-2024-12345",
            source="CISA_KEV",
            publish_date="2024-04-15",
            title="Test vulnerability",
            intel_type="101-漏洞訊息",
            cve_ids=["CVE-2024-12345"],
            raw_content="Some detail",
            reference_urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"],
        ),
        IntelItem(
            intel_id="TWISAC-202404-0001",
            source="TWCERT",
            publish_date="2024-04-15",
            title="TWCERT 情資",
            intel_type="IoC",
            attachment_urls=["https://example.com/ioc.xlsx"],
        ),
    ]


def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr("src.fetchers.storage.DATA_DIR", tmp_path)

    items = _make_items()
    path = save_items(items, "cisa_kev", tag="2024-04-15")

    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["count"] == 2
    assert data["source"] == "cisa_kev"
    assert len(data["items"]) == 2

    loaded = load_items(path)
    assert len(loaded) == 2
    assert loaded[0].intel_id == "CVE-2024-12345"
    assert loaded[0].cve_ids == ["CVE-2024-12345"]
    assert loaded[1].intel_id == "TWISAC-202404-0001"
    assert loaded[1].attachment_urls == ["https://example.com/ioc.xlsx"]


def test_save_without_tag(tmp_path, monkeypatch):
    monkeypatch.setattr("src.fetchers.storage.DATA_DIR", tmp_path)

    items = _make_items()[:1]
    path = save_items(items, "twcert")

    assert path.exists()
    assert "twcert_" in path.name
    assert path.name.endswith(".json")


def test_list_saved_files(tmp_path, monkeypatch):
    monkeypatch.setattr("src.fetchers.storage.DATA_DIR", tmp_path)

    items = _make_items()
    save_items(items, "cisa_kev")
    save_items(items, "twcert")
    save_items(items, "cisa_kev", tag="special")

    all_files = list_saved_files()
    assert len(all_files) == 3

    cisa_only = list_saved_files("cisa_kev")
    assert len(cisa_only) == 2
    assert all("cisa_kev" in f.name for f in cisa_only)

    twcert_only = list_saved_files("twcert")
    assert len(twcert_only) == 1


def test_load_nonexistent_raises():
    with pytest.raises(FileNotFoundError):
        load_items("/nonexistent/path.json")


def test_intel_item_roundtrip():
    item = _make_items()[0]
    d = item.to_dict()
    restored = IntelItem.from_dict(d)
    assert restored.intel_id == item.intel_id
    assert restored.cve_ids == item.cve_ids
    assert restored.reference_urls == item.reference_urls


def _make_analysis() -> AnalysisResult:
    return AnalysisResult(
        risk_level="High",
        summary="Test summary",
        recommendation="Apply patch",
        company_relevance="H",
        affected_assets=["server-a", "server-b"],
        responsible_unit="IT-Sec",
    )


def test_analysis_roundtrip():
    a = _make_analysis()
    d = a.to_dict()
    restored = AnalysisResult.from_dict(d)
    assert restored.risk_level == a.risk_level
    assert restored.affected_assets == a.affected_assets
    assert restored.responsible_unit == a.responsible_unit


def test_save_and_load_analysis_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr("src.fetchers.storage.DATA_DIR", tmp_path)

    pairs = [(item, _make_analysis()) for item in _make_items()]
    path = save_analysis(pairs, "cisa_kev", tag="2024-04-15")

    assert path.exists()
    assert path.name.startswith("analysis_cisa_kev_2024-04-15_")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["count"] == 2
    assert data["source"] == "cisa_kev"

    loaded = load_analysis(path)
    assert len(loaded) == 2
    intel0, analysis0 = loaded[0]
    assert intel0.intel_id == "CVE-2024-12345"
    assert analysis0.risk_level == "High"
    assert analysis0.affected_assets == ["server-a", "server-b"]


def test_save_analysis_without_tag(tmp_path, monkeypatch):
    monkeypatch.setattr("src.fetchers.storage.DATA_DIR", tmp_path)

    pairs = [(_make_items()[0], _make_analysis())]
    path = save_analysis(pairs, "twcert")

    assert path.name.startswith("analysis_twcert_")
    assert path.name.endswith(".json")


def test_load_analysis_nonexistent_raises():
    with pytest.raises(FileNotFoundError):
        load_analysis("/nonexistent/analysis.json")
