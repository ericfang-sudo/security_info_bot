from src.models import AnalysisResult, IntelItem, SheetRow


def test_sheet_row_from_intel_single_cve():
    intel = IntelItem(
        intel_id="TWISAC-202404-0001",
        source="TWCERT",
        publish_date="2024-04-15",
        title="Apache RCE 漏洞通報",
        intel_type="101-漏洞訊息",
        cve_ids=["CVE-2024-12345"],
        reference_urls=["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"],
    )
    analysis = AnalysisResult(
        risk_level="Critical",
        summary="Apache HTTP Server 存在遠端程式碼執行漏洞",
        recommendation="升級至 2.4.59 以上",
        company_relevance="H",
        affected_assets=["對外 Web 服務"],
        responsible_unit="系統組",
    )

    row = SheetRow.from_intel_and_analysis(intel, analysis)

    assert row.intel_id == "TWISAC-202404-0001"
    assert row.cve_id == "CVE-2024-12345"
    assert row.risk_level == "Critical"
    assert row.company_relevance == "H"
    assert row.status == "待處理"

    row_list = row.to_row_list()
    assert len(row_list) == 21  # A–U


def test_sheet_row_multi_cve_merged():
    intel = IntelItem(
        intel_id="TWISAC-202404-0002",
        source="TWCERT",
        publish_date="2024-04-15",
        title="多 CVE 情資",
        intel_type="101-漏洞訊息",
        cve_ids=["CVE-2024-1111", "CVE-2024-2222"],
    )
    analysis = AnalysisResult(
        risk_level="High",
        summary="test",
        recommendation="test",
        company_relevance="M",
    )

    row = SheetRow.from_intel_and_analysis(intel, analysis)

    assert row.intel_id == "TWISAC-202404-0002"
    assert row.cve_id == "CVE-2024-1111\nCVE-2024-2222"


def test_sheet_row_ioc():
    intel = IntelItem(
        intel_id="TWISAC-202404-0003",
        source="TWCERT",
        publish_date="2024-04-15",
        title="IoC 封鎖清單",
        intel_type="IoC",
    )
    analysis = AnalysisResult(
        risk_level="High",
        summary="含 IP 封鎖清單",
        recommendation="匯入防火牆封鎖",
        company_relevance="H",
    )

    row = SheetRow.from_intel_and_analysis(intel, analysis)

    assert row.recommendation == "匯入防火牆封鎖"
    assert row.intel_id == "TWISAC-202404-0003"


def test_status_not_applicable_when_no_relevance():
    """company_relevance='無' → status 自動設為「不適用」"""
    intel = IntelItem(
        intel_id="TWISAC-202605-0029",
        source="TWCERT",
        publish_date="2026-05-28",
        title="SharePoint Server 漏洞",
        intel_type="101-漏洞訊息",
    )
    analysis = AnalysisResult(
        risk_level="Low",
        summary="公司未部署 SharePoint Server，受影響機率極低。",
        recommendation="公司資產清冊未包含受影響資產，無需處置。",
        company_relevance="無",
        responsible_unit="",
    )

    row = SheetRow.from_intel_and_analysis(intel, analysis)

    assert row.status == "不適用"
    assert row.company_relevance == "無"
    assert row.responsible_unit == ""


def test_status_pending_when_relevant():
    """company_relevance 非「無」→ status 維持「待處理」"""
    intel = IntelItem(
        intel_id="TWISAC-202605-0030",
        source="TWCERT",
        publish_date="2026-05-28",
        title="Apache 漏洞",
        intel_type="101-漏洞訊息",
    )
    analysis = AnalysisResult(
        risk_level="High",
        summary="公司有部署 Apache，需盡快修補。",
        recommendation="升級至 2.4.59 以上。",
        company_relevance="H",
        responsible_unit="RR40",
    )

    row = SheetRow.from_intel_and_analysis(intel, analysis)

    assert row.status == "待處理"


def test_dedup_logic():
    existing = {"TWISAC-202404-0001", "CVE-2024-12345"}
    items = [
        IntelItem(
            intel_id="TWISAC-202404-0001", source="TWCERT", publish_date="", title="", intel_type=""
        ),
        IntelItem(
            intel_id="TWISAC-202404-0099", source="TWCERT", publish_date="", title="", intel_type=""
        ),
        IntelItem(
            intel_id="CVE-2024-12345", source="CISA_KEV", publish_date="", title="", intel_type=""
        ),
    ]

    new_items = [item for item in items if item.intel_id not in existing]
    assert len(new_items) == 1
    assert new_items[0].intel_id == "TWISAC-202404-0099"
