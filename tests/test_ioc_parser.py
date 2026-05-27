from __future__ import annotations

import base64
import io

from openpyxl import Workbook

from src.parsers.ioc_xlsx import (
    IP_PATTERN,
    extract_iocs_from_info_file,
    parse_xlsx_iocs,
    write_ioc_txt,
)

# ── helpers ──────────────────────────────────────────────────────────────────


def _make_xlsx_bytes(sheets: dict[str, list[list]]) -> bytes:
    """Build an xlsx in memory from {sheet_name: [[row], ...]}."""
    wb = Workbook()
    first = True
    for name, rows in sheets.items():
        ws = wb.active if first else wb.create_sheet(name)
        if first:
            ws.title = name
            first = False
        for row in rows:
            ws.append(row)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _make_data_uri(xlsx_bytes: bytes) -> str:
    b64 = base64.b64encode(xlsx_bytes).decode()
    return f"data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,{b64}"


# ── IP_PATTERN ────────────────────────────────────────────────────────────────


def test_ip_pattern_valid():
    assert IP_PATTERN.findall("192.168.1.1") == ["192.168.1.1"]
    assert IP_PATTERN.findall("10.0.0.1 and 172.16.0.1") == ["10.0.0.1", "172.16.0.1"]


def test_ip_pattern_invalid():
    assert IP_PATTERN.findall("999.999.999.999") == []
    assert IP_PATTERN.findall("no ip here") == []


# ── parse_xlsx_iocs ───────────────────────────────────────────────────────────


def test_parse_xlsx_extracts_ips():
    xlsx = _make_xlsx_bytes({"Sheet1": [["IP"], ["1.2.3.4"], ["5.6.7.8"]]})
    ips, hashes, domains = parse_xlsx_iocs(xlsx)
    assert set(ips) == {"1.2.3.4", "5.6.7.8"}
    assert hashes == []
    assert domains == []


def test_parse_xlsx_extracts_hashes():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    xlsx = _make_xlsx_bytes({"Sheet1": [["Hash"], [md5], [sha256], [sha1]]})
    ips, hashes, domains = parse_xlsx_iocs(xlsx)
    assert ips == []
    assert set(hashes) == {md5, sha256, sha1}
    assert domains == []


def test_parse_xlsx_extracts_domains():
    xlsx = _make_xlsx_bytes({"Sheet1": [["Domain"], ["evil.com"], ["bad.example.org"]]})
    ips, hashes, domains = parse_xlsx_iocs(xlsx)
    assert ips == []
    assert hashes == []
    assert set(domains) == {"evil.com", "bad.example.org"}


def test_parse_xlsx_mixed_twcert_ioc_format():
    """Mirrors the real TWCERT_IoC sheet: mixed IP / hash / domain in column 0."""
    sha256 = "84c88c3462ce8586c3123bbf0eb330e7ede6cc334ca29eccfd593ac54a612f89"
    rows = [
        ["來源IP/惡意程式雜湊/網域", "國家", "備註", "檔案名稱", "ATT&CK 識別碼"],
        ["174.138.22.165", "SG", None, None, "TA0011"],
        [sha256, "DE", None, "mal.exe", "T1059"],
        ["sfrclak.com", "US", None, None, "T1071"],
    ]
    xlsx = _make_xlsx_bytes({"TWCERT_IoC": rows})
    ips, hashes, domains = parse_xlsx_iocs(xlsx)
    assert "174.138.22.165" in ips
    assert sha256 in hashes
    assert "sfrclak.com" in domains


def test_parse_xlsx_skips_mitre_sheet():
    """MITRE ATT&CK sheet TTP IDs must not be misidentified as hashes."""
    xlsx = _make_xlsx_bytes(
        {
            "TWCERT_IoC": [["IP"], ["1.2.3.4"]],
            "MITRE ATT&CK": [["ID"], ["T1059"], ["TA0011"]],
        }
    )
    ips, hashes, domains = parse_xlsx_iocs(xlsx)
    assert "1.2.3.4" in ips
    assert hashes == []  # TTP IDs must not be captured as hashes


def test_parse_xlsx_dedupes():
    xlsx = _make_xlsx_bytes({"Sheet1": [["IP"], ["1.2.3.4"], ["1.2.3.4"], ["1.2.3.4"]]})
    ips, _, _ = parse_xlsx_iocs(xlsx)
    assert ips.count("1.2.3.4") == 1


def test_parse_xlsx_ip_embedded_in_cell():
    """IP extracted even when cell contains extra chars like a port suffix."""
    xlsx = _make_xlsx_bytes({"Sheet1": [["", "192.0.2.1:8080"]]})
    ips, _, _ = parse_xlsx_iocs(xlsx)
    assert "192.0.2.1" in ips


def test_parse_xlsx_per_malware_family_format():
    """Older format: per-family sheets with 'Country of Location | IP Address'."""
    rows = [
        ["Country of Location", " IP Address"],
        ["SG", "10.20.30.40"],
        ["DE", "10.20.30.41"],
    ]
    xlsx = _make_xlsx_bytes({"Amadey": rows})
    ips, _, _ = parse_xlsx_iocs(xlsx)
    assert set(ips) == {"10.20.30.40", "10.20.30.41"}


def test_parse_xlsx_bad_bytes_returns_empty():
    ips, hashes, domains = parse_xlsx_iocs(b"not an xlsx file")
    assert ips == [] and hashes == [] and domains == []


# ── extract_iocs_from_info_file ───────────────────────────────────────────────


def test_extract_iocs_from_info_file_basic():
    xlsx = _make_xlsx_bytes({"Sheet1": [["IP"], ["1.2.3.4"]]})
    info_file = [{"fileName": "test.xlsx", "file": _make_data_uri(xlsx)}]
    ips, hashes, domains = extract_iocs_from_info_file(info_file)
    assert "1.2.3.4" in ips


def test_extract_iocs_skips_non_xlsx():
    info_file = [
        {
            "fileName": "readme.txt",
            "file": "data:text/plain;base64," + base64.b64encode(b"1.2.3.4").decode(),
        },
    ]
    ips, hashes, domains = extract_iocs_from_info_file(info_file)
    assert ips == []


def test_extract_iocs_empty_list():
    assert extract_iocs_from_info_file([]) == ([], [], [])


def test_extract_iocs_merges_multiple_attachments():
    xlsx1 = _make_xlsx_bytes({"S": [["IP"], ["1.1.1.1"]]})
    xlsx2 = _make_xlsx_bytes({"S": [["IP"], ["2.2.2.2"]]})
    info_file = [
        {"fileName": "a.xlsx", "file": _make_data_uri(xlsx1)},
        {"fileName": "b.xlsx", "file": _make_data_uri(xlsx2)},
    ]
    ips, _, _ = extract_iocs_from_info_file(info_file)
    assert set(ips) == {"1.1.1.1", "2.2.2.2"}


# ── write_ioc_txt ─────────────────────────────────────────────────────────────


def test_write_ioc_txt_all_sections():
    path = write_ioc_txt("TEST-001", ["10.0.0.1", "10.0.0.2"], ["abc123" * 5 + "ab"], ["evil.com"])
    assert path is not None
    content = path.read_text()
    assert "[IPs]" in content
    assert "[Hashes]" in content
    assert "[Domains]" in content
    assert "10.0.0.1" in content
    assert "evil.com" in content
    path.unlink(missing_ok=True)


def test_write_ioc_txt_only_ips():
    path = write_ioc_txt("TEST-002", ["5.6.7.8"], [], [])
    assert path is not None
    content = path.read_text()
    assert "[IPs]" in content
    assert "[Hashes]" not in content
    assert "[Domains]" not in content
    path.unlink(missing_ok=True)


def test_write_ioc_txt_dedupes_and_sorts():
    path = write_ioc_txt("TEST-003", ["10.0.0.2", "10.0.0.1", "10.0.0.2"], [], [])
    assert path is not None
    lines = path.read_text().splitlines()
    ip_lines = [line for line in lines if line and not line.startswith("[")]
    assert ip_lines == sorted(set(["10.0.0.1", "10.0.0.2"]))
    path.unlink(missing_ok=True)


def test_write_ioc_txt_all_empty_returns_none():
    assert write_ioc_txt("TEST-004", [], [], []) is None


def test_write_ioc_txt_safe_filename():
    path = write_ioc_txt("TWISAC-001/A", ["1.2.3.4"], [], [])
    assert path is not None
    assert "TWISAC-001_A" in path.name
    path.unlink(missing_ok=True)
