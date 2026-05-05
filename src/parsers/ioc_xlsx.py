from __future__ import annotations

import re
import tempfile
from pathlib import Path

import requests
from openpyxl import load_workbook

from src.utils.logging import log

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def write_ioc_txt(intel_id: str, ips: list[str]) -> Path | None:
    """Write a deduped, sorted IP list to a temp .txt file. Returns None if list is empty."""
    unique = sorted({ip for ip in ips if ip})
    if not unique:
        return None
    safe_id = re.sub(r"[^\w\-]", "_", intel_id)
    output_path = Path(tempfile.gettempdir()) / f"ioc_{safe_id}.txt"
    output_path.write_text("\n".join(unique) + "\n", encoding="utf-8")
    log.info("Wrote %d IPs to %s", len(unique), output_path)
    return output_path


def download_and_parse_ioc_xlsx(url: str, intel_id: str) -> Path | None:
    log.info("Downloading IoC attachment from %s", url)

    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as e:
        log.error("Failed to download IoC attachment: %s", e)
        return None

    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
        tmp.write(resp.content)
        tmp_path = Path(tmp.name)

    try:
        wb = load_workbook(tmp_path, read_only=True, data_only=True)
    except Exception as e:
        log.error("Failed to open xlsx: %s", e)
        tmp_path.unlink(missing_ok=True)
        return None

    ips: set[str] = set()

    for ws in wb.worksheets:
        for row in ws.iter_rows(values_only=True):
            for cell in row:
                if cell is None:
                    continue
                cell_str = str(cell).strip()
                matches = IP_PATTERN.findall(cell_str)
                ips.update(matches)

    wb.close()
    tmp_path.unlink(missing_ok=True)

    if not ips:
        log.warning("No IPs found in IoC attachment for %s", intel_id)
        return None

    safe_id = re.sub(r"[^\w\-]", "_", intel_id)
    output_path = Path(tempfile.gettempdir()) / f"ioc_{safe_id}.txt"
    output_path.write_text("\n".join(sorted(ips)) + "\n", encoding="utf-8")
    log.info("Extracted %d IPs to %s", len(ips), output_path)
    return output_path
