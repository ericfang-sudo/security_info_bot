# Data Models

Source of truth: `src/models.py`, `src/analyzer/gemini.py` (`ANALYSIS_SCHEMA`), `src/sinks/sheets.py` (`INTEL_HEADERS`).

## IntelItem

Produced by Stage 1 (fetch). Serialised to `src/data/{source}_*.json`.

```python
@dataclass
class IntelItem:
    intel_id: str           # e.g. "TWCERT-TWISAC-202605-0028" or "CVE-2026-9082"
    source: str             # "TWCERT" or "CISA_KEV"
    publish_date: str       # ISO date string, e.g. "2026-05-27"
    title: str
    intel_type: str         # e.g. "101-漏洞訊息", "IoC"
    cve_ids: list[str]      # may be empty
    raw_content: str        # full article text
    reference_urls: list[str]
    attachment_urls: list[str]
    ioc_ips: list[str]
    ioc_hashes: list[str]
    ioc_domains: list[str]
    impact_level: str       # TWCERT severity: "1" / "2" / ""
```

Serialise: `item.to_dict()` / `IntelItem.from_dict(d)`.

## AnalysisResult

Produced by Stage 2 (Gemini). Nested inside `src/data/analysis_{source}_*.json` as `items[i].analysis`.

```python
@dataclass
class AnalysisResult:
    risk_level: str          # enum — see ANALYSIS_SCHEMA below
    summary: str             # 2-3 sentence Chinese summary
    recommendation: str      # specific mitigation steps (Chinese)
    company_relevance: str   # enum — see ANALYSIS_SCHEMA below
    affected_assets: list[str]
    responsible_unit: str    # 部門 code from asset sheet, e.g. "RR40" (not free text)
```

## ANALYSIS_SCHEMA (Gemini structured output)

Defined in `src/analyzer/gemini.py`. Gemini is constrained to return only these enum values:

| Field | Allowed values |
|:--|:--|
| `risk_level` | `Critical`, `High`, `Medium`, `Low`, `無` |
| `company_relevance` | `H`, `M`, `L`, `無` |

`affected_assets` is a free-form string array. `responsible_unit` is a free-form string but the system prompt instructs the model to fill it with the matched asset's `部門` column code (e.g. `RR40`), not a human-readable unit name.

## SheetRow (Google Sheet — 21 columns A–U)

Built by `SheetRow.from_intel_and_analysis(intel, analysis, cve_id, intel_id_suffix="", ioc_url="")`.

- `intel_id_suffix`: when an item has multiple CVEs, each row gets a suffix (`-1`, `-2`, …).
- `ioc_url`: if non-empty, appended to the `recommendation` field as `\n\nIoC 清單：{url}`.

| Col | Field | Source | Notes |
|:---:|:--|:--|:--|
| A | `record_date` | auto | `YYYY-MM-DD` (date written, not published) |
| B | `intel_id` | auto | May include `-N` suffix for multi-CVE |
| C | `source` | auto | "TWCERT" or "CISA_KEV" |
| D | `publish_date` | auto | From `IntelItem.publish_date` |
| E | `title` | auto | |
| F | `intel_type` | auto | |
| G | `cve_id` | auto | One CVE per row |
| H | `recommendation` | AI | May include IoC URL appended at the end |
| I | `risk_level` | AI | Critical / High / Medium / Low / 無 |
| J | `summary` | AI | |
| K | `company_relevance` | AI | H / M / L / 無 |
| L | `affected_assets` | AI | Comma-separated |
| M | `responsible_unit` | AI | 部門 code (e.g. `RR40`) |
| N | `status` | human | Default `"待處理"` |
| O | `tracking_link` | human | |
| P | `notes` | human | |
| Q | `completion_date` | human | |
| R | `handler` | human | |
| S | `notification_time` | auto | |
| T | `impact_level` | auto | TWCERT severity (`"1"` / `"2"` / `""`) |
| U | `reference_urls` | auto | Newline-separated |

### Tab layout

Rows are written to per-month worksheets named `YYYY-MM` derived from `IntelItem.publish_date`. Empty or malformed dates fall back to the current month (TW+8). Each tab is auto-created on first write with frozen header row, filter, bold+coloured header, WRAP alignment, and preset column widths.
