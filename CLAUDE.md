# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
uv sync --activate

# Run tests
uv run pytest tests/ -v

# Run a single test file
uv run pytest tests/test_cisa_kev_fetcher.py -v

# Dry-run without writing to Sheet or sending alerts
uv run python main.py --source cisa_kev --dry-run
uv run python main.py --source twcert --dry-run

# Fetch and save locally without analysis (no Gemini/Sheet credentials needed)
uv run python main.py --source cisa_kev --fetch-only

# Reload from a previously saved JSON file
uv run python main.py --source cisa_kev --load-data data/cisa_kev_2024-04-15_170000.json --dry-run

# List locally saved data files
uv run python main.py --list-data
```

## Architecture

The pipeline runs in this order:

```
Fetcher → Dedup (vs Google Sheet) → Gemini AI analysis → Google Sheet write → Mattermost alert
                                                        ↘ IoC .txt → Google Drive upload
```

**Two independent sources**, both producing `IntelItem` objects:
- `src/fetchers/twcert.py` — REST API client that logs in to the TWCERT enterprise portal and extracts structured threat intel. Parses base64-embedded xlsx attachments in `infoFile` to extract IP/hash/domain IoCs. Raises `TwcertLoginError` on auth failure, which triggers an ops alert.
- `src/fetchers/cisa_kev.py` — Fetches CISA's Known Exploited Vulnerabilities JSON feed and filters by `--date` (defaults to today UTC).

**Analysis** (`src/analyzer/gemini.py`): Calls Gemini with a structured JSON schema (`ANALYSIS_SCHEMA`) that enforces enum values for `risk_level` and `company_relevance`. Returns an `AnalysisResult`. Retries on 429/5xx with exponential backoff; raises `GeminiQuotaExhausted` after `max_retries`.

**Multi-CVE fan-out** (`main.py:process_intel_items`): If an `IntelItem` has multiple CVE IDs, it creates one `SheetRow` per CVE with a numeric suffix on the `intel_id` (e.g., `TWCERT-123-1`, `TWCERT-123-2`).

**Sinks** (write-side):
- `src/sinks/sheets.py` — Google Sheets via `gspread`; reads column B to deduplicate before writing. Also loads asset/unit/rules context from the same spreadsheet.
- `src/sinks/drive.py` — Uploads IoC `.txt` files to a configured Google Drive folder.
- `src/sinks/mattermost.py` — Sends Mattermost webhook alerts for High/Critical items.

**Fixture mode**: `USE_FIXTURE_DATA=true` (default) makes all Sheet reads load from `tests/fixtures/` instead of Google Sheets, so development works without credentials.

## Key data models (`src/models.py`)

- `IntelItem` — raw fetched intel; serialisable to/from JSON via `to_dict`/`from_dict` (used by `src/fetchers/storage.py` for `--save-data`/`--load-data`).
- `AnalysisResult` — Gemini output fields.
- `SheetRow` — 21-column (A–U) Google Sheet row; built by `SheetRow.from_intel_and_analysis(...)`. Column U holds `impact_level` (TWCERT severity pre-assessment).

## Configuration (`src/config.py`)

All settings are env vars loaded via `python-dotenv`. The Google Service Account credential is provided either as a file path (`GOOGLE_SA_JSON_FILE`) or as a base64-encoded JSON string (`GOOGLE_SA_JSON_B64`), which the config module writes to a temp file at runtime.

## CI (`.github/workflows/`)

Both workflows are currently **manual-dispatch only** (`workflow_dispatch`). The original schedules (TWCERT every 4h, CISA KEV daily at UTC 09:00) are disabled. Set `USE_FIXTURE_DATA: 'false'` in the workflow env to use real credentials from GitHub Secrets.
