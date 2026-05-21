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
# Both sources default to today; use --since YYYY-MM-DD to change the start date
uv run python main.py --source cisa_kev --fetch-only
uv run python main.py --source twcert --fetch-only --since 2026-05-01

# Limit items for quick testing (stops pagination early for TWCERT)
uv run python main.py --source twcert --fetch-only --limit 3

# Stage 2: analyze from a saved fetch JSON
uv run python main.py --source twcert --load-data src/data/twcert_<ts>.json --analyze-only --dry-run

# Stage 3: write Sheet from a saved analysis JSON
uv run python main.py --source twcert --load-analysis src/data/analysis_twcert_<ts>.json --write-only --dry-run

# Stage 4: send Mattermost from a saved sheet payload JSON
uv run python main.py --source twcert --load-sheet src/data/sheet_twcert_<ts>.json --dry-run

# List locally saved intermediate files (prefix filters: twcert, analysis_twcert, sheet_twcert, etc.)
uv run python main.py --list-data
uv run python main.py --list-data --source analysis_twcert
```

## Architecture

The pipeline is split into 4 independently runnable stages, each persisting a JSON handoff to `src/data/`:

```
Stage 1 Fetch → Stage 2 Analyze → Stage 3 Write Sheet → Stage 4 Notify
      ↓               ↓                   ↓
{source}_*.json  analysis_{source}_*.json  sheet_{source}_*.json
```

**Two independent sources**, both producing `IntelItem` objects. Both default to today if `--since` is omitted:
- `src/fetchers/twcert.py` — REST API client that logs in to the TWCERT enterprise portal and extracts structured threat intel. Parses base64-embedded xlsx attachments in `infoFile` to extract IP/hash/domain IoCs. Raises `TwcertLoginError` on auth failure, which triggers an ops alert. Default: today TW+8.
- `src/fetchers/cisa_kev.py` — Fetches CISA's Known Exploited Vulnerabilities JSON feed and filters by `dateAdded >= since_date`. Default: today UTC.

**Analysis** (`src/analyzer/gemini.py`): Calls Gemini with a structured JSON schema (`ANALYSIS_SCHEMA`) that enforces enum values for `risk_level` and `company_relevance`. Returns an `AnalysisResult`. Retries on 429/5xx with exponential backoff; raises `GeminiQuotaExhausted` after `max_retries`.

**Multi-CVE fan-out** (`main.py:stage_write_sheet`): If an `IntelItem` has multiple CVE IDs, it creates one `SheetRow` per CVE with a numeric suffix on the `intel_id` (e.g., `TWCERT-123-1`, `TWCERT-123-2`).

**Sinks** (write-side):
- `src/sinks/sheets.py` — Google Sheets via `gspread`; reads column B to deduplicate before writing. Also loads asset/unit/rules context from the same spreadsheet.
- `src/sinks/drive.py` — Uploads IoC `.txt` files to a configured Google Drive folder.
- `src/sinks/mattermost.py` — Sends Mattermost webhook alerts for High/Critical items.

**Fixture mode**: `USE_FIXTURE_DATA=true` (default) makes all Sheet reads load from `tests/fixtures/` instead of Google Sheets, so development works without credentials.

## Key data models (`src/models.py`)

- `IntelItem` — raw fetched intel; serialisable via `to_dict`/`from_dict`. Persisted by Stage 1.
- `AnalysisResult` — Gemini output fields; serialisable via `to_dict`/`from_dict`. Persisted by Stage 2 (inside `analysis_*.json`).
- `SheetRow` — 21-column (A–U) Google Sheet row; built by `SheetRow.from_intel_and_analysis(...)`. Column U holds `impact_level` (TWCERT severity pre-assessment).

## Configuration (`src/config.py`)

All settings are env vars loaded via `python-dotenv`. The Google Service Account credential is provided either as a file path (`GOOGLE_SA_JSON_FILE`) or as a base64-encoded JSON string (`GOOGLE_SA_JSON_B64`), which the config module writes to a temp file at runtime.

## CI (`.github/workflows/`)

Both workflows are currently **manual-dispatch only** (`workflow_dispatch`). The original schedules (TWCERT every 4h, CISA KEV daily at UTC 09:00) are disabled. Set `USE_FIXTURE_DATA: 'false'` in the workflow env to use real credentials from GitHub Secrets.
