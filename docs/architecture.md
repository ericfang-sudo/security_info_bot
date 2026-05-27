# Architecture

Automated threat-intel pipeline that fetches from two sources daily, runs Gemini analysis, and writes structured rows to Google Sheets. Intermediate artefacts (fetch JSON, analysis JSON, IoC txt) are committed to a dedicated git archive branch.

## Pipeline stages

```
Stage 1 Fetch  →  Stage 2 Analyze  →  Stage 3 Write Sheet
      ↓                  ↓
{source}/{YYYY-MM}/      {source}/{YYYY-MM}/          git archive branch (data)
  {source}_*.json          analysis_{source}_*.json     + IoC URL → Sheet col H
```

Stages are independently re-runnable via `--fetch-only`, `--analyze-only`, `--load-data`, and `--load-analysis` CLI flags. Each stage saves its output to `src/data/` locally and commits it to the archive branch (when `GIT_ARCHIVE_BRANCH` is set).

## Subsystems

### `src/fetchers/`

| File | Role |
|:--|:--|
| `twcert.py` | REST API client — logs in to the TWCERT enterprise portal, paginates intel list, fetches per-item detail. Parses `infoFile` base64 xlsx attachments for IoC extraction. Raises `TwcertLoginError` on auth failure. Default `--since`: today TW+8. |
| `cisa_kev.py` | Fetches the CISA Known Exploited Vulnerabilities JSON feed; filters entries where `dateAdded >= since_date`. Default `--since`: today UTC. |
| `storage.py` | `save_items` / `load_items` / `save_analysis` / `load_analysis` — serialise `IntelItem` and `AnalysisResult` lists to/from JSON files under `src/data/`. |

### `src/analyzer/`

| File | Role |
|:--|:--|
| `gemini.py` | Calls Gemini via the `google-genai` SDK with `ANALYSIS_SCHEMA` (structured JSON output, enforced enums). Retries on 429/5xx with exponential backoff; raises `GeminiQuotaExhausted` after `max_retries=3`. |
| `prompt.py` | `SYSTEM_PROMPT` — analysis principles, risk-level rules, output schema doc. `build_analysis_prompt(intel_content, assets_context)` — assembles the per-item user turn. |

### `src/sinks/`

| File | Role |
|:--|:--|
| `sheets.py` | `append_rows` writes `SheetRow` lists to per-month Google Sheets worksheets (named `YYYY-MM`); auto-creates tabs on first use. `get_existing_intel_ids` scopes dedup per month. `load_assets_context` loads the asset inventory from an external sheet (`ASSETS_SHEET_ID`). |
| `git_archive.py` | Commits fetch JSON, analysis JSON, and IoC txt to the `GIT_ARCHIVE_BRANCH` branch via a git worktree at `/tmp/security-info-archive`. `ioc_file_url` derives a GitHub raw URL for the committed IoC file. See [archive-branch.md](archive-branch.md). |

### `src/parsers/ioc_xlsx.py`

Parses xlsx attachments embedded in TWCERT detail responses (`infoFile`) as base64 data URIs. `parse_xlsx_iocs` returns `(ips, hashes, domains)` tuples. `write_ioc_txt` writes a structured plain-text file to `/tmp/ioc_{intel_id}.txt`.

### `src/utils/`

- `logging.py` — structured `log` singleton used throughout.
- `errors.py` — `TwcertLoginError`, `GeminiQuotaExhausted`, `send_ops_alert` (log-only). See [error-handling.md](error-handling.md).

## Cross-cutting rules

### Multi-CVE fan-out

If an `IntelItem` has multiple `cve_ids`, `main.py:stage_write_sheet` creates one `SheetRow` per CVE. Each row gets a numeric suffix on `intel_id` (e.g., `TWISAC-0028-1`, `TWISAC-0028-2`). Single-CVE items have no suffix.

### Monthly dedup scope

`get_existing_intel_ids` is called with the set of `YYYY-MM` months covered by the current batch. It reads column B of each matching worksheet and returns all existing `intel_id` values. An item is skipped if its `intel_id` already appears in any of those tabs.

### Fixture mode

`USE_FIXTURE_DATA=true` (the default) makes `sheets.py` load asset context from `tests/fixtures/sample_assets.json` instead of the live Google Sheet. CISA KEV fixture data lives in `tests/fixtures/sample_cisa_kev.json`. This allows full local development without Google credentials.

### Two-source timezone contract

- **TWCERT**: `--since` is interpreted as TW+8 midnight. Workflows pass `TZ=Asia/Taipei date +%Y-%m-%d`.
- **CISA KEV**: `--since` is compared against `dateAdded` (UTC dates). Workflows pass `date -u +%Y-%m-%d`.
