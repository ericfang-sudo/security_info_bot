# Configuration

All settings are env vars loaded at startup via `python-dotenv` (`src/config.py`). Copy `.env.example` as the canonical starting point.

## Environment variables

| Variable | Purpose | Default | Required when |
|:--|:--|:--|:--|
| `TWCERT_ACCOUNT` | TWCERT enterprise portal username | — | `--source twcert` |
| `TWCERT_PASSWORD` | TWCERT enterprise portal password | — | `--source twcert` |
| `GEMINI_API_KEY` | Google Gemini API key | — | Stage 2 (analyze) |
| `GEMINI_MODEL` | Gemini model name | `gemini-3.1-pro-preview` | No |
| `GOOGLE_SA_JSON_FILE` | Path to Service Account JSON file | — | Stage 2/3 (Google APIs) |
| `GOOGLE_SA_JSON_B64` | Base64-encoded Service Account JSON | — | Stage 2/3 (alternative) |
| `GOOGLE_SHEET_ID` | Intel Google Sheet ID | — | Stage 3 (write sheet) |
| `ASSETS_SHEET_ID` | Asset inventory Google Sheet ID | — | Stage 2 (assets context) |
| `ASSETS_WORKSHEET` | Asset sheet worksheet name | `工作表1` | No |
| `GIT_ARCHIVE_BRANCH` | Branch name for artefact archive | `""` (disabled) | No |
| `GIT_ARCHIVE_AUTO_PUSH` | Push archive branch after each commit | `false` | No (set `true` in CI) |
| `USE_FIXTURE_DATA` | Load assets/CISA KEV from `tests/fixtures/` | `true` | No |

## Google Service Account credential resolution

`src/config.py:get_service_account_path()` resolves credentials in this order:

1. If `GOOGLE_SA_JSON_FILE` is set **and** the file exists → use it directly.
2. Else if `GOOGLE_SA_JSON_B64` is set → base64-decode into a temp file (`/tmp/sa_*.json`) and use that path.
3. Otherwise → raises `RuntimeError`.

The SA must have:
- **Sheets Editor** on the intel Google Sheet (`GOOGLE_SHEET_ID`).
- **Sheets Viewer** on the asset inventory sheet (`ASSETS_SHEET_ID`).

## Fixture mode

When `USE_FIXTURE_DATA=true` (the default), `src/sinks/sheets.py:load_assets_context()` reads from `tests/fixtures/sample_assets.json` instead of the live Google Sheet. This allows local development and CI unit tests to run without any Google credentials.

Fixture files:

| File | Replaces |
|:--|:--|
| `tests/fixtures/sample_assets.json` | Live asset inventory worksheet |
| `tests/fixtures/sample_cisa_kev.json` | Live CISA KEV JSON feed |

`tests/fixtures/sample_twcert_iocs.xlsx` is used by IoC parser unit tests and has no runtime fixture-mode equivalent (TWCERT fetcher requires live credentials either way).

## `GIT_ARCHIVE_BRANCH` behaviour

- **Empty string (default)**: All `commit_files` / `ioc_file_url` calls are silent no-ops. No worktree is created. No archive branch is needed.
- **Set to a branch name** (e.g., `data`): Worktree is created at `/tmp/security-info-archive` on first use; branch is auto-created if it does not exist.
- **`GIT_ARCHIVE_AUTO_PUSH=true`**: Each `commit_files` call immediately pushes the branch to `origin`. Set this in CI; leave it `false` locally unless you want to push after every pipeline run.
