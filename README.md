# 資安威脅情資 AI 自動化分析系統

TWCERT/CC 企業情資自動化處理系統，透過 Python + Google Gemini AI 自動擷取、分析、分級並通報資安威脅情資。

## 架構概覽

```
TWCERT 企業後台 ──(Playwright)──┐
                                ├─→ 去重 → Gemini AI 分析 → Google Sheet 回填 → Mattermost 通報
CISA KEV JSON Feed ──(requests)─┘                          ↘ IoC .txt → Google Drive
```

- **TWCERT 爬蟲**：每 4 小時以 Playwright 模擬登入企業後台，擷取最新情資
- **CISA KEV 爬蟲**：每日抓取 CISA Known Exploited Vulnerabilities JSON Feed
- **AI 分析**：Gemini 3.1 Pro 結合公司資產清單與風險規章，產出風險分級、摘要與建議措施
- **通報**：High / Critical 等級即時推送至 Mattermost 資安頻道
- **紀錄**：分析結果回填 Google Sheet（20 欄 A–T），支援一 CVE 一列拆分追蹤

## 環境需求

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) 套件管理工具

## 快速開始

```bash
# 安裝依賴
uv sync

# 安裝 Playwright 瀏覽器（僅 TWCERT 爬蟲需要）
uv run playwright install chromium --with-deps

# 設定環境變數（複製範本後填入實際值）
cp .env.example .env

# 以樣板資料模擬執行（不寫入 Sheet、不發通報）
uv run python main.py --source cisa_kev --dry-run

# 指定日期測試 CISA KEV
uv run python main.py --source cisa_kev --dry-run --date 2024-04-15

# 僅擷取情資存至本機（不執行 AI 分析與通報，不需 Gemini / Sheet 憑證）
uv run python main.py --source cisa_kev --fetch-only
uv run python main.py --source cisa_kev --fetch-only --date 2024-04-15
uv run python main.py --source twcert --fetch-only

# 列出已儲存的本機資料
uv run python main.py --list-data

# 從本機資料重跑分析（跳過遠端擷取）
uv run python main.py --source cisa_kev --load-data data/cisa_kev_2024-04-15_170000.json --dry-run

# 正式執行（需設定所有環境變數）
uv run python main.py --source twcert
uv run python main.py --source cisa_kev
```

## 環境變數

| 變數名稱 | 說明 | 必填 |
|:---|:---|:---:|
| `TWCERT_ACCOUNT` | TWCERT 企業會員帳號 | TWCERT 流程 |
| `TWCERT_PASSWORD` | TWCERT 企業會員密碼 | TWCERT 流程 |
| `GEMINI_API_KEY` | Google Gemini API Key | 是 |
| `GEMINI_MODEL` | Gemini 模型名稱（預設 `gemini-3.1-pro-preview`） | 否 |
| `GOOGLE_SA_JSON_B64` | Google Service Account JSON 的 Base64 編碼 | 是 |
| `GOOGLE_SA_JSON_FILE` | 或直接指定 Service Account JSON 檔案路徑 | 擇一 |
| `GOOGLE_SHEET_ID` | 情資紀錄 Google Sheet ID | 是 |
| `GOOGLE_DRIVE_IOC_FOLDER_ID` | IoC 檔案上傳目標 Google Drive 資料夾 ID | IoC 流程 |
| `MATTERMOST_WEBHOOK` | Mattermost 資安頻道 Incoming Webhook URL | 是 |
| `MATTERMOST_OPS_WEBHOOK` | Mattermost 維運頻道 Webhook（登入失敗等警報） | 否 |
| `USE_FIXTURE_DATA` | 設為 `true` 使用樣板資料開發（預設 `true`） | 否 |

## 專案結構

```
├── main.py                     # CLI 進入點
├── pyproject.toml              # uv 套件管理
├── .github/workflows/
│   ├── twcert.yml              # GitHub Actions：每 4 小時
│   └── cisa_kev.yml            # GitHub Actions：每日 UTC 09:00
├── src/
│   ├── config.py               # 環境變數與設定
│   ├── models.py               # 資料模型（IntelItem / AnalysisResult / SheetRow）
│   ├── fetchers/
│   │   ├── twcert.py           # TWCERT Playwright 爬蟲
│   │   └── cisa_kev.py         # CISA KEV JSON 爬蟲
│   ├── analyzer/
│   │   ├── gemini.py           # Gemini API 呼叫（結構化 JSON 輸出）
│   │   └── prompt.py           # System prompt + 分析 prompt 模板
│   ├── sinks/
│   │   ├── sheets.py           # Google Sheets 讀寫（去重 / 批次寫入 / 資產載入）
│   │   ├── drive.py            # Google Drive IoC 檔案上傳
│   │   └── mattermost.py       # Mattermost Webhook 通報
│   ├── parsers/
│   │   └── ioc_xlsx.py         # xlsx 附件 → IP 清單 .txt
│   └── utils/
│       ├── logging.py
│       └── errors.py           # 錯誤類型與維運警報
└── tests/
    ├── fixtures/               # 樣板資料（資產 / 單位 / 規章 / CISA KEV）
    ├── test_cisa_kev_fetcher.py
    ├── test_sheet_writeback.py
    └── test_ioc_parser.py
```

## 測試

```bash
uv run pytest tests/ -v
```

## Google Sheet 欄位規格

系統寫入 20 欄（A–T），遵循「一 CVE 一列」原則：

| 欄 | 名稱 | 填寫方式 |
|:---:|:---|:---:|
| A | 記錄日期 | 自動 |
| B | 情資編號 | 自動 |
| C | 來源 | 自動 |
| D | 情資發布日期 | 自動 |
| E | 情資主旨 | 自動 |
| F | 情資類型 | 自動 |
| G | CVE ID | 自動 |
| H | 建議措施 | AI |
| I | AI 風險等級 | AI |
| J | AI 分析摘要 | AI |
| K | 公司風險相關性 | AI 預填 |
| L | 內部受影響資產 | AI 預填 |
| M | 處置措施負責單位 | AI 預填 |
| N | 目前狀態 | 人工 |
| O | 追蹤表單連結 | 人工 |
| P | 處理備註 | 人工 |
| Q | 處理完成日期 | 人工 |
| R | 處理人員 | 人工 |
| S | 通報時間 | 自動 |
| T | 參考連結 | 自動 |

## 部署

GitHub Actions 以 `astral-sh/setup-uv` 安裝 uv，透過 `uv sync` 還原依賴。兩個 workflow 各自獨立排程，共用同一份程式碼。

如需固定 IP（TWCERT 後台設有白名單時），將 workflow 中的 `runs-on` 改為 `self-hosted` 即可切換至自建 Runner。

## 授權

本專案僅供內部資安防禦使用。
