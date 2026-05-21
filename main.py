from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.analyzer.gemini import analyze_intel
from src.fetchers.cisa_kev import fetch_cisa_kev
from src.fetchers.storage import (
    list_saved_files,
    load_analysis,
    load_items,
    load_sheet_payload,
    save_analysis,
    save_items,
    save_sheet_payload,
)
from src.fetchers.twcert import fetch_twcert
from src.models import AnalysisResult, IntelItem, SheetRow
from src.parsers.ioc_xlsx import write_ioc_txt
from src.sinks.drive import upload_ioc_file
from src.sinks.mattermost import send_intel_alert
from src.sinks.sheets import (
    append_rows,
    get_existing_intel_ids,
    load_assets_context,
    load_rules_context,
    load_units_context,
    update_notification_time,
)
from src.utils.errors import GeminiQuotaExhausted, TwcertLoginError
from src.utils.logging import log


def stage_fetch(
    source: str,
    since_date: str | None = None,
    save: bool = False,
    limit: int | None = None,
) -> list[IntelItem]:
    if source == "twcert":
        items = fetch_twcert(since_date, limit=limit)
    elif source == "cisa_kev":
        items = fetch_cisa_kev(since_date)
        if limit is not None:
            items = items[:limit]
            log.info("Limiting to %d items", len(items))
    else:
        raise ValueError(f"Unknown source: {source}")
    if save:
        save_items(items, source, tag=since_date)
    return items


def stage_analyze(
    items: list[IntelItem],
    source: str,
    save: bool = False,
    tag: str | None = None,
    dry_run: bool = False,
    limit: int | None = None,
) -> list[tuple[IntelItem, AnalysisResult]]:
    existing_ids = set() if dry_run else get_existing_intel_ids()
    new_items = [item for item in items if item.intel_id not in existing_ids]
    if not new_items:
        log.info("No new intel items to analyze (all %d already exist)", len(items))
        return []

    if limit is not None:
        new_items = new_items[:limit]
        log.info("Limiting analysis to %d items", len(new_items))

    log.info("Analyzing %d new items (skipped %d duplicates)", len(new_items), len(items) - len(new_items))

    assets_ctx = load_assets_context()
    units_ctx = load_units_context()
    rules_ctx = load_rules_context()

    pairs: list[tuple[IntelItem, AnalysisResult]] = []
    for item in new_items:
        try:
            analysis = analyze_intel(item, assets_ctx, units_ctx, rules_ctx)
        except GeminiQuotaExhausted:
            log.error("Gemini quota exhausted, stopping. Remaining items will be processed next run.")
            break
        log.info("Analyzed %s: risk=%s, relevance=%s", item.intel_id, analysis.risk_level, analysis.company_relevance)
        pairs.append((item, analysis))

    if save and pairs:
        save_analysis(pairs, source, tag=tag)
    return pairs


def stage_write_sheet(
    pairs: list[tuple[IntelItem, AnalysisResult]],
    source: str,
    save: bool = False,
    tag: str | None = None,
    dry_run: bool = False,
) -> list[dict]:
    # Defensive re-dedup handles any Sheet writes since stage_analyze ran.
    existing_ids = set() if dry_run else get_existing_intel_ids()
    filtered = [(intel, analysis) for intel, analysis in pairs if intel.intel_id not in existing_ids]
    if not filtered:
        log.info("No new items to write to Sheet (all already exist)")
        return []

    all_rows: list[SheetRow] = []
    payload: list[dict] = []

    for intel, analysis in filtered:
        ioc_drive_link = ""
        if not dry_run:
            ioc_path: Path | None = write_ioc_txt(intel.intel_id, intel.ioc_ips, intel.ioc_hashes, intel.ioc_domains)
            if ioc_path:
                ioc_drive_link = upload_ioc_file(ioc_path)

        cve_list = intel.cve_ids if intel.cve_ids else [""]
        for idx, cve_id in enumerate(cve_list):
            suffix = str(idx + 1) if len(cve_list) > 1 else ""
            row = SheetRow.from_intel_and_analysis(
                intel=intel,
                analysis=analysis,
                cve_id=cve_id,
                intel_id_suffix=suffix,
                ioc_drive_link=ioc_drive_link,
            )
            all_rows.append(row)
            payload.append({
                "intel_id": row.intel_id,
                "cve_id": cve_id,
                "ioc_drive_link": ioc_drive_link,
                "intel": intel.to_dict(),
                "analysis": analysis.to_dict(),
            })

    if dry_run:
        log.info("[DRY RUN] Would write %d rows to Sheet", len(all_rows))
        for row in all_rows:
            log.info("  %s | %s | %s | %s", row.intel_id, row.cve_id, row.risk_level, row.title[:50])
    else:
        count = append_rows(all_rows)
        log.info("Wrote %d rows to Sheet.", count)

    if save and payload:
        save_sheet_payload(payload, source, tag=tag)
    return payload


def stage_notify(payload: list[dict], dry_run: bool = False) -> None:
    for entry in payload:
        intel = IntelItem.from_dict(entry["intel"])
        analysis = AnalysisResult.from_dict(entry["analysis"])
        cve_id: str = entry["cve_id"]
        ioc_drive_link: str = entry.get("ioc_drive_link", "")
        intel_id: str = entry["intel_id"]

        if dry_run:
            log.info("[DRY RUN] Would notify: %s (risk=%s)", intel_id, analysis.risk_level)
            continue

        notification_time = send_intel_alert(
            intel=intel,
            analysis=analysis,
            cve_id=cve_id,
            ioc_drive_link=ioc_drive_link,
        )
        if notification_time:
            update_notification_time(intel_id, notification_time)


def run(
    source: str,
    dry_run: bool = False,
    since_date: str | None = None,
    save_data: bool = False,
    load_data: str | None = None,
    fetch_only: bool = False,
    analyze_only: bool = False,
    write_only: bool = False,
    load_analysis_path: str | None = None,
    load_sheet_path: str | None = None,
    limit: int | None = None,
) -> None:
    # --- Stage 4 only ---
    if load_sheet_path:
        log.info("=== %s Stage 4: Mattermost notify ===", source.upper())
        payload = load_sheet_payload(load_sheet_path)
        stage_notify(payload, dry_run=dry_run)
        log.info("=== %s 通報完成 ===", source.upper())
        return

    # --- Stage 3+ ---
    if load_analysis_path:
        log.info("=== %s Stage 3+: Write Sheet ===", source.upper())
        pairs = load_analysis(load_analysis_path)
        payload = stage_write_sheet(pairs, source, save=True, tag=since_date, dry_run=dry_run)
        if not write_only and payload:
            stage_notify(payload, dry_run=dry_run)
        log.info("=== %s 完成 ===", source.upper())
        return

    # --- Stage 1: Fetch ---
    log.info("=== %s 情資%s開始 ===", source.upper(), "擷取" if fetch_only else "分析")
    if load_data:
        items = load_items(load_data)
        if limit is not None:
            items = items[:limit]
            log.info("Limiting to %d items", len(items))
    else:
        items = stage_fetch(source, since_date=since_date, save=save_data or fetch_only, limit=limit)

    if not items:
        log.info("No items fetched")
        return

    if fetch_only:
        log.info("Fetch-only mode: %d items saved, skipping analysis", len(items))
        return

    # --- Stage 2: Analyze ---
    pairs = stage_analyze(items, source, save=analyze_only, tag=since_date, dry_run=dry_run, limit=limit)
    if not pairs:
        return

    if analyze_only:
        log.info("Analyze-only mode: %d pairs saved, skipping Sheet write", len(pairs))
        return

    # --- Stage 3: Write Sheet ---
    payload = stage_write_sheet(pairs, source, save=write_only, tag=since_date, dry_run=dry_run)

    if write_only:
        log.info("Write-only mode: %d rows saved, skipping Mattermost notify", len(payload))
        return

    # --- Stage 4: Notify ---
    if payload:
        stage_notify(payload, dry_run=dry_run)

    log.info("=== %s 情資分析完成 ===", source.upper())


def cmd_list_data(source: str | None) -> None:
    files = list_saved_files(source)
    if not files:
        print("No saved data files found.")
        return
    print(f"Saved data files ({len(files)}):\n")
    for f in files:
        print(f"  {f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="資安情資 AI 自動化分析系統")
    parser.add_argument(
        "--source",
        help="情資來源：twcert 或 cisa_kev（--list-data 時可用任意前綴，如 analysis_twcert）",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="模擬執行，不寫入 Sheet 也不發送通報",
    )
    parser.add_argument(
        "--since",
        type=str,
        default=None,
        metavar="DATE",
        help="僅擷取指定日期（含）之後的情資 (YYYY-MM-DD)，預設為今天",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="限制 Stage 1/2 處理的最大項目數量（測試用）",
    )

    stage_group = parser.add_mutually_exclusive_group()
    stage_group.add_argument(
        "--fetch-only",
        action="store_true",
        help="僅擷取情資並儲存至本機，不執行 AI 分析與通報",
    )
    stage_group.add_argument(
        "--analyze-only",
        action="store_true",
        help="執行到 Gemini 分析後停止，將結果儲存為 analysis_*.json",
    )
    stage_group.add_argument(
        "--write-only",
        action="store_true",
        help="執行到寫入 Sheet 後停止，將 payload 儲存為 sheet_*.json（不發 Mattermost）",
    )

    parser.add_argument(
        "--save-data",
        action="store_true",
        help="將擷取的情資儲存至本機 data/ 目錄（JSON 格式）",
    )
    parser.add_argument(
        "--load-data",
        type=str,
        default=None,
        metavar="FILE",
        help="從本機 fetch JSON 載入情資，跳過遠端擷取（從 Stage 2 開始）",
    )
    parser.add_argument(
        "--load-analysis",
        type=str,
        default=None,
        metavar="FILE",
        help="從本機 analysis JSON 載入分析結果，跳過 Stage 1–2（從 Stage 3 開始）",
    )
    parser.add_argument(
        "--load-sheet",
        type=str,
        default=None,
        metavar="FILE",
        help="從本機 sheet JSON 載入 payload，跳過 Stage 1–3（僅執行 Stage 4 Mattermost 通報）",
    )
    parser.add_argument(
        "--list-data",
        action="store_true",
        help="列出已儲存的本機資料檔案",
    )

    args = parser.parse_args()

    if args.list_data:
        cmd_list_data(args.source)
        return

    if not args.source:
        parser.error("--source is required")
    if args.source not in ("twcert", "cisa_kev"):
        parser.error(f"--source must be 'twcert' or 'cisa_kev' (got '{args.source}')")

    try:
        run(
            source=args.source,
            dry_run=args.dry_run,
            since_date=args.since,
            save_data=args.save_data,
            load_data=args.load_data,
            fetch_only=args.fetch_only,
            analyze_only=args.analyze_only,
            write_only=args.write_only,
            load_analysis_path=args.load_analysis,
            load_sheet_path=args.load_sheet,
            limit=args.limit,
        )
    except TwcertLoginError:
        log.error("TWCERT login failed, ops alert already sent")
        sys.exit(1)
    except GeminiQuotaExhausted:
        log.error("Gemini quota exhausted, partial results may have been written")
        sys.exit(1)
    except Exception as e:
        log.error("Unexpected error: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
