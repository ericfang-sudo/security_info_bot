from __future__ import annotations

import json
import time

from google import genai
from google.genai import types

from src.analyzer.prompt import SYSTEM_PROMPT, build_analysis_prompt
from src.config import GEMINI_API_KEY, GEMINI_MODEL
from src.models import AnalysisResult, IntelItem
from src.utils.errors import GeminiQuotaExhausted, send_ops_alert
from src.utils.logging import log

_client: genai.Client | None = None


def _get_client() -> genai.Client:
    global _client
    if _client is None:
        _client = genai.Client(api_key=GEMINI_API_KEY)
    return _client


ANALYSIS_SCHEMA = types.Schema(
    type=types.Type.OBJECT,
    required=["risk_level", "summary", "recommendation", "company_relevance", "affected_assets", "responsible_unit"],
    properties={
        "risk_level": types.Schema(type=types.Type.STRING, enum=["Critical", "High", "Medium", "Low", "無"]),
        "summary": types.Schema(type=types.Type.STRING),
        "recommendation": types.Schema(type=types.Type.STRING),
        "company_relevance": types.Schema(type=types.Type.STRING, enum=["H", "M", "L", "無"]),
        "affected_assets": types.Schema(type=types.Type.ARRAY, items=types.Schema(type=types.Type.STRING)),
        "responsible_unit": types.Schema(type=types.Type.STRING),
    },
)


def analyze_intel(
    intel: IntelItem,
    assets_context: str,
    units_context: str,
    rules_context: str,
    max_retries: int = 3,
) -> AnalysisResult:
    client = _get_client()

    intel_text = f"標題：{intel.title}\n來源：{intel.source}\n發布日期：{intel.publish_date}\n"
    if intel.cve_ids:
        intel_text += f"CVE：{', '.join(intel.cve_ids)}\n"
    if intel.raw_content:
        intel_text += f"\n詳細內容：\n{intel.raw_content}\n"
    if intel.reference_urls:
        intel_text += f"\n參考連結：{', '.join(intel.reference_urls)}\n"

    user_prompt = build_analysis_prompt(intel_text, assets_context, units_context, rules_context)

    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    response_mime_type="application/json",
                    response_schema=ANALYSIS_SCHEMA,
                    temperature=0.2,
                ),
            )

            result = json.loads(response.text)

            return AnalysisResult(
                risk_level=result["risk_level"],
                summary=result["summary"],
                recommendation=result["recommendation"],
                company_relevance=result["company_relevance"],
                affected_assets=result.get("affected_assets", []),
                responsible_unit=result.get("responsible_unit", ""),
            )

        except Exception as e:
            error_str = str(e)
            if "429" in error_str or "RESOURCE_EXHAUSTED" in error_str:
                if attempt == max_retries - 1:
                    send_ops_alert(
                        "Gemini API 額度耗盡",
                        f"情資 {intel.intel_id} 分析失敗，已重試 {max_retries} 次。\n錯誤：{error_str}",
                    )
                    raise GeminiQuotaExhausted(error_str) from e
                wait = 2 ** (attempt + 1)
                log.warning("Gemini rate limited, retrying in %ds (attempt %d/%d)", wait, attempt + 1, max_retries)
                time.sleep(wait)
            elif "500" in error_str or "503" in error_str:
                if attempt == max_retries - 1:
                    raise
                wait = 2 ** (attempt + 1)
                log.warning("Gemini server error, retrying in %ds (attempt %d/%d)", wait, attempt + 1, max_retries)
                time.sleep(wait)
            else:
                raise

    raise RuntimeError("Unreachable")
