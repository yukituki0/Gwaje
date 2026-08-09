"""
Google Gemini API 기반 방어전략 생성 (신규 google.genai SDK 사용)
"""
import json
import os
import re

MODEL_NAME = "gemini-flash-latest"

_client = None


def _get_client():
    global _client
    if _client is None:
        from google import genai
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("환경변수 GEMINI_API_KEY가 설정되지 않았습니다.")
        _client = genai.Client(api_key=api_key.strip())  # 혹시 모를 공백 제거
    return _client


def _extract_json(text: str) -> dict:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"JSON을 찾지 못함: {text[:200]}")
    return json.loads(match.group(0))


def generate_defense(prompt: str) -> dict:
    client = _get_client()
    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt,
    )
    generated = response.text

    try:
        return _extract_json(generated)
    except (ValueError, json.JSONDecodeError) as e:
        print(f"[llm_client] JSON 파싱 실패, 원문 반환: {e}")
        return {"summary": generated.strip(), "immediate_actions": [], "long_term_actions": []}