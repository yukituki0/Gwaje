# colab/llm_client.py (Gemini 버전)
"""
Google Gemini API 기반 방어전략 생성 (무료 티어, 카드 등록 불필요)
"""
import json
import os
import re

MODEL_NAME = "gemini-2.5-flash"

_model = None


def _get_model():
    global _model
    if _model is None:
        import google.generativeai as genai
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("환경변수 GEMINI_API_KEY가 설정되지 않았습니다.")
        genai.configure(api_key=api_key)
        _model = genai.GenerativeModel(MODEL_NAME)
    return _model


def _extract_json(text: str) -> dict:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"JSON을 찾지 못함: {text[:200]}")
    return json.loads(match.group(0))


def generate_defense(prompt: str) -> dict:
    model = _get_model()
    response = model.generate_content(prompt)
    generated = response.text

    try:
        return _extract_json(generated)
    except (ValueError, json.JSONDecodeError) as e:
        print(f"[llm_client] JSON 파싱 실패, 원문 반환: {e}")
        return {"summary": generated.strip(), "immediate_actions": [], "long_term_actions": []}