"""
Google Gemini API 기반 방어전략 생성
"""
import json
import re

MODEL_NAME = "gemini-flash-lite-latest"

_client = None


def _get_client():
    global _client
    if _client is None:
        from google import genai
        from app.config import get_gemini_key  # 추가된 부분

        api_key = get_gemini_key()
        if not api_key:
            raise RuntimeError("Gemini API 키가 설정되지 않았습니다. 웹 화면의 설정에서 입력해주세요.")
        _client = genai.Client(api_key=api_key.strip())
    return _client


def _extract_json(text: str) -> dict:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"JSON을 찾지 못함: {text[:200]}")
    return json.loads(match.group(0))


def generate_defense(prompt: str) -> dict:
    client = _get_client()
    response = client.models.generate_content(model=MODEL_NAME, contents=prompt)
    generated = response.text

    try:
        return _extract_json(generated)
    except (ValueError, json.JSONDecodeError) as e:
        print(f"[llm_client] JSON 파싱 실패, 원문 반환: {e}")
        return {"summary": generated.strip(), "immediate_actions": [], "long_term_actions": []}


def reset_client():
    """새 키 저장 후 클라이언트 재생성이 필요할 때 호출"""
    global _client
    _client = None