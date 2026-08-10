"""
로컬 설정 저장/로드 (API 키 등). data/config.json에 저장, git에는 안 올라감.
"""
import json
import os

CONFIG_PATH = "data/config.json"


def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_config(updates: dict):
    config = load_config()
    config.update(updates)
    os.makedirs("data", exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def get_gemini_key() -> str:
    """환경변수 우선, 없으면 저장된 설정 파일에서"""
    return os.environ.get("GEMINI_API_KEY") or load_config().get("gemini_api_key", "")