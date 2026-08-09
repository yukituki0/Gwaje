"""
방어전략 생성 LLM 클라이언트 (연구방법론_정리.md 7.1절)
generate_defense() 하나로 모델을 감싸서, 모델을 갈아끼워도 나머지 코드는 그대로 유지되게 함.

기본값: Qwen2.5-1.5B-Instruct (노트북 CPU에서도 실행 가능한 경량 모델)
워크스테이션/Colab에서 GPU 쓸 수 있으면 MODEL_NAME을 7B로 바꾸면 됨.
"""
import json
import re

MODEL_NAME = "Qwen/Qwen2.5-1.5B-Instruct"  # 워크스테이션 가능하면 "Qwen/Qwen2.5-7B-Instruct"로 변경

_model = None
_tokenizer = None


def _load_model():
    """모델을 최초 1회만 로드 (반복 호출 시 재사용)"""
    global _model, _tokenizer
    if _model is None:
        from transformers import AutoModelForCausalLM, AutoTokenizer
        import torch

        print(f"[llm_client] 모델 로딩 중: {MODEL_NAME} (최초 1회만, 시간이 걸릴 수 있습니다)")
        _tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        _model = AutoModelForCausalLM.from_pretrained(
            MODEL_NAME,
            torch_dtype=torch.float32,  # CPU 환경 고려. GPU면 torch.bfloat16 권장
            device_map="auto",
        )
    return _model, _tokenizer


def _extract_json(text: str) -> dict:
    """모델 출력에서 JSON 부분만 추출 (앞뒤에 설명이 붙어도 대응)"""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"JSON을 찾지 못함: {text[:200]}")
    return json.loads(match.group(0))


def generate_defense(prompt: str, max_new_tokens: int = 400) -> dict:
    """
    prompt -> {"summary": ..., "immediate_actions": [...], "long_term_actions": [...]}
    """
    model, tokenizer = _load_model()

    messages = [{"role": "user", "content": prompt}]
    text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(text, return_tensors="pt")

    outputs = model.generate(
        **inputs,
        max_new_tokens=max_new_tokens,
        temperature=0.3,  # 방어전략은 일관성이 중요하므로 낮게
        do_sample=True,
    )
    generated = tokenizer.decode(outputs[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)

    try:
        return _extract_json(generated)
    except (ValueError, json.JSONDecodeError) as e:
        print(f"[llm_client] JSON 파싱 실패, 원문 반환: {e}")
        return {"summary": generated.strip(), "immediate_actions": [], "long_term_actions": []}