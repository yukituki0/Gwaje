"""
방어전략 생성 LLM 클라이언트 (연구방법론_정리.md 7.1절)
모델 교체 가능하도록 generate_defense() 하나로 감쌈
"""

def generate_defense(prompt: str) -> dict:
    """
    옵션 A: 워크스테이션/Colab Qwen2.5-7B-Instruct
    옵션 B: 경량 모델 (Qwen2.5-1.5B~3B)
    옵션 C: 최후 수단 API
    """
    raise NotImplementedError
