"""
사전 생성된 방어전략(defense_strategies.jsonl)을 조회하는 모듈.
LLM을 앱에서 직접 호출하지 않음 (7.1/9.2절 원칙 - 무거운 연산은 Colab에서 미리 끝냄).
새로운 노드/CVE 조합이라 사전 생성된 게 없으면, "생성 필요" 상태를 반환.
"""
import json
import os

_cache = None


def load_strategies(path: str = "data/defense_strategies.jsonl") -> dict:
    """node_id -> 방어전략 dict 로 캐싱해서 반환"""
    global _cache
    if _cache is None:
        _cache = {}
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    record = json.loads(line)
                    _cache[record["node_id"]] = record
        else:
            print(f"[defense_lookup] 경고: {path} 없음. 방어전략 없이 진행됩니다.")
    return _cache


def get_defense(node_id: str) -> dict:
    """
    사전 생성된 방어전략 조회.
    없으면 '생성 필요' 상태를 담은 placeholder 반환 (수동으로 Colab에서 추가 생성 필요함을 표시).
    """
    strategies = load_strategies()
    if node_id in strategies:
        return strategies[node_id]
    return {
        "node_id": node_id,
        "summary": None,
        "immediate_actions": [],
        "long_term_actions": [],
        "cisa_match_rate": None,
        "status": "not_generated",  # 앱/웹에서 이 상태면 "전략 생성 필요" 안내 표시
    }


def reload():
    """새로 생성된 jsonl을 다시 로드하고 싶을 때 호출 (캐시 초기화)"""
    global _cache
    _cache = None