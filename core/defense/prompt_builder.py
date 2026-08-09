"""
방어전략 생성용 프롬프트 구성 (연구방법론_정리.md 7.3절)
"""
import json


def build_prompt(node_info: dict) -> str:
    """
    node_info: {node_id, risk_score, cve, position, attack_path, importance}
    """
    return f"""당신은 보안 담당자를 지원하는 방어전략 자문 시스템입니다.

아래 위험 노드 정보를 바탕으로 방어전략을 제시하세요.

[위험 노드 정보]
{json.dumps(node_info, ensure_ascii=False, indent=2)}

다음을 수행하세요:
1. 이 취약점의 핵심 위험을 1~2문장으로 요약
2. 즉시 조치(patch/설정변경 등) 3가지 이내를 우선순위와 함께 제시
3. 장기적 보완조치 1~2가지 제시

반드시 아래 JSON 형식으로만 답하세요. 다른 설명은 추가하지 마세요:
{{"summary": "...", "immediate_actions": ["...", "..."], "long_term_actions": ["...", "..."]}}
"""


def build_node_info(node_id: str, G, risk_score: float, main_path: list = None) -> dict:
    """그래프에서 노드 정보를 뽑아 LLM 입력용 dict로 변환"""
    attrs = G.nodes[node_id]
    # 이 노드로 들어오는 엣지 중 CVE가 있으면 대표로 사용
    cve = None
    for pred in G.predecessors(node_id):
        edge_cve = G[pred][node_id].get("cve")
        if edge_cve:
            cve = edge_cve
            break

    return {
        "node_id": node_id,
        "risk_score": round(risk_score, 4),
        "cve": cve,
        "position": attrs.get("zone", "unknown"),
        "attack_path": main_path or [],
        "importance": attrs.get("importance", 0.0),
    }