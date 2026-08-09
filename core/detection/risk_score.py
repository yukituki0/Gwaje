"""
risk_score 라벨 생성 (연구방법론_정리.md 4.3, 4.3.1절)

risk_score = w1 * vulnerability_score (자기 취약점)
           + w2 * access_ease         (Dijkstra 접근용이성, predecessor 방향)
           + w3 * propagation_risk    (Personalized Weighted PageRank 전파, successor 방향)

초기 가중치: w1=0.3, w2=0.3, w3=0.4 (4.3.1절, 실험 후 조정 예정)

[구현 중 발견한 이슈 및 수정 (실험 로그)]
1. access_ease: 단순 역수+min-max 정규화는 attacker 자신의 cost~0 값이 극단치가 되어
   나머지 노드를 모두 0 근처로 뭉갬 -> 1/(1+cost) 형태의 bounded 변환으로 교체
2. propagation_risk: 일반 PageRank는 "얼마나 많은 링크를 받는가"만 반영해 실제 위험과
   무관하게 배경 노드가 과대평가됨 -> Personalized PageRank로 교체, 각 노드의
   vulnerability_score를 개인화 벡터(seed)로 사용해 "실제로 취약한 노드로부터 전파된
   위험"만 반영되도록 수정 (TargetNodeRank의 "목표 기준 중요도 정교화" 취지 반영)
"""
import networkx as nx
from core.detection.dijkstra import add_dijkstra_weight, all_shortest_costs_from

W1, W2, W3 = 0.3, 0.3, 0.4


def _min_max_normalize(values: dict) -> dict:
    vals = list(values.values())
    lo, hi = min(vals), max(vals)
    if hi - lo < 1e-9:
        return {k: 0.0 for k in values}
    return {k: (v - lo) / (hi - lo) for k, v in values.items()}


def compute_access_ease(G: nx.DiGraph, attacker_node: str) -> dict:
    """공격자로부터 각 노드까지 Dijkstra 누적비용 -> bounded 변환 (가까울수록 1에 가까움)"""
    costs = all_shortest_costs_from(G, attacker_node)
    ease = {node: 1.0 / (1.0 + cost) for node, cost in costs.items()}
    for node in G.nodes:
        if node not in ease:
            ease[node] = 0.0  # 도달 불가 노드
    return ease


def compute_propagation_risk(G: nx.DiGraph) -> dict:
    """
    Personalized PageRank: 각 노드의 vulnerability_score를 씨앗(seed)으로 사용.
    -> "실제로 취약한 노드"로부터 success_prob이 높은 경로를 타고 흘러온 위험만 반영.
    """
    vuln = {n: G.nodes[n].get("vulnerability_score", 0.0) for n in G.nodes}
    total = sum(vuln.values()) or 1.0
    personalization = {n: v / total for n, v in vuln.items()}

    pr = nx.pagerank(G, weight="success_prob", personalization=personalization)
    return _min_max_normalize(pr)


def compute_risk_scores(G: nx.DiGraph, attacker_node: str) -> dict:
    vuln = {n: G.nodes[n].get("vulnerability_score", 0.0) for n in G.nodes}
    ease = compute_access_ease(G, attacker_node)
    prop = compute_propagation_risk(G)

    risk = {}
    for n in G.nodes:
        risk[n] = W1 * vuln[n] + W2 * ease[n] + W3 * prop[n]
    return risk


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from core.graph.network_builder import build_base_network

    G = build_base_network()
    risk = compute_risk_scores(G, "attacker")

    print("=== risk_score (내림차순) ===")
    for node, score in sorted(risk.items(), key=lambda x: -x[1]):
        zone = G.nodes[node].get("zone", "?")
        marker = " <- 메인경로" if node in ["web_dmz", "internal_srv01", "domain_controller", "db_srv"] else ""
        print(f"  {node:20s} [{zone:8s}] risk_score={score:.4f}{marker}")