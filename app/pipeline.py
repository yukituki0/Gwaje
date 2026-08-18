"""
앱(웹/API)에서 호출하는 메인 파이프라인.
그래프 -> Dijkstra 경로 + GAT 추론 위험도 -> GAT 위험도를 엣지에 피드백 -> Dijkstra 재실행 -> 방어전략조회
"""
from core.detection.dijkstra import shortest_attack_path, add_dijkstra_weight
from app.inference import predict_risk
from app.defense_lookup import get_defense
import networkx as nx

RISK_THRESHOLD = 0.6


def apply_gat_feedback(G: nx.DiGraph, risk_scores: dict) -> nx.DiGraph:
    """
    GAT가 예측한 노드 위험도를 엣지 가중치에 반영한 새 그래프 반환.
    목적지 노드가 위험할수록(GAT 예측값이 높을수록) 그 엣지의 공격 비용을 낮춤
    -> Dijkstra가 "위험한 노드를 더 매력적인 경로"로 인식하게 됨.
    (14.9절: Kumar & Namdeo의 병렬 파이프라인과 달리, 실질적 결합을 구현)
    """
    G2 = G.copy()
    for u, v, data in G2.edges(data=True):
        target_risk = risk_scores.get(v, 0.0)
        original_cost = data["attack_cost"]
        # 위험도가 높을수록(0~1) 비용을 최대 50%까지 할인
        data["attack_cost"] = original_cost * (1.0 - 0.5 * target_risk)
    return G2


def run_pipeline(G, attacker_node=None, target_node=None) -> dict:
    if attacker_node is None:
        # gateway 타입 노드를 공격 시작점으로 (없으면 첫 번째 노드)
        gateways = [n for n in G.nodes if G.nodes[n].get("zone") == "gateway"]
        attacker_node = gateways[0] if gateways else list(G.nodes)[0]

    if target_node is None:
        # importance가 가장 높은 노드를 목표로 (동일하면 첫 번째)
        candidates = [n for n in G.nodes if n != attacker_node]
        target_node = max(candidates, key=lambda n: G.nodes[n].get("importance", 0))

    # 이하 기존과 동일
    risk_scores = predict_risk(G)
    original_path = shortest_attack_path(G, attacker_node, target_node)
    G_feedback = apply_gat_feedback(G, risk_scores)
    feedback_path = shortest_attack_path(G_feedback, attacker_node, target_node)
    path_changed = original_path["path"] != feedback_path["path"]

    defense_results = []
    targets = [n for n, score in risk_scores.items() if score >= RISK_THRESHOLD]
    for node_id in targets:
        strategy = get_defense(node_id)
        defense_results.append({"node_id": node_id, "risk_score": risk_scores[node_id], **strategy})

    return {
        "original_path": original_path,
        "feedback_path": feedback_path,
        "path_changed": path_changed,
        "risk_scores": risk_scores,
        "defense_strategies": defense_results,
    }


if __name__ == "__main__":
    from core.graph.network_builder import build_base_network
    G = build_base_network()
    result = run_pipeline(G)
    print("원래 경로:      ", " -> ".join(result["original_path"]["path"]))
    print("GAT 반영 경로:  ", " -> ".join(result["feedback_path"]["path"]))
    print("경로가 바뀌었나:", result["path_changed"])

    print("\n=== 노드별 GAT 예측 위험도 (내림차순) ===")
    for node, score in sorted(result["risk_scores"].items(), key=lambda x: -x[1]):
        print(f"  {node:20s} {score:.4f}")