"""
앱(웹/API)에서 호출하는 메인 파이프라인.
그래프 -> Dijkstra 경로 + GAT 추론 위험도 -> 사전 생성된 방어전략 조회
LLM 생성은 여기서 하지 않음 (colab/run_defense.py에서 미리 만들어 둠, 절충안 - 연구방법론_정리.md 9.2/7장).
"""
from core.detection.dijkstra import shortest_attack_path
from app.inference import predict_risk
from app.defense_lookup import get_defense

RISK_THRESHOLD = 0.6


def run_pipeline(G, attacker_node: str = "attacker", target_node: str = "db_srv") -> dict:
    path_result = shortest_attack_path(G, attacker_node, target_node)
    risk_scores = predict_risk(G)  # GAT 추론

    defense_results = []
    targets = [n for n, score in risk_scores.items() if score >= RISK_THRESHOLD]

    for node_id in targets:
        strategy = get_defense(node_id)  # LLM 즉석 호출 대신 사전 생성 결과 조회
        defense_results.append({"node_id": node_id, "risk_score": risk_scores[node_id], **strategy})

    return {
        "path": path_result,
        "risk_scores": risk_scores,
        "defense_strategies": defense_results,
    }


if __name__ == "__main__":
    from core.graph.network_builder import build_base_network
    G = build_base_network()
    result = run_pipeline(G)
    print("최적 경로:", " -> ".join(result["path"]["path"]))
    for d in result["defense_strategies"]:
        status = d.get("status", "generated")
        print(f"  {d['node_id']}: {status}, summary={str(d.get('summary'))[:50]}")