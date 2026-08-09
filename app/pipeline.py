"""
앱(웹/API)에서 호출하는 메인 파이프라인.
그래프 -> Dijkstra 경로 + GAT 추론 위험도 -> 위험 노드에 대해 LLM 방어전략 생성
학습(train)은 절대 여기 포함되지 않음 (colab/train.py에서 미리 끝내고 옴).
"""
from core.detection.dijkstra import shortest_attack_path
from core.defense.prompt_builder import build_prompt, build_node_info
from core.defense.llm_client import generate_defense
from core.defense.evaluator import match_rate
from app.inference import predict_risk

RISK_THRESHOLD = 0.6


def run_pipeline(G, attacker_node: str = "attacker", target_node: str = "db_srv") -> dict:
    path_result = shortest_attack_path(G, attacker_node, target_node)
    risk_scores = predict_risk(G)  # risk_score.py(공식계산) 대신 GAT 추론 사용

    defense_results = []
    targets = [n for n, score in risk_scores.items() if score >= RISK_THRESHOLD]

    for node_id in targets:
        info = build_node_info(node_id, G, risk_scores[node_id], path_result["path"])
        prompt = build_prompt(info)
        strategy = generate_defense(prompt)
        eval_score = match_rate(info["cve"], strategy) if info["cve"] else None
        defense_results.append({**info, **strategy, "cisa_match_rate": eval_score})

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
    print(f"방어전략 생성된 노드 수: {len(result['defense_strategies'])}")