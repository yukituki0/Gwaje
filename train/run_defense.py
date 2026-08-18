"""
[Colab 전용] risk_score 임계값 이상 노드에 대해 방어전략 사전생성 (7.5절)
실행: python -m train.run_defense
결과: data/defense_strategies.jsonl
앱은 이 결과를 app/defense_lookup.py로 조회만 함 (LLM 즉석 호출 없음).
"""
import json
import os
from core.graph.network_builder import build_base_network
from core.detection.risk_score import compute_risk_scores
from core.detection.dijkstra import shortest_attack_path
from core.defense.prompt_builder import build_prompt, build_node_info
from train.llm_client import generate_defense
from core.defense.evaluator import match_rate

RISK_THRESHOLD = 0.6  # 계획서 5.3.2 / 7.5절


def main():
    G = build_base_network()
    risk = compute_risk_scores(G, "attacker")
    main_path = shortest_attack_path(G, "attacker", "db_srv")["path"]

    targets = [node for node, score in risk.items() if score >= RISK_THRESHOLD]
    print(f"임계값 {RISK_THRESHOLD} 이상 노드 {len(targets)}개: {targets}")

    os.makedirs("data", exist_ok=True)
    with open("data/defense_strategies.jsonl", "w", encoding="utf-8") as f:
        for node_id in targets:
            info = build_node_info(node_id, G, risk[node_id], main_path)
            prompt = build_prompt(info)

            print(f"\n[{node_id}] 방어전략 생성 중...")
            strategy = generate_defense(prompt)

            eval_score = match_rate(info["cve"], strategy) if info["cve"] else None

            record = {**info, **strategy, "cisa_match_rate": eval_score}
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

            print(f"  summary: {strategy.get('summary', '')[:80]}...")
            if eval_score is not None:
                print(f"  CISA 일치율: {eval_score:.0%}")

    print("\n저장 완료: data/defense_strategies.jsonl")


if __name__ == "__main__":
    main()