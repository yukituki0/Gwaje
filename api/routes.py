"""
웹과 core/app을 잇는 얇은 계층.
"""
from fastapi import APIRouter
from pydantic import BaseModel
from core.graph.network_builder import build_base_network
from app.pipeline import run_pipeline
from app.config import save_config, get_gemini_key
import app.defense_lookup as defense_lookup

router = APIRouter()

_graph = build_base_network()


@router.get("/graph")
def get_graph():
    nodes = [{"id": n, **_graph.nodes[n]} for n in _graph.nodes]
    edges = [{"source": u, "target": v, **data} for u, v, data in _graph.edges(data=True)]
    return {"nodes": nodes, "edges": edges}


@router.get("/analysis")
def get_analysis():
    result = run_pipeline(_graph)
    return {
        "attack_path": result["path"]["path"],
        "risk_scores": result["risk_scores"],
        "defense_strategies": {d["node_id"]: d for d in result["defense_strategies"]},
    }


# ---- 관리자(설정) 기능 ----

class ApiKeyInput(BaseModel):
    gemini_api_key: str


@router.get("/settings")
def get_settings():
    key = get_gemini_key()
    masked = (key[:6] + "..." + key[-4:]) if len(key) > 10 else ""
    return {"gemini_api_key_set": bool(key), "gemini_api_key_masked": masked}


@router.post("/settings")
def set_settings(payload: ApiKeyInput):
    save_config({"gemini_api_key": payload.gemini_api_key})
    from colab.llm_client import reset_client
    reset_client()
    return {"status": "saved"}


@router.post("/admin/regenerate-defense")
def regenerate_defense():
    """위험 노드에 대해 방어전략을 다시 생성 (버튼 클릭으로 실행)"""
    from core.detection.risk_score import compute_risk_scores
    from core.detection.dijkstra import shortest_attack_path
    from core.defense.prompt_builder import build_prompt, build_node_info
    from colab.llm_client import generate_defense
    from core.defense.evaluator import match_rate
    import json

    risk = compute_risk_scores(_graph, "attacker")
    path = shortest_attack_path(_graph, "attacker", "db_srv")["path"]
    targets = [n for n, s in risk.items() if s >= 0.6]

    results = []
    for node_id in targets:
        info = build_node_info(node_id, _graph, risk[node_id], path)
        prompt = build_prompt(info)
        strategy = generate_defense(prompt)
        eval_score = match_rate(info["cve"], strategy) if info["cve"] else None
        results.append({**info, **strategy, "cisa_match_rate": eval_score})

    with open("data/defense_strategies.jsonl", "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    defense_lookup.reload()  # 캐시 갱신
    return {"status": "done", "count": len(results)}