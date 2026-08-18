"""
웹과 core/app을 잇는 얇은 계층.
"""
from fastapi import APIRouter
from pydantic import BaseModel
from core.graph.vulnet_loader import load_vulnet_graph   # network_builder 대신
from app.pipeline import run_pipeline
from app.config import save_config, get_gemini_key
import app.defense_lookup as defense_lookup

router = APIRouter()

# vuln-net-ag 실제 네트워크 사용 (14.6절 이후 최종 전환)
_graph = load_vulnet_graph("data/vulnet_networks/50_20_powerlaw_uniform_1.json")


@router.get("/graph")
def get_graph():
    nodes = [{"id": str(n), **_graph.nodes[n]} for n in _graph.nodes]
    edges = [{"source": str(u), "target": str(v), **data} for u, v, data in _graph.edges(data=True)]
    return {"nodes": nodes, "edges": edges}


@router.get("/analysis")
def get_analysis():
    result = run_pipeline(_graph)
    return {
        "attack_path": [str(n) for n in result["feedback_path"]["path"]],
        "original_path": [str(n) for n in result["original_path"]["path"]],
        "path_changed": result["path_changed"],
        "risk_scores": {str(k): v for k, v in result["risk_scores"].items()},
        "defense_strategies": {str(d["node_id"]): d for d in result["defense_strategies"]},
    }


# ---- 관리자(설정) 기능은 기존과 동일 유지 ----

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
    from train.llm_client import reset_client
    reset_client()
    return {"status": "saved"}


@router.post("/admin/regenerate-defense")
def regenerate_defense():
    from app.inference import predict_risk
    from core.detection.dijkstra import shortest_attack_path
    from core.defense.prompt_builder import build_prompt, build_node_info
    from train.llm_client import generate_defense
    from core.defense.evaluator import match_rate
    import json

    risk = predict_risk(_graph)
    gateways = [n for n in _graph.nodes if _graph.nodes[n].get("zone") == "gateway"]
    source = gateways[0] if gateways else list(_graph.nodes)[0]
    target = max([n for n in _graph.nodes if n != source], key=lambda n: _graph.nodes[n].get("importance", 0))
    path = shortest_attack_path(_graph, source, target)["path"]
    targets = [n for n, s in risk.items() if s >= 0.6]

    results = []
    for node_id in targets:
        info = build_node_info(node_id, _graph, risk[node_id], path)
        prompt = build_prompt(info)
        strategy = generate_defense(prompt)
        eval_score = match_rate(info["cve"], strategy) if info["cve"] else None
        results.append({**info, "node_id": str(node_id), **strategy, "cisa_match_rate": eval_score})

    with open("data/defense_strategies.jsonl", "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")

    defense_lookup.reload()
    return {"status": "done", "count": len(results)}