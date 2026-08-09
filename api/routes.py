"""
웹과 core/app을 잇는 얇은 계층. 새 로직 추가 없이 app.pipeline을 그대로 호출만 함 (9.1절 원칙).
"""
from fastapi import APIRouter
from core.graph.network_builder import build_base_network
from app.pipeline import run_pipeline

router = APIRouter()

# 그래프는 서버 실행 중 메모리에 유지 (나중에 동적 이벤트/타임스텝 반영 시 이 부분을 상태 관리로 확장)
_graph = build_base_network()


@router.get("/graph")
def get_graph():
    """노드/엣지 정보를 프론트엔드가 그릴 수 있는 형태로 반환"""
    nodes = [{"id": n, **_graph.nodes[n]} for n in _graph.nodes]
    edges = [{"source": u, "target": v, **data} for u, v, data in _graph.edges(data=True)]
    return {"nodes": nodes, "edges": edges}


@router.get("/analysis")
def get_analysis():
    """경로 + 위험도(GAT 추론) + 방어전략(사전생성 조회)을 한번에 반환 (6.7절 시각화용)"""
    result = run_pipeline(_graph)
    return {
        "attack_path": result["path"]["path"],
        "risk_scores": result["risk_scores"],
        "defense_strategies": {d["node_id"]: d for d in result["defense_strategies"]},
    }