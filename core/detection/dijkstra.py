"""
Dijkstra 기반 최적(최저비용) 공격 경로 탐색
가중치 = attack_cost * (1 - success_prob)  (계획서 6.3.3)
  -> 비용이 낮을수록(공격이 쉽고 성공률 높을수록) 공격자에게 유리한 경로
"""
import networkx as nx


def add_dijkstra_weight(G: nx.DiGraph) -> nx.DiGraph:
    """모든 엣지에 'cost' 속성(Dijkstra용 가중치)을 계산해서 추가"""
    for u, v, data in G.edges(data=True):
        data["cost"] = data["attack_cost"] * (1 - data["success_prob"])
    return G


def shortest_attack_path(G: nx.DiGraph, source: str, target: str) -> dict:
    """공격자(source)로부터 target까지 최소비용 경로 반환"""
    G = add_dijkstra_weight(G)
    path = nx.dijkstra_path(G, source, target, weight="cost")
    total_cost = nx.dijkstra_path_length(G, source, target, weight="cost")

    edges = []
    for u, v in zip(path[:-1], path[1:]):
        edges.append((u, v, G[u][v]["cost"]))

    return {"path": path, "total_cost": total_cost, "edges": edges}


def all_shortest_costs_from(G: nx.DiGraph, source: str) -> dict:
    """source(공격자)로부터 모든 노드까지의 최소비용 (risk_score의 w2 접근용이성 계산에 사용)"""
    G = add_dijkstra_weight(G)
    return nx.single_source_dijkstra_path_length(G, source, weight="cost")


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from core.graph.network_builder import build_base_network

    G = build_base_network()
    result = shortest_attack_path(G, "attacker", "db_srv")

    print("최적 공격 경로:", " -> ".join(result["path"]))
    print(f"누적 비용: {result['total_cost']:.4f}")
    print("\n단계별 비용:")
    for u, v, cost in result["edges"]:
        print(f"  {u} -> {v}: {cost:.4f}")