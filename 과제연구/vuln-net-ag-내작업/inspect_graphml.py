"""
생성된 graphml 하나를 열어서 구조 확인
"""
import networkx as nx

G = nx.read_graphml("attack_graphs/NETSPA_5_5_lan25_uniform_0.25.graphml")

print(f"노드 수: {G.number_of_nodes()}, 엣지 수: {G.number_of_edges()}")
print(f"방향그래프 여부: {G.is_directed()}")

print("\n=== 노드 예시 (첫 3개) ===")
for i, (node, attrs) in enumerate(G.nodes(data=True)):
    print(node, attrs)
    if i >= 2:
        break

print("\n=== 엣지 예시 (첫 3개) ===")
for i, (u, v, attrs) in enumerate(G.edges(data=True)):
    print(f"{u} -> {v}", attrs)
    if i >= 2:
        break