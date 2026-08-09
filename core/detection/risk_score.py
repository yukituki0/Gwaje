"""
risk_score 라벨 생성 (연구방법론_정리.md 4.3절)
risk_score = w1*자기취약점 + w2*Dijkstra접근용이성 + w3*Weighted PageRank 전파
초기 가중치: w1=0.3, w2=0.3, w3=0.4 (실험 후 조정 예정, 4.3.1절)
"""
import networkx as nx

W1, W2, W3 = 0.3, 0.3, 0.4

def compute_risk_scores(G: nx.DiGraph, attacker_node: str) -> dict:
    """모든 노드의 risk_score 계산"""
    # TODO: w2 - nx.shortest_path_length(G, attacker_node, weight='cost') 역수
    # TODO: w3 - success_prob 가중 PageRank (nx.pagerank 참고, weight 파라미터 활용)
    raise NotImplementedError
