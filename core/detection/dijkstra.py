"""
Dijkstra 기반 최적(최저비용) 공격 경로 탐색
가중치 = attack_cost * (1 - success_prob)  (계획서 6.3.3)
"""
import networkx as nx

def shortest_attack_path(G: nx.DiGraph, source: str, target: str):
    """공격자(source)로부터 target까지 최소비용 경로 반환"""
    raise NotImplementedError
